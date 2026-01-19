use crate::providers::DnsProviderConfig;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Buf;
use h3::client::SendRequest;
use h3_quinn::OpenStreams;
use quinn::{ClientConfig, Endpoint};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, RecordType};
use trust_dns_proto::serialize::binary::BinEncodable;

pub struct Doh3Resolver {
    client_config: ClientConfig,
}

impl Doh3Resolver {
    pub fn new() -> Self {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject.as_ref(),
                ta.spki.as_ref(),
                ta.name_constraints.as_deref(),
            )
        }));

        let mut tls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        tls_config.alpn_protocols = vec![b"h3".to_vec()];

        let client_config = ClientConfig::new(Arc::new(tls_config));

        Self { client_config }
    }

    pub async fn resolve(
        &self,
        hostname: &str,
        provider: &DnsProviderConfig,
        record_type: u16,
    ) -> Result<Vec<String>> {
        let query = self.build_dns_query(hostname, record_type)?;
        let response = self.send_doh3_request(provider, &query).await?;
        self.parse_dns_response(&response)
    }

    pub async fn resolve_raw(
        &self,
        hostname: &str,
        provider: &DnsProviderConfig,
        record_type: u16,
    ) -> Result<Vec<u8>> {
        let query = self.build_dns_query(hostname, record_type)?;
        let response = self.send_doh3_request(provider, &query).await?;
        self.extract_raw_rdata(&response)
    }

    async fn send_doh3_request(
        &self,
        provider: &DnsProviderConfig,
        dns_query: &[u8],
    ) -> Result<Vec<u8>> {
        // Resolve the server address
        let server_addr = self.resolve_server_addr(provider)?;

        // Create QUIC endpoint
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)?;
        endpoint.set_default_client_config(self.client_config.clone());

        // Connect to the server
        let connection = endpoint
            .connect(server_addr, provider.doh3_hostname)?
            .await
            .context("Failed to establish QUIC connection")?;

        // Create HTTP/3 connection
        let quinn_conn = h3_quinn::Connection::new(connection);
        let (mut driver, send_request) = h3::client::new(quinn_conn)
            .await
            .context("Failed to create HTTP/3 connection")?;

        // Drive the connection in the background
        let drive_fut = async move {
            std::future::poll_fn(|cx| driver.poll_close(cx)).await?;
            Ok::<(), h3::Error>(())
        };

        // Send the request
        let request_fut = self.send_request(send_request, provider, dns_query);

        // Run both concurrently
        let result = tokio::select! {
            result = request_fut => result,
            result = drive_fut => {
                result?;
                Err(anyhow::anyhow!("Connection closed unexpectedly"))
            }
        };

        endpoint.wait_idle().await;
        result
    }

    async fn send_request(
        &self,
        mut send_request: SendRequest<OpenStreams, bytes::Bytes>,
        provider: &DnsProviderConfig,
        dns_query: &[u8],
    ) -> Result<Vec<u8>> {
        let encoded = URL_SAFE_NO_PAD.encode(dns_query);
        let uri = format!("{}?dns={}", provider.doh3_url, encoded);

        let request = http::Request::builder()
            .method("GET")
            .uri(&uri)
            .header("accept", "application/dns-message")
            .body(())
            .context("Failed to build HTTP request")?;

        let mut stream = send_request
            .send_request(request)
            .await
            .context("Failed to send HTTP/3 request")?;

        stream.finish().await.context("Failed to finish request")?;

        let response = stream
            .recv_response()
            .await
            .context("Failed to receive HTTP/3 response")?;

        if !response.status().is_success() {
            anyhow::bail!("HTTP/3 request failed with status: {}", response.status());
        }

        // Read response body
        let mut body = Vec::new();
        while let Some(chunk) = stream
            .recv_data()
            .await
            .context("Failed to receive response data")?
        {
            body.extend_from_slice(chunk.chunk());
        }

        Ok(body)
    }

    fn resolve_server_addr(&self, provider: &DnsProviderConfig) -> Result<SocketAddr> {
        // Use the IP address directly if available, otherwise resolve
        let addr_str = format!("{}:{}", provider.doh3_host, provider.doh3_port);
        addr_str
            .to_socket_addrs()
            .context("Failed to resolve server address")?
            .next()
            .context("No address found for server")
    }

    fn build_dns_query(&self, hostname: &str, record_type: u16) -> Result<Vec<u8>> {
        let name = Name::from_ascii(hostname).context("Invalid hostname")?;
        let record_type = RecordType::from(record_type);

        let mut message = Message::new();
        message.set_id(rand::random());
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);

        let query = Query::query(name, record_type);
        message.add_query(query);

        let bytes = message.to_bytes().context("Failed to encode DNS query")?;
        Ok(bytes)
    }

    fn parse_dns_response(&self, data: &[u8]) -> Result<Vec<String>> {
        let message = Message::from_vec(data).context("Failed to parse DNS response")?;

        let mut results = Vec::new();

        for answer in message.answers() {
            let rdata = answer.data().map(|d| format!("{}", d));
            if let Some(data) = rdata {
                results.push(data);
            }
        }

        if results.is_empty() {
            anyhow::bail!("No records found");
        }

        Ok(results)
    }

    fn extract_raw_rdata(&self, data: &[u8]) -> Result<Vec<u8>> {
        let message = Message::from_vec(data).context("Failed to parse DNS response")?;

        for answer in message.answers() {
            if let Some(rdata) = answer.data() {
                use trust_dns_proto::serialize::binary::BinEncodable;
                if let Ok(bytes) = rdata.to_bytes() {
                    return Ok(bytes);
                }
            }
        }

        anyhow::bail!("No RDATA found in response")
    }
}
