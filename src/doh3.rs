use crate::providers::DnsProviderConfig;
use crate::RecordType;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Buf;
use colored::*;
use h3::client::SendRequest;
use h3_quinn::OpenStreams;
use quinn::{ClientConfig, Endpoint};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Instant;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, RecordType as DnsRecordType};
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
        verbose: bool,
    ) -> Result<Vec<String>> {
        let query = self.build_dns_query(hostname, record_type)?;
        let response = self
            .send_doh3_request(provider, &query, hostname, record_type, verbose)
            .await?;

        let result = self.parse_dns_response(&response);

        if verbose {
            match &result {
                Ok(records) => {
                    eprintln!(
                        "{}",
                        format!(
                            "  [verbose] [DoH3] ✓ Parsed {} record(s) for '{}'",
                            records.len(),
                            hostname
                        )
                        .dimmed()
                    );
                    for record in records {
                        eprintln!("{}", format!("  [verbose] [DoH3]   → {}", record).dimmed());
                    }
                }
                Err(e) => {
                    eprintln!(
                        "{}",
                        format!("  [verbose] [DoH3] ✗ Failed to parse response: {}", e).red()
                    );
                }
            }
        }

        result
    }

    pub async fn resolve_raw(
        &self,
        hostname: &str,
        provider: &DnsProviderConfig,
        record_type: u16,
        verbose: bool,
    ) -> Result<Vec<u8>> {
        let query = self.build_dns_query(hostname, record_type)?;
        let response = self
            .send_doh3_request(provider, &query, hostname, record_type, verbose)
            .await?;
        self.extract_raw_rdata(&response)
    }

    async fn send_doh3_request(
        &self,
        provider: &DnsProviderConfig,
        dns_query: &[u8],
        hostname: &str,
        record_type: u16,
        verbose: bool,
    ) -> Result<Vec<u8>> {
        let server_addr = self.resolve_server_addr(provider)?;

        if verbose {
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoH3] → Connecting to {} ({}) for '{}' ({} query)",
                    provider.name,
                    server_addr,
                    hostname,
                    RecordType::from_code(record_type)
                )
                .dimmed()
            );
        }

        let start = Instant::now();

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)?;
        endpoint.set_default_client_config(self.client_config.clone());

        if verbose {
            eprintln!(
                "{}",
                format!("  [verbose] [DoH3]   QUIC endpoint created, initiating connection...")
                    .dimmed()
            );
        }

        let connection = endpoint
            .connect(server_addr, provider.doh3_hostname)?
            .await
            .context("Failed to establish QUIC connection")?;

        let quic_elapsed = start.elapsed();

        if verbose {
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoH3]   QUIC connection established in {:.2?}",
                    quic_elapsed
                )
                .dimmed()
            );
        }

        let quinn_conn = h3_quinn::Connection::new(connection);
        let (mut driver, send_request) = h3::client::new(quinn_conn)
            .await
            .context("Failed to create HTTP/3 connection")?;

        if verbose {
            eprintln!(
                "{}",
                format!("  [verbose] [DoH3]   HTTP/3 session established").dimmed()
            );
        }

        let drive_fut = async move {
            std::future::poll_fn(|cx| driver.poll_close(cx)).await?;
            Ok::<(), h3::Error>(())
        };

        let request_fut = self.send_request(send_request, provider, dns_query, hostname, verbose);

        let result = tokio::select! {
            result = request_fut => result,
            result = drive_fut => {
                result?;
                Err(anyhow::anyhow!("Connection closed unexpectedly"))
            }
        };

        let total_elapsed = start.elapsed();

        if verbose {
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoH3]   Total request time: {:.2?}",
                    total_elapsed
                )
                .dimmed()
            );
        }

        endpoint.wait_idle().await;
        result
    }

    async fn send_request(
        &self,
        mut send_request: SendRequest<OpenStreams, bytes::Bytes>,
        provider: &DnsProviderConfig,
        dns_query: &[u8],
        hostname: &str,
        verbose: bool,
    ) -> Result<Vec<u8>> {
        let encoded = URL_SAFE_NO_PAD.encode(dns_query);
        let uri = format!("{}?dns={}", provider.doh3_url, encoded);

        if verbose {
            eprintln!(
                "{}",
                format!("  [verbose] [DoH3] → Sending HTTP/3 GET request").dimmed()
            );
            eprintln!("{}", format!("  [verbose] [DoH3]   URI: {}", uri).dimmed());
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoH3]   Query size: {} bytes (base64: {} chars)",
                    dns_query.len(),
                    encoded.len()
                )
                .dimmed()
            );
        }

        let request = http::Request::builder()
            .method("GET")
            .uri(&uri)
            .header("accept", "application/dns-message")
            .body(())
            .context("Failed to build HTTP request")?;

        let request_start = Instant::now();

        let mut stream = send_request
            .send_request(request)
            .await
            .context("Failed to send HTTP/3 request")?;

        stream.finish().await.context("Failed to finish request")?;

        let response = stream
            .recv_response()
            .await
            .context("Failed to receive HTTP/3 response")?;

        let status = response.status();
        let response_elapsed = request_start.elapsed();

        if verbose {
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoH3] ← Received HTTP/3 response (HTTP {}) in {:.2?}",
                    status, response_elapsed
                )
                .dimmed()
            );
        }

        if !status.is_success() {
            if verbose {
                eprintln!(
                    "{}",
                    format!(
                        "  [verbose] [DoH3] ✗ Request failed with HTTP status: {}",
                        status
                    )
                    .red()
                );
            }
            anyhow::bail!("HTTP/3 request failed with status: {}", status);
        }

        let mut body = Vec::new();
        while let Some(chunk) = stream
            .recv_data()
            .await
            .context("Failed to receive response data")?
        {
            body.extend_from_slice(chunk.chunk());
        }

        if verbose {
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoH3]   Response body: {} bytes for '{}'",
                    body.len(),
                    hostname
                )
                .dimmed()
            );
        }

        Ok(body)
    }

    fn resolve_server_addr(&self, provider: &DnsProviderConfig) -> Result<SocketAddr> {
        let addr_str = format!("{}:{}", provider.doh3_host, provider.doh3_port);
        addr_str
            .to_socket_addrs()
            .context("Failed to resolve server address")?
            .next()
            .context("No address found for server")
    }

    fn build_dns_query(&self, hostname: &str, record_type: u16) -> Result<Vec<u8>> {
        let name = Name::from_ascii(hostname).context("Invalid hostname")?;
        let record_type = DnsRecordType::from(record_type);

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
