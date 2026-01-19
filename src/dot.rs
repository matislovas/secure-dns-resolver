use crate::providers::DnsProviderConfig;
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, ServerName, RootCertStore, OwnedTrustAnchor};
use tokio_rustls::TlsConnector;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, RecordType};
use trust_dns_proto::serialize::binary::BinEncodable;

pub struct DotResolver {
    tls_config: Arc<ClientConfig>,
}

impl DotResolver {
    pub fn new() -> Self {
        let mut root_store = RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject.as_ref(),
                ta.spki.as_ref(),
                ta.name_constraints.as_deref(),
            )
        }));

        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Self {
            tls_config: Arc::new(config),
        }
    }

    pub async fn resolve(
        &self,
        hostname: &str,
        provider: &DnsProviderConfig,
        record_type: u16,
    ) -> Result<Vec<String>> {
        let addr = format!("{}:{}", provider.dot_host, provider.dot_port);
        let stream = TcpStream::connect(&addr)
            .await
            .context("Failed to connect to DoT server")?;

        let server_name = ServerName::try_from(provider.dot_hostname)
            .map_err(|_| anyhow::anyhow!("Invalid server name"))?;

        let connector = TlsConnector::from(self.tls_config.clone());
        let mut tls_stream = connector
            .connect(server_name, stream)
            .await
            .context("TLS handshake failed")?;

        let query = self.build_dns_query(hostname, record_type)?;
        
        // DNS over TLS uses a 2-byte length prefix
        let len = (query.len() as u16).to_be_bytes();
        tls_stream.write_all(&len).await?;
        tls_stream.write_all(&query).await?;
        tls_stream.flush().await?;

        // Read response length
        let mut len_buf = [0u8; 2];
        tls_stream.read_exact(&mut len_buf).await?;
        let response_len = u16::from_be_bytes(len_buf) as usize;

        // Read response
        let mut response = vec![0u8; response_len];
        tls_stream.read_exact(&mut response).await?;

        self.parse_dns_response(&response)
    }

    /// Resolve and return raw RDATA bytes
    pub async fn resolve_raw(
        &self,
        hostname: &str,
        provider: &DnsProviderConfig,
        record_type: u16,
    ) -> Result<Vec<u8>> {
        let addr = format!("{}:{}", provider.dot_host, provider.dot_port);
        let stream = TcpStream::connect(&addr)
            .await
            .context("Failed to connect to DoT server")?;

        let server_name = ServerName::try_from(provider.dot_hostname)
            .map_err(|_| anyhow::anyhow!("Invalid server name"))?;

        let connector = TlsConnector::from(self.tls_config.clone());
        let mut tls_stream = connector
            .connect(server_name, stream)
            .await
            .context("TLS handshake failed")?;

        let query = self.build_dns_query(hostname, record_type)?;
        
        let len = (query.len() as u16).to_be_bytes();
        tls_stream.write_all(&len).await?;
        tls_stream.write_all(&query).await?;
        tls_stream.flush().await?;

        let mut len_buf = [0u8; 2];
        tls_stream.read_exact(&mut len_buf).await?;
        let response_len = u16::from_be_bytes(len_buf) as usize;

        let mut response = vec![0u8; response_len];
        tls_stream.read_exact(&mut response).await?;

        self.extract_raw_rdata(&response)
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
