use crate::providers::DnsProviderConfig;
use crate::RecordType;
use anyhow::{Context, Result};
use colored::*;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName};
use tokio_rustls::TlsConnector;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, RecordType as DnsRecordType};
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
        verbose: bool,
    ) -> Result<Vec<String>> {
        let addr = format!("{}:{}", provider.dot_host, provider.dot_port);

        if verbose {
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoT] → Connecting to {} ({}) for '{}' ({} query)",
                    provider.name,
                    addr,
                    hostname,
                    RecordType::from_code(record_type)
                )
                .dimmed()
            );
        }

        let start = Instant::now();

        let stream = TcpStream::connect(&addr)
            .await
            .context("Failed to connect to DoT server")?;

        let connect_elapsed = start.elapsed();

        if verbose {
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoT]   TCP connection established in {:.2?}",
                    connect_elapsed
                )
                .dimmed()
            );
        }

        let server_name = ServerName::try_from(provider.dot_hostname)
            .map_err(|_| anyhow::anyhow!("Invalid server name"))?;

        let connector = TlsConnector::from(self.tls_config.clone());

        let tls_start = Instant::now();
        let mut tls_stream = connector
            .connect(server_name, stream)
            .await
            .context("TLS handshake failed")?;

        let tls_elapsed = tls_start.elapsed();

        if verbose {
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoT]   TLS handshake completed in {:.2?}",
                    tls_elapsed
                )
                .dimmed()
            );
        }

        let query = self.build_dns_query(hostname, record_type)?;

        if verbose {
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoT] → Sending DNS query ({} bytes)",
                    query.len()
                )
                .dimmed()
            );
        }

        let len = (query.len() as u16).to_be_bytes();
        tls_stream.write_all(&len).await?;
        tls_stream.write_all(&query).await?;
        tls_stream.flush().await?;

        let query_start = Instant::now();

        let mut len_buf = [0u8; 2];
        tls_stream.read_exact(&mut len_buf).await?;
        let response_len = u16::from_be_bytes(len_buf) as usize;

        let mut response = vec![0u8; response_len];
        tls_stream.read_exact(&mut response).await?;

        let query_elapsed = query_start.elapsed();
        let total_elapsed = start.elapsed();

        if verbose {
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoT] ← Received response from {} ({} bytes) in {:.2?}",
                    provider.name, response_len, query_elapsed
                )
                .dimmed()
            );
            eprintln!(
                "{}",
                format!("  [verbose] [DoT]   Total time: {:.2?}", total_elapsed).dimmed()
            );
        }

        let result = self.parse_dns_response(&response);

        if verbose {
            match &result {
                Ok(records) => {
                    eprintln!(
                        "{}",
                        format!(
                            "  [verbose] [DoT] ✓ Parsed {} record(s) for '{}'",
                            records.len(),
                            hostname
                        )
                        .dimmed()
                    );
                    for record in records {
                        eprintln!("{}", format!("  [verbose] [DoT]   → {}", record).dimmed());
                    }
                }
                Err(e) => {
                    eprintln!(
                        "{}",
                        format!("  [verbose] [DoT] ✗ Failed to parse response: {}", e).red()
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
        let addr = format!("{}:{}", provider.dot_host, provider.dot_port);

        if verbose {
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoT] → Connecting to {} ({}) for '{}' ({} query, raw)",
                    provider.name,
                    addr,
                    hostname,
                    RecordType::from_code(record_type)
                )
                .dimmed()
            );
        }

        let start = Instant::now();

        let stream = TcpStream::connect(&addr)
            .await
            .context("Failed to connect to DoT server")?;

        if verbose {
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoT]   TCP connection established in {:.2?}",
                    start.elapsed()
                )
                .dimmed()
            );
        }

        let server_name = ServerName::try_from(provider.dot_hostname)
            .map_err(|_| anyhow::anyhow!("Invalid server name"))?;

        let connector = TlsConnector::from(self.tls_config.clone());
        let mut tls_stream = connector
            .connect(server_name, stream)
            .await
            .context("TLS handshake failed")?;

        if verbose {
            eprintln!(
                "{}",
                format!("  [verbose] [DoT]   TLS handshake completed").dimmed()
            );
        }

        let query = self.build_dns_query(hostname, record_type)?;

        if verbose {
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoT] → Sending DNS query ({} bytes)",
                    query.len()
                )
                .dimmed()
            );
        }

        let len = (query.len() as u16).to_be_bytes();
        tls_stream.write_all(&len).await?;
        tls_stream.write_all(&query).await?;
        tls_stream.flush().await?;

        let mut len_buf = [0u8; 2];
        tls_stream.read_exact(&mut len_buf).await?;
        let response_len = u16::from_be_bytes(len_buf) as usize;

        let mut response = vec![0u8; response_len];
        tls_stream.read_exact(&mut response).await?;

        if verbose {
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoT] ← Received response from {} ({} bytes) in {:.2?}",
                    provider.name,
                    response_len,
                    start.elapsed()
                )
                .dimmed()
            );
        }

        self.extract_raw_rdata(&response)
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
