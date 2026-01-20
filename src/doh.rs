use crate::providers::DnsProviderConfig;
use crate::RecordType;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use colored::*;
use std::time::Instant;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, RecordType as DnsRecordType};
use trust_dns_proto::serialize::binary::BinEncodable;

pub struct DohResolver {
    client: reqwest::Client,
}

impl DohResolver {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .build()
            .expect("Failed to build HTTP client");

        Self { client }
    }

    pub async fn resolve(
        &self,
        hostname: &str,
        provider: &DnsProviderConfig,
        record_type: u16,
        verbose: bool,
    ) -> Result<Vec<String>> {
        let query = self.build_dns_query(hostname, record_type)?;
        let encoded = URL_SAFE_NO_PAD.encode(&query);

        let url = format!("{}?dns={}", provider.doh_url, encoded);

        if verbose {
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoH] → Sending {} query for '{}' to {} ({})",
                    RecordType::from_code(record_type),
                    hostname,
                    provider.name,
                    provider.doh_url
                )
                .dimmed()
            );
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoH]   Query size: {} bytes (base64: {} chars)",
                    query.len(),
                    encoded.len()
                )
                .dimmed()
            );
        }

        let start = Instant::now();

        let response = self
            .client
            .get(&url)
            .header("Accept", "application/dns-message")
            .send()
            .await
            .context("Failed to send DoH request")?;

        let status = response.status();
        let elapsed = start.elapsed();

        if verbose {
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoH] ← Received response from {} in {:.2?} (HTTP {})",
                    provider.name, elapsed, status
                )
                .dimmed()
            );
        }

        if !status.is_success() {
            if verbose {
                eprintln!(
                    "{}",
                    format!(
                        "  [verbose] [DoH] ✗ Request failed with HTTP status: {}",
                        status
                    )
                    .red()
                );
            }
            anyhow::bail!("DoH request failed with status: {}", status);
        }

        let body = response.bytes().await?;

        if verbose {
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoH]   Response body size: {} bytes",
                    body.len()
                )
                .dimmed()
            );
        }

        let result = self.parse_dns_response(&body);

        if verbose {
            match &result {
                Ok(records) => {
                    eprintln!(
                        "{}",
                        format!(
                            "  [verbose] [DoH] ✓ Parsed {} record(s) for '{}'",
                            records.len(),
                            hostname
                        )
                        .dimmed()
                    );
                    for record in records {
                        eprintln!("{}", format!("  [verbose] [DoH]   → {}", record).dimmed());
                    }
                }
                Err(e) => {
                    eprintln!(
                        "{}",
                        format!("  [verbose] [DoH] ✗ Failed to parse response: {}", e).red()
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
        let encoded = URL_SAFE_NO_PAD.encode(&query);

        let url = format!("{}?dns={}", provider.doh_url, encoded);

        if verbose {
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoH] → Sending {} query (raw) for '{}' to {} ({})",
                    RecordType::from_code(record_type),
                    hostname,
                    provider.name,
                    provider.doh_url
                )
                .dimmed()
            );
        }

        let start = Instant::now();

        let response = self
            .client
            .get(&url)
            .header("Accept", "application/dns-message")
            .send()
            .await
            .context("Failed to send DoH request")?;

        let status = response.status();
        let elapsed = start.elapsed();

        if verbose {
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoH] ← Received response from {} in {:.2?} (HTTP {})",
                    provider.name, elapsed, status
                )
                .dimmed()
            );
        }

        if !status.is_success() {
            anyhow::bail!("DoH request failed with status: {}", status);
        }

        let body = response.bytes().await?;

        if verbose {
            eprintln!(
                "{}",
                format!(
                    "  [verbose] [DoH]   Response body size: {} bytes",
                    body.len()
                )
                .dimmed()
            );
        }

        self.extract_raw_rdata(&body)
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
