use crate::providers::DnsProviderConfig;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, RecordType};
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
    ) -> Result<Vec<String>> {
        let query = self.build_dns_query(hostname, record_type)?;
        let encoded = URL_SAFE_NO_PAD.encode(&query);
        
        let url = format!("{}?dns={}", provider.doh_url, encoded);
        
        let response = self
            .client
            .get(&url)
            .header("Accept", "application/dns-message")
            .send()
            .await
            .context("Failed to send DoH request")?;
        
        if !response.status().is_success() {
            anyhow::bail!("DoH request failed with status: {}", response.status());
        }
        
        let body = response.bytes().await?;
        self.parse_dns_response(&body)
    }

    /// Resolve and return raw RDATA bytes
    pub async fn resolve_raw(
        &self,
        hostname: &str,
        provider: &DnsProviderConfig,
        record_type: u16,
    ) -> Result<Vec<u8>> {
        let query = self.build_dns_query(hostname, record_type)?;
        let encoded = URL_SAFE_NO_PAD.encode(&query);
        
        let url = format!("{}?dns={}", provider.doh_url, encoded);
        
        let response = self
            .client
            .get(&url)
            .header("Accept", "application/dns-message")
            .send()
            .await
            .context("Failed to send DoH request")?;
        
        if !response.status().is_success() {
            anyhow::bail!("DoH request failed with status: {}", response.status());
        }
        
        let body = response.bytes().await?;
        self.extract_raw_rdata(&body)
    }

    fn build_dns_query(&self, hostname: &str, record_type: u16) -> Result<Vec<u8>> {
        let name = Name::from_ascii(hostname)
            .context("Invalid hostname")?;
        
        let record_type = RecordType::from(record_type);
        
        let mut message = Message::new();
        message.set_id(rand::random());
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);
        
        let query = Query::query(name, record_type);
        message.add_query(query);
        
        let bytes = message.to_bytes()
            .context("Failed to encode DNS query")?;
        
        Ok(bytes)
    }

    fn parse_dns_response(&self, data: &[u8]) -> Result<Vec<String>> {
        let message = Message::from_vec(data)
            .context("Failed to parse DNS response")?;
        
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
        let message = Message::from_vec(data)
            .context("Failed to parse DNS response")?;
        
        for answer in message.answers() {
            if let Some(rdata) = answer.data() {
                // Get the raw bytes from the RDATA
                use trust_dns_proto::serialize::binary::BinEncodable;
                if let Ok(bytes) = rdata.to_bytes() {
                    return Ok(bytes);
                }
            }
        }
        
        anyhow::bail!("No RDATA found in response")
    }
}
