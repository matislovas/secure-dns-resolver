//! # Secure DNS Resolver
//!
//! A fast, secure, and privacy-focused DNS resolution library supporting
//! DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), and DNS-over-HTTP/3 (DoH3).
//!
//! ## Features
//!
//! - Multiple secure protocols: DoH, DoT, DoH3
//! - Built-in providers: Cloudflare, Google, Quad9, NextDNS
//! - Concurrent resolution of multiple hostnames
//! - Race mode: query all providers, use fastest response
//! - ECH (Encrypted Client Hello) config fetching
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use secure_dns_resolver::{DnsResolver, Provider, Protocol, RecordType};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let resolver = DnsResolver::new();
//!     
//!     // Resolve a single hostname
//!     let result = resolver.resolve(
//!         "example.com",
//!         &Provider::Cloudflare,
//!         &Protocol::Doh,
//!         &RecordType::A,
//!         false, // verbose
//!     ).await?;
//!     
//!     println!("Resolved: {:?}", result);
//!     Ok(())
//! }
//! ```
//!
//! ## Race Mode Example
//!
//! ```rust,no_run
//! use secure_dns_resolver::{DnsResolver, Protocol, RecordType};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let resolver = DnsResolver::new();
//!     
//!     // Race all providers - fastest wins
//!     let hostnames = vec!["google.com".to_string(), "github.com".to_string()];
//!     let results = resolver.resolve_batch_race(
//!         &hostnames,
//!         &Protocol::Doh,
//!         &RecordType::A,
//!         false,
//!     ).await;
//!     
//!     for (hostname, result) in hostnames.iter().zip(results.iter()) {
//!         match result {
//!             Ok((addresses, provider, duration)) => {
//!                 println!("{} via {:?} in {:?}: {:?}", hostname, provider, duration, addresses);
//!             }
//!             Err(e) => println!("{}: Error - {}", hostname, e),
//!         }
//!     }
//!     Ok(())
//! }
//! ```

mod doh;
mod doh3;
mod dot;
mod ech;
mod providers;
mod resolver;

// Re-export main types
pub use providers::DnsProviderConfig;
pub use resolver::DnsResolver;

// Re-export ECH parsing functions
pub use ech::parse_ech_config;

use std::fmt;

/// DNS resolution protocol
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// DNS-over-HTTPS (HTTP/2)
    Doh,
    /// DNS-over-TLS
    Dot,
    /// DNS-over-HTTPS using HTTP/3 (QUIC)
    Doh3,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Doh => write!(f, "DoH"),
            Protocol::Dot => write!(f, "DoT"),
            Protocol::Doh3 => write!(f, "DoH3"),
        }
    }
}

/// DNS provider
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Provider {
    Cloudflare,
    Google,
    Quad9,
    NextDns,
}

impl Provider {
    /// Returns a list of all available providers
    pub fn all() -> Vec<Provider> {
        vec![
            Provider::Cloudflare,
            Provider::Google,
            Provider::Quad9,
            Provider::NextDns,
        ]
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Provider::Cloudflare => write!(f, "Cloudflare"),
            Provider::Google => write!(f, "Google"),
            Provider::Quad9 => write!(f, "Quad9"),
            Provider::NextDns => write!(f, "NextDNS"),
        }
    }
}

/// DNS record type
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    HTTPS,
    SVCB,
}

impl RecordType {
    /// Convert record type to DNS type code
    pub fn to_type_code(&self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::AAAA => 28,
            RecordType::CNAME => 5,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::NS => 2,
            RecordType::HTTPS => 65,
            RecordType::SVCB => 64,
        }
    }
    
    /// Convert DNS type code to record type name
    pub fn from_code(code: u16) -> &'static str {
        match code {
            1 => "A",
            28 => "AAAA",
            5 => "CNAME",
            15 => "MX",
            16 => "TXT",
            2 => "NS",
            65 => "HTTPS",
            64 => "SVCB",
            _ => "UNKNOWN",
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::AAAA => write!(f, "AAAA"),
            RecordType::CNAME => write!(f, "CNAME"),
            RecordType::MX => write!(f, "MX"),
            RecordType::TXT => write!(f, "TXT"),
            RecordType::NS => write!(f, "NS"),
            RecordType::HTTPS => write!(f, "HTTPS"),
            RecordType::SVCB => write!(f, "SVCB"),
        }
    }
}

/// Result of a DNS resolution with timing and provider information
#[derive(Debug, Clone)]
pub struct ResolutionResult {
    /// The hostname that was resolved
    pub hostname: String,
    /// The resolved addresses/records
    pub records: Vec<String>,
    /// The provider that responded
    pub provider: Provider,
    /// Time taken for the resolution
    pub duration: std::time::Duration,
}

/// Error types for DNS resolution
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("Connection failed: {0}")]
    ConnectionError(String),
    
    #[error("Query failed: {0}")]
    QueryError(String),
    
    #[error("No records found")]
    NoRecordsFound,
    
    #[error("All providers failed: {0}")]
    AllProvidersFailed(String),
    
    #[error("Invalid hostname: {0}")]
    InvalidHostname(String),
    
    #[error("TLS error: {0}")]
    TlsError(String),
    
    #[error("HTTP error: {0}")]
    HttpError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_type_codes() {
        assert_eq!(RecordType::A.to_type_code(), 1);
        assert_eq!(RecordType::AAAA.to_type_code(), 28);
        assert_eq!(RecordType::HTTPS.to_type_code(), 65);
    }

    #[test]
    fn test_provider_all() {
        let providers = Provider::all();
        assert_eq!(providers.len(), 4);
    }

    #[test]
    fn test_record_type_from_code() {
        assert_eq!(RecordType::from_code(1), "A");
        assert_eq!(RecordType::from_code(28), "AAAA");
        assert_eq!(RecordType::from_code(999), "UNKNOWN");
    }
}
