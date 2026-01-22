use crate::Provider;

/// Configuration for a DNS provider
#[derive(Debug, Clone)]
pub struct DnsProviderConfig {
    /// Human-readable name of the provider
    pub name: &'static str,
    /// DoH (HTTP/2) endpoint URL
    pub doh_url: &'static str,
    /// DoT server IP address
    pub dot_host: &'static str,
    /// DoT server port (typically 853)
    pub dot_port: u16,
    /// DoT server hostname for TLS verification
    pub dot_hostname: &'static str,
    /// DoH3 (HTTP/3) endpoint URL
    pub doh3_url: &'static str,
    /// DoH3 server IP address
    pub doh3_host: &'static str,
    /// DoH3 server port (typically 443)
    pub doh3_port: u16,
    /// DoH3 server hostname for TLS verification
    pub doh3_hostname: &'static str,
}

impl DnsProviderConfig {
    /// Get the configuration for a specific provider
    pub fn from_provider(provider: &Provider) -> Self {
        match provider {
            Provider::Cloudflare => DnsProviderConfig {
                name: "Cloudflare",
                doh_url: "https://cloudflare-dns.com/dns-query",
                dot_host: "1.1.1.1",
                dot_port: 853,
                dot_hostname: "cloudflare-dns.com",
                doh3_url: "https://cloudflare-dns.com/dns-query",
                doh3_host: "1.1.1.1",
                doh3_port: 443,
                doh3_hostname: "cloudflare-dns.com",
            },
            Provider::Google => DnsProviderConfig {
                name: "Google",
                doh_url: "https://dns.google/dns-query",
                dot_host: "8.8.8.8",
                dot_port: 853,
                dot_hostname: "dns.google",
                doh3_url: "https://dns.google/dns-query",
                doh3_host: "8.8.8.8",
                doh3_port: 443,
                doh3_hostname: "dns.google",
            },
            Provider::Quad9 => DnsProviderConfig {
                name: "Quad9",
                doh_url: "https://dns.quad9.net/dns-query",
                dot_host: "9.9.9.9",
                dot_port: 853,
                dot_hostname: "dns.quad9.net",
                doh3_url: "https://dns.quad9.net/dns-query",
                doh3_host: "9.9.9.9",
                doh3_port: 443,
                doh3_hostname: "dns.quad9.net",
            },
            Provider::NextDns => DnsProviderConfig {
                name: "NextDNS",
                doh_url: "https://dns.nextdns.io/dns-query",
                dot_host: "45.90.28.0",
                dot_port: 853,
                dot_hostname: "dns.nextdns.io",
                doh3_url: "https://dns.nextdns.io/dns-query",
                doh3_host: "45.90.28.0",
                doh3_port: 443,
                doh3_hostname: "dns.nextdns.io",
            },
        }
    }
}
