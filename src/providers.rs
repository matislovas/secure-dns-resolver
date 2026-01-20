use crate::Provider;

#[derive(Debug, Clone)]
pub struct DnsProviderConfig {
    pub name: &'static str,
    // DoH (HTTP/2) settings
    pub doh_url: &'static str,
    // DoT settings
    pub dot_host: &'static str,
    pub dot_port: u16,
    pub dot_hostname: &'static str,
    // DoH3 (HTTP/3) settings
    pub doh3_url: &'static str,
    pub doh3_host: &'static str,
    pub doh3_port: u16,
    pub doh3_hostname: &'static str,
}

impl DnsProviderConfig {
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
            Provider::Nord => DnsProviderConfig {
                name: "Nordsec",

                doh_url: "https://dns1.nordvpn.com/dns-query",

                dot_host: "103.86.99.112",
                dot_port: 853,
                dot_hostname: "dns1.nordvpn.com",

                doh3_url: "https://dns1.nordvpn.com/dns-query",
                doh3_host: "103.86.99.112",
                doh3_port: 443,
                doh3_hostname: "dns1.nordvpn.com",
            },
        }
    }
}
