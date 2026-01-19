# Secure DNS Resolver

A fast, secure, and privacy-focused DNS resolution CLI utility written in Rust. It supports DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), and DNS-over-HTTP/3 (DoH3) protocols with multiple built-in DNS providers.

## Features

- **Multiple Secure Protocols**:
  - DNS-over-HTTPS (DoH) using HTTP/2
  - DNS-over-TLS (DoT)
  - DNS-over-HTTP/3 (DoH3) using QUIC

- **Built-in DNS Providers**:
  - Cloudflare (1.1.1.1)
  - Google (8.8.8.8)
  - Quad9 (9.9.9.9) (no DoH3 support)
  - NextDNS (45.90.28.0)

- **Concurrent Resolution**: Resolves multiple hostnames simultaneously using async Tokio runtime

- **Provider Shuffling**: Randomly select providers per hostname with automatic fallback on failure

- **ECH Support**: Fetch Encrypted Client Hello (ECH) configurations from HTTPS/SVCB records

- **Multiple Record Types**: A, AAAA, CNAME, MX, TXT, NS, HTTPS, SVCB

## Requirements

- Rust 1.70 or later
- Linux (primary target), macOS, or Windows

## Building from Source

### 1. Install Rust

If you don't have Rust installed, install it using rustup:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### 2. Clone or Create the Project

```bash
mkdir secure-dns-resolver
cd secure-dns-resolver
```

### 3. Build the Project

```bash
cargo build
```

The binary will be located at ./target/debug/secure-dns-resolver

## Usage

```bash
# Use defaults (Cloudflare, DoH)
secure-dns-resolver api.nordvpn.com example.com 15min.lt crypto.cloudflare.com

# Use DoH3 (DNS-over-HTTP3) and shuffle between providers (each resolution to randomly selecetd provider)
secure-dns-resolver --shuffle -P doh3 api.nordvpn.com example.com 15min.lt google.com crypto.cloudflare.com

# Use DoT (DNS-over-TLS) and google's DNS
secure-dns-resolver -p google -P dot api.nordvpn.com example.com 15min.lt google.com crypto.cloudflare.com

# Fetches ech (encrypted-client-hello) info (if available)
secure-dns-resolver --ech api.nordvpn.com example.com 15min.lt google.com crypto.cloudflare.com

```
