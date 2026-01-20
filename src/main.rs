mod doh;
mod doh3;
mod dot;
mod ech;
mod providers;
mod resolver;

use clap::{Parser, ValueEnum};
use colored::*;
use resolver::DnsResolver;
use std::time::Instant;

#[derive(Debug, Clone, ValueEnum)]
pub enum Protocol {
    /// DNS-over-HTTPS (HTTP/2)
    Doh,
    /// DNS-over-TLS
    Dot,
    /// DNS-over-HTTPS using HTTP/3 (QUIC)
    Doh3,
}

#[derive(Debug, Clone, ValueEnum, PartialEq, Eq, Hash)]
pub enum Provider {
    Cloudflare,
    Google,
    Quad9,
    NextDns,
    Nord,
}

impl Provider {
    pub fn all() -> Vec<Provider> {
        vec![
            Provider::Cloudflare,
            Provider::Google,
            Provider::Quad9,
            Provider::NextDns,
            Provider::Nord,
        ]
    }
}

#[derive(Debug, Clone, ValueEnum, PartialEq)]
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

#[derive(Parser, Debug)]
#[command(name = "secure-dns-resolver")]
#[command(about = "A CLI utility for DNS-over-HTTPS, DNS-over-TLS, and DNS-over-HTTP/3 resolution")]
#[command(version = "0.2.0")]
struct Args {
    /// Hostnames to resolve (space-separated)
    #[arg(required = true)]
    hostnames: Vec<String>,

    /// DNS provider to use
    #[arg(short, long, value_enum, default_value = "cloudflare")]
    provider: Provider,

    /// Protocol to use (DoH, DoT, or DoH3)
    #[arg(short = 'P', long, value_enum, default_value = "doh")]
    protocol: Protocol,

    /// DNS record type to query
    #[arg(short = 't', long, value_enum, default_value = "a")]
    record_type: RecordType,

    /// Show detailed output including all requests and responses
    #[arg(short, long)]
    verbose: bool,

    /// Query all providers simultaneously
    #[arg(short, long)]
    all_providers: bool,

    /// Fetch ECH (Encrypted Client Hello) config from HTTPS/SVCB records
    #[arg(short, long)]
    ech: bool,

    /// Race mode: query all providers simultaneously, use fastest response
    #[arg(short, long)]
    race: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    println!("{}", "═".repeat(60).cyan());
    println!("{}", "  Secure DNS Resolver".bold().cyan());
    println!("{}", "═".repeat(60).cyan());

    if args.verbose {
        println!("{}", "  [verbose] Verbose mode enabled".dimmed());
        println!(
            "{}",
            format!("  [verbose] Protocol: {:?}", args.protocol).dimmed()
        );
        println!(
            "{}",
            format!("  [verbose] Record type: {:?}", args.record_type).dimmed()
        );
        println!(
            "{}",
            format!("  [verbose] Hostnames: {:?}", args.hostnames).dimmed()
        );
    }

    let start = Instant::now();

    let resolver = DnsResolver::new();

    // Race mode: query all providers, use fastest response
    if args.race {
        println!(
            "\n{} {} via {:?}",
            "▶ Mode:".green().bold(),
            "Race (all providers, fastest wins)".cyan(),
            args.protocol
        );
        println!("{}", "─".repeat(50).dimmed());

        // ECH resolution with race
        if args.ech {
            println!("{}", "  Fetching ECH Configs...".cyan());

            let ech_results = resolver
                .resolve_batch_race_raw(
                    &args.hostnames,
                    &args.protocol,
                    65, // HTTPS record type
                    args.verbose,
                )
                .await;

            for (hostname, result) in args.hostnames.iter().zip(ech_results.iter()) {
                match result {
                    Ok((raw_data, provider, elapsed)) => match ech::parse_ech_config(raw_data) {
                        Some(ech_configs) => {
                            println!(
                                "  {} {} [via {:?} in {:.2?}] ECH Config:",
                                "✓".green().bold(),
                                hostname.yellow(),
                                provider,
                                elapsed,
                            );
                            for config in ech_configs {
                                println!("    {}", config.white());
                            }
                        }
                        None => {
                            println!(
                                "  {} {} [via {:?} in {:.2?}] → {}",
                                "○".blue(),
                                hostname.yellow(),
                                provider,
                                elapsed,
                                "No ECH config found in HTTPS record".dimmed()
                            );
                        }
                    },
                    Err(e) => {
                        println!(
                            "  {} {} → {}",
                            "✗".red().bold(),
                            hostname.yellow(),
                            e.to_string().red()
                        );
                    }
                }
            }
            println!("{}", "─".repeat(50).dimmed());
        }

        // Regular record resolution with race
        let results = resolver
            .resolve_batch_race(
                &args.hostnames,
                &args.protocol,
                &args.record_type,
                args.verbose,
            )
            .await;

        let record_type_str = format!("{:?}", args.record_type);
        println!("  {} Records:", record_type_str.cyan());

        for (hostname, result) in args.hostnames.iter().zip(results.iter()) {
            match result {
                Ok((addresses, provider, elapsed)) => {
                    println!(
                        "  {} {} [via {:?} in {:.2?}] → {}",
                        "✓".green().bold(),
                        hostname.yellow(),
                        provider,
                        elapsed,
                        addresses.join(", ").white()
                    );
                }
                Err(e) => {
                    println!(
                        "  {} {} → {}",
                        "✗".red().bold(),
                        hostname.yellow(),
                        e.to_string().red()
                    );
                }
            }
        }
    } else {
        // Original behavior: single or all providers
        let providers: Vec<Provider> = if args.all_providers {
            Provider::all()
        } else {
            vec![args.provider.clone()]
        };

        for provider in &providers {
            println!(
                "\n{} {:?} via {:?}",
                "▶ Provider:".green().bold(),
                provider,
                args.protocol
            );
            println!("{}", "─".repeat(50).dimmed());

            // ECH resolution
            if args.ech {
                println!("{}", "  Fetching ECH Configs...".cyan());

                let ech_results = resolver
                    .resolve_batch_raw(
                        &args.hostnames,
                        provider,
                        &args.protocol,
                        65, // HTTPS record type
                        args.verbose,
                    )
                    .await;

                for (hostname, result) in args.hostnames.iter().zip(ech_results.iter()) {
                    match result {
                        Ok(raw_data) => match ech::parse_ech_config(raw_data) {
                            Some(ech_configs) => {
                                println!(
                                    "  {} {} ECH Config:",
                                    "✓".green().bold(),
                                    hostname.yellow(),
                                );
                                for config in ech_configs {
                                    println!("    {}", config.white());
                                }
                            }
                            None => {
                                println!(
                                    "  {} {} → {}",
                                    "○".blue(),
                                    hostname.yellow(),
                                    "No ECH config found in HTTPS record".dimmed()
                                );
                            }
                        },
                        Err(e) => {
                            println!(
                                "  {} {} → {}",
                                "✗".red().bold(),
                                hostname.yellow(),
                                e.to_string().red()
                            );
                        }
                    }
                }
                println!("{}", "─".repeat(50).dimmed());
            }

            // Regular record resolution - all hostnames sent concurrently
            let results = resolver
                .resolve_batch(
                    &args.hostnames,
                    provider,
                    &args.protocol,
                    &args.record_type,
                    args.verbose,
                )
                .await;

            let record_type_str = format!("{:?}", args.record_type);
            println!("  {} Records:", record_type_str.cyan());

            for (hostname, result) in args.hostnames.iter().zip(results.iter()) {
                match result {
                    Ok(addresses) => {
                        println!(
                            "  {} {} → {}",
                            "✓".green().bold(),
                            hostname.yellow(),
                            addresses.join(", ").white()
                        );
                    }
                    Err(e) => {
                        println!(
                            "  {} {} → {}",
                            "✗".red().bold(),
                            hostname.yellow(),
                            e.to_string().red()
                        );
                    }
                }
            }
        }
    }

    let elapsed = start.elapsed();
    println!("\n{}", "═".repeat(60).cyan());
    println!("{} {:.2?}", "Total time:".dimmed(), elapsed);

    Ok(())
}
