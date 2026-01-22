use clap::{Parser, ValueEnum};
use colored::*;
use secure_dns_resolver::{DnsResolver, Provider, Protocol, RecordType, parse_ech_config};
use std::time::Instant;

#[derive(Debug, Clone, ValueEnum)]
enum CliProtocol {
    Doh,
    Dot,
    Doh3,
}

impl From<CliProtocol> for Protocol {
    fn from(p: CliProtocol) -> Self {
        match p {
            CliProtocol::Doh => Protocol::Doh,
            CliProtocol::Dot => Protocol::Dot,
            CliProtocol::Doh3 => Protocol::Doh3,
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
enum CliProvider {
    Cloudflare,
    Google,
    Quad9,
    Nextdns,
}

impl From<CliProvider> for Provider {
    fn from(p: CliProvider) -> Self {
        match p {
            CliProvider::Cloudflare => Provider::Cloudflare,
            CliProvider::Google => Provider::Google,
            CliProvider::Quad9 => Provider::Quad9,
            CliProvider::Nextdns => Provider::NextDns,
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
enum CliRecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Ns,
    Https,
    Svcb,
}

impl From<CliRecordType> for RecordType {
    fn from(r: CliRecordType) -> Self {
        match r {
            CliRecordType::A => RecordType::A,
            CliRecordType::Aaaa => RecordType::AAAA,
            CliRecordType::Cname => RecordType::CNAME,
            CliRecordType::Mx => RecordType::MX,
            CliRecordType::Txt => RecordType::TXT,
            CliRecordType::Ns => RecordType::NS,
            CliRecordType::Https => RecordType::HTTPS,
            CliRecordType::Svcb => RecordType::SVCB,
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "secure-dns-resolver")]
#[command(about = "A CLI utility for DNS-over-HTTPS, DNS-over-TLS, and DNS-over-HTTP/3 resolution")]
#[command(version)]
struct Args {
    /// Hostnames to resolve (space-separated)
    #[arg(required = true)]
    hostnames: Vec<String>,

    /// DNS provider to use
    #[arg(short, long, value_enum, default_value = "cloudflare")]
    provider: CliProvider,

    /// Protocol to use (DoH, DoT, or DoH3)
    #[arg(short = 'P', long, value_enum, default_value = "doh")]
    protocol: CliProtocol,

    /// DNS record type to query
    #[arg(short = 't', long, value_enum, default_value = "a")]
    record_type: CliRecordType,

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
    
    let protocol: Protocol = args.protocol.into();
    let record_type: RecordType = args.record_type.into();
    
    println!("{}", "═".repeat(60).cyan());
    println!("{}", "  Secure DNS Resolver".bold().cyan());
    println!("{}", "═".repeat(60).cyan());
    
    if args.verbose {
        println!("{}", "  [verbose] Verbose mode enabled".dimmed());
        println!("{}", format!("  [verbose] Protocol: {}", protocol).dimmed());
        println!("{}", format!("  [verbose] Record type: {}", record_type).dimmed());
        println!("{}", format!("  [verbose] Hostnames: {:?}", args.hostnames).dimmed());
    }
    
    let start = Instant::now();
    
    let resolver = DnsResolver::new();

    if args.race {
        println!(
            "\n{} {} via {}",
            "▶ Mode:".green().bold(),
            "Race (all providers, fastest wins)".cyan(),
            protocol
        );
        println!("{}", "─".repeat(50).dimmed());

        if args.ech {
            println!("{}", "  Fetching ECH Configs...".cyan());
            
            let ech_results = resolver
                .resolve_batch_race_raw(
                    &args.hostnames,
                    &protocol,
                    65,
                    args.verbose,
                )
                .await;

            for (hostname, result) in args.hostnames.iter().zip(ech_results.iter()) {
                match result {
                    Ok((raw_data, provider, elapsed)) => {
                        match parse_ech_config(raw_data) {
                            Some(ech_configs) => {
                                println!(
                                    "  {} {} [via {} in {:.2?}] ECH Config:",
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
                                    "  {} {} [via {} in {:.2?}] → {}",
                                    "○".blue(),
                                    hostname.yellow(),
                                    provider,
                                    elapsed,
                                    "No ECH config found in HTTPS record".dimmed()
                                );
                            }
                        }
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
            println!("{}", "─".repeat(50).dimmed());
        }

        let results = resolver
            .resolve_batch_race(
                &args.hostnames,
                &protocol,
                &record_type,
                args.verbose,
            )
            .await;

        println!("  {} Records:", format!("{}", record_type).cyan());

        for (hostname, result) in args.hostnames.iter().zip(results.iter()) {
            match result {
                Ok((addresses, provider, elapsed)) => {
                    println!(
                        "  {} {} [via {} in {:.2?}] → {}",
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
        let providers: Vec<Provider> = if args.all_providers {
            Provider::all()
        } else {
            vec![args.provider.into()]
        };

        for provider in &providers {
            println!(
                "\n{} {} via {}",
                "▶ Provider:".green().bold(),
                provider,
                protocol
            );
            println!("{}", "─".repeat(50).dimmed());

            if args.ech {
                println!("{}", "  Fetching ECH Configs...".cyan());
                
                let ech_results = resolver
                    .resolve_batch_raw(
                        &args.hostnames,
                        provider,
                        &protocol,
                        65,
                        args.verbose,
                    )
                    .await;

                for (hostname, result) in args.hostnames.iter().zip(ech_results.iter()) {
                    match result {
                        Ok(raw_data) => {
                            match parse_ech_config(raw_data) {
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
                            }
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
                println!("{}", "─".repeat(50).dimmed());
            }

            let results = resolver
                .resolve_batch(
                    &args.hostnames,
                    provider,
                    &protocol,
                    &record_type,
                    args.verbose,
                )
                .await;

            println!("  {} Records:", format!("{}", record_type).cyan());

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
    println!(
        "{} {:.2?}",
        "Total time:".dimmed(),
        elapsed
    );
    
    Ok(())
}
