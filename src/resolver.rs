use crate::doh::DohResolver;
use crate::doh3::Doh3Resolver;
use crate::dot::DotResolver;
use crate::providers::DnsProviderConfig;
use crate::{Protocol, Provider, RecordType};
use anyhow::Result;
use futures::future::select_ok;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

pub struct DnsResolver {
    doh: Arc<DohResolver>,
    dot: Arc<DotResolver>,
    doh3: Arc<Doh3Resolver>,
}

impl DnsResolver {
    pub fn new() -> Self {
        Self {
            doh: Arc::new(DohResolver::new()),
            dot: Arc::new(DotResolver::new()),
            doh3: Arc::new(Doh3Resolver::new()),
        }
    }

    /// Resolve all hostnames concurrently using a single provider
    pub async fn resolve_batch(
        &self,
        hostnames: &[String],
        provider: &Provider,
        protocol: &Protocol,
        record_type: &RecordType,
        verbose: bool,
    ) -> Vec<Result<Vec<String>>> {
        let config = DnsProviderConfig::from_provider(provider);
        let type_code = record_type.to_type_code();

        let mut handles: Vec<JoinHandle<Result<Vec<String>>>> = Vec::new();

        // Send all queries concurrently
        for hostname in hostnames {
            let hostname = hostname.clone();
            let config = config.clone();
            let doh = Arc::clone(&self.doh);
            let dot = Arc::clone(&self.dot);
            let doh3 = Arc::clone(&self.doh3);
            let protocol = protocol.clone();

            let handle = tokio::spawn(async move {
                match protocol {
                    Protocol::Doh => doh.resolve(&hostname, &config, type_code, verbose).await,
                    Protocol::Dot => dot.resolve(&hostname, &config, type_code, verbose).await,
                    Protocol::Doh3 => doh3.resolve(&hostname, &config, type_code, verbose).await,
                }
            });

            handles.push(handle);
        }

        // Collect all results
        let mut results = Vec::new();
        for handle in handles {
            let result = handle
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("Task failed: {}", e)));
            results.push(result);
        }

        results
    }

    /// Resolve batch and return raw record data (for ECH parsing)
    pub async fn resolve_batch_raw(
        &self,
        hostnames: &[String],
        provider: &Provider,
        protocol: &Protocol,
        type_code: u16,
        verbose: bool,
    ) -> Vec<Result<Vec<u8>>> {
        let config = DnsProviderConfig::from_provider(provider);

        let mut handles: Vec<JoinHandle<Result<Vec<u8>>>> = Vec::new();

        for hostname in hostnames {
            let hostname = hostname.clone();
            let config = config.clone();
            let doh = Arc::clone(&self.doh);
            let dot = Arc::clone(&self.dot);
            let doh3 = Arc::clone(&self.doh3);
            let protocol = protocol.clone();

            let handle = tokio::spawn(async move {
                match protocol {
                    Protocol::Doh => {
                        doh.resolve_raw(&hostname, &config, type_code, verbose)
                            .await
                    }
                    Protocol::Dot => {
                        dot.resolve_raw(&hostname, &config, type_code, verbose)
                            .await
                    }
                    Protocol::Doh3 => {
                        doh3.resolve_raw(&hostname, &config, type_code, verbose)
                            .await
                    }
                }
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            let result = handle
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("Task failed: {}", e)));
            results.push(result);
        }

        results
    }

    /// Race mode: resolve each hostname by racing all providers simultaneously
    /// Returns the result from whichever provider responds first
    pub async fn resolve_batch_race(
        &self,
        hostnames: &[String],
        protocol: &Protocol,
        record_type: &RecordType,
        verbose: bool,
    ) -> Vec<Result<(Vec<String>, Provider, Duration)>> {
        let type_code = record_type.to_type_code();

        let mut handles: Vec<JoinHandle<Result<(Vec<String>, Provider, Duration)>>> = Vec::new();

        for hostname in hostnames {
            let hostname = hostname.clone();
            let doh = Arc::clone(&self.doh);
            let dot = Arc::clone(&self.dot);
            let doh3 = Arc::clone(&self.doh3);
            let protocol = protocol.clone();

            let handle = tokio::spawn(async move {
                Self::race_providers(hostname, doh, dot, doh3, protocol, type_code, verbose).await
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            let result = handle
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("Task failed: {}", e)));
            results.push(result);
        }

        results
    }

    /// Race mode for raw data (ECH parsing)
    pub async fn resolve_batch_race_raw(
        &self,
        hostnames: &[String],
        protocol: &Protocol,
        type_code: u16,
        verbose: bool,
    ) -> Vec<Result<(Vec<u8>, Provider, Duration)>> {
        let mut handles: Vec<JoinHandle<Result<(Vec<u8>, Provider, Duration)>>> = Vec::new();

        for hostname in hostnames {
            let hostname = hostname.clone();
            let doh = Arc::clone(&self.doh);
            let dot = Arc::clone(&self.dot);
            let doh3 = Arc::clone(&self.doh3);
            let protocol = protocol.clone();

            let handle = tokio::spawn(async move {
                Self::race_providers_raw(hostname, doh, dot, doh3, protocol, type_code, verbose)
                    .await
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            let result = handle
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("Task failed: {}", e)));
            results.push(result);
        }

        results
    }

    /// Race all providers for a single hostname - first successful response wins
    async fn race_providers(
        hostname: String,
        doh: Arc<DohResolver>,
        dot: Arc<DotResolver>,
        doh3: Arc<Doh3Resolver>,
        protocol: Protocol,
        type_code: u16,
        verbose: bool,
    ) -> Result<(Vec<String>, Provider, Duration)> {
        let providers = Provider::all();

        if verbose {
            eprintln!(
                "  [verbose] Racing {} providers for {} (type {})",
                providers.len(),
                hostname,
                crate::RecordType::from_code(type_code)
            );
        }

        type RaceFuture = Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<(Vec<String>, Provider, Duration), anyhow::Error>,
                    > + Send,
            >,
        >;

        let futures: Vec<RaceFuture> = providers
            .into_iter()
            .map(|provider| {
                let hostname = hostname.clone();
                let config = DnsProviderConfig::from_provider(&provider);
                let doh = Arc::clone(&doh);
                let dot = Arc::clone(&dot);
                let doh3 = Arc::clone(&doh3);
                let protocol = protocol.clone();
                let verbose = verbose;

                Box::pin(async move {
                    let start = Instant::now();

                    let result = match protocol {
                        Protocol::Doh => doh.resolve(&hostname, &config, type_code, verbose).await,
                        Protocol::Dot => dot.resolve(&hostname, &config, type_code, verbose).await,
                        Protocol::Doh3 => {
                            doh3.resolve(&hostname, &config, type_code, verbose).await
                        }
                    };

                    let elapsed = start.elapsed();

                    match result {
                        Ok(addresses) => {
                            if verbose {
                                eprintln!(
                                    "  [verbose] ✓ {:?} responded for {} in {:.2?} with {} records",
                                    provider,
                                    hostname,
                                    elapsed,
                                    addresses.len()
                                );
                            }
                            Ok((addresses, provider, elapsed))
                        }
                        Err(e) => {
                            if verbose {
                                eprintln!(
                                    "  [verbose] ✗ {:?} failed for {} in {:.2?}: {}",
                                    provider, hostname, elapsed, e
                                );
                            }
                            Err(e)
                        }
                    }
                }) as RaceFuture
            })
            .collect();

        if futures.is_empty() {
            return Err(anyhow::anyhow!("No providers available"));
        }

        // Race all providers - first success wins
        match select_ok(futures).await {
            Ok((result, _remaining)) => {
                if verbose {
                    eprintln!(
                        "  [verbose] Race winner for {}: {:?} in {:.2?}",
                        hostname, result.1, result.2
                    );
                }
                Ok(result)
            }
            Err(e) => Err(anyhow::anyhow!("All providers failed: {}", e)),
        }
    }

    /// Race all providers for raw data (ECH)
    async fn race_providers_raw(
        hostname: String,
        doh: Arc<DohResolver>,
        dot: Arc<DotResolver>,
        doh3: Arc<Doh3Resolver>,
        protocol: Protocol,
        type_code: u16,
        verbose: bool,
    ) -> Result<(Vec<u8>, Provider, Duration)> {
        let providers = Provider::all();

        if verbose {
            eprintln!(
                "  [verbose] Racing {} providers for {} (type {}, raw)",
                providers.len(),
                hostname,
                crate::RecordType::from_code(type_code)
            );
        }

        type RaceFuture = Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<(Vec<u8>, Provider, Duration), anyhow::Error>,
                    > + Send,
            >,
        >;

        let futures: Vec<RaceFuture> =
            providers
                .into_iter()
                .map(|provider| {
                    let hostname = hostname.clone();
                    let config = DnsProviderConfig::from_provider(&provider);
                    let doh = Arc::clone(&doh);
                    let dot = Arc::clone(&dot);
                    let doh3 = Arc::clone(&doh3);
                    let protocol = protocol.clone();
                    let verbose = verbose;

                    Box::pin(async move {
                        let start = Instant::now();

                        let result = match protocol {
                            Protocol::Doh => {
                                doh.resolve_raw(&hostname, &config, type_code, verbose)
                                    .await
                            }
                            Protocol::Dot => {
                                dot.resolve_raw(&hostname, &config, type_code, verbose)
                                    .await
                            }
                            Protocol::Doh3 => {
                                doh3.resolve_raw(&hostname, &config, type_code, verbose)
                                    .await
                            }
                        };

                        let elapsed = start.elapsed();

                        match result {
                            Ok(data) => {
                                if verbose {
                                    eprintln!(
                                    "  [verbose] ✓ {:?} responded for {} in {:.2?} with {} bytes",
                                    provider, hostname, elapsed, data.len()
                                );
                                }
                                Ok((data, provider, elapsed))
                            }
                            Err(e) => {
                                if verbose {
                                    eprintln!(
                                        "  [verbose] ✗ {:?} failed for {} in {:.2?}: {}",
                                        provider, hostname, elapsed, e
                                    );
                                }
                                Err(e)
                            }
                        }
                    }) as RaceFuture
                })
                .collect();

        if futures.is_empty() {
            return Err(anyhow::anyhow!("No providers available"));
        }

        match select_ok(futures).await {
            Ok((result, _remaining)) => {
                if verbose {
                    eprintln!(
                        "  [verbose] Race winner for {}: {:?} in {:.2?}",
                        hostname, result.1, result.2
                    );
                }
                Ok(result)
            }
            Err(e) => Err(anyhow::anyhow!("All providers failed: {}", e)),
        }
    }
}
