use crate::doh::DohResolver;
use crate::doh3::Doh3Resolver;
use crate::dot::DotResolver;
use crate::providers::DnsProviderConfig;
use crate::{Protocol, Provider, RecordType};
use anyhow::Result;
use rand::seq::SliceRandom;
use std::sync::Arc;
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

    pub async fn resolve_batch(
        &self,
        hostnames: &[String],
        provider: &Provider,
        protocol: &Protocol,
        record_type: &RecordType,
    ) -> Vec<Result<Vec<String>>> {
        let config = DnsProviderConfig::from_provider(provider);
        let type_code = record_type.to_type_code();

        let mut handles: Vec<JoinHandle<Result<Vec<String>>>> = Vec::new();

        for hostname in hostnames {
            let hostname = hostname.clone();
            let config = config.clone();
            let doh = Arc::clone(&self.doh);
            let dot = Arc::clone(&self.dot);
            let doh3 = Arc::clone(&self.doh3);
            let protocol = protocol.clone();

            let handle = tokio::spawn(async move {
                match protocol {
                    Protocol::Doh => doh.resolve(&hostname, &config, type_code).await,
                    Protocol::Dot => dot.resolve(&hostname, &config, type_code).await,
                    Protocol::Doh3 => doh3.resolve(&hostname, &config, type_code).await,
                }
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            let result = handle.await.unwrap_or_else(|e| Err(anyhow::anyhow!("Task failed: {}", e)));
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
                    Protocol::Doh => doh.resolve_raw(&hostname, &config, type_code).await,
                    Protocol::Dot => dot.resolve_raw(&hostname, &config, type_code).await,
                    Protocol::Doh3 => doh3.resolve_raw(&hostname, &config, type_code).await,
                }
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            let result = handle.await.unwrap_or_else(|e| Err(anyhow::anyhow!("Task failed: {}", e)));
            results.push(result);
        }

        results
    }

    /// Resolve batch with shuffled providers - each hostname gets a random provider
    /// with automatic fallback to other providers on failure
    pub async fn resolve_batch_shuffle(
        &self,
        hostnames: &[String],
        protocol: &Protocol,
        record_type: &RecordType,
        verbose: bool,
    ) -> Vec<Result<(Vec<String>, Provider)>> {
        let type_code = record_type.to_type_code();

        let mut handles: Vec<JoinHandle<Result<(Vec<String>, Provider)>>> = Vec::new();

        for hostname in hostnames {
            let hostname = hostname.clone();
            let doh = Arc::clone(&self.doh);
            let dot = Arc::clone(&self.dot);
            let doh3 = Arc::clone(&self.doh3);
            let protocol = protocol.clone();

            let handle = tokio::spawn(async move {
                Self::resolve_with_fallback(
                    hostname,
                    doh,
                    dot,
                    doh3,
                    protocol,
                    type_code,
                    verbose,
                )
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

    /// Resolve batch with shuffled providers - returns raw data for ECH parsing
    pub async fn resolve_batch_shuffle_raw(
        &self,
        hostnames: &[String],
        protocol: &Protocol,
        type_code: u16,
        verbose: bool,
    ) -> Vec<Result<(Vec<u8>, Provider)>> {
        let mut handles: Vec<JoinHandle<Result<(Vec<u8>, Provider)>>> = Vec::new();

        for hostname in hostnames {
            let hostname = hostname.clone();
            let doh = Arc::clone(&self.doh);
            let dot = Arc::clone(&self.dot);
            let doh3 = Arc::clone(&self.doh3);
            let protocol = protocol.clone();

            let handle = tokio::spawn(async move {
                Self::resolve_raw_with_fallback(
                    hostname,
                    doh,
                    dot,
                    doh3,
                    protocol,
                    type_code,
                    verbose,
                )
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

    /// Resolve a single hostname with fallback through shuffled providers
    async fn resolve_with_fallback(
        hostname: String,
        doh: Arc<DohResolver>,
        dot: Arc<DotResolver>,
        doh3: Arc<Doh3Resolver>,
        protocol: Protocol,
        type_code: u16,
        verbose: bool,
    ) -> Result<(Vec<String>, Provider)> {
        let mut providers = Provider::all();
        
        // Shuffle providers randomly
        {
            use rand::thread_rng;
            providers.shuffle(&mut thread_rng());
        }

        let mut last_error: Option<anyhow::Error> = None;

        for provider in providers {
            let config = DnsProviderConfig::from_provider(&provider);
            
            let result = match protocol {
                Protocol::Doh => doh.resolve(&hostname, &config, type_code).await,
                Protocol::Dot => dot.resolve(&hostname, &config, type_code).await,
                Protocol::Doh3 => doh3.resolve(&hostname, &config, type_code).await,
            };

            match result {
                Ok(addresses) => {
                    return Ok((addresses, provider));
                }
                Err(e) => {
                    if verbose {
                        eprintln!(
                            "  [verbose] {} failed with {:?}: {}",
                            hostname, provider, e
                        );
                    }
                    last_error = Some(e);
                    // Continue to next provider
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("All providers failed")))
    }

    /// Resolve a single hostname (raw) with fallback through shuffled providers
    async fn resolve_raw_with_fallback(
        hostname: String,
        doh: Arc<DohResolver>,
        dot: Arc<DotResolver>,
        doh3: Arc<Doh3Resolver>,
        protocol: Protocol,
        type_code: u16,
        verbose: bool,
    ) -> Result<(Vec<u8>, Provider)> {
        let mut providers = Provider::all();
        
        // Shuffle providers randomly
        {
            use rand::thread_rng;
            providers.shuffle(&mut thread_rng());
        }

        let mut last_error: Option<anyhow::Error> = None;

        for provider in providers {
            let config = DnsProviderConfig::from_provider(&provider);
            
            let result = match protocol {
                Protocol::Doh => doh.resolve_raw(&hostname, &config, type_code).await,
                Protocol::Dot => dot.resolve_raw(&hostname, &config, type_code).await,
                Protocol::Doh3 => doh3.resolve_raw(&hostname, &config, type_code).await,
            };

            match result {
                Ok(data) => {
                    return Ok((data, provider));
                }
                Err(e) => {
                    if verbose {
                        eprintln!(
                            "  [verbose] {} failed with {:?}: {}",
                            hostname, provider, e
                        );
                    }
                    last_error = Some(e);
                    // Continue to next provider
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("All providers failed")))
    }
}
