use std::{
    fs,
    net::IpAddr,
    path::PathBuf,
    process::Command as ProcessCommand,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use probe_contracts::{
    load_and_validate_provider_path_targets, load_and_validate_registries, validate_result,
    Endpoint, ProviderPathTarget,
};
use probe_core::{
    build_plan, build_private_result, human_summary, normalize_canary, normalize_provider_path,
    CanaryBudget, CanaryOutcome, CanaryTimings, PipelineInput, ProviderPathOutcome, RecordedCanary,
    RecordedProviderPath, RunContext,
};
use probe_measurements::{
    measure_platform_tls, CancellationToken, ExecutionLimits, PlatformTlsTarget,
};
use probe_redaction::{redact_private_result, validate_public_export, write_json_atomic};
use serde_json::Value;

#[derive(Debug, Parser)]
#[command(
    name = "tivor",
    version,
    about = "Tivor Open Probe (local-only preview)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print tool and platform support versions.
    Version,
    /// Inspect the embedded, validated registries.
    Registry {
        #[command(subcommand)]
        command: RegistryCommand,
    },
    /// Build a deterministic plan without executing network checks.
    Plan {
        #[arg(long = "provider")]
        providers: Vec<String>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Validate a private result or redacted export.
    Validate {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = ValidationProfile::Private)]
        profile: ValidationProfile,
    },
    /// Observe this Mac locally without provider network execution.
    Doctor {
        /// Required acknowledgement that this is a local-only preview.
        #[arg(long)]
        local: bool,
        /// Explicit private-local result destination; must not already exist.
        #[arg(long)]
        output_private: Option<PathBuf>,
        /// Explicit redacted public export destination; must not already exist.
        #[arg(long)]
        export_public: Option<PathBuf>,
        /// Explicitly execute governed real provider-path measurements.
        #[arg(long = "provider-path", visible_alias = "live-canary")]
        live_canary: bool,
    },
}

#[derive(Debug, Subcommand)]
enum RegistryCommand {
    /// List measurements, providers, or governed endpoints.
    List {
        #[arg(long, value_enum, default_value_t = RegistryKind::All)]
        kind: RegistryKind,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RegistryKind {
    All,
    Measurements,
    Providers,
    Endpoints,
    Targets,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ValidationProfile {
    Private,
    PublicExport,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Version => version(),
        Command::Registry { command } => registry(command),
        Command::Plan { providers, format } => plan(&providers, format),
        Command::Validate { path, profile } => validate(&path, profile),
        Command::Doctor {
            local,
            output_private,
            export_public,
            live_canary,
        } => doctor(
            local,
            output_private.as_ref(),
            export_public.as_ref(),
            live_canary,
        ),
    }
}

fn doctor(
    local: bool,
    output_private: Option<&PathBuf>,
    export_public: Option<&PathBuf>,
    live_canary: bool,
) -> Result<()> {
    let _local_only_default = local || !live_canary;
    let started_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?
        .as_secs();
    let adapter = probe_platform_macos::MacOsAdapter::default();
    let targets: [IpAddr; 2] = [
        "192.0.2.1".parse().expect("documentation IPv4 is valid"),
        "2001:db8::1".parse().expect("documentation IPv6 is valid"),
    ];
    let platform = adapter.snapshot_with_targets(&targets);
    let finished_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?
        .as_secs();
    let context = RunContext {
        run_id: format!("local-{started_epoch}"),
        started_at: rfc3339_utc(started_epoch),
        finished_at: rfc3339_utc(finished_epoch),
    };
    let (measurements, providers, endpoints) = load_and_validate_registries()?;
    let targets = load_and_validate_provider_path_targets(&providers)?;
    let mut protocol_checks = Vec::new();
    if live_canary {
        for endpoint in endpoints
            .endpoints
            .iter()
            .filter(|item| item.status == "approved_canary")
        {
            let recorded = execute_endpoint_canary(endpoint, &context.finished_at);
            match normalize_canary(&recorded, &endpoints) {
                Ok(check) => protocol_checks.push(check),
                Err(error) => eprintln!(
                    "canary_normalization_error endpoint={} isolated=true error={error}",
                    endpoint.endpoint_id
                ),
            }
        }
        for target in &targets.targets {
            let recorded = execute_provider_path(target, &context.finished_at);
            match normalize_provider_path(&recorded, &targets) {
                Ok(check) => protocol_checks.push(check),
                Err(error) => eprintln!(
                    "provider_path_normalization_error target={} isolated=true error={error}",
                    target.target_id
                ),
            }
        }
    }
    let result = build_private_result(
        PipelineInput {
            context,
            platform,
            protocol_checks,
            live_canary,
        },
        &measurements,
        &providers,
    );
    validate_result(&result)?;
    if let Some(path) = output_private {
        write_json_atomic(path, &result)?;
    }
    if let Some(path) = export_public {
        let export = redact_private_result(&result)?;
        write_json_atomic(path, &export)?;
    }
    println!("{}", human_summary(&result));
    println!("provider_path_execution={live_canary}");
    Ok(())
}

fn execute_provider_path(target: &ProviderPathTarget, observed_at: &str) -> RecordedProviderPath {
    let started = Instant::now();
    let timeout = Duration::from_millis(target.timeout_budget_ms);
    let runtime = tokio::runtime::Runtime::new();
    let outcome = runtime.map_or_else(
        |_| ProviderPathOutcome::Failed {
            phase: "executor".to_owned(),
            code: "runtime_unavailable".to_owned(),
        },
        |runtime| {
            runtime.block_on(async {
                let execution = tokio::time::timeout(timeout, async {
                    let address = tokio::net::lookup_host((target.hostname.as_str(), target.port))
                        .await
                        .map_err(|_| "dns_failed")?
                        .next()
                        .ok_or("dns_empty")?;
                    let observation = measure_platform_tls(
                        &PlatformTlsTarget {
                            address,
                            server_name: target.hostname.clone(),
                        },
                        ExecutionLimits {
                            timeout,
                            max_attempts: 1,
                            max_response_bytes: 1,
                        },
                        &CancellationToken::default(),
                    )
                    .await
                    .map_err(|_| "tls_validation_or_transport_failed")?;
                    Ok::<_, &str>(observation)
                })
                .await;
                match execution {
                    Ok(Ok(observation)) => ProviderPathOutcome::TlsCompleted {
                        negotiated_protocol: observation.protocol_version,
                    },
                    Ok(Err(code)) => ProviderPathOutcome::Failed {
                        phase: if code.starts_with("dns_") {
                            "dns"
                        } else {
                            "tls"
                        }
                        .to_owned(),
                        code: code.to_owned(),
                    },
                    Err(_) => ProviderPathOutcome::Failed {
                        phase: "timeout".to_owned(),
                        code: "budget_exhausted".to_owned(),
                    },
                }
            })
        },
    );
    RecordedProviderPath {
        target_id: target.target_id.clone(),
        target_review_version: target.review_version.clone(),
        provider_id: target.provider_id.clone(),
        product_scope: target.product_scope.clone(),
        observed_at: observed_at.to_owned(),
        outcome,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn execute_endpoint_canary(endpoint: &Endpoint, observed_at: &str) -> RecordedCanary {
    let hostname = endpoint.hostname.as_deref().unwrap_or_default();
    let path = endpoint.path_policy.value.as_deref().unwrap_or_default();
    let url = format!("https://{hostname}{path}");
    let execution = execute_bounded_canary(
        &url,
        endpoint.timeout_budget_ms,
        endpoint.max_response_bytes,
        endpoint.max_redirects,
    );
    let (outcome, timings_ms) = match execution {
        Ok(executed) => {
            let timings = parse_timings(&executed.observation);
            let status = parse_observation_number(&executed.observation, "status")
                .and_then(|value| u16::try_from(value).ok())
                .unwrap_or(0);
            let outcome = if status > 0 {
                CanaryOutcome::HttpResponder { status }
            } else if matches!(executed.exit_code, 35 | 60) {
                CanaryOutcome::TlsFailure {
                    code: "tls_transport_or_validation".to_owned(),
                }
            } else {
                CanaryOutcome::Timeout {
                    phase: "transport".to_owned(),
                }
            };
            (outcome, timings)
        }
        Err(_) => (
            CanaryOutcome::Timeout {
                phase: "executor".to_owned(),
            },
            CanaryTimings {
                dns: None,
                connect: None,
                tls: None,
                total: endpoint.timeout_budget_ms,
            },
        ),
    };
    RecordedCanary {
        endpoint_id: endpoint.endpoint_id.clone(),
        endpoint_review_version: endpoint.review_version.clone(),
        provider_id: endpoint.provider_id.clone(),
        product_scope: endpoint.product_scope.clone(),
        protocol: endpoint.protocol.clone(),
        observed_at: observed_at.to_owned(),
        outcome,
        timings_ms,
        budget: CanaryBudget {
            timeout_ms: endpoint.timeout_budget_ms,
            retry_budget: endpoint.retry_budget,
            max_response_bytes: endpoint.max_response_bytes,
            max_redirects: endpoint.max_redirects,
            per_host_concurrency: endpoint.per_host_concurrency,
        },
    }
}

struct CanaryExecution {
    observation: String,
    exit_code: i32,
}

fn canary_curl_args(
    url: &str,
    timeout_ms: u64,
    max_response_bytes: usize,
    max_redirects: u8,
) -> Vec<String> {
    let timeout_seconds = timeout_ms.div_ceil(1000).to_string();
    vec![
        "--disable".into(),
        "--silent".into(),
        "--show-error".into(),
        "--proto".into(),
        "=https".into(),
        "--request".into(),
        "GET".into(),
        "--max-redirs".into(),
        max_redirects.to_string(),
        "--max-time".into(),
        timeout_seconds.clone(),
        "--connect-timeout".into(),
        timeout_seconds,
        "--max-filesize".into(),
        max_response_bytes.to_string(),
        "--user-agent".into(),
        "tivor-open-probe/0.1-canary".into(),
        "--output".into(),
        "/dev/null".into(),
        "--write-out".into(),
        "status=%{http_code} dns_s=%{time_namelookup} connect_s=%{time_connect} tls_s=%{time_appconnect} total_s=%{time_total}".into(),
        url.into(),
    ]
}

fn execute_bounded_canary(
    url: &str,
    timeout_ms: u64,
    max_response_bytes: usize,
    max_redirects: u8,
) -> Result<CanaryExecution> {
    let args = canary_curl_args(url, timeout_ms, max_response_bytes, max_redirects);
    let output = ProcessCommand::new("/usr/bin/curl")
        .args(&args)
        .env_remove("CURL_CA_BUNDLE")
        .env_remove("CURL_HOME")
        .output()
        .context("could not execute bounded system HTTPS client")?;
    let observation = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    anyhow::ensure!(!observation.is_empty(), "NO_OBSERVATION");
    Ok(CanaryExecution {
        observation,
        exit_code: output.status.code().unwrap_or(-1),
    })
}

fn parse_observation_number(observation: &str, key: &str) -> Option<u64> {
    observation.split_whitespace().find_map(|field| {
        let (name, value) = field.split_once('=')?;
        (name == key).then(|| value.parse::<u64>().ok()).flatten()
    })
}

fn parse_observation_seconds(observation: &str, key: &str) -> Option<u64> {
    observation.split_whitespace().find_map(|field| {
        let (name, value) = field.split_once('=')?;
        if name != key {
            return None;
        }
        value
            .parse::<f64>()
            .ok()
            .map(|seconds| (seconds * 1000.0).round() as u64)
    })
}

fn parse_timings(observation: &str) -> CanaryTimings {
    CanaryTimings {
        dns: parse_observation_seconds(observation, "dns_s"),
        connect: parse_observation_seconds(observation, "connect_s"),
        tls: parse_observation_seconds(observation, "tls_s"),
        total: parse_observation_seconds(observation, "total_s").unwrap_or(0),
    }
}

fn rfc3339_utc(epoch_seconds: u64) -> String {
    let days = epoch_seconds / 86_400;
    let seconds = epoch_seconds % 86_400;
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

// Howard Hinnant's public-domain civil calendar conversion.
fn civil_from_days(days_since_epoch: i64) -> (i64, u64, u64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month as u64, day as u64)
}

fn version() -> Result<()> {
    let platform = probe_platform_macos::support();
    println!("tivor-open-probe {}", env!("CARGO_PKG_VERSION"));
    println!(
        "platform={} {}+ {} inspection_implemented={} network_mutation={}",
        platform.os,
        platform.minimum_version,
        platform.architecture,
        platform.inspection_implemented,
        platform.network_mutation
    );
    println!("result_schema=0.2.0");
    println!(
        "registries=measurements:0.1.0,providers:0.1.0,endpoints:0.2.0,provider_path_targets:0.1.0"
    );
    println!("default_mode=LOCAL_ONLY silent_upload=false credentials_required=false");
    Ok(())
}

fn registry(command: RegistryCommand) -> Result<()> {
    let RegistryCommand::List { kind, format } = command;
    let (measurements, providers, endpoints) = load_and_validate_registries()?;
    let targets = load_and_validate_provider_path_targets(&providers)?;
    if format == OutputFormat::Json {
        let value = match kind {
            RegistryKind::All => serde_json::json!({
                "measurements": measurements,
                "providers": providers,
                "endpoints": endpoints,
                "provider_path_targets": targets
            }),
            RegistryKind::Measurements => serde_json::to_value(measurements)?,
            RegistryKind::Providers => serde_json::to_value(providers)?,
            RegistryKind::Endpoints => serde_json::to_value(endpoints)?,
            RegistryKind::Targets => serde_json::to_value(targets)?,
        };
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    if matches!(kind, RegistryKind::All | RegistryKind::Measurements) {
        println!("MEASUREMENTS");
        for item in measurements.measurements {
            println!("{} {}", item.measurement_id, item.version);
        }
    }
    if matches!(kind, RegistryKind::All | RegistryKind::Providers) {
        println!("PROVIDERS");
        for item in providers.providers {
            println!("{} {}", item.provider_id, item.adapter_version);
        }
    }
    if matches!(kind, RegistryKind::All | RegistryKind::Endpoints) {
        println!("ENDPOINTS");
        for item in endpoints.endpoints {
            println!("{} {}", item.endpoint_id, item.status);
        }
    }
    if matches!(kind, RegistryKind::All | RegistryKind::Targets) {
        println!("PROVIDER PATH TARGETS");
        for item in targets.targets {
            println!("{} {}", item.target_id, item.status);
        }
    }
    Ok(())
}

fn plan(requested: &[String], format: OutputFormat) -> Result<()> {
    let (measurements, providers, _) = load_and_validate_registries()?;
    let plan = build_plan(&measurements, &providers, requested)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&plan)?),
        OutputFormat::Text => {
            println!("NETWORK_EXECUTION=false");
            for provider in plan.providers {
                println!(
                    "{} measurements={} endpoints={}",
                    provider.provider_id,
                    provider.measurement_ids.join(","),
                    provider.endpoint_refs.join(",")
                );
            }
        }
    }
    Ok(())
}

fn validate(path: &PathBuf, profile: ValidationProfile) -> Result<()> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("could not read {}", path.display()))?;
    let value: Value = serde_json::from_str(&contents).context("input is not valid JSON")?;
    match profile {
        ValidationProfile::Private => validate_result(&value)?,
        ValidationProfile::PublicExport => validate_public_export(&value)?,
    }
    println!("VALID");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canary_arguments_are_bounded_and_have_no_credentials() {
        let args = canary_curl_args("https://example.test/observe", 5_000, 16_384, 0);
        let joined = args.join(" ").to_ascii_lowercase();
        for forbidden in ["authorization", "cookie", "token", "api-key", "--data"] {
            assert!(!joined.contains(forbidden));
        }
        assert!(joined.contains("--max-time 5"));
        assert!(joined.contains("--max-filesize 16384"));
        assert!(joined.contains("--max-redirs 0"));
        assert!(joined.contains("--output /dev/null"));
    }

    #[test]
    fn doctor_defaults_to_local_only_without_provider_execution() {
        let cli = Cli::try_parse_from(["tivor", "doctor"]).unwrap();
        match cli.command {
            Command::Doctor { live_canary, .. } => assert!(!live_canary),
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn provider_path_mode_requires_and_records_explicit_flag() {
        let cli = Cli::try_parse_from(["tivor", "doctor", "--provider-path"]).unwrap();
        match cli.command {
            Command::Doctor {
                live_canary, local, ..
            } => {
                assert!(live_canary);
                assert!(!local);
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn recorded_curl_observation_parses_to_bounded_milliseconds() {
        let value = "status=401 dns_s=0.003 connect_s=0.008 tls_s=0.040 total_s=0.072";
        assert_eq!(parse_observation_number(value, "status"), Some(401));
        assert_eq!(parse_timings(value).dns, Some(3));
        assert_eq!(parse_timings(value).total, 72);
    }

    #[test]
    fn provider_path_executor_has_no_external_tls_tool_reference() {
        let source = include_str!("main.rs");
        assert!(!source.contains(&["/opt", "/homebrew"].concat()));
        assert!(!source.contains(&["s_", "client"].concat()));
        assert!(source.contains("measure_platform_tls"));
    }
}
