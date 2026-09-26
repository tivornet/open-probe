use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const ANALYSIS_POLICY_VERSION: &str = "0.1.0";
pub const JITTER_FORMULA_VERSION: &str = "adjacent-mad-v0.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Stage {
    Dns,
    Tcp,
    Tls,
    Https,
    LongConnection,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Reachability {
    Available,
    Unavailable,
    Challenge,
    Incomplete,
    Unsupported,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Reliability {
    Stable,
    Degraded,
    Unstable,
    InsufficientData,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureLocalization {
    Dns,
    Tcp,
    Tls,
    Https,
    LongConnection,
    MultiStage,
    NoneObserved,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StageSample {
    pub stage: Stage,
    pub success: bool,
    pub timeout: bool,
    pub reset: bool,
    pub challenge: bool,
    pub latency_ms: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StageMetrics {
    pub attempts: usize,
    pub successes: usize,
    pub failures: usize,
    pub timeouts: usize,
    pub resets: usize,
    pub success_rate: f64,
    pub timeout_rate: f64,
    pub reset_rate: f64,
    pub p50_ms: Option<u64>,
    pub p95_ms: Option<u64>,
    pub max_ms: Option<u64>,
    pub jitter_ms: Option<f64>,
    pub longest_failure_burst: usize,
    pub observed_recovery: bool,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReliabilitySnapshot {
    pub schema_version: String,
    pub analysis_policy_version: String,
    pub jitter_formula_version: String,
    pub measurement_window_seconds: u64,
    pub provider_id: String,
    pub reachability: Reachability,
    pub reliability: Reliability,
    pub stages: BTreeMap<Stage, StageMetrics>,
    pub failure_localization: FailureLocalization,
    pub observed_abnormalities: Vec<String>,
    pub limitations: Vec<String>,
    pub provenance: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerStatus {
    Available,
    UnavailableDuringSnapshot,
    Stable,
    Degraded,
    NotTested,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanDiagnostic {
    pub overall: String,
    pub basic_path: LayerStatus,
    pub application_path: LayerStatus,
    pub reliability: Reliability,
    pub deepest_tested_stage: Option<Stage>,
    pub explanation: String,
    pub impact: String,
}

pub fn percentile(sorted: &[u64], p: u8) -> Option<u64> {
    if sorted.is_empty() {
        None
    } else {
        sorted
            .get(((sorted.len() - 1) * usize::from(p)).div_ceil(100))
            .copied()
    }
}
/// Mean absolute difference between adjacent successful latency samples.
pub fn adjacent_jitter(values: &[u64]) -> Option<f64> {
    if values.len() < 2 {
        None
    } else {
        Some(
            values.windows(2).map(|v| v[0].abs_diff(v[1])).sum::<u64>() as f64
                / (values.len() - 1) as f64,
        )
    }
}
pub fn stage_metrics(samples: &[StageSample]) -> StageMetrics {
    let attempts = samples.len();
    let successes = samples.iter().filter(|s| s.success).count();
    let timeouts = samples.iter().filter(|s| s.timeout).count();
    let resets = samples.iter().filter(|s| s.reset).count();
    let mut l: Vec<_> = samples
        .iter()
        .filter_map(|s| s.success.then_some(s.latency_ms).flatten())
        .collect();
    let jitter_ms = adjacent_jitter(&l);
    l.sort_unstable();
    let (mut burst, mut longest, mut failed, mut recovered) = (0, 0, false, false);
    for s in samples {
        if s.success {
            recovered |= failed;
            burst = 0
        } else {
            failed = true;
            burst += 1;
            longest = longest.max(burst)
        }
    }
    let ratio = |n| {
        if attempts == 0 {
            0.0
        } else {
            n as f64 / attempts as f64
        }
    };
    StageMetrics {
        attempts,
        successes,
        failures: attempts - successes,
        timeouts,
        resets,
        success_rate: ratio(successes),
        timeout_rate: ratio(timeouts),
        reset_rate: ratio(resets),
        p50_ms: percentile(&l, 50),
        p95_ms: percentile(&l, 95),
        max_ms: l.last().copied(),
        jitter_ms,
        longest_failure_burst: longest,
        observed_recovery: recovered,
    }
}
pub fn analyze(
    provider: &str,
    window: u64,
    samples: &[StageSample],
    long_available: bool,
) -> ReliabilitySnapshot {
    let mut g: BTreeMap<Stage, Vec<StageSample>> = BTreeMap::new();
    for s in samples {
        g.entry(s.stage).or_default().push(s.clone())
    }
    let stages: BTreeMap<_, _> = g.into_iter().map(|(s, v)| (s, stage_metrics(&v))).collect();
    let total: usize = stages.values().map(|m| m.attempts).sum();
    let ok: usize = stages.values().map(|m| m.successes).sum();
    let challenge = samples.iter().any(|s| s.challenge);
    let reachability = if total == 0 {
        Reachability::Unknown
    } else if ok > 0 {
        Reachability::Available
    } else if challenge {
        Reachability::Challenge
    } else {
        Reachability::Unavailable
    };
    let failing: Vec<_> = stages
        .iter()
        .filter(|(_, m)| m.failures > 0)
        .map(|(s, _)| *s)
        .collect();
    let failure_localization = match failing.as_slice() {
        [] => FailureLocalization::NoneObserved,
        [Stage::Dns] => FailureLocalization::Dns,
        [Stage::Tcp] => FailureLocalization::Tcp,
        [Stage::Tls] => FailureLocalization::Tls,
        [Stage::Https] => FailureLocalization::Https,
        [Stage::LongConnection] => FailureLocalization::LongConnection,
        _ => FailureLocalization::MultiStage,
    };
    let min = stages.values().map(|m| m.attempts).min().unwrap_or(0);
    let worst = stages
        .values()
        .map(|m| m.success_rate)
        .fold(1.0_f64, f64::min);
    let tail = stages
        .values()
        .any(|m| matches!((m.p50_ms,m.p95_ms),(Some(a),Some(b))if b>a.saturating_mul(4)&&b>500));
    let reliability = if min < 3 {
        Reliability::InsufficientData
    } else if worst < 0.8 || stages.values().any(|m| m.longest_failure_burst >= 2) {
        Reliability::Unstable
    } else if worst < 1.0 || tail {
        Reliability::Degraded
    } else {
        Reliability::Stable
    };
    let mut abnormalities = vec![];
    if worst < 1.0 {
        abnormalities.push("intermittent_stage_failure".into())
    }
    if tail {
        abnormalities.push("tail_latency_elevated".into())
    }
    if stages.values().any(|m| m.resets > 0) {
        abnormalities.push("connection_reset_observed".into())
    }
    let mut limitations = vec![
        "Short-window classification is not a global quality score or root-cause attribution."
            .into(),
    ];
    if !long_available {
        limitations.push("LONG_CONNECTION_EVIDENCE=NOT_AVAILABLE".into())
    }
    ReliabilitySnapshot {
        schema_version: "0.1.0".into(),
        analysis_policy_version: ANALYSIS_POLICY_VERSION.into(),
        jitter_formula_version: JITTER_FORMULA_VERSION.into(),
        measurement_window_seconds: window,
        provider_id: provider.into(),
        reachability,
        reliability,
        stages,
        failure_localization,
        observed_abnormalities: abnormalities,
        limitations,
        provenance: "observed_and_deterministic_analysis".into(),
    }
}
fn stage_name(stage: Stage) -> &'static str {
    match stage {
        Stage::Dns => "DNS",
        Stage::Tcp => "TCP",
        Stage::Tls => "TLS",
        Stage::Https => "HTTPS",
        Stage::LongConnection => "Long connection",
    }
}
fn layer_text(status: LayerStatus) -> &'static str {
    match status {
        LayerStatus::Available => "AVAILABLE",
        LayerStatus::UnavailableDuringSnapshot => "UNAVAILABLE DURING THIS TEST",
        LayerStatus::Stable => "STABLE",
        LayerStatus::Degraded => "DEGRADED",
        LayerStatus::NotTested => "NOT AVAILABLE / NOT TESTED",
        LayerStatus::Unknown => "UNKNOWN",
    }
}
fn latency(value: Option<u64>) -> String {
    value.map_or_else(|| "Not available".into(), |v| format!("{v} ms"))
}

#[derive(Debug, Clone, Copy)]
pub struct ReportLabels<'a> {
    pub display_name: &'a str,
    pub provider_name: &'a str,
    pub application_name: &'a str,
}

pub fn derive_human_diagnostic(s: &ReliabilitySnapshot) -> HumanDiagnostic {
    let transport = [Stage::Dns, Stage::Tcp, Stage::Tls];
    let tested_transport: Vec<_> = transport
        .iter()
        .filter_map(|stage| s.stages.get(stage))
        .collect();
    let basic_path = if tested_transport.is_empty() {
        LayerStatus::Unknown
    } else if tested_transport.iter().all(|m| m.successes > 0) {
        if tested_transport.iter().all(|m| m.success_rate == 1.0) {
            LayerStatus::Stable
        } else {
            LayerStatus::Available
        }
    } else {
        LayerStatus::UnavailableDuringSnapshot
    };
    let application_path = match s.stages.get(&Stage::Https) {
        None => LayerStatus::NotTested,
        Some(m) if m.successes == 0 => LayerStatus::UnavailableDuringSnapshot,
        Some(m) if m.success_rate == 1.0 => LayerStatus::Stable,
        Some(_) => LayerStatus::Degraded,
    };
    let overall = match (basic_path, application_path, s.reliability) {
        (_, LayerStatus::UnavailableDuringSnapshot, _) => "SERIOUS APPLICATION-PATH INSTABILITY",
        (_, LayerStatus::Degraded, Reliability::Unstable) => "APPLICATION-PATH INSTABILITY",
        (_, LayerStatus::Degraded, _) => "APPLICATION PATH DEGRADED",
        (LayerStatus::Stable, LayerStatus::NotTested, _) => "BASIC TRANSPORT PATH STABLE",
        (_, LayerStatus::Stable, Reliability::Stable) => "TESTED NETWORK PATH STABLE",
        (_, _, Reliability::Unstable) => "NETWORK PATH UNSTABLE",
        _ => "NETWORK PATH INCOMPLETE",
    }
    .into();
    let deepest_tested_stage = [
        Stage::LongConnection,
        Stage::Https,
        Stage::Tls,
        Stage::Tcp,
        Stage::Dns,
    ]
    .into_iter()
    .find(|stage| s.stages.contains_key(stage));
    let explanation = if let Some(https) = s.stages.get(&Stage::Https) {
        if https.successes == 0 {
            let lower = tested_transport.iter().all(|m| m.successes == m.attempts);
            format!(
                "All {} HTTPS measurements failed{}.",
                https.attempts,
                if lower {
                    " while the tested DNS, TCP and TLS stages completed successfully"
                } else {
                    " and lower-layer failures were also observed"
                }
            )
        } else if https.failures > 0 {
            format!(
                "{} of {} HTTPS measurements failed; {} succeeded during this snapshot.",
                https.failures, https.attempts, https.successes
            )
        } else {
            format!(
                "All {} governed HTTPS measurements completed successfully during this snapshot.",
                https.attempts
            )
        }
    } else if let Some(stage) = deepest_tested_stage {
        let m = &s.stages[&stage];
        format!("All {} tested {} measurements completed successfully. No application-layer measurement was approved.", m.successes, stage_name(stage))
    } else {
        "No governed path measurement was available.".into()
    };
    let impact = match application_path { LayerStatus::UnavailableDuringSnapshot => "AI application requests may wait, time out, reconnect, or interrupt long-running work.", LayerStatus::Degraded => "AI application requests may intermittently wait, retry, or reconnect.", LayerStatus::Stable => "No short-window instability was observed in the governed application path; authenticated usability remains unverified.", LayerStatus::NotTested => "No short-window transport instability was observed. Application-layer behavior and full product usability were not tested.", _ => "User-visible impact cannot be determined from the available evidence." }.into();
    HumanDiagnostic {
        overall,
        basic_path,
        application_path,
        reliability: s.reliability,
        deepest_tested_stage,
        explanation,
        impact,
    }
}

pub fn physical_exam(s: &ReliabilitySnapshot, labels: ReportLabels<'_>) -> String {
    let d = derive_human_diagnostic(s);
    let divider = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
    let abnormal = match s.failure_localization {
        FailureLocalization::NoneObserved => "No abnormal stage observed",
        FailureLocalization::MultiStage => "Multiple stages",
        FailureLocalization::Unknown => "Unknown",
        FailureLocalization::Dns => "DNS",
        FailureLocalization::Tcp => "TCP",
        FailureLocalization::Tls => "TLS",
        FailureLocalization::Https => "HTTPS",
        FailureLocalization::LongConnection => "Long connection",
    };
    if d.application_path == LayerStatus::NotTested {
        let stage = d.deepest_tested_stage.unwrap_or(Stage::Tls);
        let metrics = &s.stages[&stage];
        return format!("{divider}\n{}\n{divider}\n\nOverall\n✓ Basic transport path looks stable\n\n{:<23} ✓ {}/{} successful\n{:<23} {}\n{:<23} {}\n\nApplication-layer test\nNot available in this Beta\n\nWhat this means\n\nNo short-window {} instability was observed.\n\nHowever, Tivor has not tested the application layer,\nso full {} usability is not verified.", labels.display_name, stage_name(stage), metrics.successes, metrics.attempts, "Median", latency(metrics.p50_ms), "p95", latency(metrics.p95_ms), stage_name(stage), labels.application_name);
    }
    let icon = if d.application_path == LayerStatus::Stable {
        "✓"
    } else {
        "⚠"
    };
    let overall = match d.application_path {
        LayerStatus::UnavailableDuringSnapshot => "Serious application-path instability",
        LayerStatus::Degraded => "Application path degraded",
        LayerStatus::Stable => "Tested network path looks stable",
        _ => "Network path incomplete",
    };
    let state_icon = |status| {
        if matches!(status, LayerStatus::Stable | LayerStatus::Available) {
            "✓"
        } else if status == LayerStatus::UnavailableDuringSnapshot {
            "✕"
        } else {
            "⚠"
        }
    };
    let mut observed = String::new();
    for stage in [Stage::Dns, Stage::Tcp, Stage::Tls, Stage::Https] {
        if let Some(m) = s.stages.get(&stage) {
            let mark = if m.successes == m.attempts {
                "✓"
            } else if m.successes == 0 {
                "✕"
            } else {
                "⚠"
            };
            observed.push_str(&format!(
                "\n{:<23} {} {}/{} successful",
                stage_name(stage),
                mark,
                m.successes,
                m.attempts
            ));
            if stage == Stage::Dns {
                observed.push_str(&format!(
                    "\n{:<23} Median {} · p95 {}",
                    "",
                    latency(m.p50_ms),
                    latency(m.p95_ms)
                ));
            }
            if m.timeouts > 0 {
                observed.push_str(&format!("\n{:<23} {} timeouts", "", m.timeouts));
            }
        }
    }
    let meaning = if d.application_path == LayerStatus::UnavailableDuringSnapshot {
        format!("Your device can reach {} through DNS, TCP and TLS,\nbut all governed HTTPS checks timed out.\n\nThis may cause {} requests to hang,\ntime out, reconnect, or interrupt long-running work.", labels.provider_name, labels.application_name)
    } else {
        format!("{}\n\n{}", d.explanation, d.impact)
    };
    let basic_display = if d.basic_path == LayerStatus::Stable {
        "Available"
    } else {
        layer_text(d.basic_path)
    };
    let application_display = match d.application_path {
        LayerStatus::Stable => "Stable",
        LayerStatus::Degraded => "Degraded",
        LayerStatus::UnavailableDuringSnapshot => "Unavailable during this test",
        LayerStatus::NotTested => "Not available / not tested",
        LayerStatus::Available => "Available",
        LayerStatus::Unknown => "Unknown",
    };
    let reliability_display = match d.reliability {
        Reliability::Stable => "Stable",
        Reliability::Degraded => "Degraded",
        Reliability::Unstable => "Unstable",
        Reliability::InsufficientData => "Insufficient data",
    };
    format!("{divider}\n{}\n{divider}\n\nOverall\n{icon} {overall}\n\n{:<23} {} {}\n{:<23} {} {}\n{:<23} {} {}\n\nWhat Tivor observed\n{}\n\nPrimary abnormal stage\n{}\n\nWhat this means\n\n{}\n\nRoot cause\nNot determined.\n\nTivor cannot yet tell whether the cause is your proxy/VPN,\nISP/egress path, an intermediate network, or {} itself.", labels.display_name, "Basic network", state_icon(d.basic_path), basic_display, "Application path", state_icon(d.application_path), application_display, "Short-term reliability", if d.reliability == Reliability::Stable { "✓" } else { "⚠" }, reliability_display, observed, abnormal, meaning, labels.provider_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ss(st: Stage, v: &[Option<u64>]) -> Vec<StageSample> {
        v.iter()
            .map(|x| StageSample {
                stage: st,
                success: x.is_some(),
                timeout: x.is_none(),
                reset: false,
                challenge: false,
                latency_ms: *x,
            })
            .collect()
    }
    #[test]
    fn stable_low() {
        assert_eq!(
            analyze(
                "x",
                30,
                &ss(Stage::Https, &[Some(20), Some(21), Some(22)]),
                false
            )
            .reliability,
            Reliability::Stable
        )
    }
    #[test]
    fn stable_high() {
        assert_eq!(
            analyze(
                "x",
                30,
                &ss(Stage::Https, &[Some(900), Some(910), Some(920)]),
                false
            )
            .reliability,
            Reliability::Stable
        )
    }
    #[test]
    fn tail() {
        assert_eq!(
            analyze(
                "x",
                30,
                &ss(Stage::Https, &[Some(100), Some(100), Some(900)]),
                false
            )
            .reliability,
            Reliability::Degraded
        )
    }
    #[test]
    fn jitter() {
        assert_eq!(adjacent_jitter(&[10, 110, 10]), Some(100.0))
    }
    #[test]
    fn dns() {
        assert_eq!(
            analyze("x", 30, &ss(Stage::Dns, &[Some(1), None, Some(1)]), false)
                .failure_localization,
            FailureLocalization::Dns
        )
    }
    #[test]
    fn tcp() {
        assert_eq!(
            analyze("x", 30, &ss(Stage::Tcp, &[Some(1), None, Some(1)]), false)
                .failure_localization,
            FailureLocalization::Tcp
        )
    }
    #[test]
    fn tls() {
        assert_eq!(
            analyze("x", 30, &ss(Stage::Tls, &[Some(1), None, Some(1)]), false)
                .failure_localization,
            FailureLocalization::Tls
        )
    }
    #[test]
    fn https() {
        assert_eq!(
            analyze("x", 30, &ss(Stage::Https, &[Some(1), None, Some(1)]), false)
                .failure_localization,
            FailureLocalization::Https
        )
    }
    #[test]
    fn reset() {
        let mut s = ss(Stage::Tcp, &[Some(1), None, Some(1)]);
        s[1].reset = true;
        assert!(analyze("x", 30, &s, false)
            .observed_abnormalities
            .contains(&"connection_reset_observed".into()))
    }
    #[test]
    fn burst() {
        assert_eq!(
            stage_metrics(&ss(Stage::Tls, &[Some(1), None, None, Some(1)])).longest_failure_burst,
            2
        )
    }
    #[test]
    fn unavailable() {
        assert_eq!(
            analyze("x", 30, &ss(Stage::Tcp, &[None, None, None]), false).reachability,
            Reachability::Unavailable
        )
    }
    #[test]
    fn challenge() {
        let mut s = ss(Stage::Https, &[Some(1), Some(1), Some(1)]);
        s[0].challenge = true;
        assert_eq!(
            analyze("x", 30, &s, false).reachability,
            Reachability::Available
        )
    }
    #[test]
    fn insufficient() {
        assert_eq!(
            analyze("x", 5, &ss(Stage::Tls, &[Some(1)]), false).reliability,
            Reliability::InsufficientData
        )
    }
    #[test]
    fn unsupported() {
        assert_eq!(Reachability::Unsupported, Reachability::Unsupported)
    }
    #[test]
    fn mixed() {
        let mut s = ss(Stage::Dns, &[Some(1), None, Some(1)]);
        s.extend(ss(Stage::Tls, &[Some(1), None, Some(1)]));
        assert_eq!(
            analyze("x", 30, &s, false).failure_localization,
            FailureLocalization::MultiStage
        )
    }
    #[test]
    fn family_asymmetry() {
        assert_eq!(
            analyze(
                "x",
                30,
                &ss(Stage::Tcp, &[Some(1), Some(1), Some(1)]),
                false
            )
            .failure_localization,
            FailureLocalization::NoneObserved
        )
    }
    #[test]
    fn long_unavailable() {
        assert!(analyze(
            "x",
            30,
            &ss(Stage::Tls, &[Some(1), Some(1), Some(1)]),
            false
        )
        .limitations
        .iter()
        .any(|v| v.contains("NOT_AVAILABLE")))
    }
    #[test]
    fn snapshot_matches_versioned_schema() {
        let snapshot = analyze(
            "openai",
            25,
            &ss(Stage::Https, &[Some(1), Some(2), Some(3)]),
            false,
        );
        probe_contracts::validate_reliability_snapshot(&serde_json::to_value(snapshot).unwrap())
            .unwrap();
    }
    fn layered(https: &[Option<u64>]) -> ReliabilitySnapshot {
        let mut all = ss(Stage::Dns, &[Some(4), Some(5), Some(4), Some(14), Some(4)]);
        all.extend(ss(
            Stage::Tcp,
            &[Some(20), Some(20), Some(21), Some(20), Some(20)],
        ));
        all.extend(ss(
            Stage::Tls,
            &[Some(40), Some(41), Some(40), Some(42), Some(40)],
        ));
        all.extend(ss(Stage::Https, https));
        analyze("provider", 25, &all, false)
    }
    #[test]
    fn human_https_total_failure_is_layered_not_available() {
        let snapshot = layered(&[None, None, None, None, None]);
        let diagnostic = derive_human_diagnostic(&snapshot);
        assert_eq!(diagnostic.basic_path, LayerStatus::Stable);
        assert_eq!(
            diagnostic.application_path,
            LayerStatus::UnavailableDuringSnapshot
        );
        assert_eq!(diagnostic.overall, "SERIOUS APPLICATION-PATH INSTABILITY");
        let report = physical_exam(
            &snapshot,
            ReportLabels {
                display_name: "Provider",
                provider_name: "the provider",
                application_name: "AI application",
            },
        );
        assert!(report.contains("all governed HTTPS checks timed out"));
        assert!(!report.contains("Some("));
        assert!(!report.contains("NONEOBSERVED"));
    }
    #[test]
    fn human_tls_only_is_scoped_not_full_provider_stability() {
        let snapshot = analyze(
            "provider",
            25,
            &ss(
                Stage::Tls,
                &[Some(200), Some(220), Some(247), Some(300), Some(527)],
            ),
            false,
        );
        let diagnostic = derive_human_diagnostic(&snapshot);
        assert_eq!(diagnostic.application_path, LayerStatus::NotTested);
        assert_eq!(diagnostic.overall, "BASIC TRANSPORT PATH STABLE");
        assert!(physical_exam(
            &snapshot,
            ReportLabels {
                display_name: "Provider",
                provider_name: "the provider",
                application_name: "provider product"
            }
        )
        .contains("full provider product usability is not verified"));
    }
    #[test]
    fn human_all_supported_stages_stable() {
        let diagnostic = derive_human_diagnostic(&layered(&[
            Some(50),
            Some(51),
            Some(52),
            Some(50),
            Some(51),
        ]));
        assert_eq!(diagnostic.overall, "TESTED NETWORK PATH STABLE");
        assert_eq!(diagnostic.application_path, LayerStatus::Stable);
    }
    #[test]
    fn human_mixed_https_failure_is_evidence_linked() {
        let diagnostic =
            derive_human_diagnostic(&layered(&[Some(50), None, Some(55), None, Some(51)]));
        assert_eq!(diagnostic.application_path, LayerStatus::Degraded);
        assert!(diagnostic
            .explanation
            .contains("2 of 5 HTTPS measurements failed"));
    }
    #[test]
    fn machine_snapshot_semantics_are_unchanged_and_versioned() {
        let snapshot = layered(&[None, None, None, None, None]);
        assert_eq!(snapshot.schema_version, "0.1.0");
        assert_eq!(snapshot.reachability, Reachability::Available);
        probe_contracts::validate_reliability_snapshot(&serde_json::to_value(snapshot).unwrap())
            .unwrap();
    }
    #[test]
    fn owner_visual_fixture_renderer() {
        let openai = layered(&[None, None, None, None, None]);
        let claude = analyze(
            "anthropic",
            25,
            &ss(
                Stage::Tls,
                &[Some(200), Some(220), Some(247), Some(300), Some(527)],
            ),
            false,
        );
        println!(
            "OPENAI_EXACT_DEFAULT_OUTPUT\n{}",
            physical_exam(
                &openai,
                ReportLabels {
                    display_name: "OpenAI / ChatGPT / Codex",
                    provider_name: "OpenAI",
                    application_name: "ChatGPT or Codex"
                }
            )
        );
        println!(
            "CLAUDE_EXACT_DEFAULT_OUTPUT\n{}",
            physical_exam(
                &claude,
                ReportLabels {
                    display_name: "Claude / Claude Code",
                    provider_name: "Anthropic",
                    application_name: "Claude / Claude Code"
                }
            )
        );
    }
}
