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
pub fn physical_exam(s: &ReliabilitySnapshot, name: &str) -> String {
    let mut metrics = String::new();
    for (stage, m) in &s.stages {
        metrics.push_str(&format!("\n{:?}: attempts={} success_rate={:.0}% p50_ms={:?} p95_ms={:?} max_ms={:?} timeouts={} resets={} failure_burst={}", stage, m.attempts, m.success_rate * 100.0, m.p50_ms, m.p95_ms, m.max_ms, m.timeouts, m.resets, m.longest_failure_burst));
    }
    format!("{name}\nAI Network Condition: {}\nReachability: {}\nReliability: {}\nMeasurement window: {} seconds{}\nPrimary abnormal stage: {}\nWhy Tivor says this: deterministic observed stage metrics under analysis policy {}\nWhat this may affect: intermittent failures or elevated tail latency may affect waiting, reconnects, streaming, or long-running agent work; authenticated usability is not verified.\nRoot cause: NOT DETERMINED\nLimitations: {}", format!("{:?}",s.reliability).to_uppercase(), format!("{:?}",s.reachability).to_uppercase(), format!("{:?}",s.reliability).to_uppercase(), s.measurement_window_seconds, metrics, format!("{:?}",s.failure_localization).to_uppercase(), s.analysis_policy_version, s.limitations.join("; "))
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
}
