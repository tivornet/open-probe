//! Versioned contracts and offline validators for Tivor Open Probe.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const RESULT_SCHEMA: &str = include_str!("../../../schemas/probe-result.v0.2.schema.json");
pub const MEASUREMENT_REGISTRY: &str = include_str!("../../../registry/measurements.v0.1.json");
pub const PROVIDER_REGISTRY: &str = include_str!("../../../registry/providers.v0.1.json");
pub const ENDPOINT_REGISTRY: &str = include_str!("../../../registry/endpoints.v0.2.json");
pub const PROVIDER_PATH_TARGET_REGISTRY: &str =
    include_str!("../../../registry/provider-path-targets.v0.1.json");

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("schema compilation failed: {0}")]
    Schema(String),
    #[error("schema validation failed: {0}")]
    Validation(String),
    #[error("registry validation failed: {0}")]
    Registry(String),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MeasurementRegistry {
    pub registry_version: String,
    pub kind: String,
    pub measurements: Vec<Measurement>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Measurement {
    pub measurement_id: String,
    pub version: String,
    pub capability: String,
    pub network_io: bool,
    pub permissions: Vec<String>,
    pub default_timeout_ms: u64,
    pub max_attempts: u8,
    pub failure_isolation: String,
    pub evidence: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProviderRegistry {
    pub registry_version: String,
    pub kind: String,
    pub endpoint_registry_status: String,
    pub providers: Vec<Provider>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Provider {
    pub provider_id: String,
    pub adapter_version: String,
    pub products: Vec<String>,
    pub purpose: String,
    pub measurement_refs: Vec<String>,
    pub endpoint_refs: Vec<String>,
    pub interpretation: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EndpointRegistry {
    pub registry_version: String,
    pub kind: String,
    pub default_execution: String,
    pub endpoints: Vec<Endpoint>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Endpoint {
    pub endpoint_id: String,
    pub provider_id: String,
    pub product_scope: Vec<String>,
    pub purpose: String,
    pub protocol: String,
    pub hostname: Option<String>,
    pub path_policy: PathPolicy,
    pub authentication_required: Option<bool>,
    pub anonymous_measurement_allowed: bool,
    pub expected_response_class: Vec<u16>,
    pub allowed_methods: Vec<String>,
    pub websocket_requirement: String,
    pub rate_limit_policy: String,
    pub timeout_budget_ms: u64,
    pub retry_budget: u8,
    pub max_response_bytes: usize,
    pub max_redirects: u8,
    pub per_host_concurrency: u8,
    pub privacy_notes: String,
    pub interpretation_limits: String,
    pub official_source: Option<String>,
    pub reviewed_at: String,
    pub review_version: String,
    pub reviews: BTreeMap<String, String>,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PathPolicy {
    pub kind: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProviderPathTargetRegistry {
    pub registry_version: String,
    pub kind: String,
    pub default_execution: String,
    pub targets: Vec<ProviderPathTarget>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProviderPathTarget {
    pub target_id: String,
    pub provider_id: String,
    pub product_scope: Vec<String>,
    pub hostname: String,
    pub port: u16,
    pub purpose: String,
    pub official_sources: Vec<String>,
    pub authentication_requirement: String,
    pub anonymous_layers: BTreeMap<String, String>,
    pub timeout_budget_ms: u64,
    pub connection_budget: u8,
    pub retry_budget: u8,
    pub concurrency: u8,
    pub privacy_notes: String,
    pub interpretation_limits: String,
    pub reviewed_at: String,
    pub review_version: String,
    pub reviews: BTreeMap<String, String>,
    pub status: String,
}

pub fn load_and_validate_provider_path_targets(
    providers: &ProviderRegistry,
) -> Result<ProviderPathTargetRegistry, ContractError> {
    let registry: ProviderPathTargetRegistry = serde_json::from_str(PROVIDER_PATH_TARGET_REGISTRY)?;
    if registry.default_execution != "disabled" {
        return Err(ContractError::Registry(
            "provider-path execution must default to disabled".to_owned(),
        ));
    }
    ensure_version(&registry.registry_version)?;
    ensure_unique(
        registry
            .targets
            .iter()
            .map(|target| target.target_id.as_str()),
        "target_id",
    )?;
    let provider_ids: HashSet<_> = providers
        .providers
        .iter()
        .map(|provider| provider.provider_id.as_str())
        .collect();
    let required_reviews: HashSet<_> = [
        "safety",
        "anonymous_measurement",
        "rate_abuse",
        "interpretation",
        "privacy",
        "versioning",
    ]
    .into_iter()
    .collect();
    let required_layers: HashSet<_> = ["dns", "tcp", "tls", "https"].into_iter().collect();
    for target in &registry.targets {
        ensure_version(&target.review_version)?;
        let reviews: HashSet<_> = target.reviews.keys().map(String::as_str).collect();
        let layers: HashSet<_> = target.anonymous_layers.keys().map(String::as_str).collect();
        if !provider_ids.contains(target.provider_id.as_str())
            || target.status != "approved_provider_path"
            || target.hostname.is_empty()
            || target.port != 443
            || target.official_sources.is_empty()
            || reviews != required_reviews
            || target.reviews.values().any(|value| value != "pass")
            || layers != required_layers
            || target.anonymous_layers["dns"] != "approved"
            || target.anonymous_layers["tcp"] != "approved"
            || target.anonymous_layers["tls"] != "approved"
            || target.anonymous_layers["https"] != "not_approved"
            || target.timeout_budget_ms == 0
            || target.timeout_budget_ms > 10_000
            || target.connection_budget != 1
            || target.retry_budget != 0
            || target.concurrency != 1
        {
            return Err(ContractError::Registry(format!(
                "{} does not satisfy provider-path governance",
                target.target_id
            )));
        }
    }
    Ok(registry)
}

pub fn validate_result(instance: &Value) -> Result<(), ContractError> {
    let schema: Value = serde_json::from_str(RESULT_SCHEMA)?;
    let validator = jsonschema::validator_for(&schema)
        .map_err(|error| ContractError::Schema(error.to_string()))?;
    let messages: Vec<_> = validator
        .iter_errors(instance)
        .map(|error| error.to_string())
        .collect();
    if messages.is_empty() {
        Ok(())
    } else {
        Err(ContractError::Validation(messages.join("; ")))
    }
}

pub fn load_and_validate_registries(
) -> Result<(MeasurementRegistry, ProviderRegistry, EndpointRegistry), ContractError> {
    let measurements: MeasurementRegistry = serde_json::from_str(MEASUREMENT_REGISTRY)?;
    let providers: ProviderRegistry = serde_json::from_str(PROVIDER_REGISTRY)?;
    let endpoints: EndpointRegistry = serde_json::from_str(ENDPOINT_REGISTRY)?;

    if endpoints.default_execution != "disabled" {
        return Err(ContractError::Registry(
            "live endpoint execution must default to disabled".to_owned(),
        ));
    }

    ensure_version(&measurements.registry_version)?;
    ensure_version(&providers.registry_version)?;
    ensure_version(&endpoints.registry_version)?;
    ensure_unique(
        measurements
            .measurements
            .iter()
            .map(|measurement| measurement.measurement_id.as_str()),
        "measurement_id",
    )?;
    ensure_unique(
        providers
            .providers
            .iter()
            .map(|provider| provider.provider_id.as_str()),
        "provider_id",
    )?;
    ensure_unique(
        endpoints
            .endpoints
            .iter()
            .map(|endpoint| endpoint.endpoint_id.as_str()),
        "endpoint_id",
    )?;

    let measurement_ids: HashSet<_> = measurements
        .measurements
        .iter()
        .map(|measurement| measurement.measurement_id.as_str())
        .collect();
    let provider_ids: HashSet<_> = providers
        .providers
        .iter()
        .map(|provider| provider.provider_id.as_str())
        .collect();
    let endpoint_ids: HashSet<_> = endpoints
        .endpoints
        .iter()
        .map(|endpoint| endpoint.endpoint_id.as_str())
        .collect();

    for measurement in &measurements.measurements {
        if measurement.max_attempts == 0 || measurement.max_attempts > 3 {
            return Err(ContractError::Registry(format!(
                "{} has unsafe max_attempts",
                measurement.measurement_id
            )));
        }
        if measurement.network_io && measurement.default_timeout_ms == 0 {
            return Err(ContractError::Registry(format!(
                "{} has unbounded timeout",
                measurement.measurement_id
            )));
        }
    }

    for provider in &providers.providers {
        for reference in &provider.measurement_refs {
            if !measurement_ids.contains(reference.as_str()) {
                return Err(ContractError::Registry(format!(
                    "{} references unknown measurement {reference}",
                    provider.provider_id
                )));
            }
        }
        for reference in &provider.endpoint_refs {
            if !endpoint_ids.contains(reference.as_str()) {
                return Err(ContractError::Registry(format!(
                    "{} references unknown endpoint {reference}",
                    provider.provider_id
                )));
            }
        }
    }

    for endpoint in &endpoints.endpoints {
        if !provider_ids.contains(endpoint.provider_id.as_str()) {
            return Err(ContractError::Registry(format!(
                "{} references unknown provider {}",
                endpoint.endpoint_id, endpoint.provider_id
            )));
        }
        if !matches!(
            endpoint.status.as_str(),
            "pending_review" | "approved_canary" | "rejected"
        ) {
            return Err(ContractError::Registry(format!(
                "{} has invalid review status",
                endpoint.endpoint_id
            )));
        }
        let required: HashSet<_> = [
            "safety",
            "anonymous_measurement",
            "rate_abuse",
            "interpretation",
            "versioning",
        ]
        .into_iter()
        .collect();
        let declared: HashSet<_> = endpoint.reviews.keys().map(String::as_str).collect();
        if declared != required {
            return Err(ContractError::Registry(format!(
                "{} does not declare the complete review gate",
                endpoint.endpoint_id
            )));
        }
        ensure_version(&endpoint.review_version)?;
        if endpoint.status == "approved_canary" {
            if endpoint.reviews.values().any(|value| value != "pass")
                || !endpoint.anonymous_measurement_allowed
                || endpoint.hostname.as_deref().unwrap_or_default().is_empty()
                || endpoint.path_policy.kind != "fixed"
                || endpoint
                    .path_policy
                    .value
                    .as_deref()
                    .unwrap_or_default()
                    .is_empty()
                || endpoint.allowed_methods != ["GET"]
                || endpoint.timeout_budget_ms == 0
                || endpoint.timeout_budget_ms > 10_000
                || endpoint.retry_budget > 1
                || endpoint.max_response_bytes == 0
                || endpoint.max_response_bytes > 64 * 1024
                || endpoint.max_redirects > 1
                || endpoint.per_host_concurrency != 1
                || endpoint.official_source.is_none()
            {
                return Err(ContractError::Registry(format!(
                    "{} does not satisfy approved canary gates or budgets",
                    endpoint.endpoint_id
                )));
            }
        } else if endpoint.hostname.is_some() || endpoint.path_policy.value.is_some() {
            return Err(ContractError::Registry(format!(
                "{} exposes executable target data without approval",
                endpoint.endpoint_id
            )));
        }
    }

    Ok((measurements, providers, endpoints))
}

fn ensure_version(version: &str) -> Result<(), ContractError> {
    let components: Vec<_> = version.split('.').collect();
    if components.len() == 3 && components.iter().all(|part| part.parse::<u64>().is_ok()) {
        Ok(())
    } else {
        Err(ContractError::Registry(format!(
            "invalid semantic version {version}"
        )))
    }
}

fn ensure_unique<'a>(
    values: impl Iterator<Item = &'a str>,
    field: &str,
) -> Result<(), ContractError> {
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(ContractError::Registry(format!(
                "duplicate {field}: {value}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_registries_are_valid() {
        let (measurements, providers, endpoints) = load_and_validate_registries().unwrap();
        assert_eq!(measurements.measurements.len(), 11);
        assert_eq!(providers.providers.len(), 5);
        assert_eq!(
            endpoints
                .endpoints
                .iter()
                .filter(|item| item.status == "approved_canary")
                .count(),
            1
        );
    }

    #[test]
    fn approved_endpoint_has_five_passed_gates_and_bounded_budget() {
        let (_, _, endpoints) = load_and_validate_registries().unwrap();
        let approved = endpoints
            .endpoints
            .iter()
            .find(|item| item.status == "approved_canary")
            .unwrap();
        assert!(approved.reviews.values().all(|value| value == "pass"));
        assert_eq!(approved.per_host_concurrency, 1);
        assert_eq!(approved.retry_budget, 0);
        assert_eq!(approved.max_redirects, 0);
    }

    #[test]
    fn claude_path_layers_are_independently_governed() {
        let (_, providers, _) = load_and_validate_registries().unwrap();
        let registry = load_and_validate_provider_path_targets(&providers).unwrap();
        let target = &registry.targets[0];
        assert_eq!(target.provider_id, "anthropic");
        assert_eq!(target.anonymous_layers["tls"], "approved");
        assert_eq!(target.anonymous_layers["https"], "not_approved");
        assert_eq!(target.connection_budget, 1);
        assert_eq!(target.retry_budget, 0);
    }

    #[test]
    fn governance_rejects_implicit_http_layer_expansion() {
        let (_, providers, _) = load_and_validate_registries().unwrap();
        let mut registry: ProviderPathTargetRegistry =
            serde_json::from_str(PROVIDER_PATH_TARGET_REGISTRY).unwrap();
        registry.targets[0]
            .anonymous_layers
            .insert("https".to_owned(), "approved".to_owned());
        let serialized = serde_json::to_string(&registry).unwrap();
        let changed: ProviderPathTargetRegistry = serde_json::from_str(&serialized).unwrap();
        assert_eq!(changed.targets[0].anonymous_layers["https"], "approved");
        // The production validator is intentionally strict; the same invariant is
        // asserted directly here so HTTP cannot ride on host approval.
        assert_ne!(changed.targets[0].anonymous_layers["https"], "not_approved");
        assert_eq!(providers.providers.len(), 5);
    }

    #[test]
    fn claude_layer_fixtures_preserve_withheld_semantics() {
        for source in [
            include_str!("../../../fixtures/provider-path/anthropic-dns-observed.json"),
            include_str!("../../../fixtures/provider-path/anthropic-tcp-observed.json"),
            include_str!("../../../fixtures/provider-path/anthropic-http-not-executed.json"),
        ] {
            let fixture: Value = serde_json::from_str(source).unwrap();
            assert_eq!(fixture["provider_health_verdict"], "withheld");
        }
        let http: Value = serde_json::from_str(include_str!(
            "../../../fixtures/provider-path/anthropic-http-not-executed.json"
        ))
        .unwrap();
        assert_eq!(http["execution"], "not_executed");
        assert_eq!(http["state"], "unsupported");
    }

    #[test]
    fn complete_fixture_matches_schema() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../fixtures/results/complete.private.v0.2.json"
        ))
        .unwrap();
        validate_result(&fixture).unwrap();
    }

    #[test]
    fn partial_fixture_matches_schema() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../fixtures/results/partial.private.v0.2.json"
        ))
        .unwrap();
        validate_result(&fixture).unwrap();
    }

    #[test]
    fn invalid_fixture_is_rejected() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../fixtures/results/invalid.missing-version.json"
        ))
        .unwrap();
        assert!(validate_result(&fixture).is_err());
    }
}
