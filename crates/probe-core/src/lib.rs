//! Network-agnostic planning and failure-isolation types.

use std::{future::Future, pin::Pin};

use probe_contracts::{
    ContractError, Endpoint, EndpointRegistry, MeasurementRegistry, ProviderPathTarget,
    ProviderPathTargetRegistry, ProviderRegistry,
};
use probe_platform_macos::{PlatformError, PlatformErrorCode, PlatformSnapshot, Provenance};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub network_execution: bool,
    pub providers: Vec<ProviderPlan>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderPlan {
    pub provider_id: String,
    pub measurement_ids: Vec<String>,
    pub endpoint_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunContext {
    pub run_id: String,
    pub started_at: String,
    pub finished_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NormalizedEvidence {
    pub evidence_id: String,
    pub observed_at: String,
    pub provenance: String,
    pub state: String,
    pub confidence: String,
    pub privacy_classification: String,
    pub value_type: String,
    pub value: Value,
    pub address_family: Option<String>,
    pub limitations: Vec<String>,
    pub supports: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NormalizedError {
    pub code: String,
    pub phase: String,
    pub retryable: bool,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NormalizedCheck {
    pub check_id: String,
    pub check_version: String,
    pub capability: String,
    pub status: String,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u64,
    pub evidence: Vec<NormalizedEvidence>,
    pub errors: Vec<NormalizedError>,
}

#[derive(Debug)]
pub struct PipelineInput {
    pub context: RunContext,
    pub platform: Result<PlatformSnapshot, PlatformError>,
    pub protocol_checks: Vec<NormalizedCheck>,
    pub live_canary: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordedCanary {
    pub endpoint_id: String,
    pub endpoint_review_version: String,
    pub provider_id: String,
    pub product_scope: Vec<String>,
    pub protocol: String,
    pub observed_at: String,
    pub outcome: CanaryOutcome,
    pub timings_ms: CanaryTimings,
    pub budget: CanaryBudget,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CanaryOutcome {
    HttpResponder { status: u16 },
    Timeout { phase: String },
    TlsFailure { code: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanaryTimings {
    pub dns: Option<u64>,
    pub connect: Option<u64>,
    pub tls: Option<u64>,
    pub total: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanaryBudget {
    pub timeout_ms: u64,
    pub retry_budget: u8,
    pub max_response_bytes: usize,
    pub max_redirects: u8,
    pub per_host_concurrency: u8,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordedProviderPath {
    pub target_id: String,
    pub target_review_version: String,
    pub provider_id: String,
    pub product_scope: Vec<String>,
    pub observed_at: String,
    pub outcome: ProviderPathOutcome,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProviderPathOutcome {
    TlsCompleted { negotiated_protocol: String },
    Failed { phase: String, code: String },
}

pub fn normalize_provider_path(
    recorded: &RecordedProviderPath,
    registry: &ProviderPathTargetRegistry,
) -> Result<NormalizedCheck, ContractError> {
    let target = registry
        .targets
        .iter()
        .find(|item| item.target_id == recorded.target_id)
        .ok_or_else(|| {
            ContractError::Registry("recorded provider path is not registered".to_owned())
        })?;
    validate_recorded_provider_path(recorded, target)?;
    let (status, state, stages, errors, negotiated_protocol) = match &recorded.outcome {
        ProviderPathOutcome::TlsCompleted {
            negotiated_protocol,
        } => (
            "complete",
            "observed",
            json!({"dns":"observed","tcp":"observed","tls":"completed","https":"not_executed"}),
            vec![],
            Some(negotiated_protocol.clone()),
        ),
        ProviderPathOutcome::Failed { phase, code } => (
            "partial",
            "incomplete",
            json!({"dns":if phase == "dns" {"failed"} else {"observed"},"tcp":"unknown","tls":"unknown","https":"not_executed"}),
            vec![NormalizedError {
                code: "provider_path.incomplete".to_owned(),
                phase: phase.clone(),
                retryable: false,
                summary: format!(
                    "Bounded provider-path observation failed ({code}); provider verdict withheld."
                ),
            }],
            None,
        ),
    };
    Ok(NormalizedCheck {
        check_id: format!("provider_path.{}", recorded.target_id),
        check_version: "0.1.0".to_owned(),
        capability: "provider.path".to_owned(),
        status: status.to_owned(),
        started_at: recorded.observed_at.clone(),
        finished_at: recorded.observed_at.clone(),
        duration_ms: recorded.duration_ms,
        evidence: vec![NormalizedEvidence {
            evidence_id: format!("provider_path.{}.observation", recorded.target_id),
            observed_at: recorded.observed_at.clone(),
            provenance: "observed".to_owned(),
            state: state.to_owned(),
            confidence: "high".to_owned(),
            privacy_classification: "export_allowed".to_owned(),
            value_type: "provider_path_observation".to_owned(),
            value: json!({
                "target_id": recorded.target_id,
                "target_review_version": recorded.target_review_version,
                "provider_id": recorded.provider_id,
                "product_scope": recorded.product_scope,
                "stages": stages,
                "negotiated_protocol": negotiated_protocol,
                "provider_health_verdict": "withheld"
            }),
            address_family: Some("unknown".to_owned()),
            limitations: vec![target.interpretation_limits.clone()],
            supports: vec![
                "bounded anonymous DNS/TCP/validated-TLS provider-path observation".to_owned(),
            ],
        }],
        errors,
    })
}

fn validate_recorded_provider_path(
    recorded: &RecordedProviderPath,
    target: &ProviderPathTarget,
) -> Result<(), ContractError> {
    if target.status != "approved_provider_path"
        || recorded.target_review_version != target.review_version
        || recorded.provider_id != target.provider_id
        || recorded.product_scope != target.product_scope
        || target.anonymous_layers["dns"] != "approved"
        || target.anonymous_layers["tcp"] != "approved"
        || target.anonymous_layers["tls"] != "approved"
        || target.anonymous_layers["https"] != "not_approved"
    {
        return Err(ContractError::Registry(
            "recorded provider path does not match approved layer governance".to_owned(),
        ));
    }
    Ok(())
}

pub fn normalize_canary(
    recorded: &RecordedCanary,
    endpoints: &EndpointRegistry,
) -> Result<NormalizedCheck, ContractError> {
    let endpoint = endpoints
        .endpoints
        .iter()
        .find(|item| item.endpoint_id == recorded.endpoint_id)
        .ok_or_else(|| ContractError::Registry("recorded endpoint is not registered".to_owned()))?;
    validate_recorded_canary(recorded, endpoint)?;
    let (status, state, typed_outcome, errors, http_status, stage_evidence) = match &recorded
        .outcome
    {
        CanaryOutcome::HttpResponder { status } => (
            "complete",
            if matches!(status, 401 | 403) {
                "challenge"
            } else {
                "incomplete"
            },
            "http_responder_observed",
            vec![],
            Some(*status),
            json!({"dns":"observed","tcp":"observed","tls":"completed","http":"responder_observed"}),
        ),
        CanaryOutcome::Timeout { phase } => (
            "partial",
            "incomplete",
            "timeout",
            vec![NormalizedError {
                code: "canary.timeout".to_owned(),
                phase: phase.clone(),
                retryable: true,
                summary: "Bounded live canary timed out; provider verdict withheld.".to_owned(),
            }],
            None,
            json!({"dns":"unknown","tcp":"unknown","tls":"unknown","http":"not_observed"}),
        ),
        CanaryOutcome::TlsFailure { code } => (
            "partial",
            "incomplete",
            "tls_failure",
            vec![NormalizedError {
                code: "canary.tls_failure".to_owned(),
                phase: "tls".to_owned(),
                retryable: false,
                summary: format!(
                    "Bounded TLS observation failed ({code}); provider verdict withheld."
                ),
            }],
            None,
            json!({"dns":"observed","tcp":"observed","tls":"failed","http":"not_observed"}),
        ),
    };
    Ok(NormalizedCheck {
        check_id: format!("canary.{}", recorded.endpoint_id),
        check_version: "0.1.0".to_owned(),
        capability: "provider.canary".to_owned(),
        status: status.to_owned(),
        started_at: recorded.observed_at.clone(),
        finished_at: recorded.observed_at.clone(),
        duration_ms: recorded.timings_ms.total,
        evidence: vec![NormalizedEvidence {
            evidence_id: format!("canary.{}.observation", recorded.endpoint_id),
            observed_at: recorded.observed_at.clone(),
            provenance: "observed".to_owned(),
            state: state.to_owned(),
            confidence: "high".to_owned(),
            privacy_classification: "export_allowed".to_owned(),
            value_type: "live_canary_observation".to_owned(),
            value: json!({
                "endpoint_id": recorded.endpoint_id,
                "endpoint_review_version": recorded.endpoint_review_version,
                "provider_id": recorded.provider_id,
                "product_scope": recorded.product_scope,
                "protocol": recorded.protocol,
                "typed_outcome": typed_outcome,
                "stages": stage_evidence,
                "http_status": http_status,
                "timings_ms": recorded.timings_ms,
                "execution_budget": recorded.budget,
                "live_canary": true,
                "experimental": true,
                "provider_health_verdict": "withheld"
            }),
            address_family: Some("unknown".to_owned()),
            limitations: vec![
                "Observation does not prove provider-wide health, account access, entitlement, or region eligibility.".to_owned(),
                endpoint.interpretation_limits.clone(),
            ],
            supports: vec!["bounded anonymous provider-path observation".to_owned()],
        }],
        errors,
    })
}

fn validate_recorded_canary(
    recorded: &RecordedCanary,
    endpoint: &Endpoint,
) -> Result<(), ContractError> {
    if endpoint.status != "approved_canary"
        || !endpoint.anonymous_measurement_allowed
        || recorded.endpoint_review_version != endpoint.review_version
        || recorded.provider_id != endpoint.provider_id
        || recorded.product_scope != endpoint.product_scope
        || recorded.protocol != endpoint.protocol
    {
        return Err(ContractError::Registry(
            "recorded canary does not match approved endpoint governance".to_owned(),
        ));
    }
    let expected = CanaryBudget {
        timeout_ms: endpoint.timeout_budget_ms,
        retry_budget: endpoint.retry_budget,
        max_response_bytes: endpoint.max_response_bytes,
        max_redirects: endpoint.max_redirects,
        per_host_concurrency: endpoint.per_host_concurrency,
    };
    if recorded.budget != expected {
        return Err(ContractError::Registry(
            "recorded canary budget does not match approved endpoint".to_owned(),
        ));
    }
    Ok(())
}

/// Build a deterministic, schema-shaped private-local result.
///
/// The caller supplies timestamps so identical fixture inputs produce identical
/// artifacts. Provider paths are always explicitly incomplete in Slice 4.
pub fn build_private_result(
    input: PipelineInput,
    measurements: &MeasurementRegistry,
    providers: &ProviderRegistry,
) -> Value {
    let mut checks = input.protocol_checks;
    let mut limitations = vec![
        "Observed platform evidence does not identify a VPN/proxy product or prove physical path enforcement."
            .to_owned(),
    ];
    if input.live_canary {
        limitations.push("LIVE_CANARY_EXPERIMENTAL".to_owned());
        limitations
            .push("Provider health verdict is WITHHELD for all canary observations.".to_owned());
    } else {
        limitations.push("LOCAL_ONLY_PREVIEW".to_owned());
        limitations.push(
            "Provider checks were NOT_EXECUTED because endpoints remain PENDING_ENDPOINT_REVIEW."
                .to_owned(),
        );
    }
    let (ipv4, ipv6, platform_status, platform_permission) = match input.platform {
        Ok(snapshot) => {
            checks.extend(platform_checks(&input.context, &snapshot));
            (
                Some(snapshot.availability.ipv4),
                Some(snapshot.availability.ipv6),
                "available",
                "available",
            )
        }
        Err(platform_error) => {
            let permission = match platform_error.code {
                PlatformErrorCode::PermissionDenied => "denied",
                PlatformErrorCode::Unsupported => "unsupported",
                PlatformErrorCode::CommandFailed
                | PlatformErrorCode::MalformedOutput
                | PlatformErrorCode::ResourceLimit => "unsupported",
            };
            checks.push(platform_failure_check(&input.context, &platform_error));
            limitations.push(platform_error.safe_summary);
            (None, None, "limited", permission)
        }
    };

    for check in &mut checks {
        check.evidence.sort_by(|left, right| {
            left.evidence_id
                .cmp(&right.evidence_id)
                .then(left.value_type.cmp(&right.value_type))
        });
        check
            .errors
            .sort_by(|left, right| left.code.cmp(&right.code));
        check.evidence.iter_mut().for_each(|evidence| {
            evidence.limitations.sort();
            evidence.limitations.dedup();
            evidence.supports.sort();
            evidence.supports.dedup();
        });
    }
    checks.sort_by(|left, right| left.check_id.cmp(&right.check_id));
    limitations.sort();
    limitations.dedup();

    let partial =
        platform_status == "limited" || checks.iter().any(|check| check.status != "complete");
    let mut provider_paths: Vec<_> = providers
        .providers
        .iter()
        .map(|provider| {
            let evidence_ids: Vec<_> = checks
                .iter()
                .flat_map(|check| &check.evidence)
                .filter(|evidence| evidence.value["provider_id"] == provider.provider_id)
                .map(|evidence| evidence.evidence_id.clone())
                .collect();
            let has_canary_evidence = !evidence_ids.is_empty();
            json!({
                "provider_id": provider.provider_id,
                "products": provider.products,
                "adapter_version": provider.adapter_version,
                "local_path_state": "incomplete",
                "confidence": "unknown",
                "supporting_evidence_ids": evidence_ids,
                "provider_reported_state": null,
                "limitations": if has_canary_evidence {
                    vec!["CANARY OBSERVATION ONLY / PROVIDER HEALTH VERDICT WITHHELD"]
                } else if input.live_canary {
                    vec!["UNSUPPORTED_LIVE_CANARY / NOT_EXECUTED / PENDING_ENDPOINT_REVIEW"]
                } else {
                    vec!["NOT_EXECUTED / PENDING_ENDPOINT_REVIEW"]
                }
            })
        })
        .collect();
    provider_paths.sort_by(|left, right| {
        left["provider_id"]
            .as_str()
            .cmp(&right["provider_id"].as_str())
    });

    let release_readiness = release_readiness(&checks, providers);
    let mut result = json!({
        "schema_version": "0.2.0",
        "tool": {
            "name": "tivor-open-probe",
            "version": env!("CARGO_PKG_VERSION"),
            "platform_adapter": "macos-readonly-v0.1"
        },
        "run": {
            "run_id": input.context.run_id,
            "started_at": input.context.started_at,
            "finished_at": input.context.finished_at,
            "status": if partial { "partial" } else { "complete" }
        },
        "environment": {
            "os": "macos",
            "architecture": "arm64",
            "ipv4_available": ipv4,
            "ipv6_available": ipv6
        },
        "registry_versions": {
            "measurements": measurements.registry_version,
            "providers": providers.registry_version
        },
        "checks": checks,
        "provider_paths": provider_paths,
        "release_readiness": release_readiness,
        "limitations": limitations,
        "permissions": [
            {"capability":"outbound_dns","mode":"required","result":if input.live_canary {"available"} else {"not_requested"}},
            {"capability":"outbound_network","mode":"required","result":if input.live_canary {"available"} else {"not_requested"}},
            {"capability":"read_interfaces","mode":"required","result":platform_permission},
            {"capability":"read_routes","mode":"required","result":platform_permission},
            {"capability":"observe_tun","mode":"optional","result":platform_permission},
            {"capability":"write_local_file","mode":"explicit_action","result":"not_requested"},
            {"capability":"export_redacted_file","mode":"explicit_action","result":"not_requested"}
        ],
        "redaction": {
            "state": "private_local",
            "policy_id": "none",
            "validation": "not_applicable"
        }
    });
    if input.live_canary {
        result["execution"] = json!({"mode":"LIVE_CANARY","live_canary":true,"experimental":true});
    }
    result
}

fn platform_checks(context: &RunContext, snapshot: &PlatformSnapshot) -> Vec<NormalizedCheck> {
    let interface_public: Vec<_> = snapshot
        .interfaces
        .iter()
        .map(probe_platform_macos::InterfaceObservation::public_summary)
        .collect();
    let interface_private: Vec<_> = snapshot
        .interfaces
        .iter()
        .map(|interface| {
            json!({
                "name": interface.name,
                "addresses": interface.addresses.iter().map(|address| address.address.to_string()).collect::<Vec<_>>()
            })
        })
        .collect();
    let mut checks = vec![NormalizedCheck {
        check_id: "platform.interfaces".to_owned(),
        check_version: "0.1.0".to_owned(),
        capability: "interface.snapshot".to_owned(),
        status: "complete".to_owned(),
        started_at: context.started_at.clone(),
        finished_at: context.finished_at.clone(),
        duration_ms: 0,
        evidence: vec![
            evidence(
                context,
                "platform.interfaces.public",
                Provenance::Observed,
                "interface_summary",
                json!(interface_public),
                "export_allowed",
                vec!["Interface category is normalized and does not identify an owning product."],
            ),
            evidence(
                context,
                "platform.interfaces.private",
                Provenance::Observed,
                "interface_private_local",
                json!(interface_private),
                "private_local",
                vec!["Exact interface identifiers and addresses are retained only in the private local result."],
            ),
        ],
        errors: vec![],
    }];

    checks.push(NormalizedCheck {
        check_id: "platform.ip_family".to_owned(),
        check_version: "0.1.0".to_owned(),
        capability: "ip_family.observe".to_owned(),
        status: "complete".to_owned(),
        started_at: context.started_at.clone(),
        finished_at: context.finished_at.clone(),
        duration_ms: 0,
        evidence: vec![evidence(
            context,
            "platform.ip_family.availability",
            snapshot.availability.provenance,
            "ip_family_availability",
            json!({"ipv4":snapshot.availability.ipv4,"ipv6":snapshot.availability.ipv6}),
            "export_allowed",
            vec![snapshot.availability.limitation.as_str()],
        )],
        errors: vec![],
    });

    let mut route_evidence = Vec::new();
    if let Some(route) = &snapshot.default_route {
        route_evidence.push(evidence(
            context,
            "platform.route.default.public",
            route.provenance,
            "route_summary",
            json!(route.public_summary()),
            "export_allowed",
            vec![route.limitation.as_str()],
        ));
        route_evidence.push(evidence(
            context,
            "platform.route.default.private",
            route.provenance,
            "route_private_local",
            json!({"gateway":route.gateway,"interface_name":route.interface_name}),
            "private_local",
            vec!["Gateway and selected interface remain private-local."],
        ));
    }
    for (index, route) in snapshot.targeted_routes.iter().enumerate() {
        route_evidence.push(evidence(
            context,
            &format!("platform.route.targeted.{index}.public"),
            route.provenance,
            "targeted_route_summary",
            json!(route.public_summary()),
            "export_allowed",
            vec![route.limitation.as_str()],
        ));
    }
    let route_missing = route_evidence.is_empty();
    checks.push(NormalizedCheck {
        check_id: "platform.routes".to_owned(),
        check_version: "0.1.0".to_owned(),
        capability: "route.lookup".to_owned(),
        status: if route_missing { "partial" } else { "complete" }.to_owned(),
        started_at: context.started_at.clone(),
        finished_at: context.finished_at.clone(),
        duration_ms: 0,
        evidence: route_evidence,
        errors: if route_missing {
            vec![NormalizedError {
                code: "route.not_found".to_owned(),
                phase: "platform_observation".to_owned(),
                retryable: false,
                summary: "No default or targeted route evidence was available.".to_owned(),
            }]
        } else {
            vec![]
        },
    });

    checks.push(NormalizedCheck {
        check_id: "platform.tun_like".to_owned(),
        check_version: "0.1.0".to_owned(),
        capability: "interface.snapshot".to_owned(),
        status: "complete".to_owned(),
        started_at: context.started_at.clone(),
        finished_at: context.finished_at.clone(),
        duration_ms: 0,
        evidence: vec![
            evidence(
                context,
                "platform.tun_like.public",
                snapshot.tunnel.provenance,
                "tun_like_summary",
                json!(snapshot.tunnel.public_summary()),
                "export_allowed",
                vec![snapshot.tunnel.limitation.as_str()],
            ),
            evidence(
                context,
                "platform.tun_like.private",
                snapshot.tunnel.provenance,
                "tun_like_private_local",
                json!({"interface_names":snapshot.tunnel.interface_names}),
                "private_local",
                vec!["Exact TUN-like interface identifiers remain private-local."],
            ),
        ],
        errors: vec![],
    });
    checks
}

fn platform_failure_check(context: &RunContext, error: &PlatformError) -> NormalizedCheck {
    let (code, result) = match error.code {
        PlatformErrorCode::PermissionDenied => ("permission.interface_denied", "failed"),
        PlatformErrorCode::Unsupported => ("route.unsupported", "unsupported"),
        PlatformErrorCode::CommandFailed
        | PlatformErrorCode::MalformedOutput
        | PlatformErrorCode::ResourceLimit => ("run.internal", "failed"),
    };
    NormalizedCheck {
        check_id: "platform.snapshot".to_owned(),
        check_version: "0.1.0".to_owned(),
        capability: "interface.snapshot".to_owned(),
        status: result.to_owned(),
        started_at: context.started_at.clone(),
        finished_at: context.finished_at.clone(),
        duration_ms: 0,
        evidence: vec![],
        errors: vec![NormalizedError {
            code: code.to_owned(),
            phase: "platform_observation".to_owned(),
            retryable: false,
            summary: error.safe_summary.clone(),
        }],
    }
}

fn evidence(
    context: &RunContext,
    id: &str,
    provenance: Provenance,
    value_type: &str,
    value: Value,
    privacy: &str,
    limitations: Vec<&str>,
) -> NormalizedEvidence {
    NormalizedEvidence {
        evidence_id: id.to_owned(),
        observed_at: context.finished_at.clone(),
        provenance: match provenance {
            Provenance::Observed => "observed",
            Provenance::Inferred => "inferred",
            Provenance::Unknown => "unknown",
        }
        .to_owned(),
        state: "observed".to_owned(),
        confidence: "medium".to_owned(),
        privacy_classification: privacy.to_owned(),
        value_type: value_type.to_owned(),
        value,
        address_family: Some("not_applicable".to_owned()),
        limitations: limitations.into_iter().map(str::to_owned).collect(),
        supports: vec![],
    }
}

#[must_use]
pub fn human_summary(result: &Value) -> String {
    let environment = &result["environment"];
    let providers = result["provider_paths"].as_array().map_or(0, Vec::len);
    let tun_count = result["checks"]
        .as_array()
        .and_then(|checks| {
            checks
                .iter()
                .find(|check| check["check_id"] == "platform.tun_like")
        })
        .and_then(|check| check["evidence"].as_array())
        .and_then(|items| {
            items
                .iter()
                .find(|item| item["evidence_id"] == "platform.tun_like.public")
        })
        .and_then(|item| item["value"]["tunnel_like_count"].as_u64());
    let route_category = result["checks"]
        .as_array()
        .and_then(|checks| {
            checks
                .iter()
                .find(|check| check["check_id"] == "platform.routes")
        })
        .and_then(|check| check["evidence"].as_array())
        .and_then(|items| {
            items
                .iter()
                .find(|item| item["evidence_id"] == "platform.route.default.public")
        })
        .and_then(|item| item["value"]["interface_category"].as_str())
        .unwrap_or("unknown");
    let local = format!(
        "LOCAL ONLY PREVIEW\nlocal_only=true\nprovider_network_execution=false\nprovider_checks=not_executed ({providers}; pending endpoint review)\nipv4_observed={}\nipv6_observed={}\nroute_interface_category={route_category}\ntun_like_interfaces={}\nscore=not_computed\nroot_cause=not_inferred",
        environment["ipv4_available"],
        environment["ipv6_available"],
        tun_count.map_or_else(|| "unknown".to_owned(), |value| value.to_string())
    );
    if result.pointer("/execution/mode").and_then(Value::as_str) != Some("LIVE_CANARY") {
        return local;
    }
    let mut lines = vec![
        "GOVERNED PROVIDER PATH (EXPERIMENTAL)".to_owned(),
        "provider_path_execution=true".to_owned(),
        "Providers:".to_owned(),
    ];
    if let Some(paths) = result["provider_paths"].as_array() {
        for path in paths {
            let products = path["products"].as_array().map_or_else(
                || path["provider_id"].as_str().unwrap_or("unknown").to_owned(),
                |items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(" / ")
                },
            );
            let evidence_count = path["supporting_evidence_ids"]
                .as_array()
                .map_or(0, Vec::len);
            let status = if evidence_count > 0 {
                "evidence recorded"
            } else {
                "UNSUPPORTED / NOT_EXECUTED"
            };
            lines.push(format!("{products}: {status}; provider verdict WITHHELD"));
        }
    }
    lines.extend([
        "Meaning: bounded provider-path evidence only.".to_owned(),
        "score=not_computed".to_owned(),
        "root_cause=not_inferred".to_owned(),
    ]);
    lines.join("\n")
}

fn release_readiness(checks: &[NormalizedCheck], providers: &ProviderRegistry) -> Value {
    let coverage = |provider_id: &str| {
        checks.iter().any(|check| {
            check.evidence.iter().any(|evidence| {
                evidence.value["provider_id"] == provider_id
                    && matches!(evidence.state.as_str(), "observed" | "challenge")
            })
        })
    };
    let required = ["openai", "anthropic"];
    let required_providers: Vec<_> = required
        .iter()
        .map(|id| json!({"provider_id": id, "coverage": if coverage(id) {"pass"} else {"not_executed"}}))
        .collect();
    let optional_providers: Vec<_> = providers.providers.iter()
        .filter(|provider| !required.contains(&provider.provider_id.as_str()))
        .map(|provider| json!({"provider_id": provider.provider_id, "coverage": if coverage(&provider.provider_id) {"pass"} else {"unsupported"}}))
        .collect();
    json!({
        "contract_version": "0.1.0",
        "status": if required.iter().all(|id| coverage(id)) {"ready"} else {"not_ready"},
        "required_providers": required_providers,
        "optional_providers": optional_providers
    })
}

pub type IsolatedCheck<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send>>;

/// Collect independent results without converting one check failure into run failure.
pub async fn collect_isolated<T, E>(checks: Vec<IsolatedCheck<T, E>>) -> Vec<Result<T, E>> {
    let mut output = Vec::with_capacity(checks.len());
    for check in checks {
        output.push(check.await);
    }
    output
}

pub fn build_plan(
    measurements: &MeasurementRegistry,
    providers: &ProviderRegistry,
    requested: &[String],
) -> Result<Plan, ContractError> {
    let selected = providers.providers.iter().filter(|provider| {
        requested.is_empty() || requested.iter().any(|item| item == &provider.provider_id)
    });
    let provider_plans: Vec<_> = selected
        .map(|provider| ProviderPlan {
            provider_id: provider.provider_id.clone(),
            measurement_ids: provider.measurement_refs.clone(),
            endpoint_refs: provider.endpoint_refs.clone(),
        })
        .collect();
    if !requested.is_empty() && provider_plans.len() != requested.len() {
        return Err(ContractError::Registry(
            "one or more requested providers are unknown".to_owned(),
        ));
    }
    let known: std::collections::HashSet<_> = measurements
        .measurements
        .iter()
        .map(|item| item.measurement_id.as_str())
        .collect();
    if provider_plans
        .iter()
        .flat_map(|item| &item.measurement_ids)
        .any(|item| !known.contains(item.as_str()))
    {
        return Err(ContractError::Registry(
            "plan contains an unknown measurement".to_owned(),
        ));
    }
    Ok(Plan {
        network_execution: false,
        providers: provider_plans,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use probe_contracts::{load_and_validate_registries, validate_result};
    use probe_platform_macos::{
        availability, parse_ifconfig, parse_route, tunnel_observation, PlatformSnapshot,
    };

    #[test]
    fn plan_is_generic_and_no_network() {
        let (measurements, providers, _) = load_and_validate_registries().unwrap();
        let plan = build_plan(&measurements, &providers, &["cursor".to_owned()]).unwrap();
        assert!(!plan.network_execution);
        assert_eq!(plan.providers[0].provider_id, "cursor");
    }

    #[tokio::test]
    async fn failed_check_does_not_drop_other_results() {
        let checks: Vec<IsolatedCheck<u8, &'static str>> = vec![
            Box::pin(async { Ok(1) }),
            Box::pin(async { Err("fixture failure") }),
            Box::pin(async { Ok(3) }),
        ];
        let results = collect_isolated(checks).await;
        assert_eq!(results, vec![Ok(1), Err("fixture failure"), Ok(3)]);
    }

    fn context() -> RunContext {
        RunContext {
            run_id: "deterministic-run".to_owned(),
            started_at: "2026-09-26T00:00:00Z".to_owned(),
            finished_at: "2026-09-26T00:00:01Z".to_owned(),
        }
    }

    fn platform_snapshot() -> PlatformSnapshot {
        let interfaces = parse_ifconfig(
            "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\nen0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tinet 192.0.2.2 netmask 0xffffff00\n\tinet6 2001:db8::2%en0 prefixlen 64\n\tstatus: active\nutun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 9000\n\tinet 198.18.0.1 netmask 0xffffffff\n",
        )
        .unwrap();
        let default_route = parse_route(
            "route to: default\ngateway: 198.18.0.1\ninterface: utun3\n",
            None,
            &interfaces,
        )
        .unwrap();
        let targeted = parse_route(
            "route to: 192.0.2.1\ngateway: 198.18.0.1\ninterface: utun3\n",
            Some("192.0.2.1".parse().unwrap()),
            &interfaces,
        )
        .unwrap();
        PlatformSnapshot {
            adapter_version: "0.1.0".to_owned(),
            availability: availability(&interfaces),
            tunnel: tunnel_observation(&interfaces, Some(&default_route)),
            interfaces,
            default_route: Some(default_route),
            targeted_routes: vec![targeted],
        }
    }

    fn canary_fixture(name: &str) -> RecordedCanary {
        let source = match name {
            "401" => include_str!("../../../fixtures/canary/approved-401.json"),
            "403" => include_str!("../../../fixtures/canary/approved-403.json"),
            "timeout" => include_str!("../../../fixtures/canary/timeout.json"),
            "tls" => include_str!("../../../fixtures/canary/tls-failure.json"),
            "not-approved" => include_str!("../../../fixtures/canary/not-approved.json"),
            "unsupported" => include_str!("../../../fixtures/canary/unsupported-provider.json"),
            "version" => include_str!("../../../fixtures/canary/version-mismatch.json"),
            "budget" => include_str!("../../../fixtures/canary/budget-violation.json"),
            _ => panic!("unknown canary fixture"),
        };
        serde_json::from_str(source).unwrap()
    }

    #[test]
    fn local_pipeline_is_deterministic_schema_valid_and_provider_pending() {
        let (measurements, providers, _) = load_and_validate_registries().unwrap();
        let build = || {
            build_private_result(
                PipelineInput {
                    context: context(),
                    platform: Ok(platform_snapshot()),
                    protocol_checks: vec![],
                    live_canary: false,
                },
                &measurements,
                &providers,
            )
        };
        let first = build();
        let second = build();
        assert_eq!(first, second);
        validate_result(&first).unwrap();
        assert!(first["provider_paths"]
            .as_array()
            .unwrap()
            .iter()
            .all(|provider| provider["local_path_state"] == "incomplete"));
        assert!(first.to_string().contains("PENDING_ENDPOINT_REVIEW"));
        assert_eq!(first["release_readiness"]["status"], "not_ready");
    }

    #[test]
    fn failed_protocol_check_is_isolated_in_partial_result() {
        let (measurements, providers, _) = load_and_validate_registries().unwrap();
        let failed = NormalizedCheck {
            check_id: "fixture.protocol.failure".to_owned(),
            check_version: "0.1.0".to_owned(),
            capability: "https.request".to_owned(),
            status: "failed".to_owned(),
            started_at: context().started_at,
            finished_at: context().finished_at,
            duration_ms: 1,
            evidence: vec![],
            errors: vec![NormalizedError {
                code: "http.timeout".to_owned(),
                phase: "fixture".to_owned(),
                retryable: true,
                summary: "local fixture timed out".to_owned(),
            }],
        };
        let result = build_private_result(
            PipelineInput {
                context: context(),
                platform: Ok(platform_snapshot()),
                protocol_checks: vec![failed],
                live_canary: false,
            },
            &measurements,
            &providers,
        );
        validate_result(&result).unwrap();
        assert_eq!(result["run"]["status"], "partial");
        assert!(result["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["check_id"] == "platform.interfaces"));
    }

    #[test]
    fn approved_challenge_fixtures_normalize_without_health_verdict() {
        let (_, _, endpoints) = load_and_validate_registries().unwrap();
        for name in ["401", "403"] {
            let check = normalize_canary(&canary_fixture(name), &endpoints).unwrap();
            assert_eq!(check.status, "complete");
            assert_eq!(check.evidence[0].state, "challenge");
            assert_eq!(
                check.evidence[0].value["provider_health_verdict"],
                "withheld"
            );
            assert_eq!(check.evidence[0].value["endpoint_review_version"], "1.0.0");
        }
    }

    #[test]
    fn timeout_and_tls_failure_are_typed_and_isolated() {
        let (_, _, endpoints) = load_and_validate_registries().unwrap();
        let timeout = normalize_canary(&canary_fixture("timeout"), &endpoints).unwrap();
        let tls = normalize_canary(&canary_fixture("tls"), &endpoints).unwrap();
        assert_eq!(timeout.errors[0].code, "canary.timeout");
        assert_eq!(tls.errors[0].code, "canary.tls_failure");
        assert!(timeout.errors[0].summary.contains("verdict withheld"));
        assert!(tls.errors[0].summary.contains("verdict withheld"));
    }

    #[test]
    fn governance_rejects_unapproved_unsupported_mismatch_and_budget_violation() {
        let (_, _, endpoints) = load_and_validate_registries().unwrap();
        for name in ["not-approved", "unsupported", "version", "budget"] {
            assert!(normalize_canary(&canary_fixture(name), &endpoints).is_err());
        }
    }

    #[test]
    fn live_canary_enters_versioned_result_and_local_mode_stays_default() {
        let (measurements, providers, endpoints) = load_and_validate_registries().unwrap();
        let check = normalize_canary(&canary_fixture("401"), &endpoints).unwrap();
        let result = build_private_result(
            PipelineInput {
                context: context(),
                platform: Ok(platform_snapshot()),
                protocol_checks: vec![check],
                live_canary: true,
            },
            &measurements,
            &providers,
        );
        validate_result(&result).unwrap();
        assert_eq!(result["execution"]["mode"], "LIVE_CANARY");
        assert_eq!(
            result["provider_paths"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["provider_id"] == "openai")
                .unwrap()["local_path_state"],
            "incomplete"
        );
        let summary = human_summary(&result);
        assert!(summary.contains("OpenAI / ChatGPT / Codex: evidence recorded"));
        assert!(summary.contains("provider verdict WITHHELD"));
    }

    #[test]
    fn platform_observation_is_not_network_health() {
        let (measurements, providers, _) = load_and_validate_registries().unwrap();
        let result = build_private_result(
            PipelineInput {
                context: context(),
                platform: Ok(platform_snapshot()),
                protocol_checks: vec![],
                live_canary: false,
            },
            &measurements,
            &providers,
        );
        let evidence = result["checks"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|check| check["evidence"].as_array().unwrap())
            .filter(|item| {
                item["evidence_id"]
                    .as_str()
                    .unwrap()
                    .starts_with("platform.")
            });
        for item in evidence {
            assert_eq!(item["state"], "observed");
            assert_eq!(item["confidence"], "medium");
        }
        assert!(!result.to_string().contains("\"state\":\"healthy\""));
    }

    #[test]
    fn claude_tls_fixture_normalizes_without_http_or_health_verdict() {
        let (_, providers, _) = load_and_validate_registries().unwrap();
        let targets = probe_contracts::load_and_validate_provider_path_targets(&providers).unwrap();
        let recorded: RecordedProviderPath = serde_json::from_str(include_str!(
            "../../../fixtures/provider-path/anthropic-tls-completed.json"
        ))
        .unwrap();
        let check = normalize_provider_path(&recorded, &targets).unwrap();
        assert_eq!(check.evidence[0].state, "observed");
        assert_eq!(check.evidence[0].value["stages"]["https"], "not_executed");
        assert_eq!(
            check.evidence[0].value["provider_health_verdict"],
            "withheld"
        );
    }

    #[test]
    fn release_gate_requires_both_governed_provider_paths() {
        let (measurements, providers, endpoints) = load_and_validate_registries().unwrap();
        let targets = probe_contracts::load_and_validate_provider_path_targets(&providers).unwrap();
        let openai = normalize_canary(&canary_fixture("401"), &endpoints).unwrap();
        let claude: RecordedProviderPath = serde_json::from_str(include_str!(
            "../../../fixtures/provider-path/anthropic-tls-completed.json"
        ))
        .unwrap();
        let claude = normalize_provider_path(&claude, &targets).unwrap();
        let result = build_private_result(
            PipelineInput {
                context: context(),
                platform: Ok(platform_snapshot()),
                protocol_checks: vec![openai, claude],
                live_canary: true,
            },
            &measurements,
            &providers,
        );
        validate_result(&result).unwrap();
        assert_eq!(result["release_readiness"]["status"], "ready");
        let summary = human_summary(&result);
        assert!(summary.contains("Claude / Claude Code: evidence recorded"));
        assert!(summary.contains("Gemini: UNSUPPORTED / NOT_EXECUTED"));
    }
}
