//! Fail-closed public export validation. Transform generation follows in a later slice.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use probe_contracts::validate_result;
use regex::Regex;
use serde_json::Value;
use thiserror::Error;

const FORBIDDEN_KEYS: &[&str] = &[
    "password",
    "token",
    "cookie",
    "authorization",
    "client_secret",
    "refresh_token",
    "subscription_url",
    "proxy_credential",
    "mac_address",
    "hostname",
    "exact_ip",
    "public_ip",
    "private_ip",
    "local_ip",
    "raw_config",
];

const FORBIDDEN_EVERYWHERE_KEYS: &[&str] = &[
    "password",
    "token",
    "cookie",
    "authorization",
    "client_secret",
    "refresh_token",
    "subscription_url",
    "proxy_credential",
    "raw_config",
];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RedactionError {
    #[error("private result is not schema-valid")]
    InvalidInput,
    #[error("artifact is not marked as a validated public export")]
    InvalidExportState,
    #[error("forbidden field detected at {0}")]
    ForbiddenField(String),
    #[error("secret-like value detected at {0}")]
    SecretLikeValue(String),
    #[error("output path is unsafe or unavailable")]
    UnsafeOutput,
    #[error("atomic output write failed")]
    WriteFailed,
}

/// Deterministically transform a schema-valid private result into a public export.
/// Private-local and forbidden evidence records are removed as complete units.
pub fn redact_private_result(value: &Value) -> Result<Value, RedactionError> {
    validate_result(value).map_err(|_| RedactionError::InvalidInput)?;
    if value.pointer("/redaction/state").and_then(Value::as_str) != Some("private_local") {
        return Err(RedactionError::InvalidInput);
    }
    inspect_private_forbidden(value, "$")?;
    let mut output = value.clone();
    let checks = output
        .get_mut("checks")
        .and_then(Value::as_array_mut)
        .ok_or(RedactionError::InvalidInput)?;
    let mut removed_paths = Vec::new();
    for (check_index, check) in checks.iter_mut().enumerate() {
        let evidence = check
            .get_mut("evidence")
            .and_then(Value::as_array_mut)
            .ok_or(RedactionError::InvalidInput)?;
        let mut retained = Vec::with_capacity(evidence.len());
        for (evidence_index, item) in evidence.drain(..).enumerate() {
            let privacy = item
                .get("privacy_classification")
                .and_then(Value::as_str)
                .ok_or(RedactionError::InvalidInput)?;
            if matches!(privacy, "private_local" | "forbidden") {
                removed_paths.push(format!(
                    "$.checks[{check_index}].evidence[{evidence_index}]"
                ));
            } else {
                retained.push(item);
            }
        }
        *evidence = retained;
    }
    removed_paths.sort();
    output["redaction"] = serde_json::json!({
        "state": "redacted_export",
        "policy_id": "public_export_v0.1",
        "validation": "passed",
        "removed_paths": removed_paths,
        "transformed_paths": ["$.redaction", "$.permissions"]
    });
    if let Some(permissions) = output.get_mut("permissions").and_then(Value::as_array_mut) {
        for permission in permissions {
            if permission["capability"] == "export_redacted_file" {
                permission["result"] = Value::String("available".to_owned());
            }
        }
    }
    validate_public_export(&output)?;
    Ok(output)
}

fn inspect_private_forbidden(value: &Value, path: &str) -> Result<(), RedactionError> {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                let nested_path = format!("{path}.{key}");
                if FORBIDDEN_EVERYWHERE_KEYS.contains(&key.to_ascii_lowercase().as_str()) {
                    return Err(RedactionError::ForbiddenField(nested_path));
                }
                inspect_private_forbidden(nested, &nested_path)?;
            }
        }
        Value::Array(items) => {
            for (index, nested) in items.iter().enumerate() {
                inspect_private_forbidden(nested, &format!("{path}[{index}]"))?;
            }
        }
        Value::String(text) if looks_secret_like(text) => {
            return Err(RedactionError::SecretLikeValue(path.to_owned()));
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

/// Write a JSON artifact only after all validation has completed.
/// The destination must not exist; a same-directory owner-only temporary file
/// is renamed atomically and removed on every failure path.
pub fn write_json_atomic(path: &Path, value: &Value) -> Result<(), RedactionError> {
    if path.exists() || path.file_name().is_none() {
        return Err(RedactionError::UnsafeOutput);
    }
    let parent = path.parent().ok_or(RedactionError::UnsafeOutput)?;
    if !parent.is_dir() {
        return Err(RedactionError::UnsafeOutput);
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(RedactionError::UnsafeOutput)?;
    let temporary = parent.join(format!(".{file_name}.tivor-tmp"));
    if temporary.exists() {
        return Err(RedactionError::UnsafeOutput);
    }
    let serialized = serde_json::to_vec_pretty(value).map_err(|_| RedactionError::WriteFailed)?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| RedactionError::WriteFailed)?;
        file.write_all(&serialized)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|_| RedactionError::WriteFailed)?;
        fs::rename(&temporary, path).map_err(|_| RedactionError::WriteFailed)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn validate_public_export(value: &Value) -> Result<(), RedactionError> {
    validate_result(value).map_err(|_| RedactionError::InvalidInput)?;
    let redaction = value
        .get("redaction")
        .and_then(Value::as_object)
        .ok_or(RedactionError::InvalidExportState)?;
    if redaction.get("state").and_then(Value::as_str) != Some("redacted_export")
        || redaction.get("policy_id").and_then(Value::as_str) != Some("public_export_v0.1")
        || redaction.get("validation").and_then(Value::as_str) != Some("passed")
    {
        return Err(RedactionError::InvalidExportState);
    }
    inspect(value, "$")
}

fn inspect(value: &Value, path: &str) -> Result<(), RedactionError> {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                let normalized = key.to_ascii_lowercase();
                let nested_path = format!("{path}.{key}");
                if FORBIDDEN_KEYS.contains(&normalized.as_str()) {
                    return Err(RedactionError::ForbiddenField(nested_path));
                }
                inspect(nested, &nested_path)?;
            }
        }
        Value::Array(items) => {
            for (index, nested) in items.iter().enumerate() {
                inspect(nested, &format!("{path}[{index}]"))?;
            }
        }
        Value::String(text) => {
            if looks_secret_like(text) {
                return Err(RedactionError::SecretLikeValue(path.to_owned()));
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn looks_secret_like(value: &str) -> bool {
    let bearer = Regex::new(r"(?i)bearer\s+[a-z0-9._~+/=-]{12,}").expect("static regex");
    let credential_url =
        Regex::new(r"(?i)^[a-z][a-z0-9+.-]*://[^/@\s]+:[^/@\s]+@").expect("static regex");
    let cookie =
        Regex::new(r"(?i)(session|auth|access|refresh)[_-]?(token|cookie)=").expect("static regex");
    bearer.is_match(value) || credential_url.is_match(value) || cookie.is_match(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(path: &str) -> Value {
        serde_json::from_str(match path {
            "safe" => include_str!("../../../fixtures/exports/safe.redacted.v0.1.json"),
            "ip" => include_str!("../../../fixtures/exports/unsafe.exact-ip.json"),
            "token" => include_str!("../../../fixtures/exports/unsafe.token.json"),
            _ => panic!("unknown fixture"),
        })
        .unwrap()
    }

    #[test]
    fn safe_redacted_export_passes() {
        validate_public_export(&fixture("safe")).unwrap();
    }

    #[test]
    fn exact_ip_field_fails_closed() {
        assert!(matches!(
            validate_public_export(&fixture("ip")),
            Err(RedactionError::ForbiddenField(_))
        ));
    }

    #[test]
    fn secret_like_token_fails_closed() {
        assert!(matches!(
            validate_public_export(&fixture("token")),
            Err(RedactionError::SecretLikeValue(_))
        ));
    }

    #[test]
    fn private_to_public_is_deterministic_and_removes_private_evidence() {
        let private: Value = serde_json::from_str(include_str!(
            "../../../fixtures/results/complete.private.v0.2.json"
        ))
        .unwrap();
        let first = redact_private_result(&private).unwrap();
        let second = redact_private_result(&private).unwrap();
        assert_eq!(first, second);
        assert_eq!(first["checks"][0]["evidence"], serde_json::json!([]));
        validate_public_export(&first).unwrap();
    }

    #[test]
    fn atomic_write_refuses_overwrite_and_leaves_no_partial_temp() {
        let private: Value = serde_json::from_str(include_str!(
            "../../../fixtures/results/complete.private.v0.2.json"
        ))
        .unwrap();
        let public = redact_private_result(&private).unwrap();
        let path = std::env::temp_dir().join(format!(
            "tivor-redaction-{}-{}.json",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let temporary = path.parent().unwrap().join(format!(
            ".{}.tivor-tmp",
            path.file_name().unwrap().to_string_lossy()
        ));
        assert!(!path.exists());
        write_json_atomic(&path, &public).unwrap();
        assert!(path.exists());
        assert_eq!(
            write_json_atomic(&path, &public),
            Err(RedactionError::UnsafeOutput)
        );
        assert!(!temporary.exists());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn private_secret_field_fails_before_export_is_created() {
        let mut private: Value = serde_json::from_str(include_str!(
            "../../../fixtures/results/complete.private.v0.2.json"
        ))
        .unwrap();
        private["checks"][0]["evidence"][0]["value"]["token"] =
            Value::String("redacted-test-value".to_owned());
        assert!(matches!(
            redact_private_result(&private),
            Err(RedactionError::ForbiddenField(_))
        ));
    }

    #[test]
    fn live_canary_evidence_is_retained_without_sensitive_content() {
        let mut private: Value = serde_json::from_str(include_str!(
            "../../../fixtures/results/complete.private.v0.2.json"
        ))
        .unwrap();
        private["execution"] = serde_json::json!({
            "mode":"LIVE_CANARY","live_canary":true,"experimental":true
        });
        private["checks"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "check_id":"canary.openai.primary_https",
                "check_version":"0.1.0",
                "capability":"provider.canary",
                "status":"complete",
                "started_at":"2026-09-26T00:00:00Z",
                "finished_at":"2026-09-26T00:00:01Z",
                "duration_ms":72,
                "evidence":[{
                    "evidence_id":"canary.openai.primary_https.observation",
                    "observed_at":"2026-09-26T00:00:01Z",
                    "provenance":"observed",
                    "state":"challenge",
                    "confidence":"high",
                    "privacy_classification":"export_allowed",
                    "value_type":"live_canary_observation",
                    "value":{
                        "endpoint_id":"openai.primary_https",
                        "endpoint_review_version":"1.0.0",
                        "provider_id":"openai",
                        "protocol":"https",
                        "typed_outcome":"http_responder_observed",
                        "http_status":401,
                        "provider_health_verdict":"withheld"
                    },
                    "address_family":"unknown",
                    "limitations":["Observation only."],
                    "supports":[]
                }],
                "errors":[]
            }));
        let public = redact_private_result(&private).unwrap();
        validate_public_export(&public).unwrap();
        let serialized = public.to_string().to_ascii_lowercase();
        assert!(serialized.contains("openai.primary_https"));
        assert!(serialized.contains("provider_health_verdict"));
        assert!(!serialized.contains("authorization"));
        assert!(!serialized.contains("set-cookie"));
    }
}
