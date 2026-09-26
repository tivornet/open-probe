//! Provider-neutral, bounded protocol measurement primitives.

mod dns;
mod http;
mod tcp;
mod tls;
mod websocket;

use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

pub use dns::{measure_dns, DnsAnswer, DnsObservation, DnsQueryType};
pub use http::{measure_https, HttpObservation, HttpTarget, RedirectPolicy};
use serde::{Deserialize, Serialize};
pub use tcp::{measure_tcp, TcpObservation};
use thiserror::Error;
pub use tls::{measure_platform_tls, measure_tls, PlatformTlsTarget, TlsObservation, TlsTarget};
use tokio::sync::Notify;
pub use websocket::{measure_websocket, WebSocketObservation, WebSocketScheme, WebSocketTarget};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    DnsError,
    DnsNxdomain,
    ConnectRefused,
    ConnectTimeout,
    AddressUnavailable,
    TlsValidationError,
    TlsHandshakeError,
    HttpResponse,
    HttpTimeout,
    WebsocketUpgradeError,
    WebsocketTimeout,
    Cancelled,
    Unsupported,
    InternalError,
}

#[derive(Debug, Error, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[error("{code:?}: {summary}")]
pub struct MeasurementError {
    pub code: ErrorCode,
    pub summary: String,
    pub retryable: bool,
}

impl MeasurementError {
    #[must_use]
    pub fn new(code: ErrorCode, summary: impl Into<String>, retryable: bool) -> Self {
        Self {
            code,
            summary: summary.into(),
            retryable,
        }
    }
}

impl ErrorCode {
    #[must_use]
    pub const fn as_contract_code(self) -> &'static str {
        match self {
            Self::DnsError => "DNS_ERROR",
            Self::DnsNxdomain => "DNS_NXDOMAIN",
            Self::ConnectRefused => "CONNECT_REFUSED",
            Self::ConnectTimeout => "CONNECT_TIMEOUT",
            Self::AddressUnavailable => "ADDRESS_UNAVAILABLE",
            Self::TlsValidationError => "TLS_VALIDATION_ERROR",
            Self::TlsHandshakeError => "TLS_HANDSHAKE_ERROR",
            Self::HttpResponse => "HTTP_RESPONSE",
            Self::HttpTimeout => "HTTP_TIMEOUT",
            Self::WebsocketUpgradeError => "WEBSOCKET_UPGRADE_ERROR",
            Self::WebsocketTimeout => "WEBSOCKET_TIMEOUT",
            Self::Cancelled => "CANCELLED",
            Self::Unsupported => "UNSUPPORTED",
            Self::InternalError => "INTERNAL_ERROR",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ExecutionLimits {
    pub timeout: Duration,
    pub max_attempts: u8,
    pub max_response_bytes: usize,
}

impl ExecutionLimits {
    pub fn validate(self) -> Result<Self, MeasurementError> {
        if self.timeout.is_zero()
            || self.max_attempts == 0
            || self.max_attempts > 3
            || self.max_response_bytes == 0
            || self.max_response_bytes > 1024 * 1024
        {
            return Err(MeasurementError::new(
                ErrorCode::InternalError,
                "invalid execution limits",
                false,
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl CancellationToken {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        self.notify.notified().await;
    }
}

async fn bounded<T>(
    timeout: Duration,
    cancellation: &CancellationToken,
    timeout_code: ErrorCode,
    operation: impl Future<Output = Result<T, MeasurementError>>,
) -> Result<T, MeasurementError> {
    if cancellation.is_cancelled() {
        return Err(cancelled_error());
    }
    tokio::select! {
        () = cancellation.cancelled() => Err(cancelled_error()),
        result = tokio::time::timeout(timeout, operation) => match result {
            Ok(value) => value,
            Err(_) => Err(MeasurementError::new(timeout_code, "measurement deadline exceeded", true)),
        }
    }
}

fn cancelled_error() -> MeasurementError {
    MeasurementError::new(ErrorCode::Cancelled, "measurement cancelled", false)
}

fn family(address: std::net::SocketAddr) -> &'static str {
    if address.is_ipv4() {
        "ipv4"
    } else {
        "ipv6"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_reject_unbounded_retry_or_resource_policy() {
        assert!(ExecutionLimits {
            timeout: Duration::from_secs(1),
            max_attempts: 4,
            max_response_bytes: 1024,
        }
        .validate()
        .is_err());
        assert!(ExecutionLimits {
            timeout: Duration::ZERO,
            max_attempts: 1,
            max_response_bytes: 1024,
        }
        .validate()
        .is_err());
        assert!(ExecutionLimits {
            timeout: Duration::from_secs(1),
            max_attempts: 1,
            max_response_bytes: 2 * 1024 * 1024,
        }
        .validate()
        .is_err());
    }

    #[test]
    fn errors_are_not_health_verdicts() {
        assert_eq!(ErrorCode::DnsNxdomain.as_contract_code(), "DNS_NXDOMAIN");
        assert_eq!(ErrorCode::HttpResponse.as_contract_code(), "HTTP_RESPONSE");
    }
}
