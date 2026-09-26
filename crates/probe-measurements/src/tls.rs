use std::{net::SocketAddr, sync::Arc, time::Instant};

use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use rustls_platform_verifier::ConfigVerifierExt;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::{bounded, family, CancellationToken, ErrorCode, ExecutionLimits, MeasurementError};

#[derive(Debug, Clone)]
pub struct TlsTarget {
    pub address: SocketAddr,
    pub server_name: String,
    pub roots: RootCertStore,
}

/// A live client target whose certificate chain and hostname are validated by
/// the operating system verifier. No trust-store contents are exported.
#[derive(Debug, Clone)]
pub struct PlatformTlsTarget {
    pub address: SocketAddr,
    pub server_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsObservation {
    pub address_family: String,
    pub protocol_version: String,
    pub certificate_validated: bool,
    pub elapsed_ms: u64,
    pub attempts: u8,
}

pub async fn measure_tls(
    target: &TlsTarget,
    limits: ExecutionLimits,
    cancellation: &CancellationToken,
) -> Result<TlsObservation, MeasurementError> {
    let limits = limits.validate()?;
    let started = Instant::now();
    for attempt in 1..=limits.max_attempts {
        let result = bounded(
            limits.timeout,
            cancellation,
            ErrorCode::TlsHandshakeError,
            connect_tls(target),
        )
        .await;
        match result {
            Ok((_, protocol_version)) => {
                return Ok(TlsObservation {
                    address_family: family(target.address).to_owned(),
                    protocol_version,
                    certificate_validated: true,
                    elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    attempts: attempt,
                });
            }
            Err(error) if error.code == ErrorCode::Cancelled => return Err(error),
            Err(error) if !error.retryable || attempt == limits.max_attempts => return Err(error),
            Err(_) => {}
        }
    }
    Err(MeasurementError::new(
        ErrorCode::InternalError,
        "TLS retry state invalid",
        false,
    ))
}

pub async fn measure_platform_tls(
    target: &PlatformTlsTarget,
    limits: ExecutionLimits,
    cancellation: &CancellationToken,
) -> Result<TlsObservation, MeasurementError> {
    let limits = limits.validate()?;
    let started = Instant::now();
    for attempt in 1..=limits.max_attempts {
        let result = bounded(
            limits.timeout,
            cancellation,
            ErrorCode::TlsHandshakeError,
            connect_platform_tls(target),
        )
        .await;
        match result {
            Ok((_, protocol_version)) => {
                return Ok(TlsObservation {
                    address_family: family(target.address).to_owned(),
                    protocol_version,
                    certificate_validated: true,
                    elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    attempts: attempt,
                });
            }
            Err(error) if error.code == ErrorCode::Cancelled => return Err(error),
            Err(error) if !error.retryable || attempt == limits.max_attempts => return Err(error),
            Err(_) => {}
        }
    }
    Err(MeasurementError::new(
        ErrorCode::InternalError,
        "platform TLS retry state invalid",
        false,
    ))
}

async fn connect_platform_tls(
    target: &PlatformTlsTarget,
) -> Result<(TlsStream<TcpStream>, String), MeasurementError> {
    let server_name = ServerName::try_from(target.server_name.clone()).map_err(|_| {
        MeasurementError::new(ErrorCode::TlsValidationError, "invalid TLS hostname", false)
    })?;
    let config = ClientConfig::with_platform_verifier().map_err(|_| {
        MeasurementError::new(
            ErrorCode::TlsValidationError,
            "platform TLS verifier unavailable",
            false,
        )
    })?;
    let stream = TcpStream::connect(target.address)
        .await
        .map_err(map_connect_error)?;
    let tls = TlsConnector::from(Arc::new(config))
        .connect(server_name, stream)
        .await
        .map_err(map_tls_error)?;
    let protocol = tls
        .get_ref()
        .1
        .protocol_version()
        .map_or_else(|| "unknown".to_owned(), |version| format!("{version:?}"));
    Ok((tls, protocol))
}

pub(crate) async fn connect_tls(
    target: &TlsTarget,
) -> Result<(TlsStream<TcpStream>, String), MeasurementError> {
    let server_name = ServerName::try_from(target.server_name.clone()).map_err(|_| {
        MeasurementError::new(ErrorCode::TlsValidationError, "invalid TLS hostname", false)
    })?;
    let config = ClientConfig::builder()
        .with_root_certificates(target.roots.clone())
        .with_no_client_auth();
    let stream = TcpStream::connect(target.address)
        .await
        .map_err(map_connect_error)?;
    let tls = TlsConnector::from(Arc::new(config))
        .connect(server_name, stream)
        .await
        .map_err(map_tls_error)?;
    let protocol = tls
        .get_ref()
        .1
        .protocol_version()
        .map_or_else(|| "unknown".to_owned(), |version| format!("{version:?}"));
    Ok((tls, protocol))
}

fn map_connect_error(error: std::io::Error) -> MeasurementError {
    match error.kind() {
        std::io::ErrorKind::ConnectionRefused => {
            MeasurementError::new(ErrorCode::ConnectRefused, "connection refused", false)
        }
        std::io::ErrorKind::TimedOut => {
            MeasurementError::new(ErrorCode::ConnectTimeout, "connection timed out", true)
        }
        std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::NetworkUnreachable => {
            MeasurementError::new(ErrorCode::AddressUnavailable, "address unavailable", false)
        }
        _ => MeasurementError::new(ErrorCode::TlsHandshakeError, "TLS transport failed", true),
    }
}

fn map_tls_error(error: std::io::Error) -> MeasurementError {
    let diagnostic = error.to_string().to_ascii_lowercase();
    if diagnostic.contains("certificate")
        || diagnostic.contains("not valid for name")
        || diagnostic.contains("unknown issuer")
    {
        MeasurementError::new(
            ErrorCode::TlsValidationError,
            "TLS certificate validation failed",
            false,
        )
    } else {
        MeasurementError::new(
            ErrorCode::TlsHandshakeError,
            "TLS handshake failed or connection closed",
            true,
        )
    }
}

#[cfg(test)]
mod platform_verifier_tests {
    use super::*;

    #[test]
    fn platform_verifier_constructs_without_external_tls_tools() {
        ClientConfig::with_platform_verifier().expect("macOS platform verifier should construct");
    }
}
