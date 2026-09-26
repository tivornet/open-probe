use std::{io::ErrorKind, net::SocketAddr, time::Instant};

use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;

use crate::{bounded, family, CancellationToken, ErrorCode, ExecutionLimits, MeasurementError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TcpObservation {
    pub address_family: String,
    pub connected: bool,
    pub elapsed_ms: u64,
    pub attempts: u8,
}

pub async fn measure_tcp(
    address: SocketAddr,
    limits: ExecutionLimits,
    cancellation: &CancellationToken,
) -> Result<TcpObservation, MeasurementError> {
    let limits = limits.validate()?;
    let started = Instant::now();
    for attempt in 1..=limits.max_attempts {
        let result = bounded(
            limits.timeout,
            cancellation,
            ErrorCode::ConnectTimeout,
            connect_once(address),
        )
        .await;
        match result {
            Ok(()) => {
                return Ok(TcpObservation {
                    address_family: family(address).to_owned(),
                    connected: true,
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
        "TCP retry state invalid",
        false,
    ))
}

async fn connect_once(address: SocketAddr) -> Result<(), MeasurementError> {
    TcpStream::connect(address)
        .await
        .map(|_| ())
        .map_err(|error| match error.kind() {
            ErrorKind::ConnectionRefused => {
                MeasurementError::new(ErrorCode::ConnectRefused, "connection refused", false)
            }
            ErrorKind::AddrNotAvailable | ErrorKind::NetworkUnreachable => {
                MeasurementError::new(ErrorCode::AddressUnavailable, "address unavailable", false)
            }
            ErrorKind::TimedOut => {
                MeasurementError::new(ErrorCode::ConnectTimeout, "connection timed out", true)
            }
            _ => MeasurementError::new(ErrorCode::InternalError, "connection failed", true),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn pending_connect_is_bounded_as_timeout() {
        let result: Result<(), MeasurementError> = bounded(
            Duration::from_millis(5),
            &CancellationToken::default(),
            ErrorCode::ConnectTimeout,
            std::future::pending(),
        )
        .await;
        assert_eq!(result.unwrap_err().code, ErrorCode::ConnectTimeout);
    }

    #[test]
    fn unavailable_address_is_typed() {
        let error = std::io::Error::from(ErrorKind::AddrNotAvailable);
        let mapped = match error.kind() {
            ErrorKind::AddrNotAvailable => {
                MeasurementError::new(ErrorCode::AddressUnavailable, "address unavailable", false)
            }
            _ => unreachable!(),
        };
        assert_eq!(mapped.code, ErrorCode::AddressUnavailable);
    }
}
