use std::{net::SocketAddr, time::Instant};

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

use crate::{bounded, family, CancellationToken, ErrorCode, ExecutionLimits, MeasurementError};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DnsQueryType {
    A,
    Aaaa,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsAnswer {
    pub address: String,
    pub family: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsObservation {
    pub resolver_family: String,
    pub query_type: DnsQueryType,
    pub answers: Vec<DnsAnswer>,
    pub answer_count: usize,
    pub elapsed_ms: u64,
    pub attempts: u8,
}

pub async fn measure_dns(
    resolver: SocketAddr,
    name: &str,
    query_type: DnsQueryType,
    limits: ExecutionLimits,
    cancellation: &CancellationToken,
) -> Result<DnsObservation, MeasurementError> {
    let limits = limits.validate()?;
    let query = build_query(name, query_type)?;
    let started = Instant::now();
    let mut last_error = None;
    for attempt in 1..=limits.max_attempts {
        let result = bounded(
            limits.timeout,
            cancellation,
            ErrorCode::DnsError,
            dns_once(resolver, &query, query_type, limits.max_response_bytes),
        )
        .await;
        match result {
            Ok(answers) => {
                return Ok(DnsObservation {
                    resolver_family: family(resolver).to_owned(),
                    query_type,
                    answer_count: answers.len(),
                    answers,
                    elapsed_ms: elapsed_ms(started),
                    attempts: attempt,
                });
            }
            Err(error) if error.code == ErrorCode::Cancelled => return Err(error),
            Err(error) if !error.retryable || attempt == limits.max_attempts => return Err(error),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        MeasurementError::new(ErrorCode::InternalError, "DNS retry state invalid", false)
    }))
}

async fn dns_once(
    resolver: SocketAddr,
    query: &[u8],
    query_type: DnsQueryType,
    max_response_bytes: usize,
) -> Result<Vec<DnsAnswer>, MeasurementError> {
    let bind = if resolver.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await.map_err(|_| {
        MeasurementError::new(ErrorCode::DnsError, "resolver socket unavailable", true)
    })?;
    socket
        .send_to(query, resolver)
        .await
        .map_err(|_| MeasurementError::new(ErrorCode::DnsError, "resolver send failed", true))?;
    let mut response = vec![0_u8; max_response_bytes.min(65_535)];
    let (length, _) = socket
        .recv_from(&mut response)
        .await
        .map_err(|_| MeasurementError::new(ErrorCode::DnsError, "resolver receive failed", true))?;
    response.truncate(length);
    parse_response(&response, query_type)
}

fn build_query(name: &str, query_type: DnsQueryType) -> Result<Vec<u8>, MeasurementError> {
    let normalized = name.trim_end_matches('.');
    if normalized.is_empty() || normalized.len() > 253 {
        return Err(MeasurementError::new(
            ErrorCode::DnsError,
            "invalid DNS name",
            false,
        ));
    }
    let mut query = vec![0x54, 0x56, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    for label in normalized.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err(MeasurementError::new(
                ErrorCode::DnsError,
                "invalid DNS label",
                false,
            ));
        }
        query.push(u8::try_from(label.len()).map_err(|_| {
            MeasurementError::new(ErrorCode::DnsError, "DNS label too long", false)
        })?);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(
        &match query_type {
            DnsQueryType::A => 1_u16,
            DnsQueryType::Aaaa => 28_u16,
        }
        .to_be_bytes(),
    );
    query.extend_from_slice(&1_u16.to_be_bytes());
    Ok(query)
}

fn parse_response(
    response: &[u8],
    query_type: DnsQueryType,
) -> Result<Vec<DnsAnswer>, MeasurementError> {
    if response.len() < 12 || response[0..2] != [0x54, 0x56] {
        return Err(MeasurementError::new(
            ErrorCode::DnsError,
            "malformed DNS response",
            false,
        ));
    }
    let rcode = response[3] & 0x0f;
    if rcode == 3 {
        return Err(MeasurementError::new(
            ErrorCode::DnsNxdomain,
            "DNS name does not exist",
            false,
        ));
    }
    if rcode != 0 {
        return Err(MeasurementError::new(
            ErrorCode::DnsError,
            "resolver returned an error",
            true,
        ));
    }
    let questions = usize::from(u16::from_be_bytes([response[4], response[5]]));
    let answers = usize::from(u16::from_be_bytes([response[6], response[7]]));
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_name(response, offset)?;
        offset = offset
            .checked_add(4)
            .filter(|value| *value <= response.len())
            .ok_or_else(malformed)?;
    }
    let mut output = Vec::new();
    for _ in 0..answers {
        offset = skip_name(response, offset)?;
        if offset + 10 > response.len() {
            return Err(malformed());
        }
        let record_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let data_len = usize::from(u16::from_be_bytes([
            response[offset + 8],
            response[offset + 9],
        ]));
        offset += 10;
        if offset + data_len > response.len() {
            return Err(malformed());
        }
        match (record_type, data_len, query_type) {
            (1, 4, DnsQueryType::A) => output.push(DnsAnswer {
                address: std::net::Ipv4Addr::new(
                    response[offset],
                    response[offset + 1],
                    response[offset + 2],
                    response[offset + 3],
                )
                .to_string(),
                family: "ipv4".to_owned(),
            }),
            (28, 16, DnsQueryType::Aaaa) => {
                let bytes: [u8; 16] = response[offset..offset + 16]
                    .try_into()
                    .map_err(|_| malformed())?;
                output.push(DnsAnswer {
                    address: std::net::Ipv6Addr::from(bytes).to_string(),
                    family: "ipv6".to_owned(),
                });
            }
            _ => {}
        }
        offset += data_len;
    }
    Ok(output)
}

fn skip_name(message: &[u8], mut offset: usize) -> Result<usize, MeasurementError> {
    let mut labels = 0;
    loop {
        let length = *message.get(offset).ok_or_else(malformed)?;
        if length & 0xc0 == 0xc0 {
            return offset
                .checked_add(2)
                .filter(|value| *value <= message.len())
                .ok_or_else(malformed);
        }
        offset += 1;
        if length == 0 {
            return Ok(offset);
        }
        if length > 63 || labels > 127 {
            return Err(malformed());
        }
        offset = offset
            .checked_add(usize::from(length))
            .filter(|value| *value <= message.len())
            .ok_or_else(malformed)?;
        labels += 1;
    }
}

fn malformed() -> MeasurementError {
    MeasurementError::new(ErrorCode::DnsError, "malformed DNS response", false)
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
