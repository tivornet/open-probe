use std::{
    collections::{BTreeMap, HashSet},
    time::Instant,
};

use rustls::RootCertStore;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    bounded,
    tls::{connect_tls, TlsTarget},
    CancellationToken, ErrorCode, ExecutionLimits, MeasurementError,
};

const MAX_HEADER_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct HttpTarget {
    pub address: std::net::SocketAddr,
    pub server_name: String,
    pub path: String,
    pub roots: RootCertStore,
}

#[derive(Debug, Clone, Copy)]
pub struct RedirectPolicy {
    pub max_redirects: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpObservation {
    pub status: u16,
    pub responder_reached: bool,
    pub authorization_or_challenge: bool,
    pub approved_headers: BTreeMap<String, String>,
    pub body_bytes_observed: usize,
    pub redirects_followed: u8,
    pub elapsed_ms: u64,
}

pub async fn measure_https(
    target: &HttpTarget,
    redirect_policy: RedirectPolicy,
    limits: ExecutionLimits,
    cancellation: &CancellationToken,
) -> Result<HttpObservation, MeasurementError> {
    let limits = limits.validate()?;
    if redirect_policy.max_redirects > 5 || !valid_path(&target.path) {
        return Err(MeasurementError::new(
            ErrorCode::HttpResponse,
            "invalid HTTP policy or path",
            false,
        ));
    }
    let started = Instant::now();
    let mut path = target.path.clone();
    let mut visited = HashSet::new();
    let mut redirects = 0;
    loop {
        if !visited.insert(path.clone()) {
            return Err(MeasurementError::new(
                ErrorCode::HttpResponse,
                "redirect loop detected",
                false,
            ));
        }
        let response = bounded(
            limits.timeout,
            cancellation,
            ErrorCode::HttpTimeout,
            request_once(target, &path, limits.max_response_bytes),
        )
        .await?;
        if is_redirect(response.status) {
            if redirects >= redirect_policy.max_redirects {
                return Err(MeasurementError::new(
                    ErrorCode::HttpResponse,
                    "redirect limit exceeded",
                    false,
                ));
            }
            if let Some(location) = response.approved_headers.get("location") {
                if let Some(next_path) = same_origin_path(location, &target.server_name) {
                    redirects += 1;
                    path = next_path;
                    continue;
                }
            }
        }
        return Ok(HttpObservation {
            redirects_followed: redirects,
            elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            ..response
        });
    }
}

async fn request_once(
    target: &HttpTarget,
    path: &str,
    max_response_bytes: usize,
) -> Result<HttpObservation, MeasurementError> {
    let tls_target = TlsTarget {
        address: target.address,
        server_name: target.server_name.clone(),
        roots: target.roots.clone(),
    };
    let (mut stream, _) = connect_tls(&tls_target).await?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: tivor-open-probe/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        target.server_name
    );
    stream.write_all(request.as_bytes()).await.map_err(|_| {
        MeasurementError::new(ErrorCode::HttpResponse, "HTTP request write failed", true)
    })?;
    let mut buffer = Vec::with_capacity(4096);
    let hard_limit = MAX_HEADER_BYTES.saturating_add(max_response_bytes);
    let mut chunk = [0_u8; 2048];
    loop {
        let count = match stream.read(&mut chunk).await {
            Ok(count) => count,
            Err(_) if response_is_complete(&buffer)? => break,
            Err(_) => {
                return Err(MeasurementError::new(
                    ErrorCode::HttpResponse,
                    "HTTP response read failed",
                    true,
                ));
            }
        };
        if count == 0 {
            break;
        }
        if buffer.len().saturating_add(count) > hard_limit {
            return Err(MeasurementError::new(
                ErrorCode::HttpResponse,
                "HTTP response exceeded configured bound",
                false,
            ));
        }
        buffer.extend_from_slice(&chunk[..count]);
        if response_is_complete(&buffer)? {
            break;
        }
    }
    parse_response(&buffer, max_response_bytes)
}

fn response_is_complete(bytes: &[u8]) -> Result<bool, MeasurementError> {
    let Some(header_start) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Ok(false);
    };
    let header_end = header_start + 4;
    if header_end > MAX_HEADER_BYTES {
        return Err(MeasurementError::new(
            ErrorCode::HttpResponse,
            "HTTP headers exceeded configured bound",
            false,
        ));
    }
    let text = std::str::from_utf8(&bytes[..header_end]).map_err(|_| {
        MeasurementError::new(ErrorCode::HttpResponse, "malformed HTTP headers", false)
    })?;
    let content_length = text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    Ok(content_length.is_some_and(|length| bytes.len() >= header_end.saturating_add(length)))
}

fn parse_response(bytes: &[u8], max_body: usize) -> Result<HttpObservation, MeasurementError> {
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .ok_or_else(|| {
            MeasurementError::new(ErrorCode::HttpResponse, "malformed HTTP response", false)
        })?;
    if header_end > MAX_HEADER_BYTES || bytes.len().saturating_sub(header_end) > max_body {
        return Err(MeasurementError::new(
            ErrorCode::HttpResponse,
            "HTTP response exceeded configured bound",
            false,
        ));
    }
    let mut raw_headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut raw_headers);
    let status = response.parse(&bytes[..header_end]).map_err(|_| {
        MeasurementError::new(ErrorCode::HttpResponse, "malformed HTTP headers", false)
    })?;
    if !status.is_complete() {
        return Err(MeasurementError::new(
            ErrorCode::HttpResponse,
            "incomplete HTTP headers",
            false,
        ));
    }
    let code = response.code.ok_or_else(|| {
        MeasurementError::new(ErrorCode::HttpResponse, "missing HTTP status", false)
    })?;
    let mut approved = BTreeMap::new();
    for header in response.headers.iter() {
        let name = header.name.to_ascii_lowercase();
        if matches!(name.as_str(), "content-type" | "server") {
            if let Ok(value) = std::str::from_utf8(header.value) {
                approved.insert(name, sanitize_header(value));
            }
        } else if name == "location" {
            if let Ok(value) = std::str::from_utf8(header.value) {
                approved.insert(name, sanitize_location(value));
            }
        }
    }
    Ok(HttpObservation {
        status: code,
        responder_reached: true,
        authorization_or_challenge: matches!(code, 401 | 403),
        approved_headers: approved,
        body_bytes_observed: bytes.len() - header_end,
        redirects_followed: 0,
        elapsed_ms: 0,
    })
}

fn sanitize_header(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(256)
        .collect()
}

fn sanitize_location(value: &str) -> String {
    let clean = value.split(['?', '#']).next().unwrap_or("/");
    sanitize_header(clean)
}

fn valid_path(path: &str) -> bool {
    path.starts_with('/') && !path.contains(['\r', '\n']) && path.len() <= 2048
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn same_origin_path(location: &str, hostname: &str) -> Option<String> {
    if valid_path(location) {
        return Some(location.to_owned());
    }
    for prefix in [
        format!("https://{hostname}"),
        format!("https://{hostname}:443"),
    ] {
        if let Some(path) = location.strip_prefix(&prefix) {
            let normalized = if path.is_empty() { "/" } else { path };
            if valid_path(normalized) {
                return Some(normalized.to_owned());
            }
        }
    }
    None
}
