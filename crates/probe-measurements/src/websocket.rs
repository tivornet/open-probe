use std::{net::SocketAddr, pin::Pin, time::Instant};

use base64::{engine::general_purpose::STANDARD, Engine};
use rustls::RootCertStore;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    bounded,
    tls::{connect_tls, TlsTarget},
    CancellationToken, ErrorCode, ExecutionLimits, MeasurementError,
};

trait AsyncStream: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send> AsyncStream for T {}
type BoxStream = Pin<Box<dyn AsyncStream>>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum WebSocketScheme {
    Ws,
    Wss,
}

#[derive(Debug, Clone)]
pub struct WebSocketTarget {
    pub scheme: WebSocketScheme,
    pub address: SocketAddr,
    pub server_name: String,
    pub path: String,
    pub roots: RootCertStore,
    pub fixture_payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebSocketObservation {
    pub tcp_reachable: bool,
    pub tls_successful: bool,
    pub upgrade_successful: bool,
    pub fixture_bytes_sent: usize,
    pub fixture_bytes_received: usize,
    pub elapsed_ms: u64,
}

pub async fn measure_websocket(
    target: &WebSocketTarget,
    limits: ExecutionLimits,
    cancellation: &CancellationToken,
) -> Result<WebSocketObservation, MeasurementError> {
    let limits = limits.validate()?;
    if !target.path.starts_with('/')
        || target.path.contains(['\r', '\n'])
        || target.fixture_payload.len() > 125
    {
        return Err(MeasurementError::new(
            ErrorCode::WebsocketUpgradeError,
            "invalid WebSocket fixture target",
            false,
        ));
    }
    let started = Instant::now();
    bounded(
        limits.timeout,
        cancellation,
        ErrorCode::WebsocketTimeout,
        websocket_once(target, limits.max_response_bytes),
    )
    .await
    .map(|mut observation| {
        observation.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        observation
    })
}

async fn websocket_once(
    target: &WebSocketTarget,
    max_response_bytes: usize,
) -> Result<WebSocketObservation, MeasurementError> {
    let (mut stream, tls_successful): (BoxStream, bool) = match target.scheme {
        WebSocketScheme::Ws => {
            let stream = tokio::net::TcpStream::connect(target.address)
                .await
                .map_err(|_| {
                    MeasurementError::new(
                        ErrorCode::WebsocketUpgradeError,
                        "WebSocket TCP connection failed",
                        true,
                    )
                })?;
            (Box::pin(stream), false)
        }
        WebSocketScheme::Wss => {
            let tls_target = TlsTarget {
                address: target.address,
                server_name: target.server_name.clone(),
                roots: target.roots.clone(),
            };
            let (stream, _) = connect_tls(&tls_target).await?;
            (Box::pin(stream), true)
        }
    };
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| {
        MeasurementError::new(
            ErrorCode::InternalError,
            "WebSocket nonce generation failed",
            false,
        )
    })?;
    let key = STANDARD.encode(nonce);
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        target.path, target.server_name
    );
    stream.write_all(request.as_bytes()).await.map_err(|_| {
        MeasurementError::new(
            ErrorCode::WebsocketUpgradeError,
            "WebSocket handshake write failed",
            true,
        )
    })?;
    let headers = read_headers(&mut stream, 16 * 1024).await?;
    validate_upgrade(&headers, &key)?;

    let frame = masked_text_frame(&target.fixture_payload)?;
    stream.write_all(&frame).await.map_err(|_| {
        MeasurementError::new(
            ErrorCode::WebsocketUpgradeError,
            "WebSocket fixture send failed",
            true,
        )
    })?;
    let received = read_server_frame(&mut stream, max_response_bytes.min(125)).await?;
    Ok(WebSocketObservation {
        tcp_reachable: true,
        tls_successful,
        upgrade_successful: true,
        fixture_bytes_sent: target.fixture_payload.len(),
        fixture_bytes_received: received,
        elapsed_ms: 0,
    })
}

async fn read_headers(stream: &mut BoxStream, max: usize) -> Result<Vec<u8>, MeasurementError> {
    let mut output = Vec::new();
    let mut byte = [0_u8; 1];
    while output.len() < max {
        let count = stream.read(&mut byte).await.map_err(|_| {
            MeasurementError::new(
                ErrorCode::WebsocketUpgradeError,
                "WebSocket handshake read failed",
                true,
            )
        })?;
        if count == 0 {
            return Err(MeasurementError::new(
                ErrorCode::WebsocketUpgradeError,
                "connection closed during WebSocket handshake",
                true,
            ));
        }
        output.push(byte[0]);
        if output.ends_with(b"\r\n\r\n") {
            return Ok(output);
        }
    }
    Err(MeasurementError::new(
        ErrorCode::WebsocketUpgradeError,
        "WebSocket headers exceeded bound",
        false,
    ))
}

fn validate_upgrade(bytes: &[u8], key: &str) -> Result<(), MeasurementError> {
    let mut raw_headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut raw_headers);
    response.parse(bytes).map_err(|_| {
        MeasurementError::new(
            ErrorCode::WebsocketUpgradeError,
            "malformed WebSocket handshake",
            false,
        )
    })?;
    if response.code != Some(101) {
        return Err(MeasurementError::new(
            ErrorCode::WebsocketUpgradeError,
            "WebSocket upgrade rejected",
            false,
        ));
    }
    let expected = websocket_accept(key);
    let actual = response
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("sec-websocket-accept"))
        .and_then(|header| std::str::from_utf8(header.value).ok())
        .map(str::trim);
    if actual != Some(expected.as_str()) {
        return Err(MeasurementError::new(
            ErrorCode::WebsocketUpgradeError,
            "invalid WebSocket accept value",
            false,
        ));
    }
    Ok(())
}

fn websocket_accept(key: &str) -> String {
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    STANDARD.encode(digest.finalize())
}

fn masked_text_frame(payload: &[u8]) -> Result<Vec<u8>, MeasurementError> {
    if payload.len() > 125 {
        return Err(MeasurementError::new(
            ErrorCode::WebsocketUpgradeError,
            "fixture payload exceeds bound",
            false,
        ));
    }
    let mut mask = [0_u8; 4];
    getrandom::fill(&mut mask).map_err(|_| {
        MeasurementError::new(
            ErrorCode::InternalError,
            "WebSocket mask generation failed",
            false,
        )
    })?;
    let mut frame = vec![
        0x81,
        0x80 | u8::try_from(payload.len()).map_err(|_| {
            MeasurementError::new(
                ErrorCode::InternalError,
                "payload length conversion failed",
                false,
            )
        })?,
    ];
    frame.extend_from_slice(&mask);
    frame.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % 4]),
    );
    Ok(frame)
}

async fn read_server_frame(stream: &mut BoxStream, max: usize) -> Result<usize, MeasurementError> {
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header).await.map_err(|_| {
        MeasurementError::new(
            ErrorCode::WebsocketUpgradeError,
            "connection closed before fixture frame",
            true,
        )
    })?;
    if header[1] & 0x80 != 0 {
        return Err(MeasurementError::new(
            ErrorCode::WebsocketUpgradeError,
            "server frame unexpectedly masked",
            false,
        ));
    }
    let length = usize::from(header[1] & 0x7f);
    if length > max || length > 125 {
        return Err(MeasurementError::new(
            ErrorCode::WebsocketUpgradeError,
            "WebSocket frame exceeded bound",
            false,
        ));
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await.map_err(|_| {
        MeasurementError::new(
            ErrorCode::WebsocketUpgradeError,
            "incomplete WebSocket fixture frame",
            true,
        )
    })?;
    Ok(length)
}
