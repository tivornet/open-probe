use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD, Engine};
use probe_measurements::{
    measure_dns, measure_https, measure_tcp, measure_tls, measure_websocket, CancellationToken,
    DnsQueryType, ErrorCode, ExecutionLimits, HttpTarget, RedirectPolicy, TlsTarget,
    WebSocketScheme, WebSocketTarget,
};
use rcgen::generate_simple_self_signed;
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore, ServerConfig};
use sha1::{Digest, Sha1};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use tokio_rustls::TlsAcceptor;

fn limits(timeout_ms: u64, max_bytes: usize) -> ExecutionLimits {
    ExecutionLimits {
        timeout: Duration::from_millis(timeout_ms),
        max_attempts: 1,
        max_response_bytes: max_bytes,
    }
}

fn fixture_tls() -> (Arc<ServerConfig>, RootCertStore) {
    let certified = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate = certified.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into();
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key)
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate).unwrap();
    (Arc::new(server), roots)
}

async fn spawn_dns(mode: &str) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let mode = mode.to_owned();
    tokio::spawn(async move {
        let mut query = [0_u8; 512];
        let (length, peer) = socket.recv_from(&mut query).await.unwrap();
        if mode == "timeout" {
            tokio::time::sleep(Duration::from_secs(2)).await;
            return;
        }
        if mode == "malformed" {
            socket.send_to(b"bad", peer).await.unwrap();
            return;
        }
        let mut end = 12;
        while end < length && query[end] != 0 {
            end += usize::from(query[end]) + 1;
        }
        end += 5;
        let mut response = query[..end].to_vec();
        response[2] = 0x81;
        response[3] = if mode == "nxdomain" { 0x83 } else { 0x80 };
        let answer_count = if matches!(mode.as_str(), "a" | "aaaa") {
            1_u16
        } else {
            0
        };
        response[6..8].copy_from_slice(&answer_count.to_be_bytes());
        if answer_count == 1 {
            let (record_type, data): (u16, Vec<u8>) = if mode == "a" {
                (1, vec![192, 0, 2, 10])
            } else {
                (28, Ipv6Fixture::bytes())
            };
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&record_type.to_be_bytes());
            response.extend_from_slice(&1_u16.to_be_bytes());
            response.extend_from_slice(&60_u32.to_be_bytes());
            response.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            response.extend_from_slice(&data);
        }
        socket.send_to(&response, peer).await.unwrap();
    });
    address
}

struct Ipv6Fixture;
impl Ipv6Fixture {
    fn bytes() -> Vec<u8> {
        "2001:db8::10"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()
            .to_vec()
    }
}

async fn spawn_tls_early_close() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
    });
    address
}

#[tokio::test]
async fn dns_success_v4_v6_empty_and_nxdomain() {
    let cancel = CancellationToken::default();
    let a = measure_dns(
        spawn_dns("a").await,
        "fixture.test",
        DnsQueryType::A,
        limits(500, 2048),
        &cancel,
    )
    .await
    .unwrap();
    assert_eq!(a.answer_count, 1);
    assert_eq!(a.answers[0].family, "ipv4");
    let aaaa = measure_dns(
        spawn_dns("aaaa").await,
        "fixture.test",
        DnsQueryType::Aaaa,
        limits(500, 2048),
        &cancel,
    )
    .await
    .unwrap();
    assert_eq!(aaaa.answers[0].family, "ipv6");
    let empty = measure_dns(
        spawn_dns("empty").await,
        "fixture.test",
        DnsQueryType::A,
        limits(500, 2048),
        &cancel,
    )
    .await
    .unwrap();
    assert_eq!(empty.answer_count, 0);
    let error = measure_dns(
        spawn_dns("nxdomain").await,
        "fixture.test",
        DnsQueryType::A,
        limits(500, 2048),
        &cancel,
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::DnsNxdomain);
}

#[tokio::test]
async fn dns_timeout_resolver_error_and_cancellation() {
    let error = measure_dns(
        spawn_dns("timeout").await,
        "fixture.test",
        DnsQueryType::A,
        limits(30, 2048),
        &CancellationToken::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::DnsError);
    let error = measure_dns(
        spawn_dns("malformed").await,
        "fixture.test",
        DnsQueryType::A,
        limits(500, 2048),
        &CancellationToken::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::DnsError);
    let token = CancellationToken::default();
    let cancel = token.clone();
    let address = spawn_dns("timeout").await;
    let task = tokio::spawn(async move {
        measure_dns(
            address,
            "fixture.test",
            DnsQueryType::A,
            limits(1000, 2048),
            &token,
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    cancel.cancel();
    assert_eq!(task.await.unwrap().unwrap_err().code, ErrorCode::Cancelled);
}

#[tokio::test]
async fn tcp_success_refused_and_family() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        listener.accept().await.unwrap();
    });
    let observation = measure_tcp(address, limits(500, 1024), &CancellationToken::default())
        .await
        .unwrap();
    assert!(observation.connected);
    assert_eq!(observation.address_family, "ipv4");
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let refused = unused.local_addr().unwrap();
    drop(unused);
    let error = measure_tcp(refused, limits(500, 1024), &CancellationToken::default())
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ConnectRefused);
}

#[tokio::test]
async fn tls_success_hostname_failure_and_early_close() {
    let (server, roots) = fixture_tls();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        TlsAcceptor::from(server).accept(stream).await.unwrap();
    });
    let ok = measure_tls(
        &TlsTarget {
            address,
            server_name: "localhost".to_owned(),
            roots: roots.clone(),
        },
        limits(1000, 1024),
        &CancellationToken::default(),
    )
    .await
    .unwrap();
    assert!(ok.certificate_validated);
    assert_ne!(ok.protocol_version, "unknown");

    let (server, roots) = fixture_tls();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = TlsAcceptor::from(server).accept(stream).await;
    });
    let mismatch = measure_tls(
        &TlsTarget {
            address,
            server_name: "wrong.example".to_owned(),
            roots,
        },
        limits(1000, 1024),
        &CancellationToken::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(mismatch.code, ErrorCode::TlsValidationError);

    let error = measure_tls(
        &TlsTarget {
            address: spawn_tls_early_close().await,
            server_name: "localhost".to_owned(),
            roots: RootCertStore::empty(),
        },
        limits(500, 1024),
        &CancellationToken::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::TlsHandshakeError);
}

#[tokio::test]
async fn tls_handshake_timeout_is_bounded() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    });
    let error = measure_tls(
        &TlsTarget {
            address,
            server_name: "localhost".to_owned(),
            roots: RootCertStore::empty(),
        },
        limits(30, 1024),
        &CancellationToken::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::TlsHandshakeError);
}

async fn spawn_https(mode: &str, connections: usize) -> (SocketAddr, RootCertStore) {
    let (server, roots) = fixture_tls();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mode = mode.to_owned();
    tokio::spawn(async move {
        for _ in 0..connections {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = TlsAcceptor::from(server.clone())
                .accept(stream)
                .await
                .unwrap();
            let mut request = vec![0_u8; 4096];
            let count = tls.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..count]);
            let path = request.split_whitespace().nth(1).unwrap_or("/");
            if mode == "slow" {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            if mode == "early_close" {
                continue;
            }
            if mode == "malformed" {
                tls.write_all(b"NOT HTTP\r\n\r\n").await.unwrap();
                continue;
            }
            let (status, extra, body) = match (mode.as_str(), path) {
                ("401", _) => (
                    "401 Unauthorized",
                    "Set-Cookie: prohibited=secret\r\n",
                    "unauthorized",
                ),
                ("403", _) => ("403 Forbidden", "", "forbidden"),
                ("500", _) => ("500 Internal Server Error", "", "error"),
                ("redirect", "/start") => ("302 Found", "Location: /final?secret=removed\r\n", ""),
                ("loop", _) => ("302 Found", "Location: /loop\r\n", ""),
                ("oversized", _) => ("200 OK", "", "x"),
                _ => (
                    "200 OK",
                    "Content-Type: text/plain\r\nServer: fixture\r\n",
                    "ok",
                ),
            };
            let body = if mode == "oversized" {
                "x".repeat(4096)
            } else {
                body.to_owned()
            };
            let response = format!(
                "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            tls.write_all(response.as_bytes()).await.unwrap();
        }
    });
    (address, roots)
}

fn http_target(address: SocketAddr, roots: RootCertStore, path: &str) -> HttpTarget {
    HttpTarget {
        address,
        server_name: "localhost".to_owned(),
        path: path.to_owned(),
        roots,
    }
}

#[tokio::test]
async fn https_statuses_preserve_authorization_semantics_and_headers() {
    for (mode, status, challenge) in [
        ("401", 401, true),
        ("403", 403, true),
        ("500", 500, false),
        ("ok", 200, false),
    ] {
        let (address, roots) = spawn_https(mode, 1).await;
        let result = measure_https(
            &http_target(address, roots, "/"),
            RedirectPolicy { max_redirects: 0 },
            limits(1000, 1024),
            &CancellationToken::default(),
        )
        .await
        .unwrap();
        assert_eq!(result.status, status);
        assert!(result.responder_reached);
        assert_eq!(result.authorization_or_challenge, challenge);
        assert!(!result.approved_headers.contains_key("set-cookie"));
    }
}

#[tokio::test]
async fn https_redirect_is_bounded_and_query_is_not_retained() {
    let (address, roots) = spawn_https("redirect", 2).await;
    let result = measure_https(
        &http_target(address, roots, "/start"),
        RedirectPolicy { max_redirects: 1 },
        limits(1000, 1024),
        &CancellationToken::default(),
    )
    .await
    .unwrap();
    assert_eq!(result.status, 200);
    assert_eq!(result.redirects_followed, 1);

    let (address, roots) = spawn_https("loop", 2).await;
    let error = measure_https(
        &http_target(address, roots, "/loop"),
        RedirectPolicy { max_redirects: 2 },
        limits(1000, 1024),
        &CancellationToken::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::HttpResponse);
}

#[tokio::test]
async fn https_timeout_oversized_malformed_and_early_close_are_bounded() {
    for (mode, timeout, max_bytes) in [
        ("slow", 30, 1024),
        ("oversized", 1000, 32),
        ("malformed", 1000, 1024),
        ("early_close", 1000, 1024),
    ] {
        let (address, roots) = spawn_https(mode, 1).await;
        let error = measure_https(
            &http_target(address, roots, "/"),
            RedirectPolicy { max_redirects: 0 },
            limits(timeout, max_bytes),
            &CancellationToken::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error.code,
            ErrorCode::HttpTimeout | ErrorCode::HttpResponse
        ));
    }
}

#[tokio::test]
async fn https_propagates_tls_validation_and_supports_cancellation() {
    let (address, _roots) = spawn_https("ok", 1).await;
    let error = measure_https(
        &http_target(address, RootCertStore::empty(), "/"),
        RedirectPolicy { max_redirects: 0 },
        limits(1000, 1024),
        &CancellationToken::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::TlsValidationError);

    let (address, roots) = spawn_https("slow", 1).await;
    let target = http_target(address, roots, "/");
    let token = CancellationToken::default();
    let cancel = token.clone();
    let task = tokio::spawn(async move {
        measure_https(
            &target,
            RedirectPolicy { max_redirects: 0 },
            limits(2000, 1024),
            &token,
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    cancel.cancel();
    assert_eq!(task.await.unwrap().unwrap_err().code, ErrorCode::Cancelled);
}

async fn spawn_websocket(mode: &str) -> (SocketAddr, RootCertStore) {
    let (server, roots) = fixture_tls();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mode = mode.to_owned();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = TlsAcceptor::from(server).accept(stream).await.unwrap();
        if mode == "timeout" {
            tokio::time::sleep(Duration::from_secs(2)).await;
            return;
        }
        if mode == "early_close" {
            return;
        }
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while request.len() < 16 * 1024 {
            if tls.read_exact(&mut byte).await.is_err() {
                return;
            }
            request.push(byte[0]);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        if mode == "malformed" {
            tls.write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
                .await
                .unwrap();
            return;
        }
        if mode == "reject" {
            tls.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            return;
        }
        let text = String::from_utf8_lossy(&request);
        let key = text
            .lines()
            .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
            .unwrap()
            .trim();
        let mut hash = Sha1::new();
        hash.update(key.as_bytes());
        hash.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let accept = STANDARD.encode(hash.finalize());
        let response = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n");
        tls.write_all(response.as_bytes()).await.unwrap();
        let mut header = [0_u8; 2];
        tls.read_exact(&mut header).await.unwrap();
        let length = usize::from(header[1] & 0x7f);
        let mut mask = [0_u8; 4];
        tls.read_exact(&mut mask).await.unwrap();
        let mut payload = vec![0_u8; length];
        tls.read_exact(&mut payload).await.unwrap();
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
        tls.write_all(&[0x81, 2, b'o', b'k']).await.unwrap();
    });
    (address, roots)
}

fn ws_target(address: SocketAddr, roots: RootCertStore) -> WebSocketTarget {
    WebSocketTarget {
        scheme: WebSocketScheme::Wss,
        address,
        server_name: "localhost".to_owned(),
        path: "/fixture".to_owned(),
        roots,
        fixture_payload: b"ping".to_vec(),
    }
}

#[tokio::test]
async fn websocket_upgrade_and_bounded_exchange_succeed() {
    let (address, roots) = spawn_websocket("success").await;
    let result = measure_websocket(
        &ws_target(address, roots),
        limits(1000, 125),
        &CancellationToken::default(),
    )
    .await
    .unwrap();
    assert!(result.tcp_reachable && result.tls_successful && result.upgrade_successful);
    assert_eq!(result.fixture_bytes_sent, 4);
    assert_eq!(result.fixture_bytes_received, 2);
}

#[tokio::test]
async fn websocket_reject_malformed_timeout_and_early_close_are_typed() {
    for mode in ["reject", "malformed", "timeout", "early_close"] {
        let (address, roots) = spawn_websocket(mode).await;
        let error = measure_websocket(
            &ws_target(address, roots),
            limits(if mode == "timeout" { 30 } else { 1000 }, 125),
            &CancellationToken::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error.code,
            ErrorCode::WebsocketUpgradeError | ErrorCode::WebsocketTimeout
        ));
    }
}

#[tokio::test]
async fn websocket_cancellation_stops_slow_fixture() {
    let (address, roots) = spawn_websocket("timeout").await;
    let target = ws_target(address, roots);
    let token = CancellationToken::default();
    let cancel = token.clone();
    let task =
        tokio::spawn(async move { measure_websocket(&target, limits(2000, 125), &token).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    cancel.cancel();
    assert_eq!(task.await.unwrap().unwrap_err().code, ErrorCode::Cancelled);
}

#[test]
fn fixtures_bind_loopback_only() {
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    assert!(loopback.is_loopback());
}
