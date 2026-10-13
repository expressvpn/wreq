//! CONNECT through an HTTPS proxy. The hop to the proxy is built like any other connection —
//! the client's whole TLS profile, ALPN included, as a browser presents to a proxy — so a proxy
//! that chooses h2 gets its CONNECT on HTTP/2.

use std::{
    collections::BTreeSet,
    convert::Infallible,
    io::Read,
    net::{SocketAddr, TcpListener as StdListener},
    pin::Pin,
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};

use btls::ssl::{AlpnError, Ssl, SslAcceptor, SslFiletype, SslMethod, select_next_proto};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_btls::SslStream;
use wreq::tls::{AlpnProtocol, AlpsProtocol, TlsOptions};

const H2: &[u8] = b"\x02h2";
const H1: &[u8] = b"\x08http/1.1";
const AUTH: &str = "Basic dTpw";

fn acceptor(alpn: &'static [u8]) -> SslAcceptor {
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    b.set_certificate_file("tests/support/server.cert", SslFiletype::ASN1)
        .unwrap();
    b.set_private_key_file("tests/support/server.key", SslFiletype::ASN1)
        .unwrap();
    b.set_alpn_select_callback(move |_, client| {
        select_next_proto(alpn, client).ok_or(AlpnError::NOACK)
    });
    b.build()
}

async fn accept(acceptor: &SslAcceptor, tcp: TcpStream) -> Option<SslStream<TcpStream>> {
    let mut s = SslStream::new(Ssl::new(acceptor.context()).ok()?, tcp).ok()?;
    Pin::new(&mut s).accept().await.ok()?;
    Some(s)
}

/// A TLS origin answering every request with `origin`.
async fn origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = acceptor(H1);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let Some(tls) = accept(&acceptor, tcp).await else {
                continue;
            };
            tokio::spawn(hyper::server::conn::http1::Builder::new().serve_connection(
                TokioIo::new(tls),
                service_fn(|_| async {
                    Ok::<_, Infallible>(Response::new(Full::<bytes::Bytes>::from("origin")))
                }),
            ));
        }
    });
    addr
}

/// What the proxy saw of one CONNECT.
#[derive(Debug, PartialEq)]
struct Seen {
    alpn: Option<Vec<u8>>,
    authority: String,
    auth: Option<String>,
}

/// A TLS proxy preferring `alpn`, tunnelling every CONNECT to the address it names.
async fn proxy(alpn: &'static [u8]) -> (SocketAddr, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let acceptor = acceptor(alpn);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let Some(tls) = accept(&acceptor, tcp).await else {
                continue;
            };
            let negotiated = tls.ssl().selected_alpn_protocol().map(<[u8]>::to_vec);
            let log = log.clone();
            let service = service_fn(move |mut req: Request<Incoming>| {
                let log = log.clone();
                let negotiated = negotiated.clone();
                async move {
                    assert_eq!(req.method(), Method::CONNECT);
                    let authority = req.uri().authority().unwrap().to_string();
                    log.lock().unwrap().push(Seen {
                        alpn: negotiated,
                        authority: authority.clone(),
                        auth: req
                            .headers()
                            .get(http::header::PROXY_AUTHORIZATION)
                            .map(|v| v.to_str().unwrap().to_owned()),
                    });
                    tokio::spawn(async move {
                        let upgraded = hyper::upgrade::on(&mut req).await.unwrap();
                        let mut upstream = TcpStream::connect(authority).await.unwrap();
                        let _ = tokio::io::copy_bidirectional(
                            &mut TokioIo::new(upgraded),
                            &mut upstream,
                        )
                        .await;
                    });
                    Ok::<_, Infallible>(Response::new(Full::<bytes::Bytes>::default()))
                }
            });
            let io = TokioIo::new(tls);
            if alpn == H2 {
                tokio::spawn(
                    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(io, service),
                );
            } else {
                tokio::spawn(
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .with_upgrades(),
                );
            }
        }
    });
    (addr, seen)
}

fn tls_options() -> TlsOptions {
    TlsOptions::builder()
        .alpn_protocols([AlpnProtocol::HTTP2, AlpnProtocol::HTTP1])
        .alps_protocols([AlpsProtocol::HTTP2])
        .enable_ech_grease(true)
        .build()
}

async fn through(alpn: &'static [u8]) -> Seen {
    let origin = origin().await;
    let (proxy, seen) = proxy(alpn).await;
    let client = wreq::Client::builder()
        .tls_options(tls_options())
        .tls_cert_verification(false)
        .proxy(
            wreq::Proxy::all(format!("https://{proxy}"))
                .unwrap()
                .custom_http_auth(HeaderValue::from_static(AUTH)),
        )
        .build()
        .unwrap();
    let res = client
        .get(format!("https://{origin}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.text().await.unwrap(), "origin");
    let mut seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let mut one = seen.pop().unwrap();
    assert_eq!(one.authority, origin.to_string());
    one.authority.clear();
    one
}

#[tokio::test]
async fn a_proxy_choosing_h2_gets_the_connect_on_http2() {
    let seen = through(H2).await;
    assert_eq!(seen.alpn.as_deref(), Some(&H2[1..]));
    assert_eq!(seen.auth.as_deref(), Some(AUTH));
}

#[tokio::test]
async fn a_proxy_choosing_http1_gets_the_connect_on_http1() {
    let seen = through(H1).await;
    assert_eq!(seen.alpn.as_deref(), Some(&H1[1..]));
    assert_eq!(seen.auth.as_deref(), Some(AUTH));
}

/// Accepts one connection and hands back its first TLS record, never answering.
fn tap() -> (SocketAddr, mpsc::Receiver<Vec<u8>>) {
    let listener = StdListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let Ok((mut sock, _)) = listener.accept() else {
            return;
        };
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        while let Ok(n) = sock.read(&mut tmp) {
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() >= 5 && buf.len() >= 5 + (((buf[3] as usize) << 8) | buf[4] as usize) {
                break;
            }
        }
        let _ = tx.send(buf);
    });
    (addr, rx)
}

/// The ClientHello's extensions, GREASE values folded into one, with the ALPN list.
fn extensions(hello: &[u8]) -> (BTreeSet<u16>, Vec<u8>) {
    let be16 = |b: &[u8]| ((b[0] as u16) << 8) | b[1] as u16;
    // record(5) + handshake header(4) + legacy_version(2) + random(32)
    let mut p = 43;
    p += 1 + hello[p] as usize;
    p += 2 + be16(&hello[p..]) as usize;
    p += 1 + hello[p] as usize;
    let end = p + 2 + be16(&hello[p..]) as usize;
    p += 2;
    let (mut types, mut alpn) = (BTreeSet::new(), Vec::new());
    while p + 4 <= end {
        let ext = be16(&hello[p..]);
        let len = be16(&hello[p + 2..]) as usize;
        if ext == 16 {
            alpn = hello[p + 6..p + 4 + len].to_vec();
        }
        types.insert(if ext & 0x0f0f == 0x0a0a { 0x0a0a } else { ext });
        p += 4 + len;
    }
    (types, alpn)
}

async fn client_hello(via_proxy: bool) -> (BTreeSet<u16>, Vec<u8>) {
    let (addr, rx) = tap();
    let mut builder = wreq::Client::builder()
        .tls_options(tls_options())
        .resolve("tap.test", addr);
    let url = if via_proxy {
        builder =
            builder.proxy(wreq::Proxy::all(format!("https://tap.test:{}", addr.port())).unwrap());
        "https://origin.test/".to_owned()
    } else {
        format!("https://tap.test:{}/", addr.port())
    };
    let client = builder.build().unwrap();
    tokio::spawn(async move { client.get(url).send().await });
    let hello = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(10)))
        .await
        .unwrap()
        .expect("no ClientHello captured");
    extensions(&hello)
}

/// The hop to a proxy carries the same ClientHello as a request's own connection: ALPN, ALPS
/// and ECH GREASE included, which the proxy hop used to drop.
#[tokio::test]
async fn the_proxy_hop_presents_the_full_tls_profile() {
    let direct = client_hello(false).await;
    let hop = client_hello(true).await;
    assert_eq!(hop, direct);
    for ext in [16, 17513, 65037] {
        assert!(hop.0.contains(&ext), "extension {ext} missing: {:?}", hop.0);
    }
    assert_eq!(hop.1, b"\x02h2\x08http/1.1");
}

#[tokio::test]
async fn the_connect_head_on_http1_is_unchanged() {
    // A plain TCP "proxy" that records the CONNECT and refuses it.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let head = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = s.read(&mut buf).await.unwrap();
        s.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            .await
            .unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    });
    let client = wreq::Client::builder()
        .proxy(
            wreq::Proxy::all(format!("http://{addr}"))
                .unwrap()
                .custom_http_auth(HeaderValue::from_static(AUTH)),
        )
        .build()
        .unwrap();
    let err = client.get("https://origin.test/").send().await.unwrap_err();
    assert!(err.is_proxy_connect(), "{err:?}");
    assert_eq!(
        head.await.unwrap(),
        format!(
            "CONNECT origin.test:443 HTTP/1.1\r\nHost: origin.test:443\r\nProxy-Authorization: {AUTH}\r\n\r\n"
        )
    );
}
