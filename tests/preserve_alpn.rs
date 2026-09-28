use std::{
    io::Read,
    net::{SocketAddr, TcpListener},
    sync::mpsc,
    time::Duration,
};

use wreq::tls::{AlpnProtocol, TlsOptions};

/// record(5) + handshake header(4) + legacy_version(2) + random(32)
const SESSION_ID_LEN_OFFSET: usize = 43;
const EXT_ALPN: u16 = 16;

/// Accepts one connection and hands back its first TLS record, never answering.
fn tap() -> (SocketAddr, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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
            if buf.len() < 5 {
                continue;
            }
            let record_len = ((buf[3] as usize) << 8) | buf[4] as usize;
            if buf.len() >= 5 + record_len {
                break;
            }
        }
        let _ = tx.send(buf);
    });

    (addr, rx)
}

/// The ALPN protocol list, past the two-byte list-length prefix.
fn alpn_of(flight: &[u8]) -> Vec<u8> {
    assert!(
        flight.len() > SESSION_ID_LEN_OFFSET,
        "truncated ClientHello"
    );
    let be16 = |b: &[u8]| ((b[0] as u16) << 8) | b[1] as u16;

    let mut p = SESSION_ID_LEN_OFFSET;
    p += 1 + flight[p] as usize;
    let ciphers_len = be16(&flight[p..]) as usize;
    p += 2 + ciphers_len;
    p += 1 + flight[p] as usize; // compression methods
    let end = p + 2 + be16(&flight[p..]) as usize;
    p += 2;

    while p + 4 <= end {
        let ext = be16(&flight[p..]);
        let len = be16(&flight[p + 2..]) as usize;
        if ext == EXT_ALPN {
            return flight[p + 6..p + 4 + len].to_vec();
        }
        p += 4 + len;
    }
    Vec::new()
}

async fn client_hello(preserve: bool, alpn: Option<Vec<AlpnProtocol>>) -> Vec<u8> {
    let (addr, rx) = tap();
    let mut builder = wreq::Client::builder().tls_preserve_alpn(preserve);
    if let Some(alpn) = alpn {
        builder = builder.tls_options(TlsOptions::builder().alpn_protocols(alpn).build());
    }
    let client = builder.build().unwrap();
    // Enforcing HTTP/2 is what triggers the ALPN override.
    let _ = client
        .get(format!("https://{addr}/"))
        .version(http::Version::HTTP_2)
        .send()
        .await;
    rx.recv_timeout(Duration::from_secs(10))
        .expect("no ClientHello captured")
}

/// `preserve_alpn` keeps the configured list where an enforced version would narrow it.
#[tokio::test]
async fn preserve_alpn_keeps_the_configured_protocol_list() {
    let overridden = alpn_of(&client_hello(false, None).await);
    assert_eq!(
        overridden, b"\x02h2",
        "default should narrow to the enforced version"
    );

    let preserved = alpn_of(&client_hello(true, None).await);
    assert_eq!(
        preserved, b"\x02h2\x08http/1.1",
        "preserve_alpn should keep the full list"
    );

    let empty = alpn_of(&client_hello(true, Some(Vec::new())).await);
    assert_eq!(
        empty, b"\x02h2",
        "an empty configured list leaves nothing to preserve"
    );
}
