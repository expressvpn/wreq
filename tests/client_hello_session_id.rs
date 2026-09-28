use std::{
    io::Read,
    net::{SocketAddr, TcpListener},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

use wreq::tls::session_id::ClientHelloSessionId;

/// record(5) + handshake header(4) + legacy_version(2) + random(32)
const SESSION_ID_LEN_OFFSET: usize = 43;

/// Accepts `count` connections and hands back each one's first TLS record, never answering.
fn tap(count: usize) -> (SocketAddr, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        for _ in 0..count {
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
        }
    });

    (addr, rx)
}

fn session_id_of(flight: &[u8]) -> &[u8] {
    assert!(
        flight.len() > SESSION_ID_LEN_OFFSET,
        "truncated ClientHello"
    );
    assert_eq!(flight[0], 0x16, "not a TLS handshake record");
    assert_eq!(flight[5], 0x01, "not a ClientHello");
    let len = flight[SESSION_ID_LEN_OFFSET] as usize;
    &flight[SESSION_ID_LEN_OFFSET + 1..SESSION_ID_LEN_OFFSET + 1 + len]
}

/// The cipher list and extension type list — what a JA3/JA4 fingerprint reads.
fn fingerprint_shape(flight: &[u8]) -> (Vec<u16>, Vec<u16>) {
    assert!(
        flight.len() > SESSION_ID_LEN_OFFSET,
        "truncated ClientHello"
    );
    let be16 = |b: &[u8]| ((b[0] as u16) << 8) | b[1] as u16;

    let mut p = SESSION_ID_LEN_OFFSET;
    p += 1 + flight[p] as usize;
    let ciphers_len = be16(&flight[p..]) as usize;
    let ciphers = flight[p + 2..p + 2 + ciphers_len]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| be16(pair))
        .collect();
    p += 2 + ciphers_len;
    p += 1 + flight[p] as usize; // compression methods
    let end = p + 2 + be16(&flight[p..]) as usize;
    p += 2;

    let mut extensions = Vec::new();
    while p + 4 <= end {
        extensions.push(be16(&flight[p..]));
        p += 4 + be16(&flight[p + 2..]) as usize;
    }
    (ciphers, extensions)
}

async fn client_hello(session_id: Option<ClientHelloSessionId>) -> Vec<u8> {
    let (addr, rx) = tap(1);
    let client = wreq::Client::builder()
        .tls_client_hello_session_id(session_id)
        .build()
        .unwrap();
    let _ = client.get(format!("https://{addr}/")).send().await;
    rx.recv_timeout(Duration::from_secs(10))
        .expect("no ClientHello captured")
}

#[tokio::test]
async fn chosen_session_id_reaches_the_wire() {
    let chosen = [0xA5u8; ClientHelloSessionId::LEN];

    let default = client_hello(None).await;
    assert_eq!(
        session_id_of(&default).len(),
        ClientHelloSessionId::LEN,
        "BoringSSL should already send 32 random bytes"
    );

    let injected = client_hello(Some(ClientHelloSessionId::fixed(chosen))).await;
    assert_eq!(session_id_of(&injected), &chosen[..]);
}

/// The field is not a JA3 or JA4 input, and choosing it must not disturb one that is.
#[tokio::test]
async fn choosing_the_session_id_leaves_the_fingerprint_alone() {
    let default = client_hello(None).await;
    let injected = client_hello(Some(ClientHelloSessionId::fixed(
        [0x5Au8; ClientHelloSessionId::LEN],
    )))
    .await;

    assert_eq!(fingerprint_shape(&default), fingerprint_shape(&injected));
    assert_eq!(default.len(), injected.len(), "ClientHello length changed");
}

/// A source is a source, not a value: reuse is off, so each attempt must consult it again.
#[tokio::test]
async fn the_source_is_consulted_once_per_handshake() {
    let (addr, rx) = tap(2);
    let calls = Arc::new(AtomicUsize::new(0));

    let client = wreq::Client::builder()
        .pool_max_idle_per_host(0)
        .tls_client_hello_session_id(ClientHelloSessionId::new({
            let calls = calls.clone();
            move || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                let mut id = [0u8; ClientHelloSessionId::LEN];
                id[0] = n as u8;
                Some(id)
            }
        }))
        .build()
        .unwrap();

    let url = format!("https://{addr}/");
    let _ = client.get(&url).send().await;
    let first = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let _ = client.get(&url).send().await;
    let second = rx.recv_timeout(Duration::from_secs(10)).unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(session_id_of(&first)[0], 0);
    assert_eq!(session_id_of(&second)[0], 1);
}
