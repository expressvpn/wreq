//! Choosing the ClientHello `legacy_session_id`.

use std::{
    fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use btls::{
    error::ErrorStack,
    ssl::{ConnectConfiguration, SslContextRef, SslSession},
};
use foreign_types::{ForeignType, ForeignTypeRef};

/// Validity window given to the blank session, which itself never reaches the wire.
const SESSION_TIMEOUT_SECS: u32 = 3600;

/// Supplies the ClientHello `legacy_session_id`.
///
/// BoringSSL fills that field with 32 random bytes. Installing one of these with
/// [`ClientBuilder::tls_client_hello_session_id`] chooses them instead, which lets a caller
/// carry a value the peer can read before any application byte exists — while a TLS
/// handshake is still the only thing on the wire.
///
/// [`ClientBuilder::tls_client_hello_session_id`]: crate::ClientBuilder::tls_client_hello_session_id
#[derive(Clone)]
pub struct ClientHelloSessionId(Arc<dyn Fn() -> Option<[u8; Self::LEN]> + Send + Sync>);

impl ClientHelloSessionId {
    /// Length of the field, and so of every value a source may return.
    pub const LEN: usize = 32;

    /// Draws the session id from `f` on each handshake; `None` leaves BoringSSL's own fill.
    #[inline]
    pub fn new<F>(f: F) -> Self
    where
        F: Fn() -> Option<[u8; Self::LEN]> + Send + Sync + 'static,
    {
        Self(Arc::new(f))
    }

    /// Sends the same session id on every handshake.
    #[inline]
    pub fn fixed(id: [u8; Self::LEN]) -> Self {
        Self::new(move || Some(id))
    }

    #[inline]
    pub(crate) fn get(&self) -> Option<[u8; Self::LEN]> {
        (self.0)()
    }
}

impl fmt::Debug for ClientHelloSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientHelloSessionId")
    }
}

/// Makes the next ClientHello built from `cfg` carry `id` as its `legacy_session_id`.
///
/// A blank TLS 1.2 session with an id and no ticket takes BoringSSL's `SSLSessionType::kID`
/// branch (`ssl/handshake_client.cc`), which copies the id in place of `RAND_bytes`.
#[allow(unsafe_code)]
pub(crate) fn attach(
    ctx: &SslContextRef,
    cfg: &mut ConnectConfiguration,
    id: &[u8; ClientHelloSessionId::LEN],
) -> Result<(), ErrorStack> {
    unsafe {
        let raw = btls_sys::SSL_SESSION_new(ctx.as_ptr());
        if raw.is_null() {
            return Err(ErrorStack::get());
        }

        // Owned, so the reference is released on every path out of here. `set_session`
        // takes one of its own.
        let session = SslSession::from_ptr(raw);
        fill(raw, id)?;
        cfg.set_session(&session)
    }
}

#[allow(unsafe_code)]
unsafe fn fill(
    session: *mut btls_sys::SSL_SESSION,
    id: &[u8; ClientHelloSessionId::LEN],
) -> Result<(), ErrorStack> {
    unsafe {
        // TLS 1.2, never 1.3: a >=1.3 session with no ticket is classified not resumable
        // and dropped, so the id would silently never reach the wire and BoringSSL's random
        // fill would go out in its place. The ClientHello still advertises 1.3 and the
        // connection still negotiates it.
        if btls_sys::SSL_SESSION_set_protocol_version(session, btls_sys::TLS1_2_VERSION as u16) != 1
        {
            return Err(ErrorStack::get());
        }

        if btls_sys::SSL_SESSION_set1_id(session, id.as_ptr(), id.len()) != 1 {
            return Err(ErrorStack::get());
        }

        // Defensive: `SSL_SESSION_new` already stamps a valid window, and one outside it is
        // dropped by `ssl_session_is_time_valid` before the id is read.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        btls_sys::SSL_SESSION_set_time(session, now);
        btls_sys::SSL_SESSION_set_timeout(session, SESSION_TIMEOUT_SECS);
    }

    Ok(())
}
