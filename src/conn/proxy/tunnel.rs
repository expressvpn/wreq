use std::{
    fmt,
    io::{self, IoSlice},
    marker::{PhantomData, Unpin},
    pin::Pin,
    task::{self, Context, Poll},
};

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, HeaderValue, Request, Uri};
use http_body_util::Empty;
use sync_wrapper::SyncWrapper;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tower::{BoxError, Service};
use wreq_proto::{conn::http2, rt::Executor as _, upgrade::Upgraded};

use super::{
    super::{Connected, Connection, tls_info::TlsInfoFactory},
    Tunneling,
};
use crate::{
    ext::UriExt,
    rt::Executor,
    tls::{AlpnProtocol, TlsInfo, conn::MaybeHttpsStream},
};

/// Tunnel Proxy via HTTP CONNECT
///
/// This is a connector that can be used by the `Client`. It wraps
/// another connector, and after getting an underlying connection, it creates
/// an HTTP CONNECT tunnel over it.
#[derive(Debug)]
pub struct TunnelConnector<C> {
    headers: Headers,
    inner: C,
    proxy_dst: Uri,
}

#[derive(Clone, Debug)]
pub(crate) enum Headers {
    Empty,
    Auth(HeaderValue),
    Extra(HeaderMap),
}

#[derive(Debug)]
pub enum TunnelError {
    ConnectFailed(BoxError),
    Io(std::io::Error),
    Parse(httparse::Error),
    MissingHost,
    ProxyAuthRequired,
    TunnelUnexpectedEof,
    TunnelUnsuccessful,
}

impl<C> TunnelConnector<C> {
    /// Create a new tunnel connector.
    ///
    /// This wraps an underlying connector, and stores the address of a
    /// tunneling proxy server.
    ///
    /// A `TunnelConnector` can then be called with any destination. The `proxy_dst` passed to
    /// `call` will not be used to create the underlying connection, but will
    /// be used in an HTTP CONNECT request sent to the proxy destination.
    pub fn new(proxy_dst: Uri, connector: C) -> Self {
        Self {
            headers: Headers::Empty,
            inner: connector,
            proxy_dst,
        }
    }
}

impl Headers {
    /// The CONNECT headers for a proxy's credential and custom headers.
    pub(crate) fn new(auth: Option<&HeaderValue>, headers: Option<&HeaderMap>) -> Self {
        let mut this = Headers::Empty;
        if let Some(auth) = auth {
            this = this.with_auth(auth.clone());
        }
        if let Some(headers) = headers {
            this = this.with_headers(headers.clone());
        }
        this
    }

    fn with_auth(mut self, mut auth: HeaderValue) -> Self {
        // just in case the user forgot
        auth.set_sensitive(true);
        match self {
            Headers::Empty => Headers::Auth(auth),
            Headers::Auth(_) => Headers::Auth(auth),
            Headers::Extra(ref mut extra) => {
                extra.insert(http::header::PROXY_AUTHORIZATION, auth);
                self
            }
        }
    }

    fn with_headers(self, mut headers: HeaderMap) -> Self {
        match self {
            Headers::Empty => Headers::Extra(headers),
            Headers::Auth(auth) => {
                headers
                    .entry(http::header::PROXY_AUTHORIZATION)
                    .or_insert(auth);
                Headers::Extra(headers)
            }
            Headers::Extra(mut extra) => {
                extra.extend(headers);
                Headers::Extra(extra)
            }
        }
    }

    fn iter(&self) -> impl Iterator<Item = (&http::HeaderName, &HeaderValue)> {
        let auth = match self {
            Headers::Auth(auth) => Some((&http::header::PROXY_AUTHORIZATION, auth)),
            _ => None,
        };
        let extra = match self {
            Headers::Extra(extra) => Some(extra.iter()),
            _ => None,
        };
        auth.into_iter().chain(extra.into_iter().flatten())
    }
}

impl<C> Service<Uri> for TunnelConnector<C>
where
    C: Service<Uri>,
    C::Future: Send + 'static,
    C::Response: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
{
    type Response = C::Response;
    type Error = TunnelError;
    type Future = Tunneling<C::Future, C::Response, Self::Error>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(Into::into)
            .map_err(TunnelError::ConnectFailed)
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let connecting = self.inner.call(self.proxy_dst.clone());
        let headers = self.headers.clone();

        Tunneling {
            fut: Box::pin(async move {
                let conn = connecting
                    .await
                    .map_err(Into::into)
                    .map_err(TunnelError::ConnectFailed)?;
                tunnel(
                    conn,
                    dst.host().ok_or(TunnelError::MissingHost)?,
                    dst.port_or_default(),
                    &headers,
                )
                .await
            }),
            _marker: PhantomData,
        }
    }
}

async fn tunnel<T>(mut conn: T, host: &str, port: u16, headers: &Headers) -> Result<T, TunnelError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = format!(
        "\
         CONNECT {host}:{port} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         "
    )
    .into_bytes();

    match headers {
        Headers::Auth(auth) => {
            buf.extend_from_slice(b"Proxy-Authorization: ");
            buf.extend_from_slice(auth.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
        Headers::Extra(extra) => {
            for (name, value) in extra {
                buf.extend_from_slice(name.as_str().as_bytes());
                buf.extend_from_slice(b": ");
                buf.extend_from_slice(value.as_bytes());
                buf.extend_from_slice(b"\r\n");
            }
        }
        Headers::Empty => (),
    }

    // headers end
    buf.extend_from_slice(b"\r\n");

    conn.write_all(&buf).await.map_err(TunnelError::Io)?;
    conn.flush().await.map_err(TunnelError::Io)?;

    let mut buf = BytesMut::with_capacity(8192);

    loop {
        if conn.read_buf(&mut buf).await.map_err(TunnelError::Io)? == 0 {
            return Err(TunnelError::TunnelUnexpectedEof);
        }

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut res = httparse::Response::new(&mut headers);
        match res.parse(&buf).map_err(TunnelError::Parse)? {
            httparse::Status::Partial => continue,
            httparse::Status::Complete(_) => match res.code {
                Some(200) => return Ok(conn),
                Some(407) => return Err(TunnelError::ProxyAuthRequired),
                Some(_) | None => return Err(TunnelError::TunnelUnsuccessful),
            },
        }
    }
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("tunnel error: ")?;

        f.write_str(match self {
            TunnelError::MissingHost => "missing destination host",
            TunnelError::ProxyAuthRequired => "proxy authorization required",
            TunnelError::Parse(_) => "invalid proxy response",
            TunnelError::TunnelUnexpectedEof => "unexpected end of file",
            TunnelError::TunnelUnsuccessful => "unsuccessful",
            TunnelError::ConnectFailed(_) => "failed to create underlying connection",
            TunnelError::Io(_) => "io error establishing tunnel",
        })
    }
}

impl std::error::Error for TunnelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TunnelError::Io(e) => Some(e),
            TunnelError::Parse(e) => Some(e),
            TunnelError::ConnectFailed(e) => Some(&**e),
            _ => None,
        }
    }
}

/// The HTTP/2 side of a CONNECT to an HTTPS proxy: the client's own HTTP/2 options, so the
/// proxy connection opens with the emulation's SETTINGS.
#[derive(Clone)]
pub(crate) struct ProxyHttp2 {
    pub(crate) builder: http2::Builder<Executor>,
    pub(crate) exec: Executor,
}

/// A tunnel through an HTTPS proxy, on whichever protocol the proxy chose.
pub(crate) enum ProxyStream<T> {
    Http1(MaybeHttpsStream<T>),
    /// A CONNECT stream on an HTTP/2 connection to the proxy, whose `connected` it keeps.
    Http2 {
        io: SyncWrapper<Upgraded>,
        connected: Connected,
    },
}

/// `CONNECT dst` over `io`, an established connection to the proxy: on HTTP/2 when the proxy
/// chose it in ALPN — as a browser does, having offered it — and on HTTP/1.1 otherwise.
pub(crate) async fn connect_over<T>(
    io: MaybeHttpsStream<T>,
    dst: &Uri,
    headers: &Headers,
    h2: Option<&ProxyHttp2>,
) -> Result<ProxyStream<T>, TunnelError>
where
    T: AsyncRead + AsyncWrite + Connection + Unpin + Send + Sync + 'static,
{
    let host = dst.host().ok_or(TunnelError::MissingHost)?;
    let port = dst.port_or_default();
    let negotiated_h2 = match &io {
        MaybeHttpsStream::Https(tls) => tls
            .ssl()
            .selected_alpn_protocol()
            .is_some_and(|alpn| AlpnProtocol::HTTP2.eq(alpn)),
        MaybeHttpsStream::Http(_) => false,
    };
    if !negotiated_h2 {
        return tunnel(io, host, port, headers)
            .await
            .map(ProxyStream::Http1);
    }
    let h2 = h2.ok_or_else(|| {
        TunnelError::ConnectFailed("proxy chose h2, but the connector has no HTTP/2 options".into())
    })?;
    let connected = io.connected();
    let failed = |e: wreq_proto::Error| TunnelError::ConnectFailed(e.into());
    let (mut tx, conn) = h2
        .builder
        .clone()
        .handshake::<_, Empty<Bytes>>(io)
        .await
        .map_err(failed)?;
    h2.exec.execute(async move {
        if let Err(_e) = conn.await {
            debug!("proxy http2 connection error: {}", _e);
        }
    });
    tx.ready().await.map_err(failed)?;

    let mut req = Request::connect(format!("{host}:{port}"))
        .body(Empty::new())
        .map_err(|e| TunnelError::ConnectFailed(e.into()))?;
    for (name, value) in headers.iter() {
        req.headers_mut().append(name.clone(), value.clone());
    }
    let mut res = tx
        .try_send_request(req)
        .await
        .map_err(|e| failed(e.into_error()))?;
    match res.status().as_u16() {
        200..=299 => {}
        407 => return Err(TunnelError::ProxyAuthRequired),
        _ => return Err(TunnelError::TunnelUnsuccessful),
    }
    let io = wreq_proto::upgrade::on(&mut res).await.map_err(failed)?;
    Ok(ProxyStream::Http2 {
        io: SyncWrapper::new(io),
        connected,
    })
}

impl<T> ProxyStream<T> {
    /// The HTTP/1.1 tunnel's connection to the proxy; an HTTP/2 one is the dispatcher's.
    pub(crate) fn http1(&self) -> Option<&MaybeHttpsStream<T>> {
        match self {
            ProxyStream::Http1(io) => Some(io),
            ProxyStream::Http2 { .. } => None,
        }
    }
}

impl<T> fmt::Debug for ProxyStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyStream::Http1(_) => f.write_str("ProxyStream::Http1"),
            ProxyStream::Http2 { .. } => f.write_str("ProxyStream::Http2"),
        }
    }
}

impl<T: Connection> Connection for ProxyStream<T> {
    fn connected(&self) -> Connected {
        match self {
            ProxyStream::Http1(io) => io.connected(),
            ProxyStream::Http2 { connected, .. } => connected.clone(),
        }
    }
}

impl<T> TlsInfoFactory for ProxyStream<T>
where
    MaybeHttpsStream<T>: TlsInfoFactory,
{
    fn tls_info(&self) -> Option<TlsInfo> {
        self.http1().and_then(TlsInfoFactory::tls_info)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for ProxyStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ProxyStream::Http1(io) => Pin::new(io).poll_read(cx, buf),
            ProxyStream::Http2 { io, .. } => Pin::new(io.get_mut()).poll_read(cx, buf),
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ProxyStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ProxyStream::Http1(io) => Pin::new(io).poll_write(cx, buf),
            ProxyStream::Http2 { io, .. } => Pin::new(io.get_mut()).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ProxyStream::Http1(io) => Pin::new(io).poll_write_vectored(cx, bufs),
            ProxyStream::Http2 { io, .. } => Pin::new(io.get_mut()).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            ProxyStream::Http1(io) => io.is_write_vectored(),
            ProxyStream::Http2 { .. } => false,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ProxyStream::Http1(io) => Pin::new(io).poll_flush(cx),
            ProxyStream::Http2 { io, .. } => Pin::new(io.get_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ProxyStream::Http1(io) => Pin::new(io).poll_shutdown(cx),
            ProxyStream::Http2 { io, .. } => Pin::new(io.get_mut()).poll_shutdown(cx),
        }
    }
}
