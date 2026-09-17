use std::sync::Arc;

use btls::x509::{
    store::{X509Store, X509StoreBuilder},
    verify::X509CheckFlags,
};

use super::{
    Certificate, CertificateInput,
    parse::{filter_map_certs, parse_certs, parse_certs_with_stack, process_certs},
};
use crate::{Error, Result};

/// A builder for constructing a [`CertStore`].
pub struct CertStoreBuilder {
    builder: Result<X509StoreBuilder>,
}

impl CertStoreBuilder {
    fn parse_cert<'c, C, P>(mut self, cert: C, parser: P) -> Self
    where
        C: Into<CertificateInput<'c>>,
        P: Fn(&'c [u8]) -> Result<Certificate>,
    {
        if let Ok(ref mut builder) = self.builder {
            let input = cert.into();
            let result = input
                .with_parser(parser)
                .and_then(|cert| builder.add_cert(cert.0).map_err(Error::tls));

            if let Err(err) = result {
                self.builder = Err(err);
            }
        }
        self
    }

    fn parse_certs<'c, I>(mut self, certs: I, parser: fn(&'c [u8]) -> Result<Certificate>) -> Self
    where
        I: IntoIterator,
        I::Item: Into<CertificateInput<'c>>,
    {
        if let Ok(ref mut builder) = self.builder {
            let certs = filter_map_certs(certs, parser);
            if let Err(err) = process_certs(certs, builder) {
                self.builder = Err(err);
            }
        }
        self
    }

    /// Adds a DER-encoded certificate to the certificate store.
    #[inline]
    pub fn add_der_cert<'c, C>(self, cert: C) -> Self
    where
        C: Into<CertificateInput<'c>>,
    {
        self.parse_cert(cert, Certificate::from_der)
    }

    /// Adds a PEM-encoded certificate to the certificate store.
    #[inline]
    pub fn add_pem_cert<'c, C>(self, cert: C) -> Self
    where
        C: Into<CertificateInput<'c>>,
    {
        self.parse_cert(cert, Certificate::from_pem)
    }

    /// Adds multiple DER-encoded certificates to the certificate store.
    #[inline]
    pub fn add_der_certs<'c, I>(self, certs: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<CertificateInput<'c>>,
    {
        self.parse_certs(certs, Certificate::from_der)
    }

    /// Adds multiple PEM-encoded certificates to the certificate store.
    #[inline]
    pub fn add_pem_certs<'c, I>(self, certs: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<CertificateInput<'c>>,
    {
        self.parse_certs(certs, Certificate::from_pem)
    }

    /// Adds a PEM-encoded certificate stack to the certificate store.
    pub fn add_stack_pem_certs<C>(mut self, certs: C) -> Self
    where
        C: AsRef<[u8]>,
    {
        if let Ok(ref mut builder) = self.builder {
            let result = Certificate::stack_from_pem(certs.as_ref())
                .and_then(|certs| process_certs(certs.into_iter(), builder));

            if let Err(err) = result {
                self.builder = Err(err);
            }
        }
        self
    }

    /// Load certificates from their default locations.
    ///
    /// These locations are read from the `SSL_CERT_FILE` and `SSL_CERT_DIR`
    /// environment variables if present, or defaults specified at OpenSSL
    /// build time otherwise.
    pub fn set_default_paths(mut self) -> Self {
        if let Ok(ref mut builder) = self.builder
            && let Err(err) = builder.set_default_paths()
        {
            self.builder = Err(Error::tls(err));
        }
        self
    }

    /// Requires the peer certificate to be valid for `host`.
    ///
    /// The name is checked while the chain is verified against this store, which makes it
    /// independent of the request URI. BoringSSL otherwise derives the name to verify from the
    /// URI's host, and for a URI naming an IP address that is an `iPAddress` SAN match — so a
    /// certificate that identifies its server by name cannot be verified at all when the
    /// connection is made to a bare IP.
    ///
    /// Pair it with [`ClientBuilder::tls_verify_hostname(false)`]. With the URI-derived check left
    /// on, the outcome depends on the URI: a host that parses as an IP address sets `ip` on the
    /// connection's verify parameters and the name set here still applies, so both must match —
    /// but a host that is a *name* sets `hosts` there, and inheriting those **replaces** the ones
    /// set here, silently dropping this pin.
    ///
    /// Note also that the name lives on the store, not on the client: every client built from the
    /// same [`CertStore`] inherits it. Build a store per identity rather than sharing one.
    ///
    /// [`ClientBuilder::tls_verify_hostname(false)`]: crate::ClientBuilder::tls_verify_hostname
    pub fn verify_host<S: AsRef<str>>(mut self, host: S) -> Self {
        if let Ok(ref mut builder) = self.builder {
            let param = builder.verify_param_mut();
            // Same host flags BoringSSL's own hostname verification uses.
            param.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
            if let Err(err) = param.set_host(host.as_ref()) {
                self.builder = Err(Error::tls(err));
            }
        }
        self
    }

    /// Constructs the [`CertStore`].
    ///
    /// This method finalizes the builder and constructs the [`CertStore`]
    /// containing all the added certificates.
    #[inline]
    pub fn build(self) -> Result<CertStore> {
        self.builder
            .map(X509StoreBuilder::build)
            .map(Arc::new)
            .map(CertStore)
    }
}

/// A thread-safe certificate store for TLS connections.
///
/// [`CertStore`] manages a collection of trusted certificates used for verifying peer identities.
/// It is designed to be shared and reused across requests and connections, similar to `Client`.
///
/// Internally, [`CertStore`] uses an [`Arc`] for reference counting, so you do **not** need to wrap
/// it in an additional [`Rc`] or [`Arc`] for sharing between threads or tasks.
///
/// To configure a [`CertStore`], use [`CertStore::builder()`]. You can also construct it from DER
/// or PEM certificates, or load system defaults.
///
/// [`Rc`]: std::rc::Rc
/// [`Arc`]: std::sync::Arc
#[derive(Clone)]
pub struct CertStore(pub(in crate::tls) Arc<X509Store>);

impl CertStore {
    /// Creates a new [`CertStoreBuilder`].
    #[inline]
    pub fn builder() -> CertStoreBuilder {
        CertStoreBuilder {
            builder: X509StoreBuilder::new().map_err(Error::builder),
        }
    }

    /// Creates a new [`CertStore`] from a collection of DER-encoded certificates.
    #[inline]
    pub fn from_der_certs<'c, C>(certs: C) -> Result<CertStore>
    where
        C: IntoIterator,
        C::Item: Into<CertificateInput<'c>>,
    {
        parse_certs(certs, Certificate::from_der)
            .map(Arc::new)
            .map(CertStore)
    }

    /// Creates a new [`CertStore`] from a collection of PEM-encoded certificates.
    #[inline]
    pub fn from_pem_certs<'c, C>(certs: C) -> Result<CertStore>
    where
        C: IntoIterator,
        C::Item: Into<CertificateInput<'c>>,
    {
        parse_certs(certs, Certificate::from_pem)
            .map(Arc::new)
            .map(CertStore)
    }

    /// Creates a new [`CertStore`] from a PEM-encoded certificate stack.
    #[inline]
    pub fn from_pem_stack<C>(certs: C) -> Result<CertStore>
    where
        C: AsRef<[u8]>,
    {
        parse_certs_with_stack(certs, Certificate::stack_from_pem)
            .map(Arc::new)
            .map(CertStore)
    }
}
