//! Minimal WebSocket client: TLS/TCP connect, HTTP upgrade, frame codec.
//!
//! Frames are parsed from an internal buffer, so `WsReader::recv` is
//! cancel-safe and never loses bytes when its future is dropped mid-frame.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use bytes::{Buf, BytesMut};
use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::upstream::UpstreamSocks;

/// Type-erased duplex byte stream (TLS or plain TCP).
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type BoxIo = Box<dyn Io>;

const OP_CONT: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

const MAX_MESSAGE: usize = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum WsError {
    #[error("HTTP {status}: {line}")]
    Handshake { status: u16, line: String, location: Option<String> },
    #[error("empty HTTP response")]
    EmptyResponse,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("timeout")]
    Timeout,
}

impl WsError {
    pub fn is_redirect(&self) -> bool {
        matches!(self, WsError::Handshake { status, .. } if matches!(status, 301 | 302 | 303 | 307 | 308))
    }

    pub fn redirect_location(&self) -> Option<&str> {
        match self {
            WsError::Handshake { location, .. } => location.as_deref(),
            _ => None,
        }
    }

    pub fn is_timeout(&self) -> bool {
        matches!(self, WsError::Timeout)
    }

    /// Connection torn down by the peer or by something in between (typical of
    /// RST injection by a DPI box).
    pub fn is_reset(&self) -> bool {
        match self {
            WsError::EmptyResponse => true,
            WsError::Io(e) => matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
            ),
            _ => false,
        }
    }
}

// ── TLS ───────────────────────────────────────────────────────────────────────

/// Name the certificate must be valid for on a *fronted* connection. The SNI on
/// the wire is something else entirely, so we verify the certificate against a
/// Telegram-owned name instead (`*.telegram.org` covers it) rather than trusting
/// any publicly-valid certificate.
pub const FRONTED_VERIFY_NAME: &str = "web.telegram.org";

#[derive(Clone)]
pub struct TlsConfigs {
    /// Verifies the certificate against the SNI we send.
    pub normal: Arc<ClientConfig>,
    /// Verifies against [`FRONTED_VERIFY_NAME`] regardless of the SNI.
    pub fronted: Arc<ClientConfig>,
}

fn with_alpn(mut cfg: ClientConfig) -> Arc<ClientConfig> {
    // Offer only HTTP/1.1: our upgrade request is HTTP/1.1, and a browser-like
    // ALPN list is one less oddity in the ClientHello.
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

fn load_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let native = rustls_native_certs::load_native_certs();
    for e in &native.errors {
        tracing::debug!("Native cert warning: {:?}", e);
    }
    let mut added = 0usize;
    for cert in native.certs {
        if roots.add(cert).is_ok() {
            added += 1;
        }
    }
    tracing::debug!("Loaded {} native TLS root certificates", added);
    roots
}

pub fn build_tls_configs(skip_verify: bool) -> anyhow::Result<TlsConfigs> {
    if skip_verify {
        let cfg = with_alpn(
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth(),
        );
        return Ok(TlsConfigs { normal: cfg.clone(), fronted: cfg });
    }

    tls_configs_with_roots(Arc::new(load_roots()))
}

/// Both TLS configurations (normal and fronted) for an explicit trust store.
pub fn tls_configs_with_roots(roots: Arc<RootCertStore>) -> anyhow::Result<TlsConfigs> {
    let normal = with_alpn(ClientConfig::builder().with_root_certificates(roots.clone()).with_no_client_auth());
    let inner = WebPkiServerVerifier::builder(roots)
        .build()
        .map_err(|e| anyhow::anyhow!("cannot build certificate verifier: {e}"))?;
    let name = ServerName::try_from(FRONTED_VERIFY_NAME).expect("static name").to_owned();
    let fronted = with_alpn(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedNameVerifier { inner, name }))
            .with_no_client_auth(),
    );
    Ok(TlsConfigs { normal, fronted })
}

/// Full chain validation, but the hostname check uses a fixed name.
#[derive(Debug)]
struct PinnedNameVerifier {
    inner: Arc<WebPkiServerVerifier>,
    name: ServerName<'static>,
}

impl ServerCertVerifier for PinnedNameVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        self.inner.verify_server_cert(end_entity, intermediates, &self.name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// `--skip-tls-verify`: accept anything.
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

// ── Connecting ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum Target {
    /// Already resolved (the direct Telegram gateway is reached by IP).
    Addr(SocketAddr),
    /// Resolve at connect time (Cloudflare domains / workers).
    Host(String, u16),
}

#[derive(Clone, Debug)]
pub struct ConnectOpts {
    pub target: Target,
    /// HTTP `Host` header; also the SNI unless `sni` is set.
    pub host: String,
    pub sni: Option<String>,
    pub path: String,
    /// TLS (true) or plain TCP (false).
    pub secure: bool,
    /// Verify the certificate against [`FRONTED_VERIFY_NAME`] instead of the SNI.
    pub fronted: bool,
    pub timeout: Duration,
    pub buf_size: usize,
    /// Route the TCP connection through this SOCKS5 proxy (`--upstream-socks5`).
    pub upstream: Option<Arc<UpstreamSocks>>,
}

impl ConnectOpts {
    pub fn new(target: Target, host: impl Into<String>, path: impl Into<String>, timeout: Duration) -> Self {
        Self {
            target,
            host: host.into(),
            sni: None,
            path: path.into(),
            secure: true,
            fronted: false,
            timeout,
            buf_size: 256 * 1024,
            upstream: None,
        }
    }
}

pub(crate) async fn tcp_connect_direct(target: &Target) -> io::Result<TcpStream> {
    match target {
        Target::Addr(a) => TcpStream::connect(a).await,
        Target::Host(h, p) => {
            let mut addrs: Vec<SocketAddr> = tokio::net::lookup_host((h.as_str(), *p)).await?.collect();
            // IPv4 first: many networks advertise IPv6 they cannot route.
            addrs.sort_by_key(|a| a.is_ipv6());
            let mut last = None;
            for a in addrs {
                match TcpStream::connect(a).await {
                    Ok(s) => return Ok(s),
                    Err(e) => last = Some(e),
                }
            }
            Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses")))
        }
    }
}

pub fn tune_socket(tcp: &TcpStream, buf_size: usize) {
    let _ = tcp.set_nodelay(true);
    let sock = socket2::SockRef::from(tcp);
    if buf_size > 0 {
        let _ = sock.set_recv_buffer_size(buf_size);
        let _ = sock.set_send_buffer_size(buf_size);
    }
    // A peer that disappears without a FIN would otherwise keep its session (and the
    // upstream connection behind it) open until the far end gives up.
    let ka = socket2::TcpKeepalive::new().with_time(Duration::from_secs(60)).with_interval(Duration::from_secs(20));
    let _ = sock.set_tcp_keepalive(&ka);
}

/// Connect, optionally wrap in TLS, and perform the WebSocket upgrade.
/// `o.timeout` bounds the whole sequence.
pub async fn connect(tls: &TlsConfigs, o: &ConnectOpts) -> Result<WsConn, WsError> {
    timeout(o.timeout, connect_inner(tls, o)).await.map_err(|_| WsError::Timeout)?
}

async fn connect_inner(tls: &TlsConfigs, o: &ConnectOpts) -> Result<WsConn, WsError> {
    let tcp = crate::upstream::connect(&o.target, o.upstream.as_deref()).await?;
    tune_socket(&tcp, o.buf_size);

    let mut io: BoxIo = if o.secure {
        let cfg = if o.fronted { &tls.fronted } else { &tls.normal };
        let sni = o.sni.as_deref().unwrap_or(&o.host);
        let name = ServerName::try_from(sni.to_owned()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        Box::new(TlsConnector::from(cfg.clone()).connect(name, tcp).await?)
    } else {
        Box::new(tcp)
    };

    let leftover = handshake(&mut io, &o.host, &o.path).await?;
    Ok(WsConn::from_io(io, leftover))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some(i + 4);
    }
    buf.windows(2).position(|w| w == b"\n\n").map(|i| i + 2)
}

/// Send the upgrade request and read the response headers. Returns any bytes the
/// server already sent after the headers (they belong to the frame stream).
async fn handshake(io: &mut BoxIo, host: &str, path: &str) -> Result<BytesMut, WsError> {
    let mut key = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key);
    let ws_key = base64::engine::general_purpose::STANDARD.encode(key);

    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {ws_key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: binary\r\n\
         \r\n"
    );
    io.write_all(request.as_bytes()).await?;
    io.flush().await?;

    let mut buf = BytesMut::with_capacity(1024);
    let head_len = loop {
        if let Some(n) = find_header_end(&buf) {
            break n;
        }
        if buf.len() > 16 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP headers too large").into());
        }
        buf.reserve(1024);
        if io.read_buf(&mut buf).await? == 0 {
            return Err(if buf.is_empty() {
                WsError::EmptyResponse
            } else {
                io::Error::from(io::ErrorKind::UnexpectedEof).into()
            });
        }
    };

    let head = buf.split_to(head_len);
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.lines();
    let first = lines.next().unwrap_or("").trim().to_string();
    let status: u16 = first.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    if status == 101 {
        return Ok(buf);
    }
    let location = lines
        .find(|l| l.to_ascii_lowercase().starts_with("location:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string());
    Err(WsError::Handshake { status, line: first, location })
}

// ── Frame codec ───────────────────────────────────────────────────────────────

pub fn mask_in_place(data: &mut [u8], key: [u8; 4]) {
    let k = u32::from_ne_bytes(key);
    let mut chunks = data.chunks_exact_mut(4);
    for c in &mut chunks {
        let v = u32::from_ne_bytes([c[0], c[1], c[2], c[3]]) ^ k;
        c.copy_from_slice(&v.to_ne_bytes());
    }
    for (i, b) in chunks.into_remainder().iter_mut().enumerate() {
        *b ^= key[i];
    }
}

/// Append one masked (client→server) frame to `out`.
pub fn encode_frame(opcode: u8, data: &[u8], out: &mut Vec<u8>) {
    out.reserve(data.len() + 14);
    out.push(0x80 | opcode);
    let len = data.len();
    if len < 126 {
        out.push(0x80 | len as u8);
    } else if len < 65536 {
        out.push(0x80 | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    let mut key = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut key);
    out.extend_from_slice(&key);
    let start = out.len();
    out.extend_from_slice(data);
    mask_in_place(&mut out[start..], key);
}

#[derive(Debug, PartialEq, Eq)]
pub enum WsMsg {
    Data(Vec<u8>),
    Ping(Vec<u8>),
    Close(Option<u16>),
}

pub struct WsReader {
    io: ReadHalf<BoxIo>,
    buf: BytesMut,
    /// Partially assembled fragmented message.
    frag: Vec<u8>,
}

impl WsReader {
    /// Next message, or `None` on EOF. Cancel-safe.
    pub async fn recv(&mut self) -> io::Result<Option<WsMsg>> {
        loop {
            while let Some((opcode, fin, payload)) = self.parse_frame()? {
                match opcode {
                    OP_CLOSE => {
                        let code = (payload.len() >= 2).then(|| u16::from_be_bytes([payload[0], payload[1]]));
                        return Ok(Some(WsMsg::Close(code)));
                    }
                    OP_PING => return Ok(Some(WsMsg::Ping(payload))),
                    OP_PONG => {}
                    OP_TEXT | OP_BINARY | OP_CONT => {
                        if fin && self.frag.is_empty() {
                            return Ok(Some(WsMsg::Data(payload)));
                        }
                        self.frag.extend_from_slice(&payload);
                        if self.frag.len() > MAX_MESSAGE {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, "WebSocket message too large"));
                        }
                        if fin {
                            return Ok(Some(WsMsg::Data(std::mem::take(&mut self.frag))));
                        }
                    }
                    _ => {}
                }
            }
            self.buf.reserve(16 * 1024);
            if self.io.read_buf(&mut self.buf).await? == 0 {
                return Ok(None);
            }
        }
    }

    fn parse_frame(&mut self) -> io::Result<Option<(u8, bool, Vec<u8>)>> {
        let b = &self.buf[..];
        if b.len() < 2 {
            return Ok(None);
        }
        let fin = b[0] & 0x80 != 0;
        let opcode = b[0] & 0x0F;
        let masked = b[1] & 0x80 != 0;
        let mut len = (b[1] & 0x7F) as u64;
        let mut off = 2usize;
        if len == 126 {
            if b.len() < 4 {
                return Ok(None);
            }
            len = u16::from_be_bytes([b[2], b[3]]) as u64;
            off = 4;
        } else if len == 127 {
            if b.len() < 10 {
                return Ok(None);
            }
            len = u64::from_be_bytes(b[2..10].try_into().unwrap());
            off = 10;
        }
        if len as usize > MAX_MESSAGE || len > MAX_MESSAGE as u64 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("WebSocket frame too large: {len}")));
        }
        let mask_len = if masked { 4 } else { 0 };
        let total = off + mask_len + len as usize;
        if b.len() < total {
            let missing = total - b.len();
            self.buf.reserve(missing);
            return Ok(None);
        }
        let mut payload = b[off + mask_len..total].to_vec();
        if masked {
            let key = [b[off], b[off + 1], b[off + 2], b[off + 3]];
            mask_in_place(&mut payload, key);
        }
        self.buf.advance(total);
        Ok(Some((opcode, fin, payload)))
    }
}

pub struct WsWriter {
    io: WriteHalf<BoxIo>,
    scratch: Vec<u8>,
}

impl WsWriter {
    pub async fn send(&mut self, data: &[u8]) -> io::Result<()> {
        self.scratch.clear();
        encode_frame(OP_BINARY, data, &mut self.scratch);
        self.io.write_all(&self.scratch).await?;
        self.io.flush().await
    }

    /// Several frames, one flush.
    pub async fn send_batch(&mut self, parts: &[Vec<u8>]) -> io::Result<()> {
        self.scratch.clear();
        for p in parts {
            encode_frame(OP_BINARY, p, &mut self.scratch);
        }
        self.io.write_all(&self.scratch).await?;
        self.io.flush().await
    }

    pub async fn pong(&mut self, payload: &[u8]) -> io::Result<()> {
        self.scratch.clear();
        encode_frame(OP_PONG, payload, &mut self.scratch);
        self.io.write_all(&self.scratch).await?;
        self.io.flush().await
    }

    /// Best-effort close frame, then shut the stream down.
    pub async fn close(&mut self) {
        self.scratch.clear();
        encode_frame(OP_CLOSE, &1000u16.to_be_bytes(), &mut self.scratch);
        let _ = self.io.write_all(&self.scratch).await;
        let _ = self.io.flush().await;
        let _ = self.io.shutdown().await;
    }
}

/// An established WebSocket connection.
pub struct WsConn {
    pub reader: WsReader,
    pub writer: WsWriter,
}

impl WsConn {
    pub fn from_io(io: BoxIo, leftover: BytesMut) -> Self {
        let (r, w) = tokio::io::split(io);
        Self {
            reader: WsReader { io: r, buf: leftover, frag: Vec::new() },
            writer: WsWriter { io: w, scratch: Vec::new() },
        }
    }

    pub fn split(self) -> (WsReader, WsWriter) {
        (self.reader, self.writer)
    }

    pub async fn send(&mut self, data: &[u8]) -> io::Result<()> {
        self.writer.send(data).await
    }

    /// Next *data* message; pings are answered, a close ends the stream.
    pub async fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            match self.reader.recv().await? {
                Some(WsMsg::Data(d)) => return Ok(Some(d)),
                Some(WsMsg::Ping(p)) => self.writer.pong(&p).await?,
                Some(WsMsg::Close(_)) | None => return Ok(None),
            }
        }
    }

    pub async fn close(mut self) {
        self.writer.close().await;
    }

    /// Cheap liveness probe for an idle (pooled) connection: has the peer closed
    /// it, or sent a Close frame, while it sat unused? Never blocks.
    pub async fn is_alive(&mut self) -> bool {
        let r = &mut self.reader;
        match timeout(Duration::ZERO, r.io.read_buf(&mut r.buf)).await {
            Err(_) => true, // nothing to read: idle and open
            Ok(Ok(0)) | Ok(Err(_)) => false,
            Ok(Ok(_)) => !r.buf.first().is_some_and(|b| b & 0x0F == OP_CLOSE),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use tokio::net::TcpListener;

    fn server_frame(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![(if fin { 0x80 } else { 0 }) | opcode];
        let len = payload.len();
        if len < 126 {
            f.push(len as u8);
        } else if len < 65536 {
            f.push(126);
            f.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            f.push(127);
            f.extend_from_slice(&(len as u64).to_be_bytes());
        }
        f.extend_from_slice(payload);
        f
    }

    fn conn_pair() -> (WsConn, tokio::io::DuplexStream) {
        let (a, b) = duplex(1 << 20);
        (WsConn::from_io(Box::new(a), BytesMut::new()), b)
    }

    #[test]
    fn masking_matches_naive_implementation() {
        for len in [0usize, 1, 3, 4, 5, 7, 8, 31, 1000] {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let key = [0xAB, 0xCD, 0x01, 0xFE];
            let mut fast = data.clone();
            mask_in_place(&mut fast, key);
            let naive: Vec<u8> = data.iter().enumerate().map(|(i, b)| b ^ key[i % 4]).collect();
            assert_eq!(fast, naive, "len={len}");
            mask_in_place(&mut fast, key);
            assert_eq!(fast, data, "involution len={len}");
        }
    }

    #[tokio::test]
    async fn writer_frames_are_masked_and_decodable() {
        let (mut conn, mut server) = conn_pair();
        for len in [0usize, 5, 125, 126, 300, 65535, 65536, 70000] {
            let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
            conn.send(&payload).await.unwrap();
            let mut hdr = [0u8; 2];
            server.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[0], 0x82, "FIN + binary");
            assert!(hdr[1] & 0x80 != 0, "client frames must be masked");
            let l = match hdr[1] & 0x7F {
                126 => {
                    let mut e = [0u8; 2];
                    server.read_exact(&mut e).await.unwrap();
                    u16::from_be_bytes(e) as usize
                }
                127 => {
                    let mut e = [0u8; 8];
                    server.read_exact(&mut e).await.unwrap();
                    u64::from_be_bytes(e) as usize
                }
                n => n as usize,
            };
            assert_eq!(l, len);
            let mut key = [0u8; 4];
            server.read_exact(&mut key).await.unwrap();
            let mut body = vec![0u8; len];
            server.read_exact(&mut body).await.unwrap();
            mask_in_place(&mut body, key);
            assert_eq!(body, payload, "len={len}");
        }
    }

    #[tokio::test]
    async fn reader_handles_fragments_and_interleaved_ping() {
        let (mut conn, mut server) = conn_pair();
        let mut wire = Vec::new();
        wire.extend(server_frame(OP_BINARY, false, b"hel"));
        wire.extend(server_frame(OP_PING, true, b"pp"));
        wire.extend(server_frame(OP_CONT, true, b"lo"));
        wire.extend(server_frame(OP_BINARY, true, &vec![9u8; 300])); // 126-form length
        wire.extend(server_frame(OP_PONG, true, b"ignored"));
        wire.extend(server_frame(OP_BINARY, true, b"tail"));
        server.write_all(&wire).await.unwrap();

        let r = &mut conn.reader;
        assert_eq!(r.recv().await.unwrap(), Some(WsMsg::Ping(b"pp".to_vec())));
        assert_eq!(r.recv().await.unwrap(), Some(WsMsg::Data(b"hello".to_vec())));
        assert_eq!(r.recv().await.unwrap(), Some(WsMsg::Data(vec![9u8; 300])));
        assert_eq!(r.recv().await.unwrap(), Some(WsMsg::Data(b"tail".to_vec())));
        drop(server);
        assert_eq!(r.recv().await.unwrap(), None);
    }

    #[tokio::test]
    async fn reader_survives_byte_at_a_time_delivery_and_cancellation() {
        let (mut conn, mut server) = conn_pair();
        let frame = server_frame(OP_BINARY, true, &[5u8; 200]);
        let writer = tokio::spawn(async move {
            for b in frame {
                server.write_all(&[b]).await.unwrap();
                server.flush().await.unwrap();
                tokio::task::yield_now().await;
            }
            server
        });
        // Poll recv() with a tiny timeout repeatedly: every timeout drops the
        // future mid-frame. Cancel-safety means nothing may be lost.
        let msg = loop {
            match timeout(Duration::from_micros(50), conn.reader.recv()).await {
                Ok(r) => break r.unwrap(),
                Err(_) => continue,
            }
        };
        assert_eq!(msg, Some(WsMsg::Data(vec![5u8; 200])));
        let _ = writer.await;
    }

    #[tokio::test]
    async fn recv_answers_pings_and_close_ends_stream() {
        let (mut conn, mut server) = conn_pair();
        server.write_all(&server_frame(OP_PING, true, b"abc")).await.unwrap();
        server.write_all(&server_frame(OP_BINARY, true, b"data")).await.unwrap();
        server.write_all(&server_frame(OP_CLOSE, true, &1000u16.to_be_bytes())).await.unwrap();
        assert_eq!(conn.recv().await.unwrap(), Some(b"data".to_vec()));
        // the pong must have been written
        let mut hdr = [0u8; 2];
        server.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[0], 0x80 | OP_PONG);
        assert_eq!(conn.recv().await.unwrap(), None);
    }

    #[tokio::test]
    async fn liveness_probe() {
        let (mut conn, server) = conn_pair();
        assert!(conn.is_alive().await, "idle connection is alive");
        drop(server);
        assert!(!conn.is_alive().await, "peer hung up");

        let (mut conn, mut server) = conn_pair();
        server.write_all(&server_frame(OP_CLOSE, true, &[])).await.unwrap();
        assert!(!conn.is_alive().await, "close frame pending");

        let (mut conn, mut server) = conn_pair();
        server.write_all(&server_frame(OP_PING, true, b"x")).await.unwrap();
        assert!(conn.is_alive().await, "ping pending is not death");
        // and the buffered ping is still delivered afterwards
        assert_eq!(conn.reader.recv().await.unwrap(), Some(WsMsg::Ping(b"x".to_vec())));
    }

    async fn mock_server(response: &'static str, extra: Vec<u8>) -> (SocketAddr, tokio::task::JoinHandle<String>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let h = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut req = Vec::new();
            let mut b = [0u8; 256];
            while find_header_end(&req).is_none() {
                let n = s.read(&mut b).await.unwrap();
                req.extend_from_slice(&b[..n]);
            }
            let mut out = response.as_bytes().to_vec();
            out.extend(extra);
            s.write_all(&out).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            String::from_utf8(req).unwrap()
        });
        (addr, h)
    }

    fn plain_configs() -> TlsConfigs {
        let c = Arc::new(
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth(),
        );
        TlsConfigs { normal: c.clone(), fronted: c }
    }

    #[tokio::test]
    async fn handshake_ok_keeps_bytes_sent_right_after_headers() {
        let (addr, req) = mock_server(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
            server_frame(OP_BINARY, true, b"early"),
        )
        .await;
        let mut o =
            ConnectOpts::new(Target::Addr(addr), "kws2.example", "/apiws?dst=1.2.3.4&dc=2", Duration::from_secs(5));
        o.secure = false;
        let mut conn = connect(&plain_configs(), &o).await.unwrap();
        assert_eq!(conn.recv().await.unwrap(), Some(b"early".to_vec()));
        let req = req.await.unwrap();
        assert!(req.starts_with("GET /apiws?dst=1.2.3.4&dc=2 HTTP/1.1\r\n"));
        assert!(req.contains("Host: kws2.example\r\n"));
        assert!(req.contains("Upgrade: websocket\r\n"));
        assert!(req.contains("Sec-WebSocket-Protocol: binary\r\n"));
    }

    #[tokio::test]
    async fn handshake_redirect_is_reported() {
        let (addr, _) = mock_server("HTTP/1.1 302 Found\r\nLocation: https://elsewhere/\r\n\r\n", vec![]).await;
        let mut o = ConnectOpts::new(Target::Addr(addr), "h", "/apiws", Duration::from_secs(5));
        o.secure = false;
        let e = connect(&plain_configs(), &o).await.err().unwrap();
        assert!(e.is_redirect());
        assert_eq!(e.redirect_location(), Some("https://elsewhere/"));
    }

    #[tokio::test]
    async fn connect_classifies_timeout_and_refusal() {
        // Refused: bind then drop to get a closed port.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        // (Windows retries a refused connection for ~2 s before reporting it.)
        let mut o = ConnectOpts::new(Target::Addr(addr), "h", "/apiws", Duration::from_secs(15));
        o.secure = false;
        let e = connect(&plain_configs(), &o).await.err().unwrap();
        assert!(matches!(e, WsError::Io(_)) && !e.is_timeout());

        // Accepts but never answers → overall timeout.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (_s, _) = l.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let mut o = ConnectOpts::new(Target::Addr(addr), "h", "/apiws", Duration::from_millis(300));
        o.secure = false;
        assert!(connect(&plain_configs(), &o).await.err().unwrap().is_timeout());
    }

    #[tokio::test]
    async fn non_101_non_redirect_is_a_handshake_error() {
        let (addr, _) = mock_server("HTTP/1.1 404 Not Found\r\n\r\n", vec![]).await;
        let mut o = ConnectOpts::new(Target::Addr(addr), "h", "/apiws", Duration::from_secs(5));
        o.secure = false;
        let e = connect(&plain_configs(), &o).await.err().unwrap();
        assert!(matches!(e, WsError::Handshake { status: 404, .. }));
        assert!(!e.is_redirect() && !e.is_reset());
    }
}
