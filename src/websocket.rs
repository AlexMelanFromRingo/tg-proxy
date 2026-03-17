use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use rand::RngCore;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

pub type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;

#[derive(Debug, Error)]
pub enum WsError {
    #[error("HTTP {status}: {line}")]
    Handshake {
        status: u16,
        line: String,
        location: Option<String>,
    },
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
}

/// Build the rustls ClientConfig.
/// With `skip_verify=false` (default) uses system + WebPKI roots.
/// With `skip_verify=true` disables certificate verification entirely.
pub fn build_tls_config(skip_verify: bool) -> anyhow::Result<ClientConfig> {
    if skip_verify {
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        return Ok(config);
    }

    let mut roots = rustls::RootCertStore::empty();

    // Add WebPKI roots (Mozilla's trusted CAs)
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Also try native system roots (rustls-native-certs 0.8 returns a struct, not Result)
    {
        let native = rustls_native_certs::load_native_certs();
        if !native.errors.is_empty() {
            for e in &native.errors {
                tracing::debug!("Native cert warning: {:?}", e);
            }
        }
        let mut added = 0usize;
        for cert in native.certs {
            if roots.add(cert).is_ok() {
                added += 1;
            }
        }
        tracing::debug!("Loaded {} native TLS root certificates", added);
    }

    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// Connect to `ip:443` via TLS with `domain` as SNI, then perform WebSocket upgrade.
/// Returns the raw TLS stream positioned at the start of WebSocket frames.
pub async fn connect(
    ip: Ipv4Addr,
    domain: &str,
    tls_config: Arc<ClientConfig>,
    connect_timeout: Duration,
) -> Result<TlsStream, WsError> {
    let tcp = timeout(connect_timeout, TcpStream::connect((ip, 443u16)))
        .await
        .map_err(|_| WsError::Timeout)?
        .map_err(WsError::Io)?;

    // Enable TCP_NODELAY for lower latency
    let _ = tcp.set_nodelay(true);

    let connector = TlsConnector::from(tls_config);
    let server_name = ServerName::try_from(domain.to_owned())
        .map_err(|e| WsError::Io(io::Error::new(io::ErrorKind::InvalidInput, e)))?;

    let mut tls = timeout(connect_timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| WsError::Timeout)?
        .map_err(WsError::Io)?;

    // Build WebSocket upgrade request
    let mut key_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let ws_key = base64::engine::general_purpose::STANDARD.encode(key_bytes);

    let request = format!(
        "GET /apiws HTTP/1.1\r\n\
         Host: {domain}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {ws_key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: binary\r\n\
         Origin: https://web.telegram.org\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
         AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n\
         \r\n"
    );
    tls.write_all(request.as_bytes()).await.map_err(WsError::Io)?;
    tls.flush().await.map_err(WsError::Io)?;

    // Read HTTP response headers
    let mut header_buf = Vec::with_capacity(512);
    let response_timeout = Duration::from_secs(10);
    timeout(response_timeout, read_http_headers(&mut tls, &mut header_buf))
        .await
        .map_err(|_| WsError::Timeout)?
        .map_err(WsError::Io)?;

    if header_buf.is_empty() {
        return Err(WsError::EmptyResponse);
    }

    let headers_str = String::from_utf8_lossy(&header_buf);
    let mut lines = headers_str.lines();
    let first_line = lines.next().unwrap_or("").to_string();

    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    let status: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    if status == 101 {
        return Ok(tls);
    }

    // Non-101: parse Location header for redirects
    let location = lines
        .find(|l| l.to_lowercase().starts_with("location:"))
        .and_then(|l| l.splitn(2, ':').nth(1))
        .map(|v| v.trim().to_string());

    Err(WsError::Handshake {
        status,
        line: first_line,
        location,
    })
}

/// Read HTTP headers (up to blank line) into `buf`.
async fn read_http_headers(
    stream: &mut (impl AsyncRead + Unpin),
    buf: &mut Vec<u8>,
) -> io::Result<()> {
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        buf.push(byte[0]);
        // Check for \r\n\r\n or \n\n
        let len = buf.len();
        if (len >= 4 && &buf[len - 4..] == b"\r\n\r\n")
            || (len >= 2 && &buf[len - 2..] == b"\n\n")
        {
            break;
        }
        if len > 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP headers too large",
            ));
        }
    }
    Ok(())
}

// ── WebSocket frame I/O ──────────────────────────────────────────────────────

const OP_CONT: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

#[derive(Debug)]
pub enum WsFrame {
    Data(Vec<u8>),
    Ping(Vec<u8>),
    Close,
}

/// Build a WebSocket frame. If `mask=true`, generates a random 4-byte masking key.
pub fn build_frame(opcode: u8, data: &[u8], mask: bool) -> Vec<u8> {
    let len = data.len();
    let mut frame = Vec::with_capacity(len + 14);

    frame.push(0x80 | opcode); // FIN=1 + opcode

    let mask_bit = if mask { 0x80u8 } else { 0x00 };
    if len < 126 {
        frame.push(mask_bit | len as u8);
    } else if len < 65536 {
        frame.push(mask_bit | 126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(mask_bit | 127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }

    if mask {
        let mut mask_key = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut mask_key);
        frame.extend_from_slice(&mask_key);
        for (i, &b) in data.iter().enumerate() {
            frame.push(b ^ mask_key[i % 4]);
        }
    } else {
        frame.extend_from_slice(data);
    }

    frame
}

/// Send a single masked binary WebSocket frame.
pub async fn send_frame(writer: &mut (impl AsyncWrite + Unpin), data: &[u8]) -> io::Result<()> {
    let frame = build_frame(OP_BINARY, data, true);
    writer.write_all(&frame).await?;
    writer.flush().await
}

/// Send a batch of frames with a single flush.
pub async fn send_frames(
    writer: &mut (impl AsyncWrite + Unpin),
    parts: &[Vec<u8>],
) -> io::Result<()> {
    for part in parts {
        let frame = build_frame(OP_BINARY, part, true);
        writer.write_all(&frame).await?;
    }
    writer.flush().await
}

/// Send a close frame.
pub async fn send_close(writer: &mut (impl AsyncWrite + Unpin)) -> io::Result<()> {
    let frame = build_frame(OP_CLOSE, b"", true);
    let _ = writer.write_all(&frame).await;
    let _ = writer.flush().await;
    Ok(())
}

/// Read the next WebSocket frame. Returns `None` on clean close or EOF.
/// Automatically handles fragmentation (continuation frames) and pings.
pub async fn recv_frame(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<Option<WsFrame>> {
    let mut partial_data: Vec<u8> = Vec::new();

    loop {
        // Read 2-byte frame header
        let mut hdr = [0u8; 2];
        match reader.read_exact(&mut hdr).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }

        let fin = (hdr[0] & 0x80) != 0;
        let opcode = hdr[0] & 0x0F;
        let is_masked = (hdr[1] & 0x80) != 0;
        let mut length = (hdr[1] & 0x7F) as u64;

        if length == 126 {
            let mut ext = [0u8; 2];
            reader.read_exact(&mut ext).await?;
            length = u16::from_be_bytes(ext) as u64;
        } else if length == 127 {
            let mut ext = [0u8; 8];
            reader.read_exact(&mut ext).await?;
            length = u64::from_be_bytes(ext);
        }

        // Guard against absurdly large frames
        if length > 32 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("WebSocket frame too large: {} bytes", length),
            ));
        }

        let mask_key = if is_masked {
            let mut mask = [0u8; 4];
            reader.read_exact(&mut mask).await?;
            Some(mask)
        } else {
            None
        };

        let mut payload = vec![0u8; length as usize];
        reader.read_exact(&mut payload).await?;

        if let Some(mask) = mask_key {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }

        match opcode {
            OP_CLOSE => return Ok(Some(WsFrame::Close)),
            OP_PING => return Ok(Some(WsFrame::Ping(payload))),
            OP_PONG => continue,
            OP_TEXT | OP_BINARY => {
                if fin && partial_data.is_empty() {
                    return Ok(Some(WsFrame::Data(payload)));
                }
                partial_data.extend_from_slice(&payload);
                if fin {
                    return Ok(Some(WsFrame::Data(partial_data)));
                }
            }
            OP_CONT => {
                partial_data.extend_from_slice(&payload);
                if fin && !partial_data.is_empty() {
                    return Ok(Some(WsFrame::Data(partial_data)));
                }
            }
            _ => continue,
        }
    }
}

// ── TLS certificate skip-verify (for --skip-tls-verify flag) ────────────────

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

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
