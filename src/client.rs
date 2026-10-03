//! The client side of a connection: plain TCP, or TCP carrying fake-TLS records.
//! A closed set of variants (no generics, no trait objects) keeps every task
//! that holds one `Send` and lets the bridge treat both uniformly.

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::fake_tls::{FakeTlsReader, FakeTlsWriter};

pub enum ClientReader {
    Plain(OwnedReadHalf),
    Tls(FakeTlsReader),
}

pub enum ClientWriter {
    Plain(OwnedWriteHalf),
    Tls(FakeTlsWriter),
}

impl ClientReader {
    /// Up to `buf.len()` bytes; `0` means the peer is gone.
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ClientReader::Plain(r) => r.read(buf).await,
            ClientReader::Tls(r) => r.read(buf).await,
        }
    }

    pub async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            let n = self.read(&mut buf[filled..]).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            filled += n;
        }
        Ok(())
    }
}

impl ClientWriter {
    pub async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            ClientWriter::Plain(w) => w.write_all(data).await,
            ClientWriter::Tls(w) => w.write_all(data).await,
        }
    }

    pub async fn shutdown(&mut self) {
        match self {
            ClientWriter::Plain(w) => {
                let _ = w.shutdown().await;
            }
            ClientWriter::Tls(w) => w.shutdown().await,
        }
    }
}
