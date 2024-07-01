use std::{
    env,
    pin::Pin,
    task::{Context, Poll},
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpStream, UnixStream},
};
use tokio_util::codec::Framed;

use crate::{
    lockdown::{LockdownConnection, PListCodec, LOCKDOWN_PORT},
    tls,
    usbmux::{PairRecord, UsbmuxClient},
};

/// Result type
pub type Result<T> = std::result::Result<T, UsbmuxError>;

/// Usbmux Error
#[derive(Error, Debug)]
pub enum UsbmuxError {
    /// FailedRequest
    #[error("Usbmux request failed: {}", .0)]
    Error(String),
    /// IOError
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    /// UTF8 encoding/decoding error
    #[error(transparent)]
    Utf8StringError(#[from] std::str::Utf8Error),
    /// ParseIntError
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),
    /// AddrParseError
    #[error(transparent)]
    AddrParseError(#[from] std::net::AddrParseError),
    /// error parsing/serialising plis
    #[error(transparent)]
    PlistError(#[from] plist::Error),
}

/// Connection to a device, either TCP or UNIX domain sockets
#[derive(Debug)]
pub enum Connection {
    /// tcp connection
    Tcp(TcpStream),
    /// unix domain socket connection
    Unix(UnixStream),
}

impl Connection {
    /// create a new connection by connecting to the usbmuxd socket using TCP or UNIX domain socket.
    /// Set the env variable USBMUXD_SOCKET_ADDRESS prefixed with
    ///     \"TCPIP:\" to connect to a tcp socket
    ///     \"UNIX:\" to connect to a unix domain socket
    pub async fn new() -> Result<Self> {
        let usbmuxd_socket_address = env::var("USBMUXD_SOCKET_ADDRESS")
            .unwrap_or_else(|_| String::from("UNIX:/var/run/usbmuxd"));

        Connection::get(usbmuxd_socket_address.as_str()).await
    }

    /// parse the connection string and return either a tcp socket or unix domain socket connection
    async fn get(s: &str) -> Result<Self> {
        if let Some(path) = s.strip_prefix("UNIX:") {
            let stream = UnixStream::connect(path).await?;
            Ok(Connection::Unix(stream))
        } else if let Some(addr) = s.strip_prefix("TCPIP:") {
            let stream = TcpStream::connect(addr).await?;
            return Ok(Connection::Tcp(stream));
        } else {
            Err(UsbmuxError::Error(format!(
                "Unspported connection type: {}",
                s
            )))
        }
    }
}

impl AsyncRead for Connection {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Connection::Unix(x) => Pin::new(x).poll_read(cx, buf),
            Connection::Tcp(x) => Pin::new(x).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Connection {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Connection::Unix(x) => Pin::new(x).poll_write(cx, buf),
            Connection::Tcp(x) => Pin::new(x).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Connection::Unix(x) => Pin::new(x).poll_write_vectored(cx, bufs),
            Connection::Tcp(x) => Pin::new(x).poll_write_vectored(cx, bufs),
        }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        match self {
            Connection::Unix(x) => x.is_write_vectored(),
            Connection::Tcp(x) => x.is_write_vectored(),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Connection::Unix(x) => Pin::new(x).poll_flush(cx),
            Connection::Tcp(x) => Pin::new(x).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Connection::Unix(x) => Pin::new(x).poll_shutdown(cx),
            Connection::Tcp(x) => Pin::new(x).poll_shutdown(cx),
        }
    }
}

/// A stream representing a TLS connection or not
#[derive(Debug)]
pub enum TlsStream {
    /// Plain connection
    Plain(Connection),
    /// Client TLS connection
    ClientTls(tokio_rustls::client::TlsStream<Connection>),
}

impl AsyncRead for TlsStream {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TlsStream::Plain(x) => Pin::new(x).poll_read(cx, buf),
            TlsStream::ClientTls(x) => Pin::new(x).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsStream {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            TlsStream::Plain(x) => Pin::new(x).poll_write(cx, buf),
            TlsStream::ClientTls(x) => Pin::new(x).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            TlsStream::Plain(x) => Pin::new(x).poll_write_vectored(cx, bufs),
            TlsStream::ClientTls(x) => Pin::new(x).poll_write_vectored(cx, bufs),
        }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        match self {
            TlsStream::Plain(x) => x.is_write_vectored(),
            TlsStream::ClientTls(x) => x.is_write_vectored(),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TlsStream::Plain(x) => Pin::new(x).poll_flush(cx),
            TlsStream::ClientTls(x) => Pin::new(x).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TlsStream::Plain(x) => Pin::new(x).poll_shutdown(cx),
            TlsStream::ClientTls(x) => Pin::new(x).poll_shutdown(cx),
        }
    }
}

pub(crate) async fn usbmux() -> Result<UsbmuxClient<Connection>> {
    let stream = Connection::new().await?;
    Ok(UsbmuxClient::new(stream))
}

pub(crate) async fn lockdown(device_id: u32) -> Result<LockdownConnection<Connection>> {
    usbmux()
        .await?
        .connect(device_id, LOCKDOWN_PORT)
        .await
        .map(LockdownConnection::new)
}

pub(crate) struct StartServiceResponse {
    port: u16,
    with_ssl: Option<PairRecord>,
}

pub(crate) async fn start_service(
    device_id: u32,
    service: &str,
    pair_record: &crate::usbmux::PairRecord,
) -> Result<StartServiceResponse> {
    lockdown(device_id)
        .await?
        .start_session(pair_record)
        .await?
        .start_service(service)
        .await
        .map(|resp| {
            let with_ssl = match resp.enable_service_ssl.unwrap_or(false) {
                true => Some(pair_record.clone()),
                false => None,
            };
            StartServiceResponse {
                port: resp.port,
                with_ssl,
            }
        })
}

pub(crate) async fn connect_service(
    device_id: u32,
    service: StartServiceResponse,
) -> Result<Framed<TlsStream, PListCodec>> {
    let stream = usbmux()
        .await?
        .connect(device_id, service.port.to_be())
        .await
        .unwrap();

    match service.with_ssl {
        None => Ok(Framed::new(TlsStream::Plain(stream), PListCodec::new())),
        Some(pair_record) => {
            let tls_stream = tls::wrap_into_tls_client_stream(stream, &pair_record).await?;
            Ok(Framed::new(
                TlsStream::ClientTls(tls_stream),
                PListCodec::new(),
            ))
        }
    }
}
