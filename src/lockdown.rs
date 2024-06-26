use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt};
use plist::{Value, XmlWriteOptions};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::codec::{Decoder, Encoder, Framed};

use crate::{
    tls::wrap_into_tls_client_stream,
    usbmux::PairRecord,
    util::{Result, UsbmuxError},
};

/// port for the lockdown service.
pub const LOCKDOWN_PORT: u16 = 32498;
const LOCKDOWN_HEADER_LENGTH: usize = 4;

/// Lockdown message.
pub struct PListPacket {
    /// Payload of the message.
    pub payload: Vec<u8>,
}

impl std::fmt::Debug for PListPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Lockdown Message:\n{}",
            pretty_hex::pretty_hex(&self.payload)
        )
    }
}

impl TryFrom<Value> for PListPacket {
    type Error = UsbmuxError;

    fn try_from(value: Value) -> Result<Self> {
        let mut payload: Vec<u8> = Vec::new();
        plist::to_writer_xml_with_options(
            &mut payload,
            &value,
            &XmlWriteOptions::default().indent(0, 0),
        )
        .unwrap();
        Ok(Self { payload })
    }
}

impl PListPacket {
    /// Encode a message into a Lockdown packet
    pub fn encode<T: serde::ser::Serialize>(msg: T) -> Result<Self> {
        let mut buffer: Vec<u8> = Vec::new();
        plist::to_writer_xml(&mut buffer, &msg)?;
        Ok(Self { payload: buffer })
    }

    /// Decode a Lockdown packet into a message
    pub fn decode<T>(&self) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let msg = plist::from_bytes::<T>(&self.payload)?;
        Ok(msg)
    }
}

const MAX: usize = 8 * 1024 * 1024;

/// Codec for encoding and decoding Lockdown messages.
#[derive(Debug)]
pub struct PListCodec {}

impl PListCodec {
    /// Create a new LockdownCodec.
    pub fn new() -> PListCodec {
        PListCodec {}
    }
}

impl Decoder for PListCodec {
    type Item = PListPacket;
    type Error = UsbmuxError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        if src.len() < LOCKDOWN_HEADER_LENGTH {
            // Not enough data to read length marker.
            return Ok(None);
        }

        let length = u32::from_be_bytes([src[0], src[1], src[2], src[3]]) as usize;

        // Check that the length is not too large to avoid a denial of
        // service attack where the server runs out of memory.
        if length > MAX {
            return Err(UsbmuxError::IOError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame of length {} is too large.", length),
            )));
        }

        if src.len() < LOCKDOWN_HEADER_LENGTH + length {
            // The full string has not yet arrived.
            //
            // We reserve more space in the buffer. This is not strictly
            // necessary, but is a good idea performance-wise.
            src.reserve(LOCKDOWN_HEADER_LENGTH + length - src.len());

            // We inform the Framed that we need more bytes to form the next
            // frame.
            return Ok(None);
        }

        // Use advance to modify src such that it no longer contains
        // this frame.
        let payload = src[LOCKDOWN_HEADER_LENGTH..LOCKDOWN_HEADER_LENGTH + length].to_vec();
        src.advance(LOCKDOWN_HEADER_LENGTH + length);

        Ok(Some(PListPacket { payload }))
    }
}

impl Encoder<PListPacket> for PListCodec {
    type Error = UsbmuxError;

    fn encode(&mut self, msg: PListPacket, dst: &mut BytesMut) -> Result<()> {
        // Don't send a string if it is longer than the other end will
        // accept.
        let length = msg.payload.len();
        if length > MAX {
            return Err(UsbmuxError::IOError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame of length {} is too large.", length),
            )));
        }

        // Reserve space in the buffer.
        dst.reserve(length);

        let length = length as u32;

        // Write the length and string to the buffer.
        dst.extend_from_slice(&length.to_be_bytes());
        dst.extend_from_slice(&msg.payload);
        Ok(())
    }
}

/// Stream for the device. Can be an Plain, TlsClient or TlsServer stream.
#[derive(Debug)]
pub(crate) enum DeviceStream<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    /// Plain stream.
    Plain(S),
    /// TlsClient stream.
    TlsClient(tokio_rustls::client::TlsStream<S>),
    /// TlsServer stream.
    TlsServer(tokio_rustls::server::TlsStream<S>),
}

impl<S> DeviceStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Get the inner stream.
    pub fn into_inner(self) -> S {
        match self {
            DeviceStream::Plain(x) => x,
            DeviceStream::TlsClient(x) => x.into_inner().0,
            DeviceStream::TlsServer(x) => x.into_inner().0,
        }
    }
}

impl<T> AsyncRead for DeviceStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            DeviceStream::Plain(x) => Pin::new(x).poll_read(cx, buf),
            DeviceStream::TlsServer(x) => Pin::new(x).poll_read(cx, buf),
            DeviceStream::TlsClient(x) => Pin::new(x).poll_read(cx, buf),
        }
    }
}

impl<T> AsyncWrite for DeviceStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            DeviceStream::Plain(x) => Pin::new(x).poll_write(cx, buf),
            DeviceStream::TlsServer(x) => Pin::new(x).poll_write(cx, buf),
            DeviceStream::TlsClient(x) => Pin::new(x).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            DeviceStream::Plain(x) => Pin::new(x).poll_write_vectored(cx, bufs),
            DeviceStream::TlsServer(x) => Pin::new(x).poll_write_vectored(cx, bufs),
            DeviceStream::TlsClient(x) => Pin::new(x).poll_write_vectored(cx, bufs),
        }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        match self {
            DeviceStream::Plain(x) => x.is_write_vectored(),
            DeviceStream::TlsServer(x) => x.is_write_vectored(),
            DeviceStream::TlsClient(x) => x.is_write_vectored(),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            DeviceStream::Plain(x) => Pin::new(x).poll_flush(cx),
            DeviceStream::TlsServer(x) => Pin::new(x).poll_flush(cx),
            DeviceStream::TlsClient(x) => Pin::new(x).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            DeviceStream::Plain(x) => Pin::new(x).poll_shutdown(cx),
            DeviceStream::TlsServer(x) => Pin::new(x).poll_shutdown(cx),
            DeviceStream::TlsClient(x) => Pin::new(x).poll_shutdown(cx),
        }
    }
}

/// plist message request to start a session on the device using lockdown.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct StartSessionRequest {
    label: String,
    protocol_version: String,
    request: String,
    #[serde(rename = "HostID")]
    host_id: String,
    #[serde(rename = "SystemBUID")]
    system_buid: String,
}

/// plist message response to StartSession request to start a session on the device using lockdown.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct StartSessionResponse {
    #[serde(rename = "EnableSessionSSL")]
    enable_session_ssl: bool,
    request: String,
    #[serde(rename = "SessionID")]
    session_id: String,
}

/// plist message request which starts the given service on the device using lockdown.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct StartServiceRequest {
    label: String,
    request: String,
    service: String,
}

/// plist messsage response to StartService request to start a service on the device using lockdown.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct StartServiceResponse {
    /// The port on which the service is started.
    pub port: u16,
    /// The request type.
    pub request: String,
    /// The service name.
    pub service: String,
    /// flag indicating if the services requires tls or not
    #[serde(rename = "EnableServiceSSL")]
    pub enable_service_ssl: Option<bool>,
    /// The error message if any.
    pub error: Option<String>,
}

/// A connection to the Lockdown service.
#[derive(Debug)]
pub struct LockdownConnection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    stream: Framed<DeviceStream<S>, PListCodec>,
}

impl<S> LockdownConnection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    /// Create a new LockdownConnection.
    pub fn new(stream: S) -> LockdownConnection<S>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite,
    {
        let stream = Framed::new(DeviceStream::Plain(stream), PListCodec::new());

        return LockdownConnection { stream };
    }

    /// Start a lockdown session on the device and eventually enable ssl for the session.
    pub async fn start_session(
        mut self,
        pair_record: &PairRecord,
    ) -> Result<LockdownConnection<S>> {
        let request = PListPacket::encode(StartSessionRequest {
            label: "rust-usbmux".to_string(),
            request: "StartSession".to_string(),
            protocol_version: "2".to_string(),
            host_id: pair_record.host_id.clone(),
            system_buid: pair_record.system_buid.clone(),
        })?;

        self.send(request).await?;
        let response: StartSessionResponse = match self.next().await {
            Some(Ok(response)) => response.decode()?,
            None => {
                return Err(UsbmuxError::IOError(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF",
                )))
            }
            Some(Err(e)) => return Err(e),
        };

        if response.enable_session_ssl {
            let stream = self.stream.into_inner().into_inner();
            let stream = wrap_into_tls_client_stream(stream, &pair_record).await?;
            let stream = Framed::new(DeviceStream::TlsClient(stream), PListCodec::new());

            return Ok(LockdownConnection { stream });
        }

        Ok(self)
    }

    /// starting the given service on the device
    pub async fn start_service(&mut self, service: &str) -> Result<StartServiceResponse> {
        let request = PListPacket::encode(StartServiceRequest {
            label: "rust-usbmux".to_string(),
            request: "StartService".to_string(),
            service: service.to_string(),
        })?;

        self.send(request).await?;
        match self.next().await {
            Some(Ok(response)) => {
                return response.decode();
            }
            None => {
                return Err(UsbmuxError::IOError(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF",
                )))
            }
            Some(Err(e)) => return Err(e),
        }
    }

    /// Get the inner stream.
    pub fn into_inner(self) -> S {
        self.stream.into_inner().into_inner()
    }
}

impl<S> Stream for LockdownConnection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    type Item = Result<PListPacket>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream).poll_next(cx)
    }
}

impl<S> Sink<PListPacket> for LockdownConnection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    type Error = UsbmuxError;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<core::result::Result<(), Self::Error>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_ready(cx)
    }

    fn start_send(
        self: Pin<&mut Self>,
        item: PListPacket,
    ) -> core::result::Result<(), Self::Error> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).start_send(item)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<core::result::Result<(), Self::Error>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<core::result::Result<(), Self::Error>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_close(cx)
    }
}
