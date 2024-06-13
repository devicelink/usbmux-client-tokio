use std::{pin::Pin, task::{Context, Poll}};

use bytes::{Buf, BytesMut};
use futures::{Sink, Stream};
use tokio_util::codec::{Decoder, Encoder, Framed};

use crate::util::{Result, UsbmuxError};

const LOCKDOWN_HEADER_LENGTH: usize = 4;

/// Lockdown message.
pub struct LockdownPacket {
    /// Payload of the message.
    pub payload: Vec<u8>,
}

impl std::fmt::Debug for LockdownPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Lockdown Message:\n{}",
            pretty_hex::pretty_hex(&self.payload)
        )
    }
}

const MAX: usize = 8 * 1024 * 1024;

/// Codec for encoding and decoding Lockdown messages.
#[derive(Debug)]
pub struct LockdownCodec {}

impl LockdownCodec {
    /// Create a new LockdownCodec.
    pub fn new() -> LockdownCodec {
        LockdownCodec {}
    }
}

impl Decoder for LockdownCodec {
    type Item = LockdownPacket;
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

        Ok(Some(LockdownPacket { payload }))
    }
}

impl Encoder<LockdownPacket> for LockdownCodec {
    type Error = UsbmuxError;

    fn encode(&mut self, msg: LockdownPacket, dst: &mut BytesMut) -> Result<()> {
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

/// A connection to the Lockdown service.
#[derive(Debug)]
pub struct LockdownConnection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    stream: Framed<S, LockdownCodec>,
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
        let stream = Framed::new(stream, LockdownCodec::new());

        return LockdownConnection { stream };
    }

    /// Get the inner stream.
    pub fn into_inner(self) -> S {
        self.stream.into_inner()
    }
}

impl<S> Stream for LockdownConnection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    type Item = Result<LockdownPacket>;

    fn poll_next(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream).poll_next(cx)
    }
}

impl<S> Sink<LockdownPacket> for LockdownConnection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    type Error = UsbmuxError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<core::result::Result<(), Self::Error>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: LockdownPacket) -> core::result::Result<(), Self::Error> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<core::result::Result<(), Self::Error>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<core::result::Result<(), Self::Error>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_close(cx)
    }
}
