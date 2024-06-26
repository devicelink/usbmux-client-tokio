use std::path::Path;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use crate::util::{Result, UsbmuxError};
use bytes::{Buf, BytesMut};
use futures::stream::StreamExt;
use futures::Sink;
use futures::SinkExt;
use futures::Stream;
use plist;
use serde::{de, Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::net::ToSocketAddrs;
use tokio::net::UnixStream;
use tokio_util::codec::Framed;
use tokio_util::codec::{Decoder, Encoder};
use tracing::debug;

const USBMUX_HEADER_LENGTH: usize = 16;

/// USBMux header structure
pub struct UsbmuxHeader {
    /// Length of the payload
    pub length: u32,
    /// Version
    pub version: u32,
    /// Request
    pub request: u32,
    /// Tag
    pub tag: u32,
}

impl UsbmuxHeader {
    /// Create a new USBMux header
    pub fn new(length: u32, version: u32, request: u32, tag: u32) -> UsbmuxHeader {
        UsbmuxHeader {
            length,
            version,
            request,
            tag,
        }
    }

    /// Convert the header to a byte array
    pub fn to_bytes(&self) -> [u8; USBMUX_HEADER_LENGTH] {
        let mut buffer = [0u8; USBMUX_HEADER_LENGTH];
        buffer[0..4].copy_from_slice(&(USBMUX_HEADER_LENGTH as u32 + &self.length).to_le_bytes());
        buffer[4..8].copy_from_slice(&self.version.to_le_bytes());
        buffer[8..12].copy_from_slice(&self.request.to_le_bytes());
        buffer[12..16].copy_from_slice(&self.tag.to_le_bytes());
        buffer
    }

    /// Create a new USBMux header from a byte array
    pub fn from_bytes(bytes: &[u8]) -> UsbmuxHeader {
        let length = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            - USBMUX_HEADER_LENGTH as u32;
        let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let request = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let tag = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);

        UsbmuxHeader {
            length,
            version,
            request,
            tag,
        }
    }
}

impl std::fmt::Debug for UsbmuxHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Usbmux Header:\n{}",
            pretty_hex::pretty_hex(&self.to_bytes())
        )
    }
}

/// USBMux packet structure
pub struct UsbmuxPacket {
    /// USBMux header
    pub header: UsbmuxHeader,
    /// Payload
    pub payload: Vec<u8>,
}

impl UsbmuxPacket {
    /// Encode a message into a USBMux packet
    pub fn encode<T: serde::ser::Serialize>(msg: T, tag: u32) -> Result<Self> {
        let mut buffer: Vec<u8> = Vec::new();
        plist::to_writer_xml(&mut buffer, &msg)?;
        Ok(Self {
            header: UsbmuxHeader::new(buffer.len() as u32, 1, 8, tag),
            payload: buffer,
        })
    }

    /// Decode a USBMux packet into a message
    pub fn decode<T>(&self) -> Result<T>
    where
        T: de::DeserializeOwned,
    {
        let msg = plist::from_bytes::<T>(&self.payload)?;
        Ok(msg)
    }
}

impl std::fmt::Debug for UsbmuxPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}\nUsbmux Payload:\n{}",
            self.header,
            pretty_hex::pretty_hex(&self.payload)
        )
    }
}

/// USBMux codec
#[derive(Debug)]
pub struct UsbmuxCodec {}

const MAX: usize = 8 * 1024 * 1024;

impl UsbmuxCodec {
    /// Create a new USBMux codec
    pub fn new() -> UsbmuxCodec {
        UsbmuxCodec {}
    }
}

impl Decoder for UsbmuxCodec {
    type Item = UsbmuxPacket;
    type Error = UsbmuxError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        debug!("Decoding Usbmux message:\n{}", pretty_hex::pretty_hex(&src));
        if src.len() < USBMUX_HEADER_LENGTH as usize {
            // Not enough data to read length marker.
            return Ok(None);
        }

        // Read length marker.
        let mut header_bytes = [0u8; USBMUX_HEADER_LENGTH];
        header_bytes.copy_from_slice(&src[..USBMUX_HEADER_LENGTH as usize]);

        let header = UsbmuxHeader::from_bytes(&header_bytes);
        let length = header.length as usize;
        // Check that the length is not too large to avoid a denial of
        // service attack where the server runs out of memory.
        if length > MAX {
            return Err(UsbmuxError::IOError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame of length {} is too large.", length),
            )));
        }

        if src.len() < USBMUX_HEADER_LENGTH + length {
            // The full string has not yet arrived.
            //
            // We reserve more space in the buffer. This is not strictly
            // necessary, but is a good idea performance-wise.
            src.reserve(USBMUX_HEADER_LENGTH + length - src.len());

            // We inform the Framed that we need more bytes to form the next
            // frame.
            return Ok(None);
        }

        // Use advance to modify src such that it no longer contains
        // this frame.
        let data = src[USBMUX_HEADER_LENGTH..USBMUX_HEADER_LENGTH + length].to_vec();
        src.advance(USBMUX_HEADER_LENGTH + length);

        Ok(Some(UsbmuxPacket {
            header,
            payload: data,
        }))
    }
}

impl Encoder<UsbmuxPacket> for UsbmuxCodec {
    type Error = UsbmuxError;

    fn encode(&mut self, msg: UsbmuxPacket, dst: &mut BytesMut) -> Result<()> {
        debug!("Encoding Usbmux message:\n{:?}", msg);
        // Don't send a string if it is longer than the other end will
        // accept.
        let length = USBMUX_HEADER_LENGTH + msg.payload.len();
        if length > MAX {
            return Err(UsbmuxError::IOError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame of length {} is too large.", length),
            )));
        }

        // Reserve space in the buffer.
        dst.reserve(length - dst.len());

        // Write the length and string to the buffer.
        dst.extend_from_slice(&msg.header.to_bytes());
        dst.extend_from_slice(&msg.payload);
        Ok(())
    }
}

/// USBMux connection
#[derive(Debug)]
pub struct UsbmuxConnection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite,
{
    stream: Framed<S, UsbmuxCodec>,
}

impl<S> UsbmuxConnection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    /// Create a new USBMux connection
    pub fn new(stream: S) -> UsbmuxConnection<S> {
        let stream = Framed::new(stream, UsbmuxCodec::new());

        return UsbmuxConnection { stream };
    }

    /// Get the inner stream
    pub fn into_inner(self) -> S {
        self.stream.into_inner()
    }
}

impl<S> Stream for UsbmuxConnection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    type Item = Result<UsbmuxPacket>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream).poll_next(cx)
    }
}

impl<S> Sink<UsbmuxPacket> for UsbmuxConnection<S>
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
        item: UsbmuxPacket,
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
/// USBMux client
#[derive(Debug)]
pub struct UsbmuxClient<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite,
{
    connection: UsbmuxConnection<S>,
    tag: u32,
}

impl UsbmuxClient<UnixStream> {
    /// Connect to a Unix socket
    pub async fn connect_unix<P>(path: P) -> Result<UsbmuxClient<UnixStream>>
    where
        P: AsRef<Path>,
    {
        let stream = UnixStream::connect(path).await?;
        Ok(UsbmuxClient::new(stream))
    }
}

impl UsbmuxClient<TcpStream> {
    /// Connect to a TCP socket
    pub async fn connect_tcp<A: ToSocketAddrs>(addr: A) -> Result<UsbmuxClient<TcpStream>> {
        let stream = TcpStream::connect(addr).await?;
        Ok(UsbmuxClient::new(stream))
    }
}

impl<S> UsbmuxClient<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    /// Create a new USBMux client
    pub fn new(stream: S) -> UsbmuxClient<S> {
        UsbmuxClient {
            connection: UsbmuxConnection::new(stream),
            tag: 0,
        }
    }

    /// List connected devices
    pub async fn list_devices(&mut self) -> Result<Vec<DeviceEntry>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        self.send(UsbmuxRequest::ListDevices.wrapped()).await?;
        self.next::<DeviceList>().await.map(|list| list.device_list)
    }

    /// Find a device by serial number
    pub async fn find_device<T>(&mut self, device_serial: T) -> Result<DeviceEntry>
    where
        T: Into<String>,
    {
        let device_serial = device_serial.into();
        let devices: Vec<DeviceEntry> = self.list_devices().await?;
        devices
            .into_iter()
            .find(|d| d.properties.serial_number == device_serial)
            .ok_or(UsbmuxError::IOError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Device with serial number {} not found", device_serial),
            )))
    }

    /// conmnnect to a device
    pub async fn connect(mut self, device_id: u32, port_number: u16) -> Result<S> {
        self.send(
            UsbmuxRequest::Connect {
                device_id,
                port_number,
            }
            .wrapped(),
        )
        .await?;

        let response = self.next::<ResultType>().await?;
        match response.number {
            0 => Ok(self.connection.into_inner()),
            _ => Err(UsbmuxError::IOError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Error connecting to device: {:?}", response),
            ))),
        }
    }

    /// Read a pair record
    pub async fn read_pair_record<T>(&mut self, device_serial: T) -> Result<PairRecord>
    where
        T: Into<String>,
    {
        let device_serial = device_serial.into();
        self.send(
            UsbmuxRequest::ReadPairRecord {
                pair_record_id: device_serial,
            }
            .wrapped(),
        )
        .await?;
        let data = self.next::<PairRecordData>().await?.data;

        Ok(plist::from_bytes::<PairRecord>(&data)?)
    }

    async fn send<T: serde::ser::Serialize>(&mut self, request: T) -> Result<()> {
        self.tag += 1;
        let message = UsbmuxPacket::encode(request, self.tag)?;
        self.send_raw(message).await
    }

    async fn send_raw(&mut self, message: UsbmuxPacket) -> Result<()> {
        self.connection.send(message).await
    }

    async fn next<T>(&mut self) -> Result<T>
    where
        T: de::DeserializeOwned,
    {
        let message = self.next_raw().await?;
        message.decode()
    }

    /// Get the next message from the connection
    pub async fn next_raw(&mut self) -> Result<UsbmuxPacket> {
        match self.connection.next().await {
            Some(Ok(message)) => Ok(message),
            Some(Err(e)) => Err(e),
            None => Err(UsbmuxError::IOError(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Connection closed",
            ))),
        }
    }
}

/// USBMux request
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct UsbmuxRequestBase {
    #[serde(flatten)]
    /// the actual request to be send
    pub variant: UsbmuxRequest,
    /// the program name
    pub prog_name: String,
    /// the client version string
    pub client_version_string: String,
}

/// USBMux request
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "MessageType")]
pub enum UsbmuxRequest {
    /// readPairRecord request data
    ReadPairRecord {
        /// the pair record id
        #[serde(rename = "PairRecordID")]
        pair_record_id: String,
    },
    /// connect request data
    Connect {
        /// the device id
        #[serde(rename = "DeviceID")]
        device_id: u32,
        /// the port number
        #[serde(rename = "PortNumber")]
        port_number: u16,
    },
    /// ReadBuid request
    #[serde(rename = "ReadBUID")]
    ReadBuid,
    /// ListDevices request
    ListDevices,
}

impl UsbmuxRequest {
    /// Wrap the request in a UsbmuxRequestBase
    pub fn wrapped(self) -> UsbmuxRequestBase {
        let prog_name = String::from("usbmux-client-tokio");
        let client_version_string = String::from("1.0");
        UsbmuxRequestBase {
            variant: self,
            prog_name,
            client_version_string,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_serialization_deserialization() {
        let list_devices = "\
        <?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
        <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
        <plist version=\"1.0\">\n\
        <dict>\n\
            \t<key>MessageType</key>\n\
            \t<string>ListDevices</string>\n\
            \t<key>ProgName</key>\n\
            \t<string>usbmux-client-tokio</string>\n\
            \t<key>ClientVersionString</key>\n\
            \t<string>1.0</string>\n\
        </dict>\n\
        </plist>";

        let request = UsbmuxRequest::ListDevices.wrapped();
        let message = UsbmuxPacket::encode(request, 0).unwrap();
        let serialized_list_devices = String::from_utf8(message.payload).unwrap();

        assert_eq!(list_devices, serialized_list_devices);
    }
}

/// USBMux response
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct ResultType {
    /// the message type
    pub message_type: String,
    /// the number
    pub number: i32,
}

/// Device list response
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DeviceList {
    /// the actual devices
    pub device_list: Vec<DeviceEntry>,
}

/// Device entry
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct DeviceEntry {
    /// the device id
    #[serde(rename = "DeviceID")]
    pub device_id: u32,
    /// the product id
    pub properties: DeviceProperties,
}

/// Device properties
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct DeviceProperties {
    /// the device type
    pub serial_number: String,
    /// the product id
    pub connection_type: ConnectionType,
}

/// Connection type
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ConnectionType {
    /// USB connection
    USB,
    /// Network connection
    Network,
}

/// Pair record data
#[derive(Serialize, Deserialize, Debug)]
pub struct PairRecordData {
    #[serde(rename = "PairRecordData", with = "serde_bytes")]
    data: Vec<u8>,
}

/// Pair record
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PairRecord {
    /// the host id
    #[serde(rename = "HostID")]
    pub host_id: String,
    /// the system buid
    #[serde(rename = "SystemBUID")]
    pub system_buid: String,
    /// the host certificate
    #[serde(rename = "HostCertificate", with = "serde_bytes")]
    pub host_certificate: Vec<u8>,
    /// the host private key
    #[serde(rename = "HostPrivateKey", with = "serde_bytes")]
    pub host_private_key: Vec<u8>,
    /// the device certificate
    #[serde(rename = "DeviceCertificate", with = "serde_bytes")]
    pub device_certificate: Vec<u8>,
    /// the device private key
    #[serde(rename = "EscrowBag", with = "serde_bytes")]
    pub escrow_bag: Vec<u8>,
    /// the wi-fi mac address
    #[serde(rename = "WiFiMACAddress")]
    pub wi_fi_macaddress: String,
    /// the root certificate
    #[serde(rename = "RootCertificate", with = "serde_bytes")]
    pub root_certificate: Vec<u8>,
    /// the root private key
    #[serde(rename = "RootPrivateKey", with = "serde_bytes")]
    pub root_private_key: Vec<u8>,
}

impl From<PairRecordData> for PairRecord {
    fn from(data: PairRecordData) -> Self {
        plist::from_bytes(&data.data).unwrap()
    }
}

impl From<PairRecord> for PairRecordData {
    fn from(pair_record: PairRecord) -> Self {
        let mut data: Vec<u8> = Vec::new();
        plist::to_writer_xml(&mut data, &pair_record).unwrap();

        PairRecordData { data }
    }
}
