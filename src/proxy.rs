use std::{collections::HashMap, fmt::Debug, sync::Arc};

use crate::{
    lockdown::{DeviceStream, LockdownConnection, PListPacket},
    usbmux::{
        DeviceEntry, DeviceList, PairRecord, PairRecordData, ResultType, UsbmuxConnection,
        UsbmuxPacket,
    },
    util::{Result, UsbmuxError},
};
use futures::{SinkExt, StreamExt};
use plist::Value;
use std::io::Cursor;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::RwLock,
};
use tracing::{info, trace};

enum IOSConnectionProtocol<I, O>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    O: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    USBMUXD {
        incoming_stream: DeviceStream<I>,
        outgoing_stream: DeviceStream<O>,
    },
    LOCKDOWND {
        device_id: u32,
        incoming_stream: DeviceStream<I>,
        outgoing_stream: DeviceStream<O>,
    },
}

/// USBMux Proxy
#[derive(Debug)]
pub struct UsbmuxProxy {
    device_entry_store: Arc<RwLock<HashMap<String, DeviceEntry>>>,
    pair_record_store: Arc<RwLock<HashMap<u32, PairRecord>>>,
}

impl UsbmuxProxy {
    /// Create a new UsbmuxProxy instance
    pub fn new() -> Self {
        UsbmuxProxy {
            device_entry_store: Arc::new(RwLock::new(HashMap::new())),
            pair_record_store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Proxy a connection
    pub async fn proxy<I, O>(
        &self,
        incoming_stream: I,
        outgoing_stream: O,
        connection_id: u32,
    ) -> Result<()>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        O: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        println!("New connection: {}", connection_id);

        self.handle_protocol(
            IOSConnectionProtocol::USBMUXD {
                incoming_stream: DeviceStream::Plain(incoming_stream),
                outgoing_stream: DeviceStream::Plain(outgoing_stream),
            },
            connection_id,
        )
        .await?;

        Ok(())
    }

    async fn handle_protocol<I, O>(
        &self,
        mut protocol: IOSConnectionProtocol<I, O>,
        connection_id: u32,
    ) -> Result<()>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        O: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        loop {
            match protocol {
                IOSConnectionProtocol::USBMUXD {
                    incoming_stream,
                    outgoing_stream,
                } => {
                    protocol = match self
                        .handle_usbmuxd(connection_id, incoming_stream, outgoing_stream)
                        .await?
                    {
                        Some(p) => p,
                        None => return Ok(()), // Connection closed
                    };
                }
                IOSConnectionProtocol::LOCKDOWND {
                    device_id,
                    incoming_stream,
                    outgoing_stream,
                } => {
                    protocol = match self
                        .handle_lockdownd(
                            connection_id,
                            device_id,
                            incoming_stream,
                            outgoing_stream,
                        )
                        .await?
                    {
                        Some(p) => p,
                        None => return Ok(()), // Connection closed
                    };
                }
            }
        }
    }

    async fn handle_usbmuxd<I, O>(
        &self,
        connection_id: u32,
        incoming_stream: DeviceStream<I>,
        outgoing_stream: DeviceStream<O>,
    ) -> Result<Option<IOSConnectionProtocol<I, O>>>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        O: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut incoming_stream = UsbmuxConnection::new(incoming_stream);
        let mut outgoing_stream = UsbmuxConnection::new(outgoing_stream);

        loop {
            let usbmux_message = match incoming_stream.next().await {
                Some(msg) => msg?,
                None => return Ok(None), // Connection closed
            };
            log_message(connection_id, Direction::AClientToUsbmuxd, &usbmux_message);

            let usb_request = Value::from_reader(Cursor::new(usbmux_message.payload.to_vec()))?;
            let usb_request = usb_request.into_dictionary().unwrap();
            let message_type = usb_request.get("MessageType").unwrap().as_string().unwrap();
            match message_type {
                "ListDevices" => {
                    outgoing_stream.send(usbmux_message).await?;
                    let response_msg = match outgoing_stream.next().await {
                        Some(msg) => msg?,
                        None => {
                            return Err(UsbmuxError::IOError(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "Connection closed",
                            )))
                        }
                    };

                    log_message(connection_id, Direction::UsbmuxdToAClient, &response_msg);

                    let device_list: DeviceList = UsbmuxPacket::decode(&response_msg)?;
                    {
                        let mut device_entry_store = self.device_entry_store.write().await;
                        for device in device_list.device_list.iter() {
                            if device.properties.connection_type
                                != crate::usbmux::ConnectionType::USB
                            {
                                continue;
                            }

                            println!(
                                "cached device entry {} {}",
                                device.properties.serial_number, device.device_id
                            );
                            device_entry_store
                                .insert(device.properties.serial_number.clone(), device.clone());
                        }
                    }

                    incoming_stream.send(response_msg).await?;
                }
                "ReadPairRecord" => {
                    outgoing_stream.send(usbmux_message).await?;
                    let response = match outgoing_stream.next().await {
                        Some(msg) => msg?,
                        None => {
                            return Err(UsbmuxError::IOError(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "Connection closed",
                            )))
                        }
                    };

                    log_message(connection_id, Direction::UsbmuxdToAClient, &response);

                    let pair_record_data: PairRecordData = UsbmuxPacket::decode(&response)?;
                    incoming_stream.send(response).await?;

                    let serial: &str = usb_request
                        .get("PairRecordID")
                        .unwrap()
                        .as_string()
                        .unwrap();
                    let device_entry = {
                        let device_entry_store = self.device_entry_store.read().await;
                        let device_entry = match device_entry_store.get(serial) {
                            Some(device_entry) => device_entry,
                            None => {
                                return Err(UsbmuxError::IOError(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!(
                                        "Failed to get value for {} from device_entry_store",
                                        &serial
                                    ),
                                )));
                            }
                        };
                        device_entry.clone()
                    };

                    let pair_record: PairRecord = pair_record_data.into();
                    {
                        self.pair_record_store
                            .write()
                            .await
                            .insert(device_entry.device_id, pair_record.clone());
                        info!("cached pair record {:?}", device_entry.device_id);
                    }
                }
                "Connect" => {
                    let device_id = usb_request
                        .get("DeviceID")
                        .unwrap()
                        .as_unsigned_integer()
                        .unwrap() as u32;

                    outgoing_stream.send(usbmux_message).await?;

                    let connect_response_msg = match outgoing_stream.next().await {
                        Some(msg) => msg?,
                        None => {
                            return Err(UsbmuxError::IOError(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "Connection closed",
                            )))
                        }
                    };

                    log_message(
                        connection_id,
                        Direction::UsbmuxdToAClient,
                        &connect_response_msg,
                    );

                    let connect_response: ResultType = UsbmuxPacket::decode(&connect_response_msg)?;
                    if (connect_response
                        != ResultType {
                            message_type: "Result".into(),
                            number: 0,
                        })
                    {
                        return Err(UsbmuxError::IOError(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Failed to connect",
                        )));
                    }

                    incoming_stream.send(connect_response_msg).await?;

                    return Ok(Some(IOSConnectionProtocol::LOCKDOWND {
                        device_id,
                        incoming_stream: incoming_stream.into_inner(),
                        outgoing_stream: outgoing_stream.into_inner(),
                    }));
                }
                _ => {
                    outgoing_stream.send(usbmux_message).await?;
                    let response_msg = match outgoing_stream.next().await {
                        Some(msg) => msg?,
                        None => {
                            return Err(UsbmuxError::IOError(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "Connection closed",
                            )))
                        }
                    };
                    log_message(connection_id, Direction::UsbmuxdToAClient, &response_msg);

                    incoming_stream.send(response_msg).await?;
                }
            }
        }
    }

    async fn handle_lockdownd<I, O>(
        &self,
        connection_id: u32,
        device_id: u32,
        incoming_stream: DeviceStream<I>,
        outgoing_stream: DeviceStream<O>,
    ) -> Result<Option<IOSConnectionProtocol<I, O>>>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        O: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut incoming_stream = LockdownConnection::new(incoming_stream);
        let mut outgoing_stream = LockdownConnection::new(outgoing_stream);

        loop {
            let lockdown_request = match incoming_stream.next().await {
                Some(msg) => msg?,
                None => return Ok(None), // Connection closed
            };

            log_message(
                connection_id,
                Direction::AClientToUsbmuxd,
                &lockdown_request,
            );
            outgoing_stream.send(lockdown_request).await?;

            let lockdown_response: PListPacket = match outgoing_stream.next().await {
                Some(msg) => msg?,
                None => {
                    return Err(UsbmuxError::IOError(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "Connection closed",
                    )))
                }
            };
            log_message(
                connection_id,
                Direction::UsbmuxdToAClient,
                &lockdown_response,
            );
            let value = Value::from_reader(Cursor::new(&lockdown_response.payload)).unwrap();

            incoming_stream.send(lockdown_response).await?;

            let value = value.into_dictionary().unwrap();
            match value.get("EnableSessionSSL") {
                Some(Value::Boolean(true)) => {
                    let incoming_stream = incoming_stream.into_inner();
                    let outgoing_stream = outgoing_stream.into_inner();

                    let pair_record = {
                        let pair_record_store = self.pair_record_store.read().await;
                        let (_, pair_record) = match pair_record_store.get_key_value(&device_id) {
                            Some(pair_record) => pair_record,
                            None => {
                                return Err(UsbmuxError::IOError(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!(
                                        "Failed to get value for {} from pair_record_store",
                                        &device_id
                                    ),
                                )));
                            }
                        };

                        pair_record.clone()
                    };

                    return Ok(Some(IOSConnectionProtocol::LOCKDOWND {
                        device_id,
                        incoming_stream: wrap_into_tls_server_stream(incoming_stream, &pair_record)
                            .await?,
                        outgoing_stream: wrap_into_tls_client_stream(outgoing_stream, &pair_record)
                            .await?,
                    }));
                }
                _ => {}
            }
        }
    }
}

async fn wrap_into_tls_client_stream<S>(
    stream: DeviceStream<S>,
    pair_record: &PairRecord,
) -> Result<DeviceStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let stream = match stream {
        DeviceStream::Plain(stream) => {
            crate::tls::wrap_into_tls_client_stream(stream, pair_record).await?
        }
        _ => {
            return Err(UsbmuxError::IOError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Stream is already TLS.",
            )))
        }
    };

    Ok(DeviceStream::TlsClient(stream))
}

async fn wrap_into_tls_server_stream<S>(
    stream: DeviceStream<S>,
    pair_record: &PairRecord,
) -> Result<DeviceStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let stream = match stream {
        DeviceStream::Plain(stream) => {
            crate::tls::wrap_into_tls_server_stream(stream, pair_record).await?
        }
        _ => {
            return Err(UsbmuxError::IOError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Stream is already TLS.",
            )))
        }
    };

    Ok(DeviceStream::TlsServer(stream))
}

enum Direction {
    AClientToUsbmuxd,
    UsbmuxdToAClient,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Direction::AClientToUsbmuxd => write!(f, "aclient >> usbmuxd"),
            Direction::UsbmuxdToAClient => write!(f, "usbmuxd >> aclient"),
        }
    }
}

fn log_message(connection_id: u32, direction: Direction, message: impl Debug) {
    trace!(
        "Connection: {}\n============================ {} ============================\n{:?}\n",
        connection_id,
        direction,
        message
    );
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use tokio::{self, fs};

    use super::*;

    #[ignore = "Needs to be run locally"]
    #[tokio::test]
    async fn test_proxy() -> crate::util::Result<()> {
        let listening_addr = std::env::temp_dir().join("usbmuxd");
        let connecting_addr = "/var/run/usbmuxd";
        println!("USBMUX server listening on {:?}", &listening_addr);

        let listener = tokio::net::UnixListener::bind(&listening_addr)?;

        let proxy = Arc::new(UsbmuxProxy::new());
        loop {
            let proxy = Arc::clone(&proxy);
            tokio::select! {
                a = listener.accept() => {
                    let (incoming_stream, _) = a?;
                    let outgoing_stream = tokio::net::UnixStream::connect(connecting_addr).await?;
                    tokio::spawn(async move {
                        proxy
                            .proxy(incoming_stream, outgoing_stream, 0)
                            .await
                            .unwrap();
                    });
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("Shutting down...");
                    fs::remove_file(&listening_addr).await?;
                    return Ok(());
                }
            }
        }
    }
}
