use async_zip::tokio::read::seek::ZipFileReader;
use futures::SinkExt;
use futures::StreamExt;
use plist::plist;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncRead;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio_util::codec::Framed;
use tokio_util::compat::FuturesAsyncReadCompatExt;

use crate::lockdown::PListCodec;
use crate::lockdown::PListPacket;
use crate::usbmux::DeviceEntry;
use crate::usbmux::PairRecord;
use crate::util::connect_service;
use crate::util::start_service;
use crate::util::{Result, UsbmuxError};
use hex::FromHex;
use std::io::Cursor;

const META_INF_FILE_NAME: &str = "com.apple.ZipMetadata.plist";
const ZIPCONDUIT_SERVICE_NAME: &str = "com.apple.streaming_zip_conduit";

const EXTRA_BYTES: &str = "55540D00 07F3A2EC 60F6A2EC 60F3A2EC 6075780B 000104F5 01000004 14000000";

fn get_extra_bytes() -> Vec<u8> {
    let hex_string = EXTRA_BYTES.replace(" ", "");
    let bytes = Vec::from_hex(hex_string).expect("Failed to parse hex string");
    bytes
}

const CENTRAL_DIRECTORY_HEADER: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];

struct ZipHeader {
    signature: u32,
    version: u16,
    general_purpose_bit_flags: u16,
    compression_method: u16,
    last_modified_time: u16,
    last_modified_date: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    file_name_length: u16,
    extra_field_length: u16,
}

impl ZipHeader {
    fn new_zip_header<S: Into<String>>(
        name: S,
        size: u32,
        crc32: u32,
        extra_field_length: u16,
    ) -> Self {
        Self {
            signature: 0x04034b50,
            version: 20,
            general_purpose_bit_flags: 0,
            compression_method: 0,
            last_modified_time: 0xBDEF,
            last_modified_date: 0x52EC,
            crc32: crc32,
            compressed_size: size,
            uncompressed_size: size,
            file_name_length: name.into().len() as u16,
            extra_field_length,
        }
    }

    fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.signature.to_le_bytes());
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.general_purpose_bit_flags.to_le_bytes());
        bytes.extend_from_slice(&self.compression_method.to_le_bytes());
        bytes.extend_from_slice(&self.last_modified_time.to_le_bytes());
        bytes.extend_from_slice(&self.last_modified_date.to_le_bytes());
        bytes.extend_from_slice(&self.crc32.to_le_bytes());
        bytes.extend_from_slice(&self.compressed_size.to_le_bytes());
        bytes.extend_from_slice(&self.uncompressed_size.to_le_bytes());
        bytes.extend_from_slice(&self.file_name_length.to_le_bytes());
        bytes.extend_from_slice(&self.extra_field_length.to_le_bytes());
        bytes
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
enum ZipConduitResponse {
    #[serde(rename_all = "PascalCase")]
    Status(String),
    #[serde(rename_all = "PascalCase")]
    InstallProgressDict {
        percent_complete: i32,
        status: String,
        error: Option<String>,
    },
}

pub(crate) async fn install(
    device: &DeviceEntry,
    pair_record: &PairRecord,
    ipa: impl AsRef<Path>,
) -> Result<()> {
    let service: crate::util::StartServiceResponse =
        start_service(device.device_id, ZIPCONDUIT_SERVICE_NAME, pair_record).await?;

    let mut service_connection = connect_service(device.device_id, service).await?;

    let mut file = BufReader::new(File::open(&ipa).await?);
    let mut zip = ZipFileReader::with_tokio(&mut file)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let file = zip.file();
    let (file_count, total_bytes_uncompressed) =
        file.entries().iter().fold((0, 0), |(count, size), entry| {
            (count + 1, size + entry.uncompressed_size())
        });

    let file_name = &ipa
        .as_ref()
        .file_name()
        .map(|s| s.to_string_lossy())
        .ok_or(UsbmuxError::Error("Failed to get file name".to_string()))?;

    let init = plist!({
        "InstallOptionsDictionary": {
            "DisableDeltaTransfer": 1,
            "InstallDeltaTypeKey": "InstallDeltaTypeSparseIPAFiles".to_string(),
            "IsUserInitiated": 1,
            "PackageType": "Customer".to_string(),
            "PreferWifi": 1,
        },
        "InstallTransferredDirectory": 1,
        "MediaSubdir": format!("PublicStaging/{}", &file_name),
        "UserInitiatedTransfer": 1})
    .try_into()?;
    service_connection.send(init).await?;

    let mut connection = service_connection.into_inner();

    let file_name = "META-INF/".to_string();
    let extra_bytes = get_extra_bytes();
    add_file(
        &mut connection,
        file_name,
        0,
        0,
        &extra_bytes,
        Cursor::new(vec![]),
    )
    .await?;

    let meta_inf: PListPacket = plist!({
        "RecordCount": 2 + file_count,
        "StandardDirectoryPerms": 16877,
        "StandardFilePerms": -32348,
        "TotalUncompressedBytes": total_bytes_uncompressed,
        "Version": 2,
    })
    .try_into()?;

    let crc32 = crc32fast::hash(meta_inf.payload.as_slice());

    let file_name = format!("META-INF/{}", META_INF_FILE_NAME);
    let file_size = meta_inf.payload.len() as u32;

    add_file(
        &mut connection,
        file_name,
        file_size,
        crc32,
        &extra_bytes,
        Cursor::new(meta_inf.payload),
    )
    .await?;

    for index in 0..file.entries().len() {
        let reader = zip.reader_with_entry(index).await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Unable to read from zip entry: {}", e),
            )
        })?;
        let entry: &async_zip::ZipEntry = reader.entry();
        let file_name = entry.filename().clone().into_string().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Unable to convert zip string to string: {}", e),
            )
        })?;
        let file_size = entry.uncompressed_size();
        let crc32 = entry.crc32();

        add_file(
            &mut connection,
            file_name,
            file_size as u32,
            crc32,
            &extra_bytes,
            reader.compat(),
        )
        .await?;
    }

    connection.write_all(&CENTRAL_DIRECTORY_HEADER).await?;

    let mut service_connection = Framed::new(connection, PListCodec::new());

    loop {
        let response = match service_connection.next().await {
            Some(packet) => packet?.payload,
            None => return Err(UsbmuxError::Error("Unexpected end of file".to_string())),
        };

        let response: ZipConduitResponse = plist::from_bytes(&response)?;
        match response {
            ZipConduitResponse::Status(status) => {
                println!("Done installing app");
                if status == "DataComplete" {
                    return Ok(());
                }
            }
            ZipConduitResponse::InstallProgressDict {
                percent_complete,
                status,
                error,
            } => match error {
                Some(e) => {
                    return Err(UsbmuxError::Error(e));
                }
                None => {
                    println!("Progress: {}% - {}", percent_complete, status,);
                }
            },
        }
    }
}

async fn add_file<R: AsyncRead + Unpin + Sized>(
    connection: &mut crate::util::TlsStream,
    file_name: String,
    file_size: u32,
    crc32: u32,
    extra_bytes: &Vec<u8>,
    mut reader: R,
) -> Result<()> {
    let file_header =
        ZipHeader::new_zip_header(&file_name, file_size, crc32, extra_bytes.len() as u16);
    connection.write_all(&file_header.to_bytes()).await?;
    connection.write_all(&file_name.as_bytes()).await?;
    connection.write_all(extra_bytes).await?;
    tokio::io::copy(&mut reader, connection).await?;
    Ok(())
}
