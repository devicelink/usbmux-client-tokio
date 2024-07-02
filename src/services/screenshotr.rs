use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crate::{
    lockdown::PListCodec,
    util::{Result, TlsStream},
    DeviceEntry, PairRecord, UsbmuxError,
};
use futures::{FutureExt, SinkExt, Stream};
use plist::{plist, Value};
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;

use crate::util::{connect_service, start_service};

const SCREENSHOTR_SERVICE_NAME: &str = "com.apple.mobile.screenshotr";
const DL_MESSAGE_VERSION_EXCHANGE: &str = "DLMessageVersionExchange";
const DL_MESSAGE_PROCESS_MESSAGE: &str = "DLMessageProcessMessage";

/// A seervice to take screenshot fromt he device
pub struct ScreenshotrService {
    connection: Framed<TlsStream, PListCodec>,
}

impl ScreenshotrService {
    /// Create a new screenshotr service instance
    pub async fn new(device: &DeviceEntry, pair_record: &PairRecord) -> Result<ScreenshotrService> {
        let service: crate::util::StartServiceResponse =
            start_service(device.device_id, SCREENSHOTR_SERVICE_NAME, pair_record).await?;
        let mut connection = connect_service(device.device_id, service).await?;
        let _ = exchange_version(&mut connection).await?;

        Ok(ScreenshotrService {
            connection,
        })
    }

    /// Take a screenshot from the device, returns  a PNG image
    pub async fn take_screenshot(&mut self) -> Result<Vec<u8>> {
        let request = plist!([DL_MESSAGE_PROCESS_MESSAGE, {"MessageType": "ScreenShotRequest"}])
            .try_into()?;
        self.connection.send(request).await?;

        let response =
            self.connection.next().await.ok_or_else(|| {
                crate::UsbmuxError::Error("No response from service".to_string())
            })??;

        let response: Value = response.try_into()?;
        let response = response
            .as_array()
            .ok_or(UsbmuxError::Error("Expected array".to_string()))?;

        let message_type = response
            .first()
            .ok_or(UsbmuxError::Error(
                "Expected array with at least one element".to_string(),
            ))?
            .as_string()
            .ok_or(UsbmuxError::Error("Expected string".to_string()))?;
        if message_type != DL_MESSAGE_PROCESS_MESSAGE {
            return Err(UsbmuxError::Error(format!(
                "Expected DL_MESSAGE_PROCESS_MESSAGE but got {}",
                message_type
            )));
        }

        response
            .get(1)
            .ok_or(UsbmuxError::Error(
                "Expected array with at least two elements".to_string(),
            ))?
            .as_dictionary()
            .ok_or(UsbmuxError::Error("Expected dictionary".to_string()))?
            .get("ScreenShotData")
            .ok_or(UsbmuxError::Error("Expected ScreenShotData".to_string()))?
            .as_data()
            .ok_or(UsbmuxError::Error("Expected data".to_string()))
            .map(|d| d.to_vec())
    }
}

async fn exchange_version(connection: &mut Framed<TlsStream, PListCodec>) -> Result<(u64, u64)> {
    let version = read_version(connection).await?;
    let version_exchange_request =
        plist!([DL_MESSAGE_VERSION_EXCHANGE, "DLVersionsOk", version.0]).try_into()?;
    connection.send(version_exchange_request).await?;

    let value: Value = connection
        .next()
        .await
        .ok_or_else(|| crate::UsbmuxError::Error("No response from service".to_string()))??
        .try_into()?;

    let response = value
        .as_array()
        .ok_or(UsbmuxError::Error("Expected array".to_string()))?
        .first()
        .ok_or(UsbmuxError::Error(
            "Expected array with at least one element".to_string(),
        ))?
        .as_string()
        .ok_or(UsbmuxError::Error("Expected string".to_string()))?;
    if response != "DLMessageDeviceReady" {
        return Err(UsbmuxError::Error(format!(
            "Expected DLMessageDeviceReady but got {}",
            response
        )));
    }

    Ok(version)
}

async fn read_version(connection: &mut Framed<TlsStream, PListCodec>) -> Result<(u64, u64)> {
    let value: Value = connection
        .next()
        .await
        .ok_or_else(|| crate::UsbmuxError::Error("No response from service".to_string()))??
        .try_into()?;

    let version = value
        .as_array()
        .ok_or(UsbmuxError::Error("Version is not an array".to_owned()))?;
    let type_name = version
        .first()
        .ok_or(UsbmuxError::Error("Version array is empty".to_owned()))?
        .as_string()
        .ok_or(UsbmuxError::Error("Version is not a string".to_owned()))?;
    if type_name != DL_MESSAGE_VERSION_EXCHANGE {
        return Err(UsbmuxError::Error(format!(
            "expected version exchange message but received: {}",
            type_name
        )));
    }

    let major = version
        .get(1)
        .ok_or(UsbmuxError::Error("Version array is empty".to_owned()))?
        .as_unsigned_integer()
        .ok_or(UsbmuxError::Error("Version is not a u64".to_owned()))?;

    let minor = version
        .get(2)
        .ok_or(UsbmuxError::Error("Version array is empty".to_owned()))?
        .as_unsigned_integer()
        .ok_or(UsbmuxError::Error("Version is not a u64".to_owned()))?;

    Ok((major, minor))
}

impl Stream for ScreenshotrService {
    type Item = Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Implement logic to capture a new screenshot and yield it as a stream item
        // This is a simplified example to illustrate the concept
        let screenshot: std::result::Result<Vec<u8>, UsbmuxError> =
            futures::ready!(self.take_screenshot().boxed().poll_unpin(cx));
        Poll::Ready(Some(screenshot))
    }
}

#[cfg(test)]
mod tests {
    use crate::{usbmux, ConnectionType};

    const PNG_SIGNATURE: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];

    use super::*;

    #[tokio::test]
    async fn test_new() -> crate::util::Result<()> {
        let device = usbmux()
            .await?
            .list_devices()
            .await?
            .into_iter()
            .find(|d| d.properties.connection_type == ConnectionType::Usb)
            .ok_or_else(|| crate::UsbmuxError::Error("No USB device found".to_string()))?;
        let pair_record = usbmux()
            .await?
            .read_pair_record(&device.properties.serial_number)
            .await?;

        // // Call the new function and assert the result
        let mut screenshotr = ScreenshotrService::new(&device, &pair_record).await?;
        let screenshot = screenshotr.take_screenshot().await?;

        let screenshot_signature = &screenshot[..8];
        assert_eq!(
            screenshot_signature, PNG_SIGNATURE,
            "The screenshot is not a PNG file."
        );

        let screenshot = screenshotr.try_next().await?.unwrap();
        let screenshot_signature = &screenshot[..8];
        assert_eq!(
            screenshot_signature, PNG_SIGNATURE,
            "The screenshot is not a PNG file."
        );

        Ok(())
    }
}
