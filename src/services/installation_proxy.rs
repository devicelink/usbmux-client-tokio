use std::{collections::HashMap, fmt::Display, str::FromStr};

use futures::SinkExt;
use plist::{plist, Dictionary, Value};
use serde::{Deserialize, Serialize};
use tokio_stream::StreamExt;

use crate::{
    usbmux::{DeviceEntry, PairRecord},
    util::{connect_service, start_service, Result, UsbmuxError},
};

const INSTALLATON_PROXY_SERVICE_NAME: &str = "com.apple.mobile.installation_proxy";

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Command {
    command: String,
    client_options: BrowseAppsRequest,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BrowseAppsRequest {
    return_attributes: Vec<String>,
    application_type: Option<String>,
    show_launch_prohibited_apps: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BrowseReponse {
    current_index: Option<u64>,
    current_amount: Option<u64>,
    status: String,
    current_list: Option<Vec<AppInfo>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct AppInfo {
    #[serde(rename = "ApplicationDSID")]
    pub application_ds_id: Option<i32>,
    pub application_type: String,
    #[serde(rename = "CFBundleDisplayName")]
    pub cf_bundle_display_name: String,
    #[serde(rename = "CFBundleExecutable")]
    pub cf_bundle_executable: String,
    #[serde(rename = "CFBundleIdentifier")]
    pub cf_bundle_identifier: String,
    #[serde(rename = "CFBundleName")]
    pub cf_bundle_name: String,
    #[serde(rename = "CFBundleShortVersionString")]
    pub cf_bundle_short_version_string: String,
    #[serde(rename = "CFBundleVersion")]
    pub cf_bundle_version: String,
    pub container: Option<String>,
    pub entitlements: HashMap<String, Value>,
    pub environment_variables: Option<HashMap<String, String>>,
    pub minimum_os_version: Option<String>,
    pub path: String,
    pub profile_validated: Option<bool>,
    #[serde(rename = "SBAppTags")]
    pub sb_app_tags: Option<Vec<String>>,
    pub signer_identity: Option<String>,
    #[serde(rename = "UIDeviceFamily")]
    pub ui_device_family: Vec<u32>,
    #[serde(rename = "UIRequiredDeviceCapabilities")]
    pub ui_required_device_capabilities: Option<Vec<String>>,
    #[serde(rename = "UIFileSharingEnabled")]
    pub ui_file_sharing_enabled: Option<bool>,
}

/// Application type
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum AppType {
    All,
    User,
    System,
    Filesharing,
}

impl From<&str> for AppType {
    fn from(s: &str) -> Self {
        match s {
            "all" => AppType::All,
            "user" => AppType::User,
            "system" => AppType::System,
            "filesharing" => AppType::Filesharing,
            _ => AppType::User,
        }
    }
}

impl Display for AppType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppType::All => write!(f, "all"),
            AppType::User => write!(f, "user"),
            AppType::System => write!(f, "system"),
            AppType::Filesharing => write!(f, "filesharing"),
        }
    }
}

pub(crate) async fn list_apps(
    device: &DeviceEntry,
    pair_record: &PairRecord,
    application_type: AppType,
    show_launch_prohibited_apps: bool,
) -> Result<Vec<AppInfo>> {
    let service: crate::util::StartServiceResponse = start_service(
        device.device_id,
        INSTALLATON_PROXY_SERVICE_NAME,
        pair_record,
    )
    .await?;

    let application_type = match application_type {
        AppType::User => Some(AppType::User),
        AppType::System => Some(AppType::System),
        AppType::Filesharing => Some(AppType::Filesharing),
        AppType::All => None,
    };
    let mut service_connection = connect_service(device.device_id, service).await?;

    let request = plist!({
        "Command": "Browse",
        "ClientOptions": {
            "ReturnAttributes": &[
                "ApplicationDSID",
                "ApplicationType",
                "CFBundleDisplayName",
                "CFBundleExecutable",
                "CFBundleIdentifier",
                "CFBundleName",
                "CFBundleShortVersionString",
                "CFBundleVersion",
                "Container",
                "Entitlements",
                "EnvironmentVariables",
                "MinimumOSVersion",
                "Path",
                "ProfileValidated",
                "SBAppTags",
                "SignerIdentity",
                "UIDeviceFamily",
                "UIRequiredDeviceCapabilities",
                "UIFileSharingEnabled",
            ],
            "ApplicationType": application_type,
            "ShowLaunchProhibitedApps": show_launch_prohibited_apps,
        }
    })
    .try_into()?;

    service_connection.send(request).await?;

    let mut apps = Vec::new();

    loop {
        let response: BrowseReponse = match service_connection.next().await {
            Some(response) => response?.decode()?,
            None => return Err(UsbmuxError::Error("Unexpected end of file".to_string())),
        };

        apps.append(&mut response.current_list.unwrap_or(Vec::new()));

        if response.status == "Complete" {
            break;
        }
    }

    Ok(apps)
}

pub(crate) async fn uninstall(
    device: &DeviceEntry,
    pair_record: &PairRecord,
    bundle_id: &str,
) -> Result<()> {
    let service = start_service(
        device.device_id,
        INSTALLATON_PROXY_SERVICE_NAME,
        &pair_record,
    )
    .await?;

    let mut service_connection = connect_service(device.device_id, service).await?;

    let packet = plist!({
        "Command":               "Uninstall",
        "ApplicationIdentifier": bundle_id,
        "ClientOptions":         {},
    })
    .try_into()?;

    service_connection.send(packet).await?;

    loop {
        let response: Dictionary = match service_connection.next().await {
            Some(packet) => plist::from_bytes(&packet?.payload)?,
            None => return Err(UsbmuxError::Error("Unexpected end of file".to_string())),
        };

        let status = response
            .get("Status")
            .ok_or(UsbmuxError::Error("Missing Status".to_string()))?
            .as_string()
            .ok_or(UsbmuxError::Error("Status is not a string".to_string()))?;
        println!("Status: {:?}", status);
        if status == "Complete" {
            break;
        }
    }

    Ok(())
}
