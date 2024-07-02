mod lockdown;
mod proxy;
mod services;
mod tls;
mod usbmux;
mod util;

use crate::proxy::UsbmuxProxy;
use crate::util::{usbmux, Result};
use clap::{Parser, Subcommand};
use services::installation_proxy::{list_apps, AppType};
use services::screenshotr::ScreenshotrService;
use std::cmp::max;
use std::{os::unix::fs::PermissionsExt, sync::Arc};
use usbmux::{ConnectionType, DeviceEntry, PairRecord};
use util::UsbmuxError;

use tokio::net::{UnixListener, UnixStream};

#[derive(Subcommand)]
enum AppCommands {
    /// List available devices
    List {
        #[clap(short, long, default_value_t=AppType::User)]
        application_type: AppType,
        #[clap(short, long, default_value_t = false)]
        show_launch_prohibited_apps: bool,
    },
    Install {
        /// Path to the app to install
        app_path: String,
    },
    /// Uninstall app with bundle_identifier
    Uninstall {
        /// Bundle identifier of the app to uninstall
        bundle_identifier: String,
    },
}

#[derive(Subcommand)]
enum DeviceCommands {
    /// List available devices
    List,
    /// Take a screenshot from the device
    Screenshot{
        /// Path to the app to install
        output: String,
    },
}

#[derive(Subcommand)]
enum Commands {
    #[command(subcommand)]
    App(AppCommands),
    #[command(subcommand)]
    Device(DeviceCommands),
    Proxy {
        source: String,
        target: String,
    },
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[structopt(short, long, env = "DEVICE_SERIAL")]
    device_serial: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    match args.command {
        Commands::Device(DeviceCommands::List) => {
            let devices: Vec<DeviceEntry> = usbmux().await?.list_devices().await?;
            let id_width = max(devices
                .iter()
                .map(|d| d.device_id.to_string().len())
                .max()
                .unwrap_or(0), 6); // Default to 8 if no devices
            let serial_width = max(devices
                .iter()
                .map(|d| d.properties.serial_number.len())
                .max()
                .unwrap_or(0), 25); // Default to 6

                println!(
                    "{:<id_width$} {:<serial_width$} ConnectionType",
                    "DeviceID", "Serial",
                    id_width = id_width + 2,
                    serial_width = serial_width + 2
                );

                devices.into_iter().for_each(|device| {
                println!(
                    "{:<id_width$} {:<serial_width$} {:?}",
                    device.device_id,
                    device.properties.serial_number,
                    device.properties.connection_type,
                    id_width = id_width + 2,
                    serial_width = serial_width + 2,
                );
            });
        }
        Commands::Device(DeviceCommands::Screenshot { output }) => {
            let (device, pair_record) = device(args.device_serial).await?;
            let mut screenshotr = ScreenshotrService::new(&device, &pair_record).await?;
            let screenshot = screenshotr.take_screenshot().await?;

            std::fs::write(output, screenshot)?;
        }
        Commands::App(AppCommands::List {
            application_type,
            show_launch_prohibited_apps,
        }) => {
            let (device, pair_record) = device(args.device_serial).await?;
            let apps = list_apps(
                &device,
                &pair_record,
                application_type,
                show_launch_prohibited_apps,
            )
            .await?;
            apps.into_iter().for_each(|app| {
                println!("{}: {}", app.cf_bundle_identifier, app.cf_bundle_name);
            });
        }
        Commands::App(AppCommands::Uninstall { bundle_identifier }) => {
            let (device, pair_record) = device(args.device_serial).await?;
            services::installation_proxy::uninstall(&device, &pair_record, &bundle_identifier)
                .await?;
        }
        Commands::App(AppCommands::Install { app_path }) => {
            let (device, pair_record) = device(args.device_serial).await?;
            services::zipconduit::install(&device, &pair_record, &app_path).await?;
        }
        Commands::Proxy { source, target } => {
            proxy(source, target).await?;
        }
    }

    Ok(())
}

pub async fn proxy(source_path: String, target_path: String) -> Result<()> {
    let mut connection_counter = 0u32;
    let listener = UnixListener::bind(&source_path)?;
    let a = listener.local_addr()?;
    let socket_path = a.as_pathname().unwrap();
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o777))?;
    println!("Forwarding from {} => {}", &source_path, &target_path);

    let usbmux_proxy: Arc<UsbmuxProxy> = Arc::new(UsbmuxProxy::new());
    loop {
        let target_path = target_path.clone();
        let (incoming_socket, _) = listener.accept().await.unwrap();
        let usbmux_proxy = Arc::clone(&usbmux_proxy);
        tokio::spawn(async move {
            let outgoing_stream = UnixStream::connect(&target_path).await.unwrap();

            usbmux_proxy
                .proxy(incoming_socket, outgoing_stream, connection_counter)
                .await
                .unwrap();
        });
        connection_counter += 1;
    }
}

async fn device(device_serial: Option<String>) -> Result<(DeviceEntry, PairRecord)> {
    let mut devices = usbmux().await?.list_devices().await?;
    devices.sort_by_key(|device| if device.properties.connection_type == ConnectionType::Usb { 0 } else { 1 });

    let device = match device_serial {
        Some(device_serial) => devices
            .into_iter()
            .find(|device| device.properties.serial_number == device_serial)
            .ok_or_else(|| {
                UsbmuxError::Error(format!(
                    "Device with serial number {} not found",
                    device_serial
                ))
            }),
        None => devices
            .into_iter()

            .next()
            .ok_or_else(|| UsbmuxError::Error("Device not found".to_owned())),
    }?;

    let pair_record = usbmux()
        .await?
        .read_pair_record(&device.properties.serial_number)
        .await?;

    Ok((device, pair_record))
}
