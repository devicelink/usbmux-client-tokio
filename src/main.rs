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
use std::{os::unix::fs::PermissionsExt, sync::Arc};
use usbmux::ConnectionType;

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
enum Commands {
    /// List available devices
    #[command(subcommand)]
    App(AppCommands),
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

    let device = match args.device_serial {
        Some(device_serial) => usbmux().await?.find_device(&device_serial).await?,
        None => usbmux()
            .await?
            .list_devices()
            .await?
            .into_iter().find(|d| d.properties.connection_type == ConnectionType::Usb)
            .expect("No USB device found"),
    };
    let pair_record = usbmux()
        .await?
        .read_pair_record(&device.properties.serial_number)
        .await?;

    match args.command {
        Commands::App(AppCommands::List {
            application_type,
            show_launch_prohibited_apps,
        }) => {
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
            services::installation_proxy::uninstall(&device, &pair_record, &bundle_identifier)
                .await?;
        }
        Commands::App(AppCommands::Install { app_path }) => {
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
