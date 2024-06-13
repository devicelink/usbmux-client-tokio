mod lockdown;
mod proxy;
mod tls;
mod usbmux;
mod util;

use crate::proxy::UsbmuxProxy;
use crate::util::Result;
use std::{
    os::unix::fs::PermissionsExt,
    sync::Arc,
};

use tokio::net::{UnixListener, UnixStream};

use crate::
    usbmux::{ConnectionType, UsbmuxClient}
;

const DEVICE_SERIAL: &str = "00008101-000E20623638001E";

#[tokio::main]
async fn main() -> () {
    // check().await;
    proxy("/var/run/usbmuxd".into(), "/var/run/usbmuxx".into())
        .await
        .unwrap();
}

    pub async fn proxy(source_path: String, target_path: String) -> Result<()> {
        let mut connection_counter = 0u32;
        let listener = UnixListener::bind(&source_path)?;
        let a = listener.local_addr()?;
        let socket_path = a.as_pathname().unwrap();
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o777))?;
        println!("Listening on: {}", &target_path);

        let usbmux_proxy = Arc::new(UsbmuxProxy::new());
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

async fn check() {
    let socket_path = "/var/run/usbmuxd";
    let mut mux_client = UsbmuxClient::connect_unix(socket_path).await.unwrap();

    let device_list = mux_client.list_devices().await.unwrap();
    let device = device_list
        .iter()
        .find(|d| {
            d.properties.serial_number == DEVICE_SERIAL
                && d.properties.connection_type == ConnectionType::USB
        })
        .expect(
            format!(
                "Unable to fine device with serial number: {}",
                DEVICE_SERIAL
            )
            .as_str(),
        );

    let pair_record = mux_client.read_pair_record(DEVICE_SERIAL).await.unwrap();
    // println!("pair record: {:?}", pair_record);

    println!("{}", pretty_hex::pretty_hex(&pair_record.host_certificate));
    println!("{}", pretty_hex::pretty_hex(&pair_record.host_private_key));
}
