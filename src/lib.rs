#![crate_type = "lib"]
#![forbid(unsafe_code)]
#![forbid(missing_debug_implementations)]
#![forbid(missing_docs)]

//! # usbmux-client-tokio
//! 
//! Example:
//! 
//! check [UsbmuxConnection](struct.UsbmuxConnection.html) to learn how to use the UsbmuxConnection

mod lockdown;
mod tls;
mod proxy;
mod usbmux;
mod util;

pub use usbmux::*;
pub use util::*;
pub use proxy::*;
pub use lockdown::*;

/// load crypto stuff
pub fn load_crypto() {
    rustls::crypto::aws_lc_rs::default_provider().install_default().unwrap();
}