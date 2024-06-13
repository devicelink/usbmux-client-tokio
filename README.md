[![Crates.io](https://img.shields.io/crates/v/usbmux-client-tokio.svg)](https://crates.io/crates/usbmux-client-tokio)
[![Docs.rs](https://docs.rs/usbmux-client-tokio/badge.svg)](https://docs.rs/usbmux-client-tokio)
[![Build](https://github.com/devicelink/usbmux-client-tokio/actions/workflows/build.yaml/badge.svg?branch=main)](https://github.com/devicelink/usbmux-client-tokio/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# Usbmux implementation in Rust and tokio

This library contains the necessary codecs to parse usbmux and lockdown messages needed to communicate with iOS devices.

It contains a proxy implementation to connect 2 usbmux streams and a client which supports basic functionality.

# References

[Libimobiledevice](https://github.com/libimobiledevice/usbmuxd)
[The Apple Wiki](https://theapplewiki.com/wiki/Usbmux)
[Go iOS](https://github.com/danielpaulus/go-ios)

