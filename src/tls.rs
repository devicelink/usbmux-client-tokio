use std::{
    io::Cursor,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use crate::util::{Result, UsbmuxError};
use rustls::{
    client::danger::ServerCertVerifier, pki_types::CertificateDer, ClientConfig, ServerConfig,
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::usbmux::PairRecord;

pub(crate) enum Stream<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    Plain(S),
    TlsClient(tokio_rustls::client::TlsStream<S>),
    TlsServer(tokio_rustls::server::TlsStream<S>),
}

impl<T> AsyncRead for Stream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(x) => Pin::new(x).poll_read(cx, buf),
            Stream::TlsServer(x) => Pin::new(x).poll_read(cx, buf),
            Stream::TlsClient(x) => Pin::new(x).poll_read(cx, buf),
        }
    }
}

impl<T> AsyncWrite for Stream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(x) => Pin::new(x).poll_write(cx, buf),
            Stream::TlsServer(x) => Pin::new(x).poll_write(cx, buf),
            Stream::TlsClient(x) => Pin::new(x).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(x) => Pin::new(x).poll_write_vectored(cx, bufs),
            Stream::TlsServer(x) => Pin::new(x).poll_write_vectored(cx, bufs),
            Stream::TlsClient(x) => Pin::new(x).poll_write_vectored(cx, bufs),
        }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        match self {
            Stream::Plain(x) => x.is_write_vectored(),
            Stream::TlsServer(x) => x.is_write_vectored(),
            Stream::TlsClient(x) => x.is_write_vectored(),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(x) => Pin::new(x).poll_flush(cx),
            Stream::TlsServer(x) => Pin::new(x).poll_flush(cx),
            Stream::TlsClient(x) => Pin::new(x).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(x) => Pin::new(x).poll_shutdown(cx),
            Stream::TlsServer(x) => Pin::new(x).poll_shutdown(cx),
            Stream::TlsClient(x) => Pin::new(x).poll_shutdown(cx),
        }
    }
}

pub(crate) async fn wrap_into_tls_server_stream<S: AsyncRead + AsyncWrite + Unpin>(
    stream: Stream<S>,
    pair_record: &PairRecord,
) -> Result<Stream<S>> {
    let stream = match stream {
        Stream::Plain(stream) => stream,
        _ => return Err(UsbmuxError::IOError(std::io::Error::new(std::io::ErrorKind::InvalidData, "Stream is already TLS."))),
    };

    let root_certs = certs(&mut Cursor::new(&pair_record.host_certificate))
        .filter_map(|cert| match cert {
            Ok(cert) => Some(cert),
            Err(_) => None,
        })
        .collect::<Vec<CertificateDer>>();

    let root_key = pkcs8_private_keys(&mut Cursor::new(&pair_record.host_private_key))
        .filter_map(|key| match key {
            Ok(key) => Some(key.into()),
            Err(_) => None,
        })
        .next()
        .unwrap();

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(root_certs, root_key)
        .unwrap();

    let tls_stream = TlsAcceptor::from(Arc::new(config)).accept(stream).await?;
    Ok(Stream::TlsServer(tls_stream))
}

pub(crate) async fn wrap_into_tls_client_stream<S: AsyncRead + AsyncWrite + Unpin>(
    stream: Stream<S>,
    pair_record: &PairRecord,
) -> Result<Stream<S>> {
    let stream = match stream {
        Stream::Plain(stream) => stream,
        _ => return Err(UsbmuxError::IOError(std::io::Error::new(std::io::ErrorKind::InvalidData, "Stream is already TLS."))),
    };
    
    let certs = certs(&mut Cursor::new(&pair_record.host_certificate))
        .filter_map(|cert| match cert {
            Ok(cert) => Some(cert),
            Err(_) => None,
        })
        .collect::<Vec<CertificateDer>>();

    let key = pkcs8_private_keys(&mut Cursor::new(&pair_record.host_private_key))
        .filter_map(|key| match key {
            Ok(key) => Some(key.into()),
            Err(_) => None,
        })
        .next()
        .unwrap();

    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification {}))
        .with_client_auth_cert(certs, key)
        .unwrap();
    config.enable_sni = false;

    let tls_stream = TlsConnector::from(Arc::new(config))
        .connect("apple.com".try_into().unwrap(), stream)
        .await?;
    Ok(Stream::TlsClient(tls_stream))
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::prelude::v1::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        return Ok(rustls::client::danger::ServerCertVerified::assertion());
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> std::prelude::v1::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> std::prelude::v1::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        [
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,

        ]
        .to_vec()
    }
}
