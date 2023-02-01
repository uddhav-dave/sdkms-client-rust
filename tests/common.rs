#![allow(unused_imports)]
#![allow(dead_code)]

use sdkms::{api_model::*, SdkmsClient, Error as SdkmsError};
#[cfg(feature = "async")]
use simple_hyper_client::{Client as HttpClient};
#[cfg(not(feature = "async"))]
use simple_hyper_client::blocking::{Client as HttpClient};
use simple_hyper_client::HttpsConnector;
use tokio_native_tls::native_tls::{TlsConnector, Certificate};
use std::env;
use std::fs::File;
use std::io::Read;
use rand::prelude::*;
use once_cell::sync::Lazy;

static API_ENDPOINT : Lazy<String> = Lazy::new(|| {
    env::var_os("FORTANIX_API_ENDPOINT").expect("API Endpoint env var not set").into_string().unwrap()
});
static SSL_CERT: Lazy<Certificate> = Lazy::new(|| {
    fetch_cert()
});
static API_KEY: Lazy<String> = Lazy::new(|| {
    env::var_os("FORTANIX_API_KEY").expect("API Key env var not set").into_string().unwrap()
});

//We want this function to panic if the environment variables are not set
fn fetch_cert() -> Certificate {
    match env::var_os("FORTANIX_SSL_CA_CERT") {
        Some(v) => {
            let mut cert_file = File::open(v).expect("invalid path to cert");
            let mut cert_raw = Vec::new();
            cert_file.read_to_end(&mut cert_raw).expect("Cannot read certificate");
            let certificate = Certificate::from_pem(&cert_raw).expect("Failed to read certificate");
            certificate
        },
        None => panic!("SSL certificate env var not set")
    }
}

pub fn get_client() -> Result<SdkmsClient, SdkmsError> {
    let mut ssl_builder = TlsConnector::builder();
    ssl_builder.add_root_certificate(SSL_CERT.clone());
    let ssl = ssl_builder.build()?;
    let connector = HttpsConnector::new(ssl.into());
    let client = HttpClient::with_connector(connector);

    SdkmsClient::builder()
        .with_http_client(client)
        .with_api_endpoint(&API_ENDPOINT)
        .with_api_key(&API_KEY)
        .user_agent("sdkms-test-agent")
        .build()
}

pub(crate) fn get_api_key() -> String {
    API_KEY.to_string()
}

pub fn sobject_to_string(s: &Sobject) -> String {
    format!(
        "{{ {} {} group({}) enabled: {} created: {} }}",
        s.kid.map_or("?".to_owned(), |kid| kid.to_string()),
        s.name.as_ref().map(String::as_str).unwrap_or_default(),
        s.group_id.map_or("?".to_owned(), |kid| kid.to_string()),
        s.enabled,
        s.created_at.to_utc_datetime().unwrap(),
    )
}

pub fn random_name(size: usize) -> String {
    let char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    let mut s = String::with_capacity(size);
    let mut rng = thread_rng();
    for _ in 0..size {
        let r = rng.gen_range(0, char_set.len());
        s.push_str(&char_set[r..r + 1]);
    }
    s
}
