#[allow(unused_imports)]
#[allow(dead_code)]

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

struct EnvDetails {
    endpoint: String, 
    api_key: String,
    certificate: Option<Certificate>
}

fn get_env_vars() -> EnvDetails {
    let endpoint = match env::var_os("FORTANIX_API_ENDPOINT") {
        Some(v) => v.into_string().unwrap(),
        None => panic!("API endpoint not set")
    };
    let api_key = match env::var_os("FORTANIX_API_KEY") {
        Some(v) => v.into_string().unwrap(),
        None => panic!("API Key not set")
    };
    let certificate = match env::var_os("FORTANIX_SSL_CA_CERT") {
        Some(v) => {
            let mut cert_file = File::open(v).expect("invalid path to cert");
            let mut cert_raw = Vec::new();
            cert_file.read_to_end(&mut cert_raw).expect("Cannot read certificate");
            let certificate = Certificate::from_pem(&cert_raw).expect("Failed to read certificate");
            Some(certificate)
        },
        None => None
    };
    
    EnvDetails{endpoint, api_key, certificate}
}

pub fn get_client() -> Result<SdkmsClient, SdkmsError> {
    let env_details = get_env_vars();

    let mut ssl_builder = TlsConnector::builder();
    if let Some(certificate) = env_details.certificate {
        ssl_builder.add_root_certificate(certificate);
    }
    let ssl = ssl_builder.build()?;
    let connector = HttpsConnector::new(ssl.into());
    let client = HttpClient::with_connector(connector);
    SdkmsClient::builder()
        .with_http_client(client)
        .with_api_endpoint(&env_details.endpoint)
        .with_api_key(&env_details.api_key)
        .user_agent("sdkms-test-agent")
        .build()
}

#[cfg(feature="async")]
pub async fn get_client_session() -> Result<SdkmsClient, SdkmsError> {
    let env_details = get_env_vars();
    get_client()?
        .authenticate_with_api_key(&env_details.api_key)
        .await
}

#[cfg(not(feature="async"))]
pub fn get_client_session() -> Result<SdkmsClient, SdkmsError> {
    let env_details = get_env_vars();
    get_client()?.authenticate_with_api_key(&env_details.api_key)
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