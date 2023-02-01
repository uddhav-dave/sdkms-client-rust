use sdkms::api_model::*;
use sdkms::{Error as SdkmsError, SdkmsClient};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::{thread, time};
use uuid::Uuid;
use once_cell::sync::Lazy;
use std::env;

static MY_API_KEY: Lazy<String> = Lazy::new(|| {
    env::var_os("FORTANIX_API_KEY").expect("API Key env var not set").into_string().unwrap()
});
static PLUGIN_ID: Lazy<String> = Lazy::new(|| {
    env::var_os("FORTANIX_PLUGIN_ID").expect("API Key env var not set").into_string().unwrap()
});

fn main() -> Result<(), SdkmsError> {
    env_logger::init();

    let client = SdkmsClient::builder()
        .with_api_endpoint("https://sdkms.fortanix.com")
        .with_api_key(&MY_API_KEY)
        .build()?;

    let input = PluginInput {
        data: "hello, world!".as_bytes().to_owned().into(),
        hash_alg: DigestAlgorithm::Sha256,
    };
    let input = serde_json::to_value(&input)?;
    let plugin_id = Uuid::from_str(&PLUGIN_ID).expect("valid uuid");
    let pa = client.request_approval_to_invoke_plugin(&plugin_id, &input, None)?;
    while pa.status(&client)? == ApprovalStatus::Pending {
        println!("Request is pending...");
        thread::sleep(time::Duration::from_secs(10));
    }
    let output = pa.result(&client)??;
    let output: SignResponse = serde_json::from_value(output)?;
    println!("Signature: {}", base64::encode(output.signature));
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct PluginInput {
    data: Blob,
    hash_alg: DigestAlgorithm,
}
