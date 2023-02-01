use sdkms::{Error as SdkmsError, SdkmsClient};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
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

    let input = PluginInput { x: 10, y: 20 };
    let plugin_id = Uuid::from_str(&PLUGIN_ID).expect("valid uuid");
    let output: PluginOutput = client.invoke_plugin_nice(&plugin_id, &input)?;
    println!("{} + {} = {}", input.x, input.y, output.sum);
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PluginInput {
    x: i32,
    y: i32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PluginOutput {
    sum: i32,
}
