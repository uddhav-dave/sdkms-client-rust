//! Run using `cargo run --example async_client --features async`
//! 
use sdkms::api_model::*;
use sdkms::SdkmsClient;
use sdkms::Error as SdkmsError;
use std::env;
use log::*;
use once_cell::sync::Lazy;

static MY_API_KEY: Lazy<String> = Lazy::new(|| {
    env::var_os("FORTANIX_API_KEY").expect("API Key env var not set").into_string().unwrap()
});
const KEY_NAME: &'static str = "AES Key";

#[tokio::main]
async fn main() -> Result<(), SdkmsError> {
    env_logger::init();

    let client = SdkmsClient::builder()
        .with_api_endpoint("https://sdkms.fortanix.com")
        .with_api_key(&MY_API_KEY)
        .user_agent("sdkms-test-agent")
        .build()?;

    let encrypt_req = EncryptRequest {
        plain: "hello, world!".as_bytes().to_owned().into(),
        alg: Algorithm::Aes,
        key: Some(SobjectDescriptor::Name(KEY_NAME.to_owned())),
        mode: Some(CryptMode::Symmetric(CipherMode::Cbc)),
        iv: None,
        ad: None,
        tag_len: None,
    };
    let encrypt_resp = client.encrypt(&encrypt_req).await?;

    let decrypt_req = DecryptRequest {
        cipher: encrypt_resp.cipher,
        iv: encrypt_resp.iv,
        key: Some(SobjectDescriptor::Name(KEY_NAME.to_owned())),
        mode: Some(CryptMode::Symmetric(CipherMode::Cbc)),
        alg: None,
        ad: None,
        tag: None,
        masked: None,
    };
    let decrypt_resp = client.decrypt(&decrypt_req).await?;
    let plain = String::from_utf8(decrypt_resp.plain.into()).expect("valid utf8");
    debug!("{}", plain);

    let client_config = client.get_client_configs().await?;
    debug!("{:?}", client_config);
    Ok(())
}