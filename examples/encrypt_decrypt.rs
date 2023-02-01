use sdkms::api_model::*;
use sdkms::{Error as SdkmsError, SdkmsClient};
use once_cell::sync::Lazy;
use std::env;

static MY_API_KEY: Lazy<String> = Lazy::new(|| {
    env::var_os("FORTANIX_API_KEY").expect("API Key env var not set").into_string().unwrap()
});
static KEY_NAME: Lazy<String> = Lazy::new(|| {
    env::var_os("FORTANIX_KEY_NAME").expect("API Key env var not set").into_string().unwrap()
});

fn main() -> Result<(), SdkmsError> {
    env_logger::init();

    let client = SdkmsClient::builder()
        .with_api_endpoint("https://sdkms.fortanix.com")
        .with_api_key(&MY_API_KEY)
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
    let encrypt_resp = client.encrypt(&encrypt_req)?;

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
    let decrypt_resp = client.decrypt(&decrypt_req)?;
    let plain = String::from_utf8(decrypt_resp.plain.into()).expect("valid utf8");
    println!("{}", plain);
    Ok(())
}
