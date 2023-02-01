use sdkms::api_model::*;
use sdkms::{Error as SdkmsError, SdkmsClient};
use std::str::FromStr;
use uuid::Uuid;
use once_cell::sync::Lazy;
use std::env;

static MY_USERNAME: Lazy<String> = Lazy::new(|| {
    env::var_os("FORTANIX_USERNAME").expect("User name env var not set").into_string().unwrap()
});
static MY_PASSWORD: Lazy<String> = Lazy::new(|| {
    env::var_os("FORTANIX_PASSWORD").expect("Password env var not set").into_string().unwrap()
});
static MY_ACCT_ID: Lazy<String> = Lazy::new(|| {
    env::var_os("FORTANIX_ACCOUNT_ID").expect("Account ID env var not set").into_string().unwrap()
});

fn main() -> Result<(), SdkmsError> {
    env_logger::init();

    let client = SdkmsClient::builder()
        .with_api_endpoint("https://sdkms.fortanix.com")
        .build()?
        .authenticate_user(&MY_USERNAME, &MY_PASSWORD)?;

    let acct_id = Uuid::from_str(&MY_ACCT_ID).expect("valid uuid");
    client.select_account(&SelectAccountRequest { acct_id })?;
    let user_id = client.entity_id().unwrap();
    let user = client.get_user(&user_id)?;
    println!("User: {:#?}", user);

    client.terminate()?;
    Ok(())
}
