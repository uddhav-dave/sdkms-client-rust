use sdkms::{api_model::*, Error as SdkmsError};

#[allow(unused_imports)]
#[allow(dead_code)]
#[path = "../common.rs"]
mod common;

const SAMPLE_KEY: &'static str = "TestKey-123";

#[cfg(feature="async")]
#[tokio::test]
async fn test_encrypt_decrypt() -> Result<(), SdkmsError> {
    let client = common::get_client().unwrap();
    let message = "hello, world!".to_string();

    let sobject = check_create_aes_key(SAMPLE_KEY).await?;
    
    let encrypt_req = EncryptRequest {
        plain: message.as_bytes().to_owned().into(),
        alg: Algorithm::Aes,
        key: Some(SobjectDescriptor::Name(SAMPLE_KEY.to_string())),
        mode: Some(CryptMode::Symmetric(CipherMode::Cbc)),
        iv: None,
        ad: None,
        tag_len: None,
    };
    let encrypt_resp = client.encrypt(&encrypt_req).await?;

    let decrypt_req = DecryptRequest {
        cipher: encrypt_resp.cipher,
        iv: encrypt_resp.iv,
        key: Some(SobjectDescriptor::Name(SAMPLE_KEY.to_string())),
        mode: Some(CryptMode::Symmetric(CipherMode::Cbc)),
        alg: None,
        ad: None,
        tag: None,
        masked: None,
    };
    let decrypt_resp = client.decrypt(&decrypt_req).await?;
    let plain = String::from_utf8(decrypt_resp.plain.into()).expect("valid utf8");
    assert_eq!(plain, message);

    client.delete_sobject(&sobject.kid.unwrap()).await?;

    Ok(())
}

#[cfg(feature="async")]
#[tokio::test]
async fn check_sessions() -> Result<(), SdkmsError> {
    let client = common::get_client_session().await?;
    assert!(client.expires_in().is_some());
    Ok(())
}

#[cfg(feature="async")]
#[tokio::test]
async fn check_client_config() -> Result<(), SdkmsError> {
    let client = common::get_client_session().await?;
    let configuration = client.get_client_configs().await;
    debug_assert!(configuration.is_ok(), "Could not fetch Client Configuration. Error {:?}", configuration);
    Ok(())
}

#[cfg(feature="async")]
async fn check_create_aes_key(name: &'static str) -> Result<Sobject, SdkmsError> {
    let client = common::get_client()?;
    let sobject_req = SobjectRequest {
        name: Some(name.to_string()),
        obj_type: Some(ObjectType::Aes),
        key_ops: Some(
            KeyOperations::ENCRYPT | KeyOperations::DECRYPT | KeyOperations::APPMANAGEABLE,
        ),
        key_size: Some(256),
        ..Default::default()
    };
    match client.create_sobject(&sobject_req).await {
        Ok(sobject) => Ok(sobject),
        Err(Error::Conflict(_)) => {
            client.get_sobject(None, &SobjectDescriptor::Name(name.to_string())).await
        },
        Err(error) => Err(error),
    }
}
