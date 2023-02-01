use super::*;

use serde::de::Error as DeserializeError;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt::Debug;
use serde::de::Unexpected;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
/// Contains the attributes that are returned to the caller when a new
/// credential is created, or a new assertion is requested.
pub struct PublicKeyCredential<T>
where
    T: Debug + Clone + Eq + PartialEq,
{
    /// Credential's identifier.
    pub id: Base64<UrlSafe>,

    /// Type of credential.
    pub r#type: PublicKeyCredentialType,

    /// Can be [`AuthenticatorAttestationResponse`] or [`AuthenticatorAssertionResponse`].
    pub response: T,

    /// This field contains client extension output entries produced
    /// by the extension’s client extension processing.
    pub get_client_extension_results: Option<AuthenticationExtensionsClientOutputs>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialEntity<T>
where
    T: Debug + Clone + Eq + PartialEq,
{
    /// Name of the entity.
    pub name: String,

    #[serde(flatten)]
    /// Can be relying party or user.
    pub entity: T,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum COSEAlgorithmIdentifier {
    /// ECDSA w/ SHA-256
    /// https://datatracker.ietf.org/doc/draft-ietf-cose-rfc8152bis-algs/12/
    Es256 = -7,
}

impl Serialize for COSEAlgorithmIdentifier {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer
    {
        serializer.serialize_i64(*self as i64)
    }
}

impl<'de> Deserialize<'de> for COSEAlgorithmIdentifier {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>
    {
        let value: i64 = Deserialize::deserialize(deserializer)?;

        Ok(match value {
            -7 => COSEAlgorithmIdentifier::Es256,
            value => return Err(D::Error::invalid_value(
                Unexpected::Signed(value),
                &"a signing algo value from IANA COSE Algorithms registry that is supported by DSM"
            )),
        })
    }
}
