/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::*;

/// Options to use for key agreement mechanism.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum AgreeKeyMechanism {
    /// Diffie-Hellman key exchange mechanism
    DiffieHellman
}

/// Request body to perform key agreement.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgreeKeyRequest {
    /// Activation date of the agreed key
    #[serde(default)]
    pub activation_date: Option<Time>,
    /// Deactivation date of the agreed key
    #[serde(default)]
    pub deactivation_date: Option<Time>,
    /// Identifier of the private key used for agreement
    pub private_key: SobjectDescriptor,
    /// Identifier of the public key used for agreement
    pub public_key: SobjectDescriptor,
    /// Mechanism to use for key derivation.
    pub mechanism: AgreeKeyMechanism,
    /// Name of the agreed-upon key. Key names must be unique within an account.
    /// The name is ignored for transient keys.
    pub name: Option<String>,
    /// Group ID of the security group that this security object should belong to. The user or
    /// application creating this security object must be a member of this group. If no group is
    /// specified, the default group for the requesting application will be used.
    #[serde(default)]
    pub group_id: Option<Uuid>,
    /// Type of key to be derived. NB. for security reasons, you shouldn't specify anything but HMAC or Secret.
    pub key_type: ObjectType,
    /// Key size in bits. If less than the output size of the algorithm, the secret's most-significant bits will be truncated.
    pub key_size: u32,
    /// Whether the agreed key should have cryptographic operations enabled
    pub enabled: Option<bool>,
    /// Description of the agreed key
    #[serde(default)]
    pub description: Option<String>,
    /// User-defined metadata for this key stored as key-value pairs.
    #[serde(default)]
    pub custom_metadata: Option<HashMap<String,String>>,
    /// Optional array of key operations to be enabled for this security object. If not
    /// provided the service will provide a default set of key operations. Note that if you
    /// provide an empty array, all key operations will be disabled.
    #[serde(default)]
    pub key_ops: Option<KeyOperations>,
    /// State of the agreed key
    #[serde(default)]
    pub state: Option<SobjectState>,
    /// If set to true, the resulting key will be transient.
    pub transient: Option<bool>
}

/// Request body to finalise a multi-part decryption.
#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct DecryptFinalRequest {
    /// Identifier of the sobject used for finalizing multi-part decryption
    #[serde(default)]
    pub key: Option<SobjectDescriptor>,
    /// Current state of the encrypted cipher
    pub state: Blob,
    /// Tag value of the encrypted cipher. Only applicable when using GCM mode.
    #[serde(default)]
    pub tag: Option<Blob>
}

/// Final response body of a multi-part decryption.
#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct DecryptFinalResponse {
    /// Decrypted bytes
    pub plain: Blob
}

/// Request body to initialize multi-part decryption.
#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct DecryptInitRequest {
    /// Identifier of the sobject used for initializing multi-part decryption
    #[serde(default)]
    pub key: Option<SobjectDescriptor>,
    /// Algorithm used for multi-part decryption
    #[serde(default)]
    pub alg: Option<Algorithm>,
    /// Mode of multi-part decryption. Required for symmetric algorithms.
    #[serde(default)]
    pub mode: Option<CipherMode>,
    /// Initialization vector. Required for symmetric algorithms.
    #[serde(default)]
    pub iv: Option<Blob>,
    /// Authenticated data. Only applicable when using GCM mode.
    #[serde(default)]
    pub ad: Option<Blob>
}

/// Response body for initializing multi-part decryption.
#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct DecryptInitResponse {
    /// The key id is returned for non-transient keys.
    #[serde(default)]
    pub kid: Option<Uuid>,
    /// Opaque data, not to be interpreted or modified by the client and must be provided with next request.
    pub state: Blob
}

/// Request body to decrypt data using a symmetric or asymmetric key.
#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct DecryptRequest {
    /// Reference to the sobject used for decryption
    #[serde(default)]
    pub key: Option<SobjectDescriptor>,
    /// Algorithm to be used for decryption
    #[serde(default)]
    pub alg: Option<Algorithm>,
    /// Encrypted bytes
    pub cipher: Blob,
    /// Mode of decryption. Applicable for symmetric algorithms.
    #[serde(default)]
    pub mode: Option<CryptMode>,
    /// Initialization vector. Applicable for symmetric algorithms.
    #[serde(default)]
    pub iv: Option<Blob>,
    /// Authenticated data. Only applicable when using GCM mode.
    #[serde(default)]
    pub ad: Option<Blob>,
    /// Tag is only applicable when using GCM mode.
    #[serde(default)]
    pub tag: Option<Blob>,
    /// This flag is only useful with `DECRYPT` permission. When this flag is `true`,
    /// decryption returns masked output. Setting it to `false` is equivalent to not using
    /// this flag.
    /// With `MASKDECRYPT` permission, this flag is ignored.
    #[serde(default)]
    pub masked: Option<bool>
}

/// Reponse body of POST /crypto/v1/decrypt
#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct DecryptResponse {
    /// The key id of the key used to decrypt. Returned for non-transient keys.
    #[serde(default)]
    pub kid: Option<Uuid>,
    /// Decrypted bytes
    pub plain: Blob
}

/// Request body for multi-part decryption.
#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct DecryptUpdateRequest {
    /// Identifier of the sobject used for multi-part decryption
    #[serde(default)]
    pub key: Option<SobjectDescriptor>,
    /// Encrypted bytes
    pub cipher: Blob,
    /// Currrent state of the encrypted cipher
    pub state: Blob
}

/// Reponse body of multi-part decryption.
#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct DecryptUpdateResponse {
    /// Decrypted bytes
    pub plain: Blob,
    /// Current state of the multi part decrypted object. 
    /// Opaque data, not to be interpreted or modified by the client and must be provided with next request.
    pub state: Blob
}

/// Mechanism to be used when deriving a new key from an existing key.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum DeriveKeyMechanism {
    EncryptData (
        EncryptRequest
    ),
    Bip32MasterKey {
        network: Bip32Network
    },
    Bip32HardenedChild {
        index: u32
    }
}

/// Request body to derive a key.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeriveKeyRequest {
    /// Activation date of the derived key
    #[serde(default)]
    pub activation_date: Option<Time>,
    /// Deactivation date of the derived key
    #[serde(default)]
    pub deactivation_date: Option<Time>,
    /// Identifier of the sobject from which new key will be derived
    #[serde(default)]
    pub key: Option<SobjectDescriptor>,
    /// Name of the derived key. Key names must be unique within an account.
    pub name: Option<String>,
    /// Group ID of the security group that this security object should belong to. The user or
    /// application creating this security object must be a member of this group. If no group is
    /// specified, the default group for the requesting application will be used.
    #[serde(default)]
    pub group_id: Option<Uuid>,
    /// Type of key to be derived.
    pub key_type: ObjectType,
    /// Key size of the derived key in bits.
    pub key_size: u32,
    /// Mechanism to use for key derivation.
    pub mechanism: DeriveKeyMechanism,
    /// Whether the derived key should have cryptographic operations enabled.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Description for derived key
    #[serde(default)]
    pub description: Option<String>,
    /// User-defined metadata for this key stored as key-value pairs.
    #[serde(default)]
    pub custom_metadata: Option<HashMap<String,String>>,
    /// Optional array of key operations to be enabled for this security object. If not
    /// provided the service will provide a default set of key operations. Note that if you
    /// provide an empty array, all key operations will be disabled.
    #[serde(default)]
    pub key_ops: Option<KeyOperations>,
    /// State of the derived key
    #[serde(default)]
    pub state: Option<SobjectState>,
    /// If set to true, the derived key will be transient.
    #[serde(default)]
    pub transient: Option<bool>
}

/// Request to compute the hash of arbitrary data.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct DigestRequest {
    /// Hash Algorithm to compute digest
    pub alg: DigestAlgorithm,
    /// Raw binary data
    pub data: Blob
}

/// Response body of a hash operation.
#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct DigestResponse {
    /// Hashed binary output
    pub digest: Blob
}

/// Request body to finalize a multi-part encryption.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptFinalRequest {
    /// Reference to the sobject used for finalizing multi-part encryption
    #[serde(default)]
    pub key: Option<SobjectDescriptor>,
    /// Last state of the encrypted cipher
    pub state: Blob,
    /// Size of authentication tag.
    /// Tag length is only applicable when using GCM mode.
    #[serde(default)]
    pub tag_len: Option<usize>
}

/// Final response body of a multi-part encryption.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptFinalResponse {
    /// Final encrypted bytes
    pub cipher: Blob,
    /// Tag is only returned for symmetric encryption with GCM mode.
    #[serde(default)]
    pub tag: Option<Blob>
}

/// Request body to initialize multi-part encryption.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptInitRequest {
    /// Reference to the sobject used for initializing multi-part encryption
    #[serde(default)]
    pub key: Option<SobjectDescriptor>,
    /// Algorithm to be used for multipart encryption
    pub alg: Algorithm,
    /// Cipher mode of operation for symmetric multi-part encryption
    #[serde(default)]
    pub mode: Option<CipherMode>,
    /// Initialization vector
    #[serde(default)]
    pub iv: Option<Blob>,
    /// Authenticated data, required for AEAD algorithms
    #[serde(default)]
    pub ad: Option<Blob>
}

/// Response body of initializing multi-part encryption.
#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct EncryptInitResponse {
    /// Key id is returned for non-transient keys.
    #[serde(default)]
    pub kid: Option<Uuid>,
    /// Initialization vector. Only returned for symmetric encryption.
    #[serde(default)]
    pub iv: Option<Blob>,
    /// Current state of the encrypted cipher. 
    /// Opaque data, not to be interpreted or modified by the client and must be provided with next request.
    pub state: Blob
}

/// A request to encrypt data using a symmetric or asymmetric key.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct EncryptRequest {
    /// Reference to Sobject used for encryption
    #[serde(default)]
    pub key: Option<SobjectDescriptor>,
    /// Encryption Algorithm
    pub alg: Algorithm,
    /// Data bytes to be encrypted
    pub plain: Blob,
    /// Mode is required for symmetric algorithms.
    #[serde(default)]
    pub mode: Option<CryptMode>,
    /// Initialization vector is optional and will be randomly generated if not specified.
    #[serde(default)]
    pub iv: Option<Blob>,
    /// Authenticated data is only applicable when using GCM mode.
    #[serde(default)]
    pub ad: Option<Blob>,
    /// Tag length is only applicable when using GCM mode.
    #[serde(default)]
    pub tag_len: Option<usize>
}

/// Response of POST /crypto/v1/encrypt
#[derive(Default, Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct EncryptResponse {
    /// Key id is returned for non-transient keys.
    #[serde(default)]
    pub kid: Option<Uuid>,
    /// Encrypted bytes
    pub cipher: Blob,
    /// Initialization vector is only returned for symmetric encryption.
    #[serde(default)]
    pub iv: Option<Blob>,
    /// Tag is only returned for symmetric encryption with GCM mode.
    #[serde(default)]
    pub tag: Option<Blob>
}

/// Request body for continuing multi part encryption
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptUpdateRequest {
    /// Reference to the sobject used for continuing multi part encryption
    #[serde(default)]
    pub key: Option<SobjectDescriptor>,
    /// Data bytes to be encrypted
    pub plain: Blob,
    /// Last state of the encrypted cipher
    pub state: Blob
}

/// Response body of multi-part encryption.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptUpdateResponse {
    /// Encrypted bytes object from multi-part flow
    pub cipher: Blob,
    /// Current state of the encrypted cipher
    /// Opaque data, not to be interpreted or modified by the client and must be provided with next request.
    pub state: Blob
}

/// Key Format
#[derive(Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub enum KeyFormat {
    Default,
    Pkcs8
}

/// Request body for HMAC or CMAC operation.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct MacRequest {
    /// Identifier of the sobject used for HMAC/CMAC
    #[serde(default)]
    pub key: Option<SobjectDescriptor>,
    /// Hash algorithm is required for HMAC.
    #[serde(default)]
    pub alg: Option<DigestAlgorithm>,
    /// Raw binary data
    pub data: Blob
}

/// Response body of HMAC or CMAC operation.
#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct MacResponse {
    /// Key id
    #[serde(default)]
    pub kid: Option<Uuid>,
    /// MAC generated for the input data.
    pub mac: Blob
}

/// Options for mechanism to be used when transforming a key
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum TransformKeyMechanism {
    Bip32WeakChild {
        /// The index of a weak child is an integer between 0 and 2**31 - 1.
        index: u32
    }
}

/// Request body to transform a key.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransformKeyRequest {
    /// Activation date of the transformed key
    #[serde(default)]
    pub activation_date: Option<Time>,
    /// Deactivation date of the transformed key
    #[serde(default)]
    pub deactivation_date: Option<Time>,
    /// Identifier of the sobject which will be transformed
    #[serde(default)]
    pub key: Option<SobjectDescriptor>,
    /// Name of the transformed key. Key names must be unique within an account.
    pub name: Option<String>,
    /// Group ID of the group that this security object should belong to. The user or
    /// application creating this security object must be a member of this group. If no group is
    /// specified, the default group for the requesting application will be used.
    #[serde(default)]
    pub group_id: Option<Uuid>,
    /// Type of the transformed key.
    pub key_type: ObjectType,
    /// Mechanism to use for key transformation.
    pub mechanism: TransformKeyMechanism,
    /// Whether the transformed key should have cryptographic operations enabled.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Description of the transformed key
    #[serde(default)]
    pub description: Option<String>,
    /// User-defined metadata for this key stored as key-value pairs.
    #[serde(default)]
    pub custom_metadata: Option<HashMap<String,String>>,
    /// Optional array of key operations to be enabled for this security object. If not
    /// provided the service will provide a default set of key operations. Note that if you
    /// provide an empty array, all key operations will be disabled.
    #[serde(default)]
    pub key_ops: Option<KeyOperations>,
    /// State of the transformed key
    #[serde(default)]
    pub state: Option<SobjectState>,
    /// If set to true, the transformed key will be transient.
    #[serde(default)]
    pub transient: Option<bool>
}

/// Request body to perform key unwrapping.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct UnwrapKeyRequest {
    /// The wrapping key
    #[serde(default)]
    pub key: Option<SobjectDescriptor>,
    /// Algorithm to be used for unwrapping
    pub alg: Algorithm,
    /// Object type of the key being unwrapped
    pub obj_type: ObjectType,
    /// RSA-specific options for unwrapping
    #[serde(default)]
    pub rsa: Option<RsaOptions>,
    /// A serialized Security Object, previously wrapped with another key
    pub wrapped_key: Blob,
    /// Mode is required for symmetric algorithms
    #[serde(default)]
    pub mode: Option<CryptMode>,
    /// Initialization vector is required for symmetric algorithms
    #[serde(default)]
    pub iv: Option<Blob>,
    /// Authenticated data is only applicable if mode is GCM
    #[serde(default)]
    pub ad: Option<Blob>,
    /// Tag is required if mode is GCM.
    #[serde(default)]
    pub tag: Option<Blob>,
    /// Name to be given to the resulting security object if persisted
    pub name: Option<String>,
    /// Group ID of the security group that the resulting security object should belong to. The user or
    /// application creating this security object must be a member of this group. If no group is
    /// specified, the default group for the requesting application will be used
    #[serde(default)]
    pub group_id: Option<Uuid>,
    /// Whether the unwrap key should have cryptographic operations enabled
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Description of the unwrapped key
    #[serde(default)]
    pub description: Option<String>,
    /// User-defined metadata for the resulting key stored as key-value pairs.
    #[serde(default)]
    pub custom_metadata: Option<HashMap<String,String>>,
    /// Optional array of key operations to be enabled for the resulting security object. If not
    /// provided the service will provide a default set of key operations. Note that if you provide
    /// an empty array, all key operations will be disabled.
    #[serde(default)]
    pub key_ops: Option<KeyOperations>,
    /// Whether the unwrapped key should be a transient key
    #[serde(default)]
    pub transient: Option<bool>,
    /// Checksum value of the wrapped key
    #[serde(default)]
    pub kcv: Option<String>
}

/// Rquest body to verify a MAC value.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifyMacRequest {
    /// Identifier of the sobject used for MAC verification
    #[serde(default)]
    pub key: Option<SobjectDescriptor>,
    /// Algorithm is required for HMAC.
    #[serde(default)]
    pub alg: Option<DigestAlgorithm>,
    /// Bytes value over which MAC needs to be verified
    pub data: Blob,
    /// MAC to verify. Note that the previously available
    /// field `digest` is deprecated and this should be used
    /// instead.
    #[serde(default)]
    pub mac: Option<Blob>
}

/// Request body to perform key wrapping.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct WrapKeyRequest {
    /// The wrapping key.
    #[serde(default)]
    pub key: Option<SobjectDescriptor>,
    /// The key to be wrapped.
    #[serde(default)]
    pub subject: Option<SobjectDescriptor>,
    /// Id of the key to be wrapped (legacy, mutually exclusive with `subject`).
    #[serde(default)]
    pub kid: Option<Uuid>,
    /// Algorithm for key wrapping
    pub alg: Algorithm,
    /// Mode is required for symmetric algorithms.
    #[serde(default)]
    pub mode: Option<CryptMode>,
    /// Initialization vector
    #[serde(default)]
    pub iv: Option<Blob>,
    /// Authenticated data is only applicable if mode is GCM.
    #[serde(default)]
    pub ad: Option<Blob>,
    /// Tag length is required when mode is GCM.
    #[serde(default)]
    pub tag_len: Option<usize>,
    /// Key format for wrapping
    #[serde(default)]
    pub key_format: Option<KeyFormat>
}

/// Result of key wrapping operation.
#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct WrapKeyResponse {
    /// Binary object of the wrapped key
    pub wrapped_key: Blob,
    /// Initialization vector is only returned for symmetric algorithms.
    #[serde(default)]
    pub iv: Option<Blob>,
    /// Tag is only returned for symmetric algorithm with GCM mode.
    #[serde(default)]
    pub tag: Option<Blob>
}

pub struct OperationAgree;
#[allow(unused)]
impl Operation for OperationAgree {
    type PathParams = ();
    type QueryParams = ();
    type Body = AgreeKeyRequest;
    type Output = Sobject;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/agree")
    }
}

impl SdkmsClient {
    pub async fn agree(&self, req: &AgreeKeyRequest) -> Result<Sobject> {
        self.execute::<OperationAgree>(req, (), None).await
    }
    pub async fn request_approval_to_agree(
        &self, req: &AgreeKeyRequest,
        description: Option<String>) -> Result<PendingApproval<OperationAgree>> {
        self.request_approval::<OperationAgree>(req, (), None, description).await
    }
}

pub struct OperationCreateDigest;
#[allow(unused)]
impl Operation for OperationCreateDigest {
    type PathParams = ();
    type QueryParams = ();
    type Body = DigestRequest;
    type Output = DigestResponse;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/digest")
    }
}

impl SdkmsClient {
    pub async fn create_digest(&self, req: &DigestRequest) -> Result<DigestResponse> {
        self.execute::<OperationCreateDigest>(req, (), None).await
    }
}

pub struct OperationDecrypt;
#[allow(unused)]
impl Operation for OperationDecrypt {
    type PathParams = ();
    type QueryParams = ();
    type Body = DecryptRequest;
    type Output = DecryptResponse;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/decrypt")
    }
}

impl SdkmsClient {
    pub async fn decrypt(&self, req: &DecryptRequest) -> Result<DecryptResponse> {
        self.execute::<OperationDecrypt>(req, (), None).await
    }
    pub async fn request_approval_to_decrypt(
        &self, req: &DecryptRequest,
        description: Option<String>) -> Result<PendingApproval<OperationDecrypt>> {
        self.request_approval::<OperationDecrypt>(req, (), None, description).await
    }
}

pub struct OperationDecryptFinal;
#[allow(unused)]
impl Operation for OperationDecryptFinal {
    type PathParams = ();
    type QueryParams = ();
    type Body = DecryptFinalRequest;
    type Output = DecryptFinalResponse;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/decrypt/final")
    }
}

impl SdkmsClient {
    pub async fn decrypt_final(&self, req: &DecryptFinalRequest) -> Result<DecryptFinalResponse> {
        self.execute::<OperationDecryptFinal>(req, (), None).await
    }
}

pub struct OperationDecryptInit;
#[allow(unused)]
impl Operation for OperationDecryptInit {
    type PathParams = ();
    type QueryParams = ();
    type Body = DecryptInitRequest;
    type Output = DecryptInitResponse;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/decrypt/init")
    }
}

impl SdkmsClient {
    pub async fn decrypt_init(&self, req: &DecryptInitRequest) -> Result<DecryptInitResponse> {
        self.execute::<OperationDecryptInit>(req, (), None).await
    }
}

pub struct OperationDecryptUpdate;
#[allow(unused)]
impl Operation for OperationDecryptUpdate {
    type PathParams = ();
    type QueryParams = ();
    type Body = DecryptUpdateRequest;
    type Output = DecryptUpdateResponse;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/decrypt/update")
    }
}

impl SdkmsClient {
    pub async fn decrypt_update(&self, req: &DecryptUpdateRequest) -> Result<DecryptUpdateResponse> {
        self.execute::<OperationDecryptUpdate>(req, (), None).await
    }
}

pub struct OperationDerive;
#[allow(unused)]
impl Operation for OperationDerive {
    type PathParams = ();
    type QueryParams = ();
    type Body = DeriveKeyRequest;
    type Output = Sobject;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/derive")
    }
}

impl SdkmsClient {
    pub async fn derive(&self, req: &DeriveKeyRequest) -> Result<Sobject> {
        self.execute::<OperationDerive>(req, (), None).await
    }
    pub async fn request_approval_to_derive(
        &self, req: &DeriveKeyRequest,
        description: Option<String>) -> Result<PendingApproval<OperationDerive>> {
        self.request_approval::<OperationDerive>(req, (), None, description).await
    }
}

pub struct OperationEncrypt;
#[allow(unused)]
impl Operation for OperationEncrypt {
    type PathParams = ();
    type QueryParams = ();
    type Body = EncryptRequest;
    type Output = EncryptResponse;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/encrypt")
    }
}

impl SdkmsClient {
    pub async fn encrypt(&self, req: &EncryptRequest) -> Result<EncryptResponse> {
        self.execute::<OperationEncrypt>(req, (), None).await
    }
    pub async fn request_approval_to_encrypt(
        &self, req: &EncryptRequest,
        description: Option<String>) -> Result<PendingApproval<OperationEncrypt>> {
        self.request_approval::<OperationEncrypt>(req, (), None, description).await
    }
}

pub struct OperationEncryptFinal;
#[allow(unused)]
impl Operation for OperationEncryptFinal {
    type PathParams = ();
    type QueryParams = ();
    type Body = EncryptFinalRequest;
    type Output = EncryptFinalResponse;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/encrypt/final")
    }
}

impl SdkmsClient {
    pub async fn encrypt_final(&self, req: &EncryptFinalRequest) -> Result<EncryptFinalResponse> {
        self.execute::<OperationEncryptFinal>(req, (), None).await
    }
}

pub struct OperationEncryptInit;
#[allow(unused)]
impl Operation for OperationEncryptInit {
    type PathParams = ();
    type QueryParams = ();
    type Body = EncryptInitRequest;
    type Output = EncryptInitResponse;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/encrypt/init")
    }
}

impl SdkmsClient {
    pub async fn encrypt_init(&self, req: &EncryptInitRequest) -> Result<EncryptInitResponse> {
        self.execute::<OperationEncryptInit>(req, (), None).await
    }
}

pub struct OperationEncryptUpdate;
#[allow(unused)]
impl Operation for OperationEncryptUpdate {
    type PathParams = ();
    type QueryParams = ();
    type Body = EncryptUpdateRequest;
    type Output = EncryptUpdateResponse;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/encrypt/update")
    }
}

impl SdkmsClient {
    pub async fn encrypt_update(&self, req: &EncryptUpdateRequest) -> Result<EncryptUpdateResponse> {
        self.execute::<OperationEncryptUpdate>(req, (), None).await
    }
}

pub struct OperationMac;
#[allow(unused)]
impl Operation for OperationMac {
    type PathParams = ();
    type QueryParams = ();
    type Body = MacRequest;
    type Output = MacResponse;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/mac")
    }
}

impl SdkmsClient {
    pub async fn mac(&self, req: &MacRequest) -> Result<MacResponse> {
        self.execute::<OperationMac>(req, (), None).await
    }
    pub async fn request_approval_to_mac(
        &self, req: &MacRequest,
        description: Option<String>) -> Result<PendingApproval<OperationMac>> {
        self.request_approval::<OperationMac>(req, (), None, description).await
    }
}

pub struct OperationMacVerify;
#[allow(unused)]
impl Operation for OperationMacVerify {
    type PathParams = ();
    type QueryParams = ();
    type Body = VerifyMacRequest;
    type Output = VerifyResponse;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/macverify")
    }
}

impl SdkmsClient {
    pub async fn mac_verify(&self, req: &VerifyMacRequest) -> Result<VerifyResponse> {
        self.execute::<OperationMacVerify>(req, (), None).await
    }
}

pub struct OperationSign;
#[allow(unused)]
impl Operation for OperationSign {
    type PathParams = ();
    type QueryParams = ();
    type Body = SignRequest;
    type Output = SignResponse;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/sign")
    }
}

impl SdkmsClient {
    pub async fn sign(&self, req: &SignRequest) -> Result<SignResponse> {
        self.execute::<OperationSign>(req, (), None).await
    }
    pub async fn request_approval_to_sign(
        &self, req: &SignRequest,
        description: Option<String>) -> Result<PendingApproval<OperationSign>> {
        self.request_approval::<OperationSign>(req, (), None, description).await
    }
}

pub struct OperationTransform;
#[allow(unused)]
impl Operation for OperationTransform {
    type PathParams = ();
    type QueryParams = ();
    type Body = TransformKeyRequest;
    type Output = Sobject;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/transform")
    }
}

impl SdkmsClient {
    pub async fn transform(&self, req: &TransformKeyRequest) -> Result<Sobject> {
        self.execute::<OperationTransform>(req, (), None).await
    }
    pub async fn request_approval_to_transform(
        &self, req: &TransformKeyRequest,
        description: Option<String>) -> Result<PendingApproval<OperationTransform>> {
        self.request_approval::<OperationTransform>(req, (), None, description).await
    }
}

pub struct OperationUnwrap;
#[allow(unused)]
impl Operation for OperationUnwrap {
    type PathParams = ();
    type QueryParams = ();
    type Body = UnwrapKeyRequest;
    type Output = Sobject;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/unwrapkey")
    }
}

impl SdkmsClient {
    pub async fn unwrap(&self, req: &UnwrapKeyRequest) -> Result<Sobject> {
        self.execute::<OperationUnwrap>(req, (), None).await
    }
    pub async fn request_approval_to_unwrap(
        &self, req: &UnwrapKeyRequest,
        description: Option<String>) -> Result<PendingApproval<OperationUnwrap>> {
        self.request_approval::<OperationUnwrap>(req, (), None, description).await
    }
}

pub struct OperationVerify;
#[allow(unused)]
impl Operation for OperationVerify {
    type PathParams = ();
    type QueryParams = ();
    type Body = VerifyRequest;
    type Output = VerifyResponse;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/verify")
    }
}

impl SdkmsClient {
    pub async fn verify(&self, req: &VerifyRequest) -> Result<VerifyResponse> {
        self.execute::<OperationVerify>(req, (), None).await
    }
}

pub struct OperationWrap;
#[allow(unused)]
impl Operation for OperationWrap {
    type PathParams = ();
    type QueryParams = ();
    type Body = WrapKeyRequest;
    type Output = WrapKeyResponse;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/crypto/v1/wrapkey")
    }
}

impl SdkmsClient {
    pub async fn wrap(&self, req: &WrapKeyRequest) -> Result<WrapKeyResponse> {
        self.execute::<OperationWrap>(req, (), None).await
    }
    pub async fn request_approval_to_wrap(
        &self, req: &WrapKeyRequest,
        description: Option<String>) -> Result<PendingApproval<OperationWrap>> {
        self.request_approval::<OperationWrap>(req, (), None, description).await
    }
}

