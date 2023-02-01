/* Copyright (c) Fortanix, Inc.
*
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::api_model::*;
use headers::{HeaderValue, HeaderMap};
use serde::Deserialize;
use simple_hyper_client::hyper::header::*;

#[cfg(feature = "async")]
use simple_hyper_client::{Client as HttpClient};
#[cfg(not(feature = "async"))]
use simple_hyper_client::blocking::{Client as HttpClient};

use simple_hyper_client::{Bytes};
use uuid::Uuid;

use std::convert::TryInto;
use anyhow::Context;
use std::fmt;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_API_ENDPOINT: &'static str = "https://sdkms.fortanix.com";

pub type Result<T> = ::std::result::Result<T, Error>;

pub enum Auth {
    Basic(String),
    Bearer(String),
}

impl Auth {
    pub fn from_api_key(api_key: &str) -> Self {
        Auth::Basic(api_key.to_owned())
    }

    pub fn from_user_pass<T: fmt::Display>(username: T, password: &str) -> Self {
        Auth::Basic(base64::encode(format!("{}:{}", username, password)))
    }

    pub fn format_header(&self) -> Result<HeaderValue> {
        let value = match *self {
            Auth::Basic(ref basic) => format!("Basic {}", basic),
            Auth::Bearer(ref bearer) => format!("Bearer {}", bearer),
        };
        let bytes = Bytes::from(value);
        Ok(HeaderValue::from_maybe_shared(bytes).context("invalid characters in auth header")?)
    }
}

/// A builder for [`SdkmsClient`]
pub struct SdkmsClientBuilder {
    client: Option<HttpClient>,
    api_endpoint: Option<String>,
    auth: Option<Auth>,
    headers: Option<HeaderMap>,
}

impl SdkmsClientBuilder {
    /// This can be used to customize the underlying HTTP client if desired.
    pub fn with_http_client(mut self, client: HttpClient) -> Self {
        self.client = Some(client);
        self
    }

    /// This can be used to set a default user_agent
    pub fn user_agent<V>(mut self, value: V) -> Self
    where
        V: TryInto<HeaderValue>,
    {
        let mut header = self.headers.unwrap_or(HeaderMap::new());
        match value.try_into() {
            Ok(value) => {
                header.append(USER_AGENT, value);
            },
            Err(_) => panic!(),
        }
        self.headers = Some(header);
        self
    }

    /// This can be used to set the API endpoint. Otherwise the [default endpoint] is used.
    pub fn with_api_endpoint(mut self, api_endpoint: &str) -> Self {
        self.api_endpoint = Some(api_endpoint.to_owned());
        self
    }

    /// This can be used to make API calls without establishing a session.
    /// The API key will be passed along as HTTP Basic auth header on all API calls.
    pub fn with_api_key(mut self, api_key: &str) -> Self {
        self.auth = Some(Auth::from_api_key(api_key));
        self
    }

    /// This can be used to restore an established session.
    pub fn with_access_token(mut self, access_token: &str) -> Self {
        self.auth = Some(Auth::Bearer(access_token.to_owned()));
        self
    }

    /// Build [`SdkmsClient`]
    pub fn build(self) -> Result<SdkmsClient> {
        let client = match self.client {
            Some(client) => client,
            None => {
                #[cfg(feature = "native-tls")]
                {
                    use simple_hyper_client::HttpsConnector;
                    use tokio_native_tls::native_tls::TlsConnector;

                    let ssl = TlsConnector::new()?;
                    let connector = HttpsConnector::new(ssl.into());
                    HttpClient::with_connector(connector)
                }
                #[cfg(not(feature = "native-tls"))]
                panic!("You should either provide an HTTP Client or compile this crate with native-tls feature");
            }
        };

        let header = match self.headers {
            None => None,
            _ => self.headers
        };

        Ok(SdkmsClient {
            client,
            api_endpoint: self
                .api_endpoint
                .unwrap_or_else(|| DEFAULT_API_ENDPOINT.to_owned()),
            auth: self.auth,
            last_used: AtomicU64::new(0),
            auth_response: None,
            header,
        })
    }
}

/// A client session with DSM.
///
/// REST APIs are exposed as methods on this type. Communication with DSM API endpoint is protected with TLS and this
/// type uses [`simple_hyper_client::blocking::Client`] along with [`tokio_native_tls::TlsConnector`] for HTTP/TLS.
///
/// When making crypto API calls using an API key, it is possible to pass the API key as an HTTP Basic Authorization
/// header along with each request. This can be achieved by setting the API key using
/// [`SdkmsClientBuilder::with_api_key()`]. Note that some features, e.g. transient keys, may not be available when
/// using this authentication method. To be able to use such features, you can establish a session using any of the
/// following methods:
/// - [`authenticate_with_api_key()`](#method.authenticate_with_api_key)
/// - [`authenticate_with_cert()`](#method.authenticate_with_cert)
/// - [`authenticate_app()`](#method.authenticate_app)
///
/// Note that certain non-cryptographic APIs require a user session, which can be established using
/// [`authenticate_user()`](#method.authenticate_user). This includes many APIs such as:
/// - [`create_group()`](#method.create_group)
/// - [`create_app()`](#method.create_app)
/// - ...
///
/// Also note that a user session is generally not permitted to call crypto APIs. In case your current authorization
/// is not appropriate for a particular API call, you'll get an error to that effect from DSM.
///
/// Certain APIs are "approvable", i.e. they can be subject to an approval policy. In such cases there are two methods
/// on [`SdkmsClient`], e.g. [`encrypt()`] / [`request_approval_to_encrypt()`]. Whether or not you need to call
/// [`request_approval_to_encrypt()`] depends on the approval policy that is applicable to the security object being
/// used in your request. You can find out if a particular request is subject to an approval policy by first calling
/// the regular API, e.g. [`encrypt()`] and checking if the response indicates that an approval request is needed at
/// which point you can call [`request_approval_to_encrypt()`]. There is an example of how to do this in
/// [the repository](https://github.com/fortanix/sdkms-client-rust/blob/master/examples/approval_request.rs).
///
/// [`simple_hyper_client::blocking::Client`]: https://docs.rs/simple-hyper-client/0.1.0/simple_hyper_client/blocking/struct.Client.html
/// [`tokio_native_tls::TlsConnector`]: https://docs.rs/tokio-native-tls/0.3.0/tokio_native_tls/struct.TlsConnector.html
/// [`SdkmsClientBuilder::with_api_key()`]: ./struct.SdkmsClientBuilder.html#method.with_api_key
/// [`SdkmsClient`]: ./struct.SdkmsClient.html
/// [`encrypt()`]: #method.encrypt
/// [`request_approval_to_encrypt()`]: #method.request_approval_to_encrypt
pub struct SdkmsClient {
    pub(super) auth: Option<Auth>,
    pub(super) api_endpoint: String,
    pub(super) client: HttpClient,
    pub(super) last_used: AtomicU64, // Time.0
    pub(super) auth_response: Option<AuthResponse>,
    pub(super) header: Option<HeaderMap>,
}

impl SdkmsClient {
    pub fn builder() -> SdkmsClientBuilder {
        SdkmsClientBuilder {
            client: None,
            api_endpoint: None,
            auth: None,
            headers: None,
        }
    }

    pub fn api_endpoint(&self) -> &str {
        &self.api_endpoint
    }

    pub fn auth_response(&self) -> Option<&AuthResponse> {
        self.auth_response.as_ref()
    }

    pub fn entity_id(&self) -> Option<Uuid> {
        self.auth_response().map(|ar| ar.entity_id)
    }

    pub fn has_session(&self) -> bool {
        match self.auth {
            Some(Auth::Bearer(_)) => true,
            _ => false,
        }
    }
}

impl Drop for SdkmsClient {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

impl SdkmsClient {
    pub fn expires_in(&self) -> Option<u64> {
        let expires_at = self.last_used.load(Ordering::Relaxed)
            + self.auth_response().map_or(0, |ar| ar.expires_in as u64);
        expires_at.checked_sub(now().0)
    }
}

pub(super) fn json_decode_reader<R: Read, T: for<'de> Deserialize<'de>>(
    rdr: R,
) -> serde_json::Result<T> {
    match serde_json::from_reader(rdr) {
        // When the body of the response is empty, attempt to deserialize null value instead
        Err(ref e) if e.is_eof() && e.line() == 1 && e.column() == 0 => {
            serde_json::from_value(serde_json::Value::Null)
        }
        v => v,
    }
}

pub(super) fn now() -> Time {
    Time(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Invalid system time")
            .as_secs(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    #[test]
    fn client_is_send_and_sync() {
        assert_send::<SdkmsClient>();
        assert_sync::<SdkmsClient>();

        assert_send::<SdkmsClientBuilder>();
        assert_sync::<SdkmsClientBuilder>();
    }
}
