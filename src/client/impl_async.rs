use crate::api_model::*;
use crate::operations::*;
use super::common::*;

use super::SdkmsClient;
use std::fmt;
use std::io::Read;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use headers::HeaderMapExt;
use headers::{ContentType, HeaderMap};
use simple_hyper_client::{aggregate, Buf};
use uuid::Uuid;
use simple_hyper_client::Client as HttpClient;
use simple_hyper_client::{Method, StatusCode};
use simple_hyper_client::hyper::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};

pub struct PendingApproval<O: Operation>(Uuid, PhantomData<O>);

impl<O: Operation> fmt::Debug for PendingApproval<O> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, formatter)
    }
}

impl <O: Operation> PendingApproval<O> {

    pub fn from_request_id(request_id: Uuid) -> Self {
        PendingApproval(request_id, PhantomData)
    }

    pub fn request_id(&self) -> Uuid {
        self.0
    }

    pub async fn status(&self, sdkms: &SdkmsClient) -> Result<ApprovalStatus> {
        Ok(self.get(sdkms).await?.status)
    }

    pub async fn get(&self, sdkms:&SdkmsClient) -> Result<ApprovalRequest> {
        sdkms.get_approval_request(&self.0).await
    }

    pub async fn result(&self, sdkms:&SdkmsClient) -> Result<Result<O::Output>> {
        let result = sdkms.get_approval_request_result(&self.0).await?;
        Ok(if result.is_ok() {
            serde_json::from_value::<O::Output>(result.body).map_err(Error::EncoderError)
        } else {
            let msg: String = serde_json::from_value(result.body).map_err(Error::EncoderError)?;
            Err(Error::from_status(
                StatusCode::from_u16(result.status).unwrap(),
                msg,
            ))
        })
    }
}

impl<O: Operation> Clone for PendingApproval<O> {
    fn clone(&self) -> Self {
        PendingApproval(self.0, PhantomData)
    }
}

impl SdkmsClient {    
    // pub async fn terminate(&mut self) -> Result<()> {
    //     if let Some(Auth::Bearer(_)) = self.auth {
    //         self.json_request(Method::POST, "/sys/v1/session/terminate", None::<&()>).await?;
    //         self.auth = None;
    //     }
    //     Ok(())
    // }

    pub async fn invoke_plugin_nice<I, O>(&self, id: &Uuid, req: &I) -> Result<O>
    where
        I: Serialize,
        O: for<'de> Deserialize<'de>,
    {
        let req = serde_json::to_value(req)?;
        let output = self.execute::<OperationInvokePlugin>(&req, (id,), None).await?;
        Ok(serde_json::from_value(output)?)
    }

    pub async fn execute<O: Operation>(
        &self,
        body: &O::Body,
        p: <O::PathParams as TupleRef<'_>>::Ref,
        q: Option<&O::QueryParams>,
    ) -> Result<O::Output> {
        self.json_request(O::method(), &O::path(p, q), O::to_body(body).as_ref()).await
    }

    pub async fn request_approval<O: Operation>(
        &self,
        body: &O::Body,
        p: <O::PathParams as TupleRef<'_>>::Ref,
        q: Option<&O::QueryParams>,
        description: Option<String>,
    ) -> Result<PendingApproval<O>> {
        let request = self.create_approval_request(&ApprovalRequestRequest {
            operation: Some(O::path(p, q)),
            method: Some(format!("{}", O::method())),
            body: O::to_body(body),
            description,
        }).await?;
        Ok(PendingApproval::from_request_id(request.request_id))
    }
    
    async fn authenticate_client(&self, auth: Option<&Auth>) -> Result<Self> {
        let auth_response: AuthResponse = json_request_with_auth(
            &self.client,
            &self.api_endpoint,
            Method::POST,
            "/sys/v1/session/auth",
            auth,
            None,
            None::<&()>,
        ).await?;
        Ok(SdkmsClient {
            client: self.client.clone(),
            api_endpoint: self.api_endpoint.clone(),
            auth: Some(Auth::Bearer(auth_response.access_token.clone())),
            last_used: AtomicU64::new(now().0),
            auth_response: Some(auth_response),
            header: None,
        })
    }

    pub async fn authenticate_with_api_key(&self, api_key: &str) -> Result<Self> {
        self.authenticate_client(Some(Auth::from_api_key(api_key)).as_ref()).await
    }

    pub async fn authenticate_with_cert(&self, app_id: Option<&Uuid>) -> Result<Self> {
        self.authenticate_client(app_id.map(|id| Auth::from_user_pass(id, "")).as_ref()).await
    }

    pub async fn authenticate_app(&self, app_id: &Uuid, app_secret: &str) -> Result<Self> {
        self.authenticate_client(Some(Auth::from_user_pass(app_id, app_secret)).as_ref()).await
    }

    pub async fn authenticate_user(&self, email: &str, password: &str) -> Result<Self> {
        self.authenticate_client(Some(Auth::from_user_pass(email, password)).as_ref()).await
    }

    async fn json_request<E, D>(&self, method: Method, uri: &str, req: Option<&E>) -> Result<D>
    where
        E: Serialize,
        D: for<'de> Deserialize<'de>,
    {
        let Self {
            ref client,
            ref api_endpoint,
            ref auth,
            ..
        } = *self;
        let result = json_request_with_auth(client, api_endpoint, method, uri, auth.as_ref(), self.header.as_ref(), req).await?;
        self.last_used.store(now().0, Ordering::Relaxed);
        Ok(result)
    }
}

async fn json_request_with_auth<E, D>(
    client: &HttpClient,
    api_endpoint: &str,
    method: Method,
    path: &str,
    auth: Option<&Auth>,
    head: Option<&HeaderMap>,
    body: Option<&E>,
) -> Result<D>
where
    E: Serialize,
    D: for<'de> Deserialize<'de>,
{
    let url = format!("{}{}", api_endpoint, path);
    let mut req = client.request(method.clone(), &url)?;
    let mut headers = head.unwrap_or(&HeaderMap::new()).clone();
    if let Some(auth) = auth {
        headers.insert(AUTHORIZATION, auth.format_header());
    }
    if let Some(request_body) = body {
        headers.typed_insert(ContentType::json());
        let body = serde_json::to_string(request_body).map_err(Error::EncoderError)?;
        req = req.body(body);
    }
    req = req.headers(headers);
    match req.send().await {
        Err(e) => {
            debug!("Error {} {}", method, url);
            Err(Error::NetworkError(e))
        }
        Ok(res) if res.status().is_success() => {
            debug!("{} {} {}", res.status().as_u16(), method, url);
            let body = res.into_body();
            let body = aggregate(body).await.map_err(Into::<simple_hyper_client::Error>::into)?;
            let body: D = json_decode_reader(body.reader()).map_err(|err| Error::EncoderError(err))?;
            return Ok(body);
        }
        Ok(res) => {
            debug!("{} {} {}", res.status().as_u16(), method, url);
            let status = res.status();
            let body = aggregate(res).await.map_err(Into::<simple_hyper_client::Error>::into)?;
            let mut buffer = String::new();
            body.reader().read_to_string(&mut buffer).map_err(|err| Error::IoError(err))?;
            return Err(Error::from_status(status, buffer))
        }
    }
}
