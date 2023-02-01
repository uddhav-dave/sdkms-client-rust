/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::*;

pub struct OperationCompleteFido2Auth;
#[allow(unused)]
impl Operation for OperationCompleteFido2Auth {
    type PathParams = ();
    type QueryParams = ();
    type Body = PublicKeyCredential<AuthenticatorAssertionResponse>;
    type Output = ();

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/session/auth/2fa/fido2")
    }
}

impl SdkmsClient {
    pub async fn complete_fido2_auth(&self, req: &PublicKeyCredential<AuthenticatorAssertionResponse>) -> Result<()> {
        self.execute::<OperationCompleteFido2Auth>(req, (), None).await
    }
}

pub struct OperationMfaNewChallenge;
#[allow(unused)]
impl Operation for OperationMfaNewChallenge {
    type PathParams = ();
    type QueryParams = MfaChallengeParams;
    type Body = ();
    type Output = MfaChallengeResponse;

    fn method() -> Method {
        Method::POST
    }
    fn path(p: <Self::PathParams as TupleRef>::Ref, q: Option<&Self::QueryParams>) -> String {
        format!("/sys/v1/session/config_2fa/new_challenge?{q}", q = q.encode())
    }
    fn to_body(body: &Self::Body) -> Option<serde_json::Value> { None }}

impl SdkmsClient {
    pub async fn mfa_new_challenge(&self, query_params: Option<&MfaChallengeParams>) -> Result<MfaChallengeResponse> {
        self.execute::<OperationMfaNewChallenge>(&(), (), query_params).await
    }
}

