/* Copyright (c) Fortanix, Inc.
*
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#![allow(non_camel_case_types)]

use super::*;
use crate::client::*;
use crate::operations::*;
use serde::{Deserialize, Serialize};
use simple_hyper_client::Method;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::Duration;
use std::net::IpAddr;
use strum::EnumIter;
use uuid::Uuid;
use openapiv3::OpenAPI;

pub use crate::generated::*;
use crate::operations::UrlEncode;

impl CryptMode {
    pub fn rsa_oaep(hash: DigestAlgorithm) -> Self {
        CryptMode::Rsa(RsaEncryptionPadding::Oaep {
            mgf: Mgf::Mgf1 { hash },
        })
    }
}

impl SignatureMode {
    pub fn rsa_pss(hash: DigestAlgorithm) -> Self {
        SignatureMode::Rsa(RsaSignaturePadding::Pss {
            mgf: Mgf::Mgf1 { hash },
        })
    }
}

// Fixes

impl Default for SobjectEncoding {
    fn default() -> Self {
        SobjectEncoding::Json
    }
}

impl Default for RsaOptions {
    fn default() -> Self {
        RsaOptions {
            key_size: None,
            public_exponent: None,
            encryption_policy: None,
            signature_policy: None,
            minimum_key_length: None,
        }
    }
}

impl ToString for AppRole {
    fn to_string(&self) -> String {
        match *self {
            AppRole::Admin => "admin".to_string(),
            AppRole::Crypto => "app".to_string(),
        }
    }
}

impl ToString for ObjectType {
    fn to_string(&self) -> String {
        match *self {
            ObjectType::Aes => "AES".to_string(),
            ObjectType::Des => "DES".to_string(),
            ObjectType::Des3 => "DES3".to_string(),
            ObjectType::Rsa => "RSA".to_string(),
            ObjectType::Dsa => "DSA".to_string(),
            ObjectType::Ec => "EC".to_string(),
            ObjectType::Opaque => "OPAQUE".to_string(),
            ObjectType::Hmac => "HMAC".to_string(),
            ObjectType::Secret => "SECRET".to_string(),
            ObjectType::Seed => "SEED".to_string(),
            ObjectType::Round5Beta => "ROUND5BETA".to_string(),
            ObjectType::LedaBeta => "LEDABETA".to_string(),
            ObjectType::Lms => "LMS".to_string(),
            ObjectType::Certificate => "CERTIFICATE".to_string(),
            ObjectType::Pbe => "PBE".to_string(),
            ObjectType::Aria => "ARIA".to_string(),
            ObjectType::Kcdsa => "KCDSA".to_string(),
            ObjectType::EcKcdsa => "ECKCDSA".to_string(),
            ObjectType::Bip32 => "BIP32".to_string(),
            ObjectType::Bls => "BLS".to_string(),
        }
    }
}

impl fmt::Display for SobjectEncoding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SobjectEncoding::Json => write!(f, "json"),
            SobjectEncoding::Value => write!(f, "value"),
        }
    }
}

impl fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ApprovalStatus::Pending => write!(f, "PENDING"),
            ApprovalStatus::Approved => write!(f, "APPROVED"),
            ApprovalStatus::Denied => write!(f, "DENIED"),
            ApprovalStatus::Failed => write!(f, "FAILED"),
        }
    }
}

impl fmt::Display for MfaProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
       match *self {
            MfaProtocol::U2f => write!(f, "U2f"),
            MfaProtocol::Fido2 => write!(f, "Fido2"),
        }
    }
}

impl Default for MfaProtocol {
    fn default() -> Self {
        MfaProtocol::Fido2
    }
}

impl Default for AppSort {
    fn default() -> Self {
        AppSort::ByAppId {
            order: Order::Ascending,
            start: None,
        }
    }
}

impl Default for RoleSort {
    fn default() -> Self {
        RoleSort::ByRoleId { order: Order::Ascending, start: None }
    }
}

impl Default for SobjectSort {
    fn default() -> Self {
        SobjectSort::ByKid {
            order: Order::Ascending,
            start: None,
        }
    }
}

impl Default for PluginSort {
    fn default() -> Self {
        PluginSort::ByPluginId {
            order: Order::Ascending,
            start: None,
        }
    }
}

impl Default for UserSort {
    fn default() -> Self {
        UserSort::ByUserId {
            order: Order::Ascending,
            start: None,
        }
    }
}

impl Default for AccountSort {
    fn default() -> Self {
        AccountSort::ByAccountId { order: Order::default()}
    }
}

impl Default for AppRole {
    fn default() -> Self {
        AppRole::Crypto
    }
}

impl Default for SubscriptionType {
    fn default() -> SubscriptionType {
        SubscriptionType::Trial { expires_at: None }
    }
}

impl std::cmp::Eq for TepSchema {}
