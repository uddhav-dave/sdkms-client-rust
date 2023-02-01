/* Copyright (c) Fortanix, Inc.
*
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use chrono::prelude::*;
use serde::de::Error as DeserializeError;
use serde::ser::Error as SerializeError;
use serde::ser::SerializeSeq;
use serde::ser::SerializeStruct;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use simple_hyper_client::StatusCode;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use std::time::SystemTime;
use std::{fmt, io};
use time::format_description::FormatItem;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};
#[cfg(feature = "native-tls")]
use tokio_native_tls::native_tls;
use uuid::Uuid;
use rustc_serialize::base64::{ToBase64, URL_SAFE, FromBase64};
use simple_hyper_client::hyper::Method;

mod fido;
mod approval_request;
mod app;
mod crypto;
mod error;
mod key_mgmt;
mod plugin;
mod session;
mod generated;
mod log;

pub use self::generated::*;
pub use self::fido::*;
pub use self::approval_request::*;
pub use self::app::*;
pub use self::crypto::*;
pub use self::error::*;
pub use self::key_mgmt::*;
pub use self::plugin::*;
pub use self::session::*;
pub use self::log::*;

use crate::operations::UrlEncode;
/// Arbitrary binary data that is serialized/deserialized to/from base 64 string.
#[derive(Default, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Blob(Vec<u8>);

impl From<Vec<u8>> for Blob {
    fn from(d: Vec<u8>) -> Self {
        Blob(d)
    }
}

impl From<String> for Blob {
    fn from(s: String) -> Self {
        Blob(s.into_bytes())
    }
}

impl From<Base64<UrlSafe>> for Blob {
    fn from(input: Base64<UrlSafe>) -> Self {
        Blob(input.into_inner())
    }
}


impl<'a> From<&'a str> for Blob {
    fn from(s: &str) -> Self {
        Blob(s.as_bytes().to_owned())
    }
}

impl From<Blob> for Vec<u8> {
    fn from(d: Blob) -> Self {
        d.0
    }
}

impl Deref for Blob {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Blob {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Serialize for Blob {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Blob {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'a> serde::de::Visitor<'a> for Visitor {
            type Value = Blob;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "base64-encoded string")
            }

            fn visit_str<E: de::Error>(self, string: &str) -> Result<Blob, E> {
                Ok(Blob(base64::decode(string).map_err(|_| {
                    de::Error::invalid_value(de::Unexpected::Str(string), &"base64 encoded string")
                })?))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

impl AsRef<[u8]> for Blob {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ToString for Blob {
    fn to_string(&self) -> String {
        base64::encode(&self.0)
    }
}

pub type Name = String;
pub type Email = String;

/// `Time` stores the number of seconds since Unix epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Default)]
pub struct Time(pub u64);

static ISO_8601_FORMAT: &[FormatItem<'_>] =
    format_description!("[year][month][day]T[hour][minute][second]Z");

impl Serialize for Time {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let utc = self
            .to_utc_datetime()
            .map_err(|e| S::Error::custom(e.to_string()))?;
        let s = utc
            .format(ISO_8601_FORMAT)
            .map_err(|e| S::Error::custom(e.to_string()))?;
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for Time {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(deserializer)?;
        let t = PrimitiveDateTime::parse(&s, ISO_8601_FORMAT).map_err(|e| {
            D::Error::custom(format!("expected date/time in ISO-8601 format: {}", e))
        })?;

        Time::try_from(t.assume_utc()).map_err(|e| D::Error::custom(e))
    }
}

pub fn serialize_time_esformat<S: Serializer>(t: &Time, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&t.to_esformat().ok_or_else(|| S::Error::custom("date/time value too far into the future"))?)
}

pub fn deserialize_time_esformat<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Time, D::Error> {
    let s: String = Deserialize::deserialize(deserializer)?;
    Time::from_esformat(&s).map_err(|e| match e {
        InvalidTime::ParseError(_) => D::Error::custom(format!("invalid value \"{}\", expected date/time in ISO 8601 format", s)),
        other => D::Error::custom(format!("invalid date/time \"{}\": {}", s, other)),
    })
}

impl Time {
    const ES_FORMAT: &'static str = "%Y-%m-%dT%H:%M:%SZ";

    pub fn now() -> Self {
        let t = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        Self(t.as_secs())
    }

    pub fn to_utc_datetime(&self) -> Result<OffsetDateTime, TimeOutOfRange> {
        if self.0 > i64::MAX as u64 {
            return Err(TimeOutOfRange::TooLarge);
        }
        OffsetDateTime::from_unix_timestamp(self.0 as i64).map_err(|_| TimeOutOfRange::TooLarge)
    }

    pub fn from_esformat(time: &str) -> Result<Self, InvalidTime> {
        let utc = Utc.datetime_from_str(time, Time::ES_FORMAT)?;
        Time::try_from(utc.timestamp())
    }

    pub fn to_esformat(&self) -> Option<String> {
        self.to_datetime().map(|utc| utc.format(Time::ES_FORMAT).to_string())
    }

    pub fn to_datetime(&self) -> Option<DateTime<Utc>> {
        if self.0 > i64::MAX as u64 {
            // otherwise we end up with a date before Unix epoch since
            // `self.0 as i64` would be negative.
            return None;
        }
        Utc.timestamp_opt(self.0 as i64, 0).single()
    }

}

impl TryFrom<OffsetDateTime> for Time {
    type Error = TimeOutOfRange;

    fn try_from(t: OffsetDateTime) -> Result<Self, Self::Error> {
        if t.unix_timestamp() < 0 {
            return Err(TimeOutOfRange::BeforeUnixEpoch);
        }
        Ok(Time(t.unix_timestamp() as u64))
    }
}

impl TryFrom<i64> for Time {
    type Error = InvalidTime;

    fn try_from(t: i64) -> Result<Self, Self::Error> {
        if t < 0 { Err(InvalidTime::BeforeUnixEpoch) } else { Ok(Time(t as u64)) }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum InvalidTime {
    ParseError(chrono::ParseError),
    BeforeUnixEpoch,
    TooFarIntoFuture,
}

impl From<chrono::ParseError> for InvalidTime {
    fn from(err: chrono::ParseError) -> Self {
        InvalidTime::ParseError(err)
    }
}

impl fmt::Display for InvalidTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidTime::ParseError(err) => write!(f, "{}", err),
            InvalidTime::BeforeUnixEpoch => write!(f, "date/time values before 1970-01-01 00:00:00 UTC are not accepted"),
            InvalidTime::TooFarIntoFuture => write!(f, "date/time value lies too far into the future"),
        }
    }
}

impl std::error::Error for InvalidTime {}

#[derive(Debug)]
pub enum TimeOutOfRange {
    BeforeUnixEpoch,
    TooLarge,
}

impl fmt::Display for TimeOutOfRange {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use TimeOutOfRange::*;
        match *self {
            BeforeUnixEpoch => write!(fmt, "date/times before Unix epoch (Jan. 1, 1970 00:00:00 UTC) cannot be stored as `Time`"),
            TooLarge => write!(fmt, "`Time` value is out of range for `OffsetDateTime`"),
        }
    }
}

impl std::error::Error for TimeOutOfRange {}

#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Debug)]
pub enum Order {
    Ascending,
    Descending,
}

impl FromStr for Order {
    type Err = ();

    fn from_str(order: &str) -> Result<Self, ()> {
        match order {
            "asc" => Ok(Order::Ascending),
            "desc" => Ok(Order::Descending),
            _ => Err(()),
        }
    }
}

impl fmt::Display for Order {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Order::Ascending => write!(f, "asc"),
            Order::Descending => write!(f, "desc"),
        }
    }
}

impl Default for Order {
    fn default() -> Self {
        Order::Ascending
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct CustomMetadata(pub HashMap<String, String>);

impl Serialize for CustomMetadata {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .iter()
            .map(|(k, v)| (format!("custom_metadata.{}", k), v))
            .collect::<HashMap<_, _>>()
            .serialize(serializer)
    }
}

mod custom_metadata_params_de {
    use super::CustomMetadata;
    use serde::de::{self, Deserialize, Deserializer, IgnoredAny, MapAccess, Visitor};
    use std::collections::HashMap;
    use std::fmt;

    enum Key {
        Key(String),
        Ignored,
    }

    struct KeyVisitor;
    impl<'de> Visitor<'de> for KeyVisitor {
        type Value = Key;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("`custom_metadata.{key}` where {key} is an arbitrary identifier")
        }

        fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
            let prefix = "custom_metadata.";
            if value.starts_with(prefix) {
                return Ok(Key::Key(value[prefix.len()..].to_owned()));
            }
            Ok(Key::Ignored)
        }
    }

    impl<'de> Deserialize<'de> for Key {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer.deserialize_identifier(KeyVisitor)
        }
    }

    struct CMVisitor;
    impl<'de> Visitor<'de> for CMVisitor {
        type Value = CustomMetadata;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("map containing key/value pairs of form custom_metadata.K = V ")
        }

        fn visit_map<M: MapAccess<'de>>(self, mut access: M) -> Result<Self::Value, M::Error> {
            let mut map = HashMap::with_capacity(access.size_hint().unwrap_or(0));

            while let Some(key) = access.next_key::<Key>()? {
                match key {
                    Key::Key(key) => {
                        let value = access.next_value::<String>()?;
                        map.insert(key, value);
                    }
                    Key::Ignored => {
                        let _ = access.next_value::<IgnoredAny>()?;
                    }
                }
            }
            Ok(CustomMetadata(map))
        }
    }

    impl<'de> Deserialize<'de> for CustomMetadata {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer.deserialize_map(CMVisitor)
        }
    }
}

impl UrlEncode for CustomMetadata {
    fn url_encode(&self, m: &mut HashMap<String, String>) {
        for (key, value) in self.0.clone().into_iter() {
            m.insert(key, value);
        }
    }
}

#[derive(Clone, Debug)]
pub enum Removable<T> {
    Keep(T),
    Remove,
}

mod removable_serde_impl {
    use serde_json::Value;

    use super::*;

    impl<'de, T: for<'a> Deserialize<'a>> Deserialize<'de> for Removable<T> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let value = Value::deserialize(deserializer)?;
            match value {
                Value::String(ref v) if v == "remove" => return Ok(Removable::Remove),
                Value::String(ref v) => return Err(D::Error::custom(format!("unknown variant `{}`, expected `remove` or other supported type", v))),
                _ => {}
            }
            match T::deserialize(value) {
                Ok(val) => Ok(Removable::Keep(val)),
                Err(e) => Err(D::Error::custom(e)),
            }
        }
    }

    impl<T: Serialize + Clone> Serialize for Removable<T> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            match self {
                Removable::Remove => "remove".serialize(serializer),
                Removable::Keep(t) => t.serialize(serializer),
            }
        }
    }
}



#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Base64<T>(Vec<u8>, std::marker::PhantomData<T>);

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UrlSafe;

impl<T> Base64<T> {
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl<T> std::ops::Deref for Base64<T> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<T> From<Vec<u8>> for Base64<T> {
    fn from(data: Vec<u8>) -> Self {
        Base64(data, std::marker::PhantomData)
    }
}

impl ToString for Base64<UrlSafe> {
    fn to_string(&self) -> String {
        self.0.to_base64(URL_SAFE)
    }
}

impl<T> std::str::FromStr for Base64<T> {
    type Err = rustc_serialize::base64::FromBase64Error;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        Ok(string.from_base64()?.into())
    }
}

impl<T> Serialize for Base64<T> where Base64<T>: ToString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for Base64<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let string = String::deserialize(deserializer)?;
        Ok(Self::from_str(&string).map_err(|_| {
            serde::de::Error::invalid_value(serde::de::Unexpected::Str(&string), &"base64 encoded string")
        })?)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HyperHttpMethod(pub Method);

impl Serialize for HyperHttpMethod {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for HyperHttpMethod {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let method = String::deserialize(deserializer)?
            .parse::<Method>()
            .map_err(D::Error::custom)?;

        Ok(HyperHttpMethod(method))
    }
}

// pub trait Input: Sized + Send + Sync + 'static {
//     type Model;
//     fn parse(req: &mut Request) -> MaybeFuture<Result<Self>>;
//     fn expect_body_complete_read() -> bool;
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_groups_modern() {
        let id = Uuid::parse_str("34e03147-9f71-4be9-9a54-3feda0843393").unwrap();
        let mut a = HashMap::new();
        a.insert(id, Some(AppPermissions::ENCRYPT | AppPermissions::DECRYPT));
        let a = AppGroups::from(a);
        let json = r#"{"34e03147-9f71-4be9-9a54-3feda0843393":["ENCRYPT","DECRYPT"]}"#;
        assert_eq!(serde_json::to_string(&a).unwrap(), json);
        assert_eq!(a, serde_json::from_str(&json).unwrap());

        let mut a = HashMap::new();
        a.insert(id, Some(AppPermissions::empty()));
        let a = AppGroups::from(a);
        let json = r#"{"34e03147-9f71-4be9-9a54-3feda0843393":[]}"#;
        assert_eq!(serde_json::to_string(&a).unwrap(), json);
        assert_eq!(a, serde_json::from_str(&json).unwrap());

        let a = AppGroups::from(HashMap::new());
        let json = r#"{}"#;
        assert_eq!(serde_json::to_string(&a).unwrap(), json);
        assert_eq!(a, serde_json::from_str(&json).unwrap());
    }

    #[test]
    fn app_groups_legacy() {
        let id = Uuid::parse_str("34e03147-9f71-4be9-9a54-3feda0843393").unwrap();
        let mut a = HashMap::new();
        a.insert(id, None);
        let a = AppGroups::from(a);
        let json = r#"["34e03147-9f71-4be9-9a54-3feda0843393"]"#;
        assert_eq!(a, serde_json::from_str(&json).unwrap());

        let a = AppGroups::from(HashMap::new());
        let json = r#"[]"#;
        assert_eq!(a, serde_json::from_str(&json).unwrap());
    }

    #[test]
    fn time() {
        let t = Time::now();
        t.to_utc_datetime().expect("in bounds");
        serde_json::to_string(&t).expect("in bounds and correct format");

        let t: Time = serde_json::from_str(r#""20200315T012345Z""#).expect("valid date/time");
        assert_eq!(t.0, 1584235425);

        let t: Time = serde_json::from_str(r#""19700101T000000Z""#).expect("valid date/time");
        assert_eq!(t.0, 0);

        let err = serde_json::from_str::<Time>(r#""20220119T024257""#).unwrap_err();
        assert_eq!(
            err.to_string(),
            "expected date/time in ISO-8601 format: a character literal was not valid"
        );

        let err = serde_json::from_str::<Time>(r#""19670120T012345Z""#).unwrap_err();
        assert_eq!(
            err.to_string(),
            "date/times before Unix epoch (Jan. 1, 1970 00:00:00 UTC) cannot be stored as `Time`"
        );

        let err = Time(i64::MAX as u64 + 10).to_utc_datetime().unwrap_err();
        assert_eq!(
            err.to_string(),
            "`Time` value is out of range for `OffsetDateTime`"
        );

        let err = Time::try_from(OffsetDateTime::from_unix_timestamp(-1).unwrap()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "date/times before Unix epoch (Jan. 1, 1970 00:00:00 UTC) cannot be stored as `Time`"
        );
    }
}
