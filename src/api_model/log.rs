use super::*;
use serde::{de::IntoDeserializer, Deserialize, Serialize};
use itertools::join;

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Default, Hash)]
pub struct AuditLogTime(pub u64);

impl TryFrom<i64> for AuditLogTime {
    type Error = InvalidTime;

    fn try_from(t: i64) -> Result<Self, Self::Error> {
        if t < 0 { Err(InvalidTime::BeforeUnixEpoch) } else { Ok(AuditLogTime(t as u64)) }
    }
}

impl AuditLogTime {
    pub fn from_esformat(time: &str) -> Result<Self, InvalidTime> {
        let utc = Utc.datetime_from_str(time, Time::ES_FORMAT)?;
        AuditLogTime::try_from(utc.timestamp())
    }
    
    pub fn to_datetime(&self) -> Option<DateTime<Utc>> {
        if self.0 > i64::MAX as u64 {
            // otherwise we end up with a date before Unix epoch since
            // `self.0 as i64` would be negative.
            return None;
        }
        Utc.timestamp_opt(self.0 as i64, 0).single()
    }

    pub fn to_esformat(&self) -> Option<String> {
        self.to_datetime().map(|utc| utc.format(Time::ES_FORMAT).to_string())
    }
}

impl Serialize for AuditLogTime {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_esformat().ok_or_else(|| S::Error::custom("date/time value too far into the future"))?)
    }
}

impl<'de> Deserialize<'de> for AuditLogTime {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(deserializer)?;
        AuditLogTime::from_esformat(&s).map_err(|e| match e {
            InvalidTime::ParseError(_) => D::Error::custom(format!("invalid value \"{}\", expected date/time in ISO 8601 format", s)),
            other => D::Error::custom(format!("invalid date/time \"{}\": {}", s, other)),
        })
    }
}

impl FromStr for SeverityLevel {
    type Err = serde::de::value::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SeverityLevel::deserialize(s.into_deserializer())
    }
}

impl FromStr for ActionType {
    type Err = serde::de::value::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ActionType::deserialize(s.into_deserializer())
    }
}

impl UrlEncode for Vec<String> {
    fn url_encode(&self, m: &mut HashMap<String, String>) {
        m.insert("actor_type".to_string(), self.join(","));
    }
}

impl UrlEncode for Vec<SeverityLevel> {
    fn url_encode(&self, m: &mut HashMap<String, String>) {
        let value = join(self.clone().into_iter(),",");
        m.insert("severity".to_string(), value);
    }
}

impl UrlEncode for Vec<ActionType> {
    fn url_encode(&self, m: &mut HashMap<String, String>) {
        let value = join(self.clone().into_iter(),",");
        m.insert("action_type".to_string(), value);
    }
}

impl fmt::Display for ActionType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ActionType::Administrative => write!(f, "ADMINISTRATIVE"),
            ActionType::Auth => write!(f, "AUTH"),
            ActionType::CryptoOperation => write!(f, "CRYPTOOPERATION"),
            ActionType::RunPlugin => write!(f, "RUNPLUGIN"),
            ActionType::Custom => write!(f, "CUSTOM"),
            ActionType::Other => write!(f, "OTHER"),
        }
    }
}

impl fmt::Display for SeverityLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SeverityLevel::Info => write!(f, "INFO"),
            SeverityLevel::Warning => write!(f, "WARNING"),
            SeverityLevel::Error => write!(f, "ERROR"),
            SeverityLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}
