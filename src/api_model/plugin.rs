use super::*;

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct PluginVersion {
    pub major: u32,
    pub minor: u32,
}

impl Serialize for PluginVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let version = format!("{}.{}", self.major, self.minor);
        serializer.serialize_str(&version)
    }
}

impl<'de> Deserialize<'de> for PluginVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let version: String = Deserialize::deserialize(deserializer)?;
        let mut components = version.split(".");
        let major = components
            .next()
            .ok_or_else(|| D::Error::custom("no major version found"))?
            .parse::<u32>()
            .map_err(D::Error::custom)?;
        let minor = components
            .next()
            .ok_or_else(|| D::Error::custom("no minor version found"))?
            .parse::<u32>()
            .map_err(D::Error::custom)?;
        Ok(PluginVersion { major, minor })
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}.{}", self.major, self.minor)
    }
}

pub type PluginOutput = serde_json::Value;
