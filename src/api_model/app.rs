use super::*;

// AppGroups contains a list of groups and optionally permissions granted to an app in each group.
// In order to get information about the app permissions in each group, you should set
// `group_permissions` to true in GetAppParams/ListAppsParams when making app-related requests.
// When creating a new app, you should always specify desired permissions for each group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppGroups(HashMap<Uuid, Option<AppPermissions>>);

impl Deref for AppGroups {
    type Target = HashMap<Uuid, Option<AppPermissions>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AppGroups {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<HashMap<Uuid, Option<AppPermissions>>> for AppGroups {
    fn from(d: HashMap<Uuid, Option<AppPermissions>>) -> Self {
        AppGroups(d)
    }
}

impl From<AppGroups> for HashMap<Uuid, Option<AppPermissions>> {
    fn from(d: AppGroups) -> Self {
        d.0
    }
}

impl Serialize for AppGroups {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .iter()
            .map(|(id, perm)| (id, perm.unwrap_or(AppPermissions::empty())))
            .collect::<HashMap<_, _>>()
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AppGroups {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum S {
            Modern(HashMap<Uuid, AppPermissions>),
            Legacy(HashSet<Uuid>),
        }
        
        Ok(AppGroups(match S::deserialize(deserializer)? {
            S::Modern(map) => map.into_iter().map(|(id, perm)| (id, Some(perm))).collect(),
            S::Legacy(set) => set.into_iter().map(|id| (id, None)).collect(),
        }))
    }
}