use super::*;

#[derive(Clone, Debug, Default)]
pub struct ListSobjectsResponse {
    pub metadata: Option<Metadata>,
    pub items: Vec<Sobject>,
}

impl ListSobjectsResponse {
    pub fn new(is_with_metadata: bool, total_cnt: usize, items: Vec<Sobject>) -> Self {
        let metadata = if is_with_metadata {
            Some(Metadata {
                total_count: Some(total_cnt),
                filtered_count: Some(items.len()),
            })
        } else {
            None
        };

        ListSobjectsResponse { metadata, items }
    }

    // for backward compatibility, used by plugins
    pub fn into_vector(self) -> Vec<Sobject> {
        self.items
    }
}

impl Serialize for ListSobjectsResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.metadata.is_some() {
            let mut state = serializer.serialize_struct("ListSobjectsResponse", 2)?;
            state.serialize_field(
                "metadata",
                &self.metadata.as_ref().expect("expected metadta"),
            )?;
            state.serialize_field("items", &self.items)?;
            return state.end();
        } else {
            let mut seq = serializer.serialize_seq(Some(self.items.len()))?;
            for item in self.items.iter() {
                seq.serialize_element(item)?;
            }
            return seq.end();
        }
    }
}

// This is only required for provider/sdkms to deserialize data for clients
impl<'de> Deserialize<'de> for ListSobjectsResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct GetAllResponseVisitor;

        impl<'de> serde::de::Visitor<'de> for GetAllResponseVisitor {
            type Value = ListSobjectsResponse;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("GetAllResponseItem")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<ListSobjectsResponse, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let mut items: Vec<Sobject> = Vec::new();
                loop {
                    let data = seq.next_element()?;
                    if let Some(item) = data {
                        items.push(item);
                    } else {
                        break;
                    }
                }
                Ok(ListSobjectsResponse {
                    metadata: None,
                    items,
                })
            }

            fn visit_map<V>(self, mut map: V) -> Result<ListSobjectsResponse, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut metadata = None;
                let mut items = Vec::new();
                loop {
                    if let Some(key) = map.next_key::<String>()? {
                        match key.as_str() {
                            "metadata" => metadata = map.next_value()?,
                            "items" => items = map.next_value()?,
                            other => {
                                return Err(serde::de::Error::invalid_value(
                                    serde::de::Unexpected::Str(&format!(
                                        "unexpected key {}",
                                        other
                                    )),
                                    &self,
                                ))
                            }
                        }
                    } else {
                        break;
                    }
                }

                Ok(ListSobjectsResponse { items, metadata })
            }
        }

        deserializer.deserialize_seq(GetAllResponseVisitor)
    }
}

impl std::iter::IntoIterator for ListSobjectsResponse {
    type Item = Sobject;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}
