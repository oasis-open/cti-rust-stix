//! Top level STIX object structures and implementation
use crate::{
    base::Stix,
    custom_objects::CustomObject,
    cyber_observable_objects::sco::CyberObject,
    domain_objects::sdo::DomainObject,
    error::StixError as Error,
    json,
    meta_objects::{
        extension_definition::ExtensionDefinition, language_content::LanguageContent,
        marking_definition::MarkingDefinition,
    },
    relationship_objects::RelationshipObject,
    types::{ExtensionType, Identified},
};
use serde::{Deserialize, Serialize};
use strum::AsRefStr;

/// Possible STIX Objects
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, AsRefStr)]
#[serde(untagged)]
pub enum StixObject {
    #[strum(serialize = "sdo")]
    Sdo(DomainObject),
    #[strum(serialize = "sro")]
    Sro(RelationshipObject),
    #[strum(serialize = "sco")]
    Sco(CyberObject),
    #[strum(serialize = "language-content")]
    LanguageContent(LanguageContent),
    // #[strum(serialize = "object-marking")]
    // ObjectMarking(ObjectMarking),
    #[strum(serialize = "extension-definition")]
    ExtensionDefinition(ExtensionDefinition),
    #[strum(serialize = "marking-definition")]
    MarkingDefinition(MarkingDefinition),
    #[strum(serialize = "custom")]
    Custom(CustomObject),
}

impl StixObject {
    /// Get the object type of a STIX Object
    pub fn get_object_type(&self) -> Result<&str, Error> {
        match self {
            // If the object is a custom object, check its extensions property for its type
            StixObject::Custom(custom_object) => match custom_object.get_object_type()? {
                ExtensionType::NewSdo => Ok("sdo"),
                ExtensionType::NewSro => Ok("sro"),
                ExtensionType::NewSco => Ok("sco"),
                _ => unreachable!(),
            },
            _ => Ok(self.as_ref()),
        }
    }

    /// Get the specific type of the STIX Object
    pub fn get_type(&self) -> &str {
        match self {
            StixObject::Sdo(sdo) => sdo.object_type.as_ref(),
            StixObject::Sro(sro) => sro.object_type.as_ref(),
            StixObject::Sco(sco) => sco.object_type.as_ref(),
            StixObject::LanguageContent(_) => "language-content",
            // StixObject::ObjectMarking(_) = > "object-marking",
            StixObject::ExtensionDefinition(_) => "extension-definition",
            StixObject::MarkingDefinition(_) => "marking-definition",
            Self::Custom(custom) => custom.object_type.as_ref(),
        }
    }

    /// Get the id of the STIX Object
    pub fn get_id(&self) -> String {
        match self {
            StixObject::Sdo(sdo) => sdo.get_id().to_string(),
            StixObject::Sro(sro) => sro.get_id().to_string(),
            StixObject::Sco(sco) => sco.get_id().to_string(),
            StixObject::LanguageContent(language_content) => language_content.get_id().to_string(),
            // StixObject::ObjectMarking(object_marking) = > "object_marking.get_id().to_string()",
            StixObject::ExtensionDefinition(extension_definition) => {
                extension_definition.get_id().to_string()
            }
            StixObject::MarkingDefinition(marking_definition) => {
                marking_definition.get_id().to_string()
            }
            Self::Custom(custom) => custom.get_id().to_string(),
        }
    }

    /// If the type of STIX Object can be versioned, return its modified datetime as a String.
    /// If it cannot be versioned, return `None`.
    pub fn get_modified(&self) -> Option<String> {
        match self {
            StixObject::Sdo(sdo) => Some(sdo.common_properties.modified.as_ref()?.to_string()),
            StixObject::Sro(sro) => Some(sro.common_properties.modified.as_ref()?.to_string()),
            StixObject::Sco(_) => None,
            StixObject::LanguageContent(language_content) => Some(
                language_content
                    .common_properties
                    .modified
                    .as_ref()?
                    .to_string(),
            ),
            // StixObject::ObjectMarking(_) => None,
            StixObject::ExtensionDefinition(extension_definition) => Some(
                extension_definition
                    .common_properties
                    .modified
                    .as_ref()?
                    .to_string(),
            ),
            StixObject::MarkingDefinition(marking_definition) => Some(
                marking_definition
                    .common_properties
                    .modified
                    .as_ref()?
                    .to_string(),
            ),

            Self::Custom(custom) => custom.get_modified(),
        }
    }

    /// Deserialize amy STIX Object from a JSON string
    pub fn from_json(json_str: &str, allow_custom: bool) -> Result<Self, Error> {
        // Identify the type of STIX Object from the JSON (or treat it as a custom object if the type is not recognized)
        let object_type = json::get_object_type_from_json(json_str)?;

        // Use the appropriate JSON deserializer function to create an object of the correct type
        match object_type.as_ref() {
            "sdo" => Ok(StixObject::Sdo(DomainObject::from_json(
                json_str,
                allow_custom,
            )?)),
            "sro" => Ok(StixObject::Sro(RelationshipObject::from_json(
                json_str,
                allow_custom,
            )?)),
            "sco" => Ok(StixObject::Sco(CyberObject::from_json(
                json_str,
                allow_custom,
            )?)),
            "language-content" => Ok(StixObject::LanguageContent(LanguageContent::from_json(
                json_str,
                allow_custom,
            )?)),
            "extension-definition" => Ok(StixObject::ExtensionDefinition(
                ExtensionDefinition::from_json(json_str, allow_custom)?,
            )),
            "marking-definition" => Ok(StixObject::MarkingDefinition(
                MarkingDefinition::from_json(json_str, allow_custom)?,
            )),
            // "object-marking" => Ok(StixObject::ObjectMarking(ObjectMarking::from_json(json_str, allow_custom)?)),
            "custom" => Ok(StixObject::Custom(CustomObject::from_json(json_str)?)),
            // Any unrecognized type will cause get_object_type_from_json() to return an `object_type` of "custom"
            _ => unreachable!(),
        }
    }
}

impl Stix for StixObject {
    fn stix_check(&self) -> Result<(), Error> {
        match self {
            StixObject::Sdo(sdo) => sdo.stix_check(),
            StixObject::Sro(sro) => sro.stix_check(),
            StixObject::Sco(sco) => sco.stix_check(),
            StixObject::LanguageContent(language_content) => language_content.stix_check(),
            // StixObject::ObjectMarking(object_marking) => object_marking.stix_check(),
            StixObject::ExtensionDefinition(extension_definition) => {
                extension_definition.stix_check()
            }
            StixObject::MarkingDefinition(marking_definition) => marking_definition.stix_check(),
            StixObject::Custom(custom) => custom.stix_check(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::object::*;

    #[test]
    fn reserialize_stix_object() {
        let mut json_str = r#"{
                "type": "identity",
                "name": "Identity",
                "description": "Responsible for managing personal digital identity",
                "roles": ["User", "Administrator"],
                "identity_class": "individual",
                "sectors": ["Technology","Aerospace"],
                "contact_information": "alex.johnson@example.com",
                "spec_version": "2.1",
                "id": "identity--12345678-1234-5678-1234-567812345678",
                "created": "2016-05-12T08:17:27Z",
                "modified": "2016-05-12T08:17:27Z",
                "external_references": [
                    {
                        "source_name": "capec",
                        "external_id": "CAPEC-163"
                    }
                ]
            }"#
        .to_string();
        json_str.retain(|c| !c.is_whitespace());

        let object = StixObject::from_json(&json_str, false).unwrap();

        let mut new_json = serde_json::to_string_pretty(&object).unwrap();
        new_json.retain(|c| !c.is_whitespace());

        assert_eq!(json_str, new_json)
    }
}
