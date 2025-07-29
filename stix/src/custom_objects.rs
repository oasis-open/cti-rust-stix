//! Contains the implementation logic for unrecognized custom STIX Objects.

use crate::{
    base::{CommonProperties, CommonPropertiesBuilder, Stix},
    cyber_observable_objects::sco::check_sco_properties,
    domain_objects::sdo::check_sdo_properties,
    error::{add_error, return_multiple_errors, StixError as Error},
    relationship_objects::{check_sro_properties, Related, RelationshipObjectBuilder},
    types::{
        get_extension_type, stix_case, DictionaryValue, ExtensionType, ExternalReference,
        Identified, Identifier, StixDictionary,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;
use std::{collections::BTreeMap, str::FromStr};

/// A STIX object of unknown type.
///
/// This struct exists to represent custom STIX objects that do not have a recognized "type" field.
/// The object must have an `extensions` dictionary containing an extension with an `extension_type` of "new-sdo", "new-sro", or "new-sco".
///
/// The properties common to all STIX objects are accessible and validated, with the validation informed by the object type inferred from the new object extension.
///
/// Any other fields in the JSON string are stored in a flattened `custom_properties` Map, which will re-serialize back to the same fields when the object is serialized to a
/// JSON string.
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomObject {
    /// Identifies the type of STIX Object.
    #[serde(rename = "type")]
    pub object_type: String,
    /// Common object properties
    #[serde(flatten)]
    pub common_properties: CommonProperties,
    /// Custom properties for the object
    #[serde(flatten)]
    pub custom_properties: BTreeMap<String, Value>,
}

impl CustomObject {
    /// Deserializes a  custom object from a JSON String.
    /// Checks that all fields conform to the STIX 2.1 standard
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let object: Self =
            serde_json::from_str(json).map_err(|e| Error::DeserializationError(e.to_string()))?;
        object.stix_check()?;

        Ok(object)
    }

    /// Returns whether a custom STIX Object is an SDO, SRO, or SCO, as determined by its new object extension
    pub fn get_object_type(&self) -> Result<ExtensionType, Error> {
        // Custom Objects in STIX 2.1 MUST include an extension with extension_type of "new-sdo," "new-sro," or "new-sco" defining the object type
        let mut object_type = None;
        match &self.common_properties.extensions {
            Some(extensions) => {
                // Loop through all extensions looking for a custom object extension type (it is possible that there are both custom property and custom object extensions for the same object)
                for (extension_key, extension) in extensions.iter() {
                    let Ok(id) = Identifier::from_str(extension_key) else {
                        continue;
                    };
                    if id.get_type() == "extension-definition" {
                        match get_extension_type(extension).ok_or(Error::CustomMissingExtension)? {
                            // If this is a property extension, keep looking
                            ExtensionType::PropertyExtension => continue,
                            ExtensionType::ToplevelPropertyExtension => continue,
                            object_extension => {
                                object_type = Some(object_extension);
                                break;
                            }
                        }
                    }
                }
            }
            None => return Err(Error::CustomMissingExtension),
        };

        object_type.ok_or(Error::CustomMissingExtension)
    }

    /// Returns the `modified` timestamp as a String if it exists, or `None` if it does not
    pub fn get_modified(&self) -> Option<String> {
        self.common_properties
            .modified
            .as_ref()
            .map(|modified| modified.to_string())
    }

    /// Returns whether the object is revoked or not
    pub fn is_revoked(&self) -> bool {
        matches!(self.common_properties.revoked, Some(true))
    }

    /// Adds a sighting SRO to the object
    pub fn add_sighting(self) -> Result<RelationshipObjectBuilder, Error> {
        let sighting_of_ref = self.get_id().to_owned();

        RelationshipObjectBuilder::new_sighting(sighting_of_ref)
    }
}

impl Identified for CustomObject {
    /// Returns a reference to the identifier of the `CustomObject`.
    ///
    /// This implementation accesses the `id` field from the `common_properties`
    /// of the `CustomObject`, providing a way to retrieve the unique identifier
    /// associated with this object.
    fn get_id(&self) -> &Identifier {
        &self.common_properties.id
    }
}

impl Related for CustomObject {
    fn add_relationship<T: Related + Identified>(
        self,
        target: T,
        relationship_type: String,
    ) -> Result<RelationshipObjectBuilder, Error> {
        let source_id = self.get_id().to_owned();
        let target_id = target.get_id().to_owned();

        RelationshipObjectBuilder::new(source_id, target_id, &relationship_type)
    }
}

impl Stix for CustomObject {
    fn stix_check(&self) -> Result<(), Error> {
        let mut common_errors = Vec::new();

        // Check common properties
        add_error(&mut common_errors, self.common_properties.stix_check());

        // Early return if the common properties are not formatted correctly.
        // We check the common properties first because this will catch any errors in `extensions` before we try to read them
        return_multiple_errors(common_errors)?;

        // Get the custom object type, returning an error if it cannot be found
        let object_type = self.get_object_type()?;

        let mut errors = Vec::new();

        // Check object type specific constraints on common properties
        match object_type {
            // The custom object is an SDO
            ExtensionType::NewSdo => {
                add_error(&mut errors, check_sdo_properties(&self.common_properties));
            }
            // The custom object is an SRO
            ExtensionType::NewSro => {
                add_error(&mut errors, check_sro_properties(&self.common_properties));
            }
            // The custom object is an SCO
            ExtensionType::NewSco => {
                add_error(&mut errors, check_sco_properties(&self.common_properties));
            }
            // This must be a custom object extension type
            _ => unreachable!(),
        }

        // Validate custom properties. This does not include any special object specific constraints
        self.custom_properties.stix_check()?;

        return_multiple_errors(errors)
    }
}

/// Builder struct for Custom Objects.
///
/// This follows the "Rust builder pattern," where we  use a `new()` function to construct a Builder
/// with a minimum set of required fields, then set additional fields with their own setter functions.
/// Once all fields have been set, the `build()` function will take all of the fields in the Builder
/// struct and use them to create the final `CustomObject` struct.
#[derive(Clone, Debug)]
pub struct CustomObjectBuilder {
    // The object type
    object_type: String,
    // Common STIX object properties
    common_properties: CommonPropertiesBuilder,
    // The map of custom properties
    custom_properties: BTreeMap<String, Value>,
}

impl CustomObjectBuilder {
    /// Creates a new STIX 2.1 `CustomObjectBuilder` for an SDO with a given name, map of custom properties, and extension definition id for the "new-sdo" extension
    ///
    /// Automatically generates an `id`
    /// Other  fields are set to their Default (which is `None`` for optional fields)
    pub fn new_sdo(
        type_name: &str,
        custom_properties: BTreeMap<String, Value>,
        extension_definition: &str,
    ) -> Result<CustomObjectBuilder, Error> {
        // Build the common properties with generated and default values
        let default_common_properties = CommonPropertiesBuilder::new("sdo", type_name)?;

        // Create a "new-sdo" extension
        let mut object_extension = StixDictionary::new();
        object_extension.insert(
            "extension_type",
            DictionaryValue::String("new-sdo".to_string()),
        )?;

        // Add that extension, with its extension definition id, to the common properties
        let common_properties =
            default_common_properties.add_extension(extension_definition, object_extension)?;

        Ok(CustomObjectBuilder {
            object_type: type_name.to_string(),
            common_properties,
            custom_properties,
        })
    }

    /// Creates a new STIX 2.1 `CustomObjectBuilder` for an SRO with a given name, map of custom properties, and extension definition id for the "new-sro" extension
    ///
    /// Automatically generates an `id`
    /// Other  fields are set to their Default (which is `None`` for optional fields)
    pub fn new_sro(
        type_name: &str,
        custom_properties: BTreeMap<String, Value>,
        extension_definition: &str,
    ) -> Result<CustomObjectBuilder, Error> {
        // Build the common properties with generated and default values
        let default_common_properties = CommonPropertiesBuilder::new("sro", type_name)?;

        // Create a "new-sro" extension
        let mut object_extension = StixDictionary::new();
        object_extension.insert(
            "extension_type",
            DictionaryValue::String("new-sro".to_string()),
        )?;

        // Add that extension, with its extension definition id, to the common properties
        let common_properties =
            default_common_properties.add_extension(extension_definition, object_extension)?;

        Ok(CustomObjectBuilder {
            object_type: type_name.to_string(),
            common_properties,
            custom_properties,
        })
    }

    /// Creates a new STIX 2.1 `CustomObjectBuilder` for an SCO with a given name, map of custom properties, and extension definition id for the "new-sco" extension
    ///
    /// Automatically generates a UUIDv4-based `id`
    /// Other  fields are set to their Default (which is `None`` for optional fields)
    pub fn new_sco(
        type_name: &str,
        custom_properties: BTreeMap<String, Value>,
        extension_definition: &str,
    ) -> Result<CustomObjectBuilder, Error> {
        // Build the common properties with generated and default values
        let default_common_properties = CommonPropertiesBuilder::new("sco", type_name)?;

        // Create a "new-sco" extension
        let mut object_extension = StixDictionary::new();
        object_extension.insert(
            "extension_type",
            DictionaryValue::String("new-sco".to_string()),
        )?;

        // Add that extension, with its extension definition id, to the common properties
        let common_properties =
            default_common_properties.add_extension(extension_definition, object_extension)?;

        Ok(CustomObjectBuilder {
            object_type: type_name.to_string(),
            common_properties,
            custom_properties,
        })
    }

    /// Create a new STIX 2.1 `CustomObjectBuilder` by cloning the fields from an existing `CustomObject`
    /// When built, this will create `CustomObject` as a newer version of the original object.
    ///
    /// Only custom SDOs and SROs can be versioned
    pub fn version(old: &CustomObject) -> Result<CustomObjectBuilder, Error> {
        if old.is_revoked() {
            return Err(Error::UnableToVersion(format!(
                "Custom object {} is revoked. Versioning a revoked object is prohibited.",
                old.common_properties.id
            )));
        }

        if old.get_object_type()? == ExtensionType::NewSco {
            return Err(Error::UnableToVersion(format!(
                "Custom object {} is an SCO. SCOs cannot be versioned.",
                old.common_properties.id
            )));
        }

        let object_type = old.object_type.clone();
        let old_properties = old.common_properties.clone();
        let common_properties = CommonPropertiesBuilder::version("sdo", &old_properties)?;
        let custom_properties = old.custom_properties.clone();

        Ok(CustomObjectBuilder {
            object_type,
            common_properties,
            custom_properties,
        })
    }

    // Setter functions for optional common properties

    /// Set the optional `created_by_ref` field for a custom object under construction.
    /// This is only allowed when creating a new object, not when versioning an existing one,
    /// as only the original creator of an object can version it.
    pub fn created_by_ref(mut self, id: Identifier) -> Result<Self, Error> {
        self.common_properties = self.common_properties.clone().created_by_ref(id)?;
        Ok(self)
    }

    /// Set the optional `labels` field for a custom object under construction.
    pub fn labels(mut self, labels: Vec<String>) -> Self {
        self.common_properties = self.common_properties.clone().labels(labels);
        self
    }

    /// Set the optional `confidence` field for a custom object under construction.
    pub fn confidence(mut self, confidence: u8) -> Self {
        self.common_properties = self.common_properties.clone().confidence(confidence);
        self
    }

    /// Set the optional `lang` field for a custom object under construction.
    /// If the language is English ("en"), this does not need to be set (but it can be if specificity is desired).
    pub fn lang(mut self, language: String) -> Self {
        self.common_properties = self.common_properties.clone().lang(language);
        self
    }

    /// Set the optional `external_references` field for a custom object under construction.
    pub fn external_references(mut self, references: Vec<ExternalReference>) -> Self {
        self.common_properties = self
            .common_properties
            .clone()
            .external_references(references);
        self
    }

    /// Set the optional `object_marking_refs` field for a custom object under construction.
    pub fn object_marking_refs(mut self, references: Vec<Identifier>) -> Self {
        self.common_properties = self
            .common_properties
            .clone()
            .object_marking_refs(references);
        self
    }

    /// Add an additional extension to the `extensions` field for a custom object under construction
    pub fn add_extension(
        mut self,
        key: &str,
        extension: StixDictionary<DictionaryValue>,
    ) -> Result<Self, Error> {
        self.common_properties = self
            .common_properties
            .clone()
            .add_extension(key, extension)?;
        Ok(self)
    }

    /// Builds a new custom STIX object, using the information found in the CustombjectBuilder
    ///
    /// This performs a final check that all required fields for a given object type are included before construction.
    /// This also runs the `stick_check()` validation method on the newly constructed object.
    pub fn build(self) -> Result<CustomObject, Error> {
        let common_properties = self.common_properties.build();

        let object = CustomObject {
            object_type: self.object_type,
            common_properties,
            custom_properties: self.custom_properties,
        };

        let mut errors = Vec::new();

        // Check required and prohibited fields for the object type
        let object_type = object.get_object_type()?;

        if object_type == ExtensionType::NewSco {
            if object.common_properties.created_by_ref.is_some() {
                errors.push(Error::IllegalBuilderProperty {
                    object: "Custom objects".to_string(),
                    object_type: "SCO".to_string(),
                    field: "created_by_ref".to_string(),
                });
            }

            if object.common_properties.revoked.is_some() {
                errors.push(Error::IllegalBuilderProperty {
                    object: "Custom objects".to_string(),
                    object_type: "SCO".to_string(),
                    field: "revoked".to_string(),
                });
            }

            if object.common_properties.labels.is_some() {
                errors.push(Error::IllegalBuilderProperty {
                    object: "Custom objects".to_string(),
                    object_type: "SCO".to_string(),
                    field: "labels".to_string(),
                });
            }

            if object.common_properties.confidence.is_some() {
                errors.push(Error::IllegalBuilderProperty {
                    object: "Custom objects".to_string(),
                    object_type: "SCO".to_string(),
                    field: "confidence".to_string(),
                });
            }

            if object.common_properties.lang.is_some() {
                errors.push(Error::IllegalBuilderProperty {
                    object: "Custom objects".to_string(),
                    object_type: "SCO".to_string(),
                    field: "lang".to_string(),
                });
            }

            if object.common_properties.external_references.is_some() {
                errors.push(Error::IllegalBuilderProperty {
                    object: "Custom objects".to_string(),
                    object_type: "SCO".to_string(),
                    field: "external_references".to_string(),
                });
            }
        }

        if object_type != ExtensionType::NewSco && object.common_properties.defanged.is_some() {
            errors.push(Error::IllegalBuilderProperty {
                object: "Custom objects".to_string(),
                object_type: stix_case(object_type.as_ref()),
                field: "defanged".to_string(),
            });
        }

        add_error(&mut errors, object.stix_check());

        return_multiple_errors(errors)?;

        Ok(object)
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use serde_json::{Number, Value};

    use crate::{
        custom_objects::{CustomObject, CustomObjectBuilder},
        types::{Identifier, Timestamp},
    };

    // Functions for editing otherwise un-editable fields, for testing only
    impl CustomObject {
        fn test_id(mut self) -> Self {
            let object_type = self.object_type.as_ref();
            self.common_properties.id = Identifier::new_test(object_type);
            self
        }

        fn created(mut self, datetime: &str) -> Self {
            self.common_properties.created = Some(Timestamp(datetime.parse().unwrap()));
            self
        }

        fn modified(mut self, datetime: &str) -> Self {
            self.common_properties.modified = Some(Timestamp(datetime.parse().unwrap()));
            self
        }
    }

    #[test]
    fn deserialize_custom() {
        let json = r#"{
        "type": "my-favorite-sdo",
        "spec_version": "2.1",
        "id": "my-favorite-sdo--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2014-02-20T09:16:08.989000Z",
        "modified": "2014-02-20T09:16:08.989000Z",
        "name": "This is the name of my favorite",
        "some_property_name1": "value1",
        "some_property_name2": 3,
        "extensions": {
            "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62" : {
                "extension_type" : "new-sdo"
            }
        }
        }"#;

        let result = CustomObject::from_json(json).unwrap();

        let mut custom_properties = BTreeMap::new();

        custom_properties.insert(
            "name".to_string(),
            Value::String("This is the name of my favorite".to_string()),
        );
        custom_properties.insert(
            "some_property_name1".to_string(),
            Value::String("value1".to_string()),
        );
        custom_properties.insert(
            "some_property_name2".to_string(),
            Value::Number(Number::from_u128(3).unwrap()),
        );

        let expected = CustomObjectBuilder::new_sdo(
            "my-favorite-sdo",
            custom_properties,
            "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62",
        )
        .unwrap()
        .build()
        .unwrap()
        .created("2014-02-20T09:16:08.989Z")
        .modified("2014-02-20T09:16:08.989Z")
        .test_id();

        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_custom_wrong_ext() {
        let json = r#"{
            "type": "my-favorite-sdo",
            "spec_version": "2.1",
            "id": "my-favorite-sdo--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2014-02-20T09:16:08.989000Z",
            "modified": "2014-02-20T09:16:08.989000Z",
            "name": "This is the name of my favorite",
            "some_property_name1": "value1",
            "some_property_name2": 3,
            "extensions": {
                "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62" : {
                    "extension_type" : "property-extension"
                }
            }
            }"#;

        let result = CustomObject::from_json(json);

        assert!(result.is_err());
    }

    #[test]
    fn deserialize_custom_no_ext() {
        let json = r#"{
            "type": "my-favorite-sdo",
            "spec_version": "2.1",
            "id": "my-favorite-sdo--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2014-02-20T09:16:08.989000Z",
            "modified": "2014-02-20T09:16:08.989000Z",
            "name": "This is the name of my favorite",
            "some_property_name1": "value1",
            "some_property_name2": 3
            }"#;

        let result = CustomObject::from_json(json);

        assert!(result.is_err());
    }

    #[test]
    fn serialize_custom() {
        let mut custom_properties = BTreeMap::new();

        custom_properties.insert(
            "name".to_string(),
            Value::String("This is the name of my favorite".to_string()),
        );
        custom_properties.insert(
            "some_property_name1".to_string(),
            Value::String("value1".to_string()),
        );
        custom_properties.insert(
            "some_property_name2".to_string(),
            Value::Number(Number::from_u128(3).unwrap()),
        );

        let custom_object = CustomObjectBuilder::new_sdo(
            "my-favorite-sdo",
            custom_properties,
            "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62",
        )
        .unwrap()
        .build()
        .unwrap()
        .created("2014-02-20T09:16:08.989Z")
        .modified("2014-02-20T09:16:08.989Z")
        .test_id();

        let mut result = serde_json::to_string_pretty(&custom_object).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
        "type": "my-favorite-sdo",
        "spec_version": "2.1",
        "id": "my-favorite-sdo--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2014-02-20T09:16:08.989Z",
        "modified": "2014-02-20T09:16:08.989Z",
        "extensions": {
            "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62" : {
                "extension_type" : "new-sdo"
            }
        },
        "name": "This is the name of my favorite",
        "some_property_name1": "value1",
        "some_property_name2": 3
        }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected);
    }
}
