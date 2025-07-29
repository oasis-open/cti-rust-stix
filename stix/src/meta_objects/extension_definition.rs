//! Data structures and functions for implementing Extension Definition SMOs

use crate::{
    base::{CommonProperties, CommonPropertiesBuilder, Stix},
    error::{add_error, return_multiple_errors, StixError as Error},
    json,
    relationship_objects::{Related, RelationshipObjectBuilder},
    types::{ExtensionType, ExternalReference, GranularMarking, Identified, Identifier},
};
use log::warn;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// An Extension Definition Stix Meta Object (SMO).
///
/// The STIX Extension Definition object allows producers of threat intelligence to extend existing STIX objects or to create entirely new STIX objects in a standardized way.
/// This object contains detailed information about the extension and any additional properties and or objects that it defines. This extension mechanism **MUST NOT** be used
/// to redefine existing standardized objects or properties.
///
/// There are three ways to extend STIX using STIX Extensions.
///
/// 1. Define one or more new STIX Object types.
/// 2. Define additional properties for an existing STIX Object type as a nested property extension. This is typically done to represent a sub-component or module of one or
/// more STIX Object types.
/// 3. Define additional properties for an existing STIX Object type at the object's top-level. This can be done to represent properties that form an inherent part of the
/// definition of an object type.
///
/// When defining a STIX extension using the nested property extension mechanism the `extensions` property **MUST** include the extension definition's UUID that defines the extension
/// definition object and the `extension_type` property.
///
/// The three uses of this extension facility **MAY** be combined into a single Extension Definition object when appropriate.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_32j232tfvtly>
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ExtensionDefinition {
    #[serde(rename = "type")]
    pub object_type: String,
    /// Common STIX object properties
    #[serde(flatten)]
    pub common_properties: CommonProperties,
    /// A name used for display purposes during execution, development, or debugging.
    pub name: String,
    /// A detailed explanation of what data the extension conveys and how it is intended to be used.
    /// The `schema` property is the normative definition of the extension, and this property, if present, is for documentation purposes only.
    ///
    /// While the description property is optional this property **SHOULD** be populated.
    pub description: Option<String>,
    /// The normative definition of the extension, either as a URL or as plain text explaining the definition.
    ///
    /// A URL **SHOULD** point to a JSON schema or a location that contains information about the schema.
    pub schema: String,
    /// The version of this extension. Producers of STIX extensions are encouraged to follow standard semantic versioning procedures where the version number follows the
    /// pattern, MAJOR.MINOR.PATCH. This will allow consumers to distinguish between the three different levels of compatibility typically identified by such versioning strings.
    pub version: String,
    /// This property specifies one or more extension types contained within this extension.
    ///
    /// The values for this property **MUST** come from the `extension-type-enum` enumeration.
    ///
    /// When this property includes `toplevel-property-extension` then the `extension_properties` property **SHOULD** include one or more property names.
    pub extension_types: Vec<ExtensionType>,
    /// This property contains the list of new property names that are added to an object by an extension.
    ///
    /// This property **MUST** only be used when the `extension_types` property includes a value of `toplevel-property-extension`.
    /// In other words, when new properties are being added at the top-level of an existing object.
    pub extension_properties: Option<Vec<String>>,
}

impl ExtensionDefinition {
    /// Deserializes an ExtensionDefintion SMO from a JSON String.
    /// Checks that all fields conform to the STIX 2.1 standard
    /// If the `allow_custom` flag is flase, checks that there are no fields in the JSON String that are not in the SDO type definition
    pub fn from_json(json: &str, allow_custom: bool) -> Result<Self, Error> {
        let extension_definition: Self =
            serde_json::from_str(json).map_err(|e| Error::DeserializationError(e.to_string()))?;
        extension_definition.stix_check()?;

        if !allow_custom {
            json::field_check(&extension_definition, json)?;
        }

        Ok(extension_definition)
    }

    pub fn is_revoked(&self) -> bool {
        matches!(self.common_properties.revoked, Some(true))
    }

    pub fn add_sighting(self) -> Result<RelationshipObjectBuilder, Error> {
        let sighting_of_ref = self.get_id().to_owned();

        RelationshipObjectBuilder::new_sighting(sighting_of_ref)
    }
}

impl Identified for ExtensionDefinition {
    fn get_id(&self) -> &Identifier {
        &self.common_properties.id
    }
}

impl Related for ExtensionDefinition {
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

impl Stix for ExtensionDefinition {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Check common properties
        add_error(&mut errors, self.common_properties.stix_check());

        // Check that required common properties fields are present and prohibited common properties fields are absent

        // Check that the `spec_version` field exists for Extension Definition SMOs
        if self.common_properties.spec_version.is_none() {
            errors.push(Error::ValidationError(
                "Extension Definition SMOs must have a `spec_version` property.".to_string(),
            ));
        }
        // Check that the `created_by_ref` field exists for Extension Definition SMOs
        if self.common_properties.created_by_ref.is_none() {
            errors.push(Error::ValidationError(
                "Extension Definition SMOs must have a `created_by_ref` property.".to_string(),
            ));
        }
        // Check that the `created` field exists for Extension Definition SMOs
        if self.common_properties.created.is_none() {
            errors.push(Error::ValidationError(
                "Extension Definition SMOs must have a `created` property.".to_string(),
            ));
        }
        // Check that the `modified` field exists for Extension Definition SMOs
        if self.common_properties.modified.is_none() {
            errors.push(Error::ValidationError(
                "Extension Definition SMOs must have a `modified` property.".to_string(),
            ));
        }
        // Check that the `confidence` property is `None` for Extension Definition SMOs
        if self.common_properties.confidence.is_some() {
            errors.push(Error::ValidationError(
                "Extension Definition SMOs cannot have a `confidence` property.".to_string(),
            ));
        }
        // Check that the `lang` property is `None` for Extension Definition SMOs
        if self.common_properties.lang.is_some() {
            errors.push(Error::ValidationError(
                "Extension Definition SMOs cannot have a `lang` property.".to_string(),
            ));
        }
        // Check that the `defanged` property is `None` for Extension Definition SMOs
        if self.common_properties.defanged.is_some() {
            errors.push(Error::ValidationError(
                "Extension Definition SMOs cannot have a `defanged` property.".to_string(),
            ));
        }
        // // Check that the `extensions` property is `None` for Extension Definition SMOs
        // if self.common_properties.extensions.is_some() {
        //     errors.push(Error::ValidationError(
        //         "Extension Definition SMOs cannot have a `extensions` property.".to_string(),
        //     ));
        // }

        // Check specific ExtensionDefinition type constraints
        if self.object_type != "extension-definition" {
            errors.push(Error::ValidationError(
                "Extension Definition SMOs must have a type of 'extenion-definition'".to_string(),
            ));
        }

        if self.description.is_none() || self.description == Some("".to_string()) {
            warn!("The `description` field of an Extension Definition should be populated.")
        }

        if self
            .extension_types
            .iter()
            .any(|e| *e == ExtensionType::ToplevelPropertyExtension)
        {
            if self.extension_properties.is_none() {
                warn!("When `extension_types` includes `toplevel-property-extensions`, `extension_properties` should include one or more property names.")
            }
        } else if self.extension_properties.is_some() {
            errors.push(Error::ValidationError("The `extension_types` property must only be used when `extension_types` includes a value of `toplevel-property-extensions`. Currently it does not.".to_string()));
        }

        return_multiple_errors(errors)
    }
}

/// Builder struct for Extension Definition SMOs.
///
/// This follows the "Rust builder pattern," where we  use a `new()` function to construct a Builder
/// with a minimum set of required fields, then set additional fields with their own setter functions.
/// Once all fields have been set, the `build()` function will take all of the fields in the Builder
/// struct and use them to create the final `LanguageContent` struct.
///
/// Note: Because the `schema`, `version`, and `extension_types` properties are required for Extension Definition SMOs,
/// the `build()` method will error if those fields are not set before it is called.
#[derive(Clone, Debug)]
pub struct ExtensionDefinitionBuilder {
    /// Common STIX properties
    common_properties: CommonPropertiesBuilder,
    name: String,
    description: Option<String>,
    schema: Option<String>,
    version: Option<String>,
    extension_types: Option<Vec<ExtensionType>>,
    extension_properties: Option<Vec<String>>,
}

impl ExtensionDefinitionBuilder {
    // Creates a new STIX 2.1 `ExtensionDefinitionBuilder` with a given name
    ///
    /// Automatically generates an `id`
    ///
    /// Other fields are set to their Default (which is `None`` for optional fields)
    pub fn new(name: &str) -> Result<Self, Error> {
        // Build the common properties with generated and default values
        let common_properties =
            CommonPropertiesBuilder::new("extension-definition", "extension-definition")?;

        Ok(Self {
            common_properties,
            name: name.to_string(),
            description: Default::default(),
            schema: Default::default(),
            version: Default::default(),
            extension_types: Default::default(),
            extension_properties: Default::default(),
        })
    }

    /// Create a new STIX 2.1 `ExtensionDefinitionBuilder` by cloning the fields from an existing `ExtensionDefinition`
    /// When built, this will create `ExtensionDefinition` as a newer version of the original object.
    pub fn version(old: &ExtensionDefinition) -> Result<ExtensionDefinitionBuilder, Error> {
        if old.is_revoked() {
            return Err(Error::UnableToVersion(format!(
                "ExtensionDefinition {} is revoked. Versioning a revoked object is prohibited.",
                old.common_properties.id
            )));
        }

        let old_properties = old.common_properties.clone();
        let common_properties =
            CommonPropertiesBuilder::version("extension-definition", &old_properties)?;
        let name = old.name.clone();
        let description = old.description.clone();
        let schema = Some(old.schema.clone());
        let version = Some(old.version.clone());
        let extension_types = Some(old.extension_types.clone());
        let extension_properties = old.extension_properties.clone();

        Ok(ExtensionDefinitionBuilder {
            common_properties,
            name,
            description,
            schema,
            version,
            extension_types,
            extension_properties,
        })
    }

    // Setter functions for common properties

    /// Set the optional `created_by_ref` field for a Extension Definition SMO under construction
    /// This is only allowed when creating a new Extension Definition SMO, not when versioning an existing one,
    /// as only the original creator of an object can version it.
    pub fn created_by_ref(mut self, id: Identifier) -> Result<Self, Error> {
        self.common_properties = self.common_properties.clone().created_by_ref(id)?;
        Ok(self)
    }

    /// Set the optional `labels` field for an Extension Definition SMO under construction
    pub fn labels(mut self, labels: Vec<String>) -> Self {
        self.common_properties = self.common_properties.clone().labels(labels);
        self
    }

    /// Set the optional `confidence` field for an Extension Definition SMO under construction
    pub fn confidence(mut self, confidence: u8) -> Self {
        self.common_properties = self.common_properties.clone().confidence(confidence);
        self
    }

    /// Set the optional `external_references` field for an Extension Definition SMO under construction
    pub fn external_references(mut self, references: Vec<ExternalReference>) -> Self {
        self.common_properties = self
            .common_properties
            .clone()
            .external_references(references);
        self
    }

    /// Set the optional `object_marking_refs` field for an Extension Definition SMO under construction
    pub fn object_marking_refs(mut self, references: Vec<Identifier>) -> Self {
        self.common_properties = self
            .common_properties
            .clone()
            .object_marking_refs(references);
        self
    }

    /// Set the optional `granular_markings` field for an Extension Definition SMO under construction.
    pub fn granular_markings(mut self, markings: Vec<GranularMarking>) -> Self {
        self.common_properties = self.common_properties.clone().granular_markings(markings);
        self
    }

    // Setter functions for Extension Definition specific properties

    /// Set the optional `description` field for an Extension Definition SMO under construction
    pub fn description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    /// Set the required `schema` field for an Extension Definition SMO under construction
    pub fn schema(mut self, schema: String) -> Self {
        self.schema = Some(schema);
        self
    }

    /// Set the required `version` field for an Extension Definition SMO under construction
    pub fn set_version(mut self, version: String) -> Self {
        self.version = Some(version);
        self
    }

    /// Set the required `extension_types` field for an Extension Definition SMO under construction
    pub fn extension_types(mut self, extension_types: Vec<ExtensionType>) -> Self {
        self.extension_types = Some(extension_types);
        self
    }

    /// Set the optional `extension_properties` field for an Extension Definition SMO under construction
    pub fn extension_properties(mut self, extension_properties: Vec<String>) -> Self {
        self.extension_properties = Some(extension_properties);
        self
    }

    /// Builds a new Extension Definition SMO, using the information found in the ExtensionDefinitionBuilder
    ///
    /// This runs the `stick_check()` validation method on the newly constructed SMO.
    pub fn build(self) -> Result<ExtensionDefinition, Error> {
        let mut errors = Vec::new();

        // Check that required fields are included before creating the object

        if self.schema.is_none() {
            errors.push(Error::MissingBuilderProperty {
                object_type: "extension-definition".to_string(),
                property: "schema".to_string(),
            })
        }

        if self.version.is_none() {
            errors.push(Error::MissingBuilderProperty {
                object_type: "extension-definition".to_string(),
                property: "version".to_string(),
            })
        }

        if self.extension_types.is_none() {
            errors.push(Error::MissingBuilderProperty {
                object_type: "extension-definition".to_string(),
                property: "extension_types".to_string(),
            })
        }

        return_multiple_errors(errors)?;

        let common_properties = self.common_properties.build();

        let name = self.name;
        let description = self.description;
        // PANIC: All unwraps are safe because we would have returned earlier if any of the Options were None
        let schema = self.schema.unwrap();
        let version = self.version.unwrap();
        let extension_types = self.extension_types.unwrap();
        let extension_properties = self.extension_properties;

        let extension_definition = ExtensionDefinition {
            object_type: "extension-definition".to_string(),
            common_properties,
            name,
            description,
            schema,
            version,
            extension_types,
            extension_properties,
        };

        extension_definition.stix_check()?;

        Ok(extension_definition)
    }
}
