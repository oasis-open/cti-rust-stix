//! A collection of STIX wide properties and features that could be used by any STIX object or type.

#![allow(dead_code)]

use crate::{
    error::{add_error, return_multiple_errors, StixError as Error},
    extensions::{
        check_extension, FileExtensions, NetworkTrafficExtensions, ProcessExtensions,
        UserAccountExtensions,
    },
    types::{
        stix_case, DictionaryValue, ExtensionType, ExternalReference, GranularMarking, Identifier,
        StixDictionary, Timestamp,
    },
};
use language_tags::LanguageTag;
use log::warn;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::str::FromStr;
use strum::{EnumString, IntoEnumIterator};

/// A trait for all STIX 2.1 compliant objects and properties.
pub trait Stix {
    /// Method that ensures that all fields in the object or property conform to the STIX 2.1 standard.
    fn stix_check(&self) -> Result<(), Error>;
}

/// Properties that are common across multiple STIX Objects.
///
/// This struct is intended to be nested and flattened inside of a specific STIX Object,
/// with the validator ensuring that properties that cannot exist for that object are not included.
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Default, Deserialize)]
pub struct CommonProperties {
    /// The version of the STIX specification used to represent this object (**MUST** be 2.1 in STIX 2.1).
    ///
    /// Required property for SDOs, SROs, and Meta Objects.
    pub spec_version: Option<String>,
    /// Uniquely identifies this object.
    ///
    /// For objects that support versioning, all objects with the same `id` are considered different versions of the same object and the version of the object is identified by
    /// its `modified` property.
    pub id: Identifier,
    /// Specifies the identity that describes the entity that created this object.
    ///
    /// Can be omitted for objects with anonymous creators, except for Extenion Objects, for which it is a required property.
    pub created_by_ref: Option<Identifier>,
    /// Represents the time at which the object was originally created.
    /// The object creator can use the time it deems most appropriate as the time the object was created.
    ///
    /// The minimum precision **MUST** be milliseconds but **MAY** be more precise.
    /// This **MUST** remain constant even if a new version of the same object is created.
    ///
    /// Required property for SDOs, SROs, and Meta Objects.
    pub created: Option<Timestamp>,
    /// Represents the time that this particular version of the object was last modified.
    /// The object creator can use the time it deems most appropriate as the time this version of the object was modified.
    ///
    /// The minimum precision **MUST** be milliseconds but **MAY** be more precise.
    /// This **MUST** be later than or equal to `created`. This is set each time a new version of an object is created.
    ///
    /// Required property for SDOs, SROs, Extension Objects, and Language Marking Objects.
    pub modified: Option<Timestamp>,
    /// Indicates whether the object has been revoked.
    ///
    /// Revoked objects are no longer considered valid by the object creator. Revoking an object is permanent; future versions of the object with this `id` **MUST NOT** be created.
    pub revoked: Option<bool>,
    /// Specifies an optional set of terms used to describe this object.
    /// The terms are user-defined or trust-group defined and their meaning is outside the scope of this specification.
    pub labels: Option<Vec<String>>,
    /// Identifies the confidence that the creator has in the correctness of their data.
    ///
    /// **MUST** be a number in the range of 0-100.
    /// Omitted if the confidence is unspecified.
    pub confidence: Option<u8>,
    /// Identifies the language of the text content in this object.
    ///
    /// **MUST** be a language code conformant to [RFC5646](https://www.rfc-editor.org/info/rfc5646).
    /// If omitted, then the language of the content is `en` (English).
    pub lang: Option<String>,
    /// Specifies a list of external references which refers to non-STIX information.
    /// Provides descriptions, URLs, or IDs to other system's records.
    pub external_references: Option<Vec<ExternalReference>>,
    /// Specifies a list of identities of marking-definition objects that apply to this object.
    pub object_marking_refs: Option<Vec<Identifier>>,
    pub granular_markings: Option<Vec<GranularMarking>>,
    /// This property defines whether or not the data contained within the object has been defanged.
    ///
    /// `None` is the same as `Some(false)`
    /// This property **MUST NOT** be used for any STIX Objects other than SCOs.
    pub defanged: Option<bool>,
    /// Specifies any extensions of the object, as a dictionary.
    ///
    /// Dictionary keys SHOULD be the id of a STIX Extension object or the name of a predefined object extension found in this specification,
    /// depending on the type of extension being used.
    ///
    /// The corresponding dictionary values **MUST** contain the contents of the extension instance.
    pub extensions: Option<StixDictionary<StixDictionary<DictionaryValue>>>,
}

impl Stix for CommonProperties {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(spec_version) = &self.spec_version {
            if spec_version != "2.1" {
                errors.push(Error::ValidationError(format!(
                    "The spec version of Object {} is {}. It must be 2.1.",
                    self.id, spec_version
                )));
            }
        }
        if let Some(creator) = &self.created_by_ref {
            add_error(&mut errors, creator.stix_check());
            if creator.get_type() != "identity" {
                errors.push(Error::ValidationError(format!("Object {} has a 'created by' reference to an object of type '{}'. Only an Identity SDO can be the creator of another STIX object.",
                    self.id,
                    creator.get_type()
                )));
            }
        }
        if let (Some(created), Some(modified)) = (&self.created, &self.modified) {
            if modified < created {
                errors.push(Error::ValidationError(format!("Object {} has a modified timestamp of {} and a created timestamp of {}. The former cannot be earlier than the latter.",
                    self.id,
                    modified,
                    created
                )));
            }
        }
        if let Some(confidence_number) = self.confidence {
            if confidence_number > 100 {
                errors.push(Error::ValidationError(format!("The confidence value of Object {} is {}. An object's confidence value cannot be greater than 100.",
                    self.id,
                    confidence_number
                )));
            }
        }
        if let Some(external_references) = &self.external_references {
            add_error(&mut errors, external_references.stix_check());
        }
        if let Some(language) = &self.lang {
            match LanguageTag::parse(language) {
                Ok(tag) => if let Err(e) = LanguageTag::validate(&tag) {
                    errors.push(Error::ValidationError(format!("Object {}'s `language` is {}. A `language` must conform to RFC5646. Details: {}",
                    self.id,
                    language,
                    e
                )));
                }
                Err(e) => errors.push(Error::ValidationError(format!("Object {}'s `language` is {}. A `language` must conform to RFC5646. Details: {}",
                    self.id,
                    language,
                    e
                ))),
            }
        }
        if let Some(granular_markings) = &self.granular_markings {
            add_error(&mut errors, granular_markings.stix_check());
        }
        if let Some(extensions) = &self.extensions {
            add_error(&mut errors, extensions.stix_check());
            for (key, value) in extensions.iter() {
                // Check constraints for general extensions, idetified by using a STIX identifer as the extension key
                if let Ok(id) = Identifier::from_str(key) {
                    if id.get_type() != "extension-definition" {
                        warn!("If `extensions` keys are STIX Object id's, they should be the id of an Extension Definition SMO. Object {} has an extension id key {}.",
                            self.id,
                            key
                        )
                    }

                    if !value.keys().any(|k| k == "extension_type") {
                        errors.push(Error::ValidationError(format!("If an `extensions` dictionary entry is not predefined object extension, the 'extension_type' property must be present in that dictionary entry. Object {} has an extension with key {} that is missing that property",
                            self.id,
                            key,
                        )));
                    }

                    for (inner_key, inner_value) in value.iter() {
                        if inner_key == "extension_type" {
                            if let DictionaryValue::String(inner_value_string) = inner_value {
                                if ExtensionType::iter()
                                    .all(|x| x.as_ref() != stix_case(inner_value_string))
                                {
                                    errors.push(Error::ValidationError(format!("The value of an 'extension_type' property in an `extensions` dictionary entry must come from the `extension-type-enum` enumeration. Object {} has an extension with key {} whose `extension_type` value is {}.",
                                        self.id,
                                        key,
                                        inner_value
                                    )));
                                }
                            } else {
                                errors.push(Error::ValidationError(format!("The value of an 'extension_type' property in an `extensions` dictionary entry must come from the `extension-type-enum` enumeration. Object {} has an extension with key {} whose `extension_type` value is {}.",
                                        self.id,
                                        key,
                                        inner_value
                                    )));
                            }
                        }
                    }
                // Check known SCO-specific predefined extensions
                } else {
                    match self.id.get_type() {
                    "file" => if FileExtensions::iter().any(|x| x.as_ref() == stix_case(key)) {
                        add_error(&mut errors, check_extension(key, value));
                    } else {
                        errors.push(Error::WrongExtension)
                    }
                    "network-traffic" => if NetworkTrafficExtensions::iter().any(|x| x.as_ref() == stix_case(key)) {
                        add_error(&mut errors, check_extension(key, value));
                    } else {
                        errors.push(Error::WrongExtension)
                    }
                    "process" => if ProcessExtensions::iter().any(|x| x.as_ref() == stix_case(key)) {
                        add_error(&mut errors, check_extension(key, value));
                    } else {
                       errors.push(Error::WrongExtension)
                    }
                    "user-account" => if UserAccountExtensions::iter().any(|x| x.as_ref() == stix_case(key)) {
                        add_error(&mut errors, check_extension(key, value));
                    } else {
                        errors.push(Error::WrongExtension)
                    }
                    _ => warn!("`extensions` keys should be the id of an Extension Definition SMO, unless you are using a predefined object extension. Confirm that object {}'s extension key {} is a predefined object extension.",
                        self.id,
                        key
                    )
            }

                    add_error(&mut errors, value.stix_check());
                }
            }
        }

        return_multiple_errors(errors)
    }
}

/// Builder struct for common STIX properties.
///
/// This follows the "Rust builder pattern," where we  use a `new()` function to construct a Builder
/// with a minimum set of required fields, then set additional fields with their own setter functions.
/// Once all fields have been set, the `build()` function will take all of the fields in the Builder
/// struct and use them to create the final `CommonProperties` struct.
///
/// This struct is intended to be nested inside of a STIX Object's `Builder` struct to help with building
/// that object by constructing the common properties.
///
/// Because different STIX Objects have different common properties, they should check that they have all
/// required properties and do not have any omitted properties as part of their own `stix_check()` function
/// during the build stage.
#[derive(Clone, Debug, Serialize)]
pub struct CommonPropertiesBuilder {
    /// The kind of Stix Object for which we are building the common properties
    stix_object: StixObject,
    /// Whether we are creating a new object or versioning an existing one.
    pub builder_type: BuilderType,
    /// The common properties that will be added to the object being built
    pub properties: CommonProperties,
}

impl CommonPropertiesBuilder {
    /// Construct a `CommonPropertiesBuilder` with default values for the properties
    /// Used when building a new STIX Object.
    pub fn new(object_name: &str, type_name: &str) -> Result<CommonPropertiesBuilder, Error> {
        let stix_object =
            StixObject::from_str(&stix_case(object_name)).map_err(Error::UnrecognizedObject)?;
        let properties = CommonProperties {
            spec_version: Some("2.1".to_string()),
            id: Identifier::new(&stix_case(type_name))?,
            created_by_ref: Default::default(),
            created: Default::default(),
            modified: Default::default(),
            revoked: Default::default(),
            labels: Default::default(),
            confidence: Default::default(),
            // Under STIX 2.1, a missing `lang` field is treated as "en"
            lang: Default::default(),
            external_references: Default::default(),
            object_marking_refs: Default::default(),
            granular_markings: Default::default(),
            defanged: Default::default(),
            extensions: Default::default(),
        };

        Ok(CommonPropertiesBuilder {
            stix_object,
            builder_type: BuilderType::Creation,
            properties,
        })
    }

    /// Construct a `CommonPropertiesBuilder` by cloning an existing set of properites
    /// Used when versioning an existing STIX Object.
    pub fn version(
        object_name: &str,
        old: &CommonProperties,
    ) -> Result<CommonPropertiesBuilder, Error> {
        let stix_object =
            StixObject::from_str(&stix_case(object_name)).map_err(Error::UnrecognizedObject)?;
        let properties = CommonProperties {
            spec_version: old.spec_version.clone(),
            id: old.id.clone(),
            created_by_ref: old.created_by_ref.clone(),
            created: old.created.clone(),
            modified: old.modified.clone(),
            revoked: Default::default(),
            labels: old.labels.clone(),
            confidence: old.confidence,
            lang: old.lang.clone(),
            external_references: old.external_references.clone(),
            object_marking_refs: old.object_marking_refs.clone(),
            granular_markings: old.granular_markings.clone(),
            defanged: old.defanged,
            extensions: old.extensions.clone(),
        };

        Ok(CommonPropertiesBuilder {
            stix_object,
            builder_type: BuilderType::Version,
            properties,
        })
    }

    // Setter functions for common properties

    /// Set the `created_by_ref` field for an object under construction
    /// This is only allowed when creating a new object, not when versioning an existing one,
    /// as only the original creator of an object can version it.
    pub fn created_by_ref(mut self, id: Identifier) -> Result<Self, Error> {
        match self.builder_type {
            BuilderType::Creation => {
                self.properties.created_by_ref = Some(id);
                Ok(self)
            }
            BuilderType::Version => Err(Error::UnableToVersion(
                "You are not allowed to change the creator when versioning an existing object"
                    .to_string(),
            )),
        }
    }

    /// Set the optional `labels` field for an object under construction.
    pub fn labels(mut self, labels: Vec<String>) -> Self {
        self.properties.labels = Some(labels);
        self
    }

    /// Set the optional `confidence` field for an object under construction.
    pub fn confidence(mut self, confidence: u8) -> Self {
        self.properties.confidence = Some(confidence);
        self
    }

    /// Set the optional `lang` field for an object under construction.
    /// If the language is English ("en"), this does not need to be set (but it can be if specificity is desired).
    pub fn lang(mut self, language: String) -> Self {
        self.properties.lang = Some(language);
        self
    }

    /// Set the optional `external_references` field for an object under construction.
    pub fn external_references(mut self, references: Vec<ExternalReference>) -> Self {
        self.properties.external_references = Some(references);
        self
    }

    /// Set the optional `object_marking_refs` field for an object under construction.
    pub fn object_marking_refs(mut self, references: Vec<Identifier>) -> Self {
        self.properties.object_marking_refs = Some(references);
        self
    }

    /// Set the optional `defanged` field to `Some(true)` for an object under construction.
    pub fn defanged(mut self) -> Self {
        self.properties.defanged = Some(true);
        self
    }

    /// Set the optional `granular_markings` field for an object under construction.
    pub fn granular_markings(mut self, markings: Vec<GranularMarking>) -> Self {
        self.properties.granular_markings = Some(markings);
        self
    }

    /// Add an optional extension to the `extensions` field for an object under construction, creating the field if it does not already exist.
    pub fn add_extension(
        mut self,
        key: &str,
        extension: StixDictionary<DictionaryValue>,
    ) -> Result<Self, Error> {
        if let Some(ref mut extensions) = self.properties.extensions {
            extensions.insert(key, extension)?
        } else {
            let mut extensions = StixDictionary::new();
            extensions.insert(key, extension)?;
            self.properties.extensions = Some(extensions);
        }

        Ok(self)
    }

    pub fn build(&self) -> CommonProperties {
        let properties = self.properties.clone();

        // If the object is not an SCO, set the `created` datetime, and if it is also not a Data Markings, set the `modified` datetime.
        let (created, modified) = match self.stix_object {
            StixObject::Sco => (None, None),
            StixObject::MarkingDefinition => {
                // Get the current datetime, for setting `modified` and conditionally `created`
                let now = Timestamp::now();
                // If we are creating a new object, `created` is set to the time of creation
                // If we are versioning an existing object, `created` stays the same as before
                let created = match self.builder_type {
                    BuilderType::Creation => Some(now.clone()),
                    BuilderType::Version => properties.created,
                };
                (created, None)
            }
            _ => {
                // Get the current datetime, for setting `modified` and conditionally `created`
                let now = Timestamp::now();
                // If we are creating a new object, `created` is set to the time of creation
                // If we are versioning an existing object, `created` stays the same as before
                let created = match self.builder_type {
                    BuilderType::Creation => Some(now.clone()),
                    BuilderType::Version => properties.created,
                };
                let modified = Some(now);
                (created, modified)
            }
        };

        CommonProperties {
            spec_version: properties.spec_version,
            id: properties.id,
            created_by_ref: properties.created_by_ref,
            created,
            granular_markings: properties.granular_markings,
            modified,
            // Since we are making a new object or new version of an object, we cannot create it already revoked
            revoked: None,
            labels: properties.labels,
            confidence: properties.confidence,
            lang: properties.lang,
            external_references: properties.external_references,
            defanged: properties.defanged,
            object_marking_refs: properties.object_marking_refs,
            extensions: properties.extensions,
        }
    }
}

/// List of possible STIX Objects that have some of the common properties.
#[derive(Clone, Debug, PartialEq, Eq, EnumString, Serialize)]
#[strum(serialize_all = "kebab-case")]
pub enum StixObject {
    Sdo,
    Sro,
    Sco,
    ExtensionDefinition,
    LanguageContent,
    MarkingDefinition,
    Custom,
}

/// Whether the object under construction is a new object or a version of an existing one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum BuilderType {
    Creation,
    Version,
}
