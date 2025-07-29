//! Data structures and functions for implementing Lanugage Content SMOs

use std::str::FromStr;

use crate::{
    base::{CommonProperties, CommonPropertiesBuilder, Stix},
    error::{add_error, return_multiple_errors, StixError as Error},
    json,
    relationship_objects::{Related, RelationshipObjectBuilder},
    types::{
        DictionaryValue, ExternalReference, GranularMarking, Identified, Identifier,
        StixDictionary, Timestamp,
    },
};
use language_tags::LanguageTag;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// A Language Content Stix Meta Object (SMO).
///
/// The Language Content object represents text content for STIX Objects represented in languages other than that of the original object. Language content may be a
/// translation of the original object by a third-party, a first-source translation by the original publisher, or additional official language content provided at the time
/// of creation.
///
/// Language Content contains two important sets of properties:
/// - The `object_ref` and `object_modified` properties specify the target object that the language content applies to.
///    - For example, to provide additional language content for a Campaign, the `object_ref` property should be set to the `id` of the Campaign and the `object_modified`
///      property set to its modified time. Most relationships in STIX are not specific to a particular version of a STIX object, but because language content provides the
///      translation of specific text, the `object_modified` property is necessary to provide that specificity.
/// - The `content` property is a dictionary which maps to properties in the target object in order to provide a translation of them.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_z9r1cwtu8jja>
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanguageContent {
    #[serde(rename = "type")]
    pub object_type: String,
    /// Common STIX object properties
    #[serde(flatten)]
    pub common_properties: CommonProperties,
    /// The `object_ref` property identifies the `id` of the object that this LanguageContent applies to. It **MUST** be the identifier for a STIX Object.
    pub object_ref: Identifier,
    /// The `object_modified` property identifies the modified time of the object that this LanguageContent applies to. It **MUST** be an exact match for the `modified` time
    /// of the STIX Object being referenced.
    pub object_modified: Option<Timestamp>,
    /// The contents property contains the actual Language Content (translation).
    ///
    /// The keys in the dictionary **MUST** be RFC 5646 language codes for which language content is being provided.
    ///
    /// The values each consist of a Vec that mirrors the properties in the target object (identified by `object_ref` and `object_modified`).
    pub contents: StixDictionary<StixDictionary<ContentType>>,
}

impl LanguageContent {
    /// Deserializes a LanguageContent SMO from a JSON String.
    /// Checks that all fields conform to the STIX 2.1 standard
    /// If the `allow_custom` flag is flase, checks that there are no fields in the JSON String that are not in the SDO type definition
    pub fn from_json(json: &str, allow_custom: bool) -> Result<Self, Error> {
        let language_content: Self =
            serde_json::from_str(json).map_err(|e| Error::DeserializationError(e.to_string()))?;
        language_content.stix_check()?;

        if !allow_custom {
            json::field_check(&language_content, json)?;
        }

        Ok(language_content)
    }

    pub fn is_revoked(&self) -> bool {
        matches!(self.common_properties.revoked, Some(true))
    }

    pub fn add_sighting(self) -> Result<RelationshipObjectBuilder, Error> {
        let sighting_of_ref = self.get_id().to_owned();

        RelationshipObjectBuilder::new_sighting(sighting_of_ref)
    }
}

/// Returns a reference to the identifier of the `LanguageContent`.
///
/// This implementation retrieves the `id` field from the `common_properties`
/// of the `LanguageContent`, allowing access to the unique identifier
/// associated with this object.
impl Identified for LanguageContent {
    fn get_id(&self) -> &Identifier {
        &self.common_properties.id
    }
}

impl Related for LanguageContent {
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

impl Stix for LanguageContent {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Check common properties
        add_error(&mut errors, self.common_properties.stix_check());

        // Check that required common properties fields are present and prohibited common properties fields are absent

        // Check that the `spec_version` field exists for Language Content SMOs
        if self.common_properties.spec_version.is_none() {
            errors.push(Error::ValidationError(
                "Language Content SMOs must have a `spec_version` property.".to_string(),
            ));
        }
        // Check that the `created` field exists for Language Content SMOs
        if self.common_properties.created.is_none() {
            errors.push(Error::ValidationError(
                "Language Content SMOs must have a `created` property.".to_string(),
            ));
        }
        // Check that the `modified` field exists for Language Content SMOs
        if self.common_properties.modified.is_none() {
            errors.push(Error::ValidationError(
                "Language Content SMOs must have a `modified` property.".to_string(),
            ));
        }
        // Check that the `lang` property is `None` for Language Content SMOs
        if self.common_properties.lang.is_some() {
            errors.push(Error::ValidationError(
                "Language Content SMOs cannot have a `lang` property.".to_string(),
            ));
        }
        // Check that the `defanged` property is `None` for Language Content SMOs
        if self.common_properties.defanged.is_some() {
            errors.push(Error::ValidationError(
                "Language Content SMOs cannot have a `defanged` property.".to_string(),
            ));
        }

        // Check specific LanguageContent type constraints
        if self.object_type != "language-content" {
            errors.push(Error::ValidationError(
                "Language Content SMOs must have a type of 'language-content'".to_string(),
            ));
        }

        // Validate that the `contents` field is a valid STIX Dictionary
        add_error(&mut errors, self.contents.stix_check());
        for (key, value) in self.contents.iter() {
            // Check that a dictionary key is an RFC5646 language code
            match LanguageTag::parse(key) {
                Ok(tag) => if let Err(e) = LanguageTag::validate(&tag) {
                    errors.push(Error::ValidationError(format!("One of the keys for LanguageContent Object {}'s `contents` dictionary is {}. A `content` key must conform to RFC5646. Details: {}",
                    self.common_properties.id,
                    key,
                    e
                )));
                }
                Err(e) => errors.push(Error::ValidationError(format!("One of the keys for LanguageContent Object {}'s `contents` dictionary is {}. A `content` key must conform to RFC5646. Details: {}",
                    self.common_properties.id,
                    key,
                    e
                ))),
            }
            // Check that the nested dictionary is a valid STIX Dictionary
            add_error(&mut errors, value.stix_check());
        }

        return_multiple_errors(errors)
    }
}

/// Options for the values of a LanguageContent `contents` dictionary
///
/// These values **MUST** mirror the original properties of the target object (e.g. if the original property is a String, the corresponding value must be a String)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ContentType {
    /// Translation of a single String
    String(String),
    /// Translation of a list of items. If no translation is provided for one or more elements of the original list, the untranlated items must be represented by ""
    List(Vec<String>),
    /// Translation of an entire STIX object or dictionary, represented as a nested LanguageContent object with its own properties based on the translated object or dictionary
    Object(Box<LanguageContent>),
}

impl Stix for ContentType {
    fn stix_check(&self) -> Result<(), Error> {
        match self {
            ContentType::String(string) => string.stix_check(),
            ContentType::List(list) => list.stix_check(),
            ContentType::Object(content) => content.stix_check(),
        }
    }
}

/// Builder struct for Language Content SMOs.
///
/// This follows the "Rust builder pattern," where we  use a `new()` function to construct a Builder
/// with a minimum set of required fields, then set additional fields with their own setter functions.
/// Once all fields have been set, the `build()` function will take all of the fields in the Builder
/// struct and use them to create the final `LanguageContent` struct.
///
/// Note: Because the `contents` dictionary property must be nonempty, the `build()` method will error
/// if no entries are added to this property, or if the `created_by_ref` property is not set.
#[derive(Clone, Debug)]
pub struct LanguageContentBuilder {
    /// Common STIX properties
    common_properties: CommonPropertiesBuilder,
    object_ref: Identifier,
    object_modified: Option<Timestamp>,
    contents: StixDictionary<StixDictionary<ContentType>>,
}

impl LanguageContentBuilder {
    /// Creates a new STIX 2.1 `LanguageContentBuilder` with a given `object_ref`
    ///
    /// The `object_ref` field must be a valid Stix id
    ///
    /// Automatically generates an `id`
    /// The `contents` field is created as an empty dictionary, whose entries must be added prior to the final build
    /// Other fields are set to their Default (which is `None`` for optional fields)
    pub fn new(object_ref: &str) -> Result<Self, Error> {
        // Parses the provided `object_ref` as a STIX id
        let object_ref_id = Identifier::from_str(object_ref)?;

        // Build the common properties with generated and default values
        let common_properties =
            CommonPropertiesBuilder::new("language-content", "language-content")?;

        Ok(Self {
            common_properties,
            object_ref: object_ref_id,
            object_modified: None,
            contents: StixDictionary::new(),
        })
    }

    /// Create a new STIX 2.1 `LanguageContentBuilder` by cloning the fields from an existing `LanguageContent`
    /// When built, this will create `LanguageContent` as a newer version of the original object.
    pub fn version(old: &LanguageContent) -> Result<Self, Error> {
        if old.is_revoked() {
            return Err(Error::UnableToVersion(format!(
                "LanguageContent SMO {} is revoked. Versioning a revoked object is prohibited.",
                old.common_properties.id
            )));
        }

        let object_ref = old.object_ref.clone();
        let object_modified = old.object_modified.clone();
        let contents = old.contents.clone();

        let old_properties = old.common_properties.clone();
        let common_properties =
            CommonPropertiesBuilder::version("language-content", &old_properties)?;

        Ok(Self {
            common_properties,
            object_ref,
            object_modified,
            contents,
        })
    }

    // Setter functions for common properties

    /// Set the `created_by_ref` field for a Language Content SMO under construction
    /// This is only allowed when creating a new Language Content SMO, not when versioning an existing one,
    /// as only the original creator of an object can version it.
    pub fn created_by_ref(mut self, id: Identifier) -> Result<Self, Error> {
        self.common_properties = self.common_properties.clone().created_by_ref(id)?;
        Ok(self)
    }

    /// Set the optional `labels` field for an Language Content SMO under construction
    pub fn labels(mut self, labels: Vec<String>) -> Self {
        self.common_properties = self.common_properties.clone().labels(labels);
        self
    }

    /// Set the optional `confidence` field for an Language Content SMO under construction
    pub fn confidence(mut self, confidence: u8) -> Self {
        self.common_properties = self.common_properties.clone().confidence(confidence);
        self
    }

    /// Set the optional `external_references` field for an Language Content SMO under construction
    pub fn external_references(mut self, references: Vec<ExternalReference>) -> Self {
        self.common_properties = self
            .common_properties
            .clone()
            .external_references(references);
        self
    }

    /// Set the optional `object_marking_refs` field for an Language Content SMO under construction
    pub fn object_marking_refs(mut self, references: Vec<Identifier>) -> Self {
        self.common_properties = self
            .common_properties
            .clone()
            .object_marking_refs(references);
        self
    }

    /// Set the optional `granular_markings` field for a Language Content SMO under construction.
    pub fn granular_markings(mut self, markings: Vec<GranularMarking>) -> Self {
        self.common_properties = self.common_properties.clone().granular_markings(markings);
        self
    }

    /// Add an optional extension to the `extensions` field for a Language Content SMO under construction, creating the field if it does not exist
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

    // Setter functions for Language Content specific properties

    /// Setter function for the optional `object_modified` property
    pub fn object_modified(mut self, object_modified: &str) -> Result<Self, Error> {
        self.object_modified = Some(Timestamp(
            object_modified.parse().map_err(Error::DateTimeError)?,
        ));
        Ok(self)
    }

    /// Add an element to the content dictionary
    pub fn insert_content(
        mut self,
        lang: &str,
        content: StixDictionary<ContentType>,
    ) -> Result<Self, Error> {
        self.contents.insert(lang, content)?;
        Ok(self)
    }

    /// Builds a new Language Content SMO, using the information found in the LanguageContentBuilder
    ///
    /// This runs the `stick_check()` validation method on the newly constructed SMO, which includes check that the `contents` dictionary is nonempty.
    pub fn build(self) -> Result<LanguageContent, Error> {
        let common_properties = self.common_properties.build();

        let object_ref = self.object_ref;
        let object_modified = self.object_modified;
        let contents = self.contents;

        let language_content = LanguageContent {
            object_type: "language-content".to_string(),
            common_properties,
            object_ref,
            object_modified,
            contents,
        };

        language_content.stix_check()?;

        Ok(language_content)
    }
}
