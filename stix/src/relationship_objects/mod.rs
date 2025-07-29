//! Data structures and functions for implementing STIX Relationship Objects (SROs).

#![allow(dead_code)]

pub mod types;

use crate::{
    base::{CommonProperties, CommonPropertiesBuilder, Stix},
    error::{add_error, return_multiple_errors, StixError as Error},
    json,
    relationship_objects::types::RelationshipType,
    types::{
        DictionaryValue, ExternalReference, GranularMarking, Identified, Identifier, ScoTypes,
        SdoTypes, SroTypes, StixDictionary, StixMetaTypes, Timestamp,
    },
};

use convert_case::{Case, Casing};
use log::warn;
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_opt_u64;
use serde_with::skip_serializing_none;
use std::str::FromStr;
use strum::{AsRefStr, Display as StrumDisplay, IntoEnumIterator};

/// A trait for all STIX Objects that can be related by SROs.
pub trait Related {
    fn add_relationship<T: Related + Identified>(
        self,
        target: T,
        relationship_type: String,
    ) -> Result<RelationshipObjectBuilder, Error>;
}

/// Represents a STIX Relationship Object (SRO).
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RelationshipObject {
    /// Identifies the type of STIX Object.
    ///
    /// For SROs, this is either "relationship" for a generic relationship or "sighting"
    #[serde(flatten)]
    pub object_type: RelationshipObjectType,
    /// Common object properties
    #[serde(flatten)]
    pub common_properties: CommonProperties,
    /// Provides more details and context about the Relationship, potentially including its purpose and its key characteristics.
    pub description: Option<String>,
}

impl RelationshipObject {
    /// Deserializes an SRO from a JSON String.
    /// Checks that all fields conform to the STIX 2.1 standard
    /// If the `allow_custom` flag is flase, checks that there are no fields in the JSON String that are not in the SRO type definition
    pub fn from_json(json: &str, allow_custom: bool) -> Result<Self, Error> {
        let relationship_object: Self =
            serde_json::from_str(json).map_err(|e| Error::DeserializationError(e.to_string()))?;
        relationship_object.stix_check()?;

        if !allow_custom {
            json::field_check(&relationship_object, json)?;
        }

        Ok(relationship_object)
    }

    pub fn is_revoked(&self) -> bool {
        matches!(self.common_properties.revoked, Some(true))
    }

    /// Retunrs the relationship type for generic SROs or "sighting" if the SRO is a Sighting
    pub fn get_relationship_type(&self) -> &str {
        match &self.object_type {
            RelationshipObjectType::Relationship(relationship) => {
                relationship.relationship_type.as_ref()
            }
            RelationshipObjectType::Sighting(_) => "sighting",
        }
    }
}

/// Returns a reference to the identifier of the `RelationshipObject`.
// This implementation accesses the `id` field from the `common_properties`
// of the `RelationshipObject`, providing a way to retrieve the unique
// identifier associated with this object.
impl Identified for RelationshipObject {
    fn get_id(&self) -> &Identifier {
        &self.common_properties.id
    }
}

impl Stix for RelationshipObject {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Check that we have the correct common properties for an SRO
        add_error(&mut errors, check_sro_properties(&self.common_properties));

        // Check common properties
        add_error(&mut errors, self.common_properties.stix_check());

        // Check specific properties for the type of SRO
        match &self.object_type {
            RelationshipObjectType::Relationship(relationship) => add_error(
                &mut errors,
                relationship.stix_check().map_err(|e| {
                    Error::ValidationError(format!(
                        "Relationship Object {} is not a valid generic relationship: {}",
                        self.get_id(),
                        e
                    ))
                }),
            ),
            RelationshipObjectType::Sighting(sighting) => add_error(
                &mut errors,
                sighting.stix_check().map_err(|e| {
                    Error::ValidationError(format!(
                        "Relationship Object {} is not a valid sighting: {}",
                        self.get_id(),
                        e
                    ))
                }),
            ),
        }

        return_multiple_errors(errors)
    }
}

// Checks that the required properties for an SRO are present and that the prohibited fields for an SRO are not present
pub fn check_sro_properties(properties: &CommonProperties) -> Result<(), Error> {
    let mut errors = Vec::new();

    // Check that the `spec_version` field exists for SROs
    if properties.spec_version.is_none() {
        errors.push(Error::ValidationError(
            "SDOs must have a `spec_version` property.".to_string(),
        ));
    }
    // Check that the `created` field exists for SROs
    if properties.created.is_none() {
        errors.push(Error::ValidationError(
            "SDOs must have a `created` property.".to_string(),
        ));
    }
    // Check that the `modified` field exists for SROs
    if properties.modified.is_none() {
        errors.push(Error::ValidationError(
            "SDOs must have a `modified` property.".to_string(),
        ));
    }
    // Check that the `defanged` property is `None` for SROs
    if properties.defanged.is_some() {
        errors.push(Error::ValidationError(
            "SDOs cannot have a `defanged` property.".to_string(),
        ));
    }

    return_multiple_errors(errors)
}

/// Whether the SRO is a standard generic or a sighting
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, AsRefStr, StrumDisplay)]
#[serde(tag = "type", rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum RelationshipObjectType {
    Relationship(Relationship),
    Sighting(Sighting),
}

/// Nested struct for properties only found in generic SROs
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relationship {
    /// The type of relationship
    ///
    /// This **SHOULD** be a value specified for the source and target objects, but **MAY** be any String
    #[serde(flatten)]
    pub relationship_type: RelationshipType,
    /// The id of the source (from) object. **MUST** be the id of an SRO or SCO
    pub source_ref: Identifier,
    /// The id of the target (to) object. **MUST** be the id of an SRO or SCO
    pub target_ref: Identifier,
    /// An optional timestamp representing the earliest time at which the Relationship exists.
    ///
    /// May be a future time if used as an estimate
    pub start_time: Option<Timestamp>,
    /// An optional timestamp representing the latest time at which the Relationship exists.
    ///
    /// **MUST** be later than `start_time`
    /// May be a future time if used as an estimate
    pub stop_time: Option<Timestamp>,
}
impl Stix for Relationship {
    fn stix_check(&self) -> Result<(), Error> {
        if let RelationshipType::Custom(custom_type) = &self.relationship_type {
            warn!("A relationship type should come from the STIX relationship types vocabulary. Relationship type {} is not in the vocabulary.",
                custom_type
            );
        } else {
            self.relationship_type
                .validate(&self.source_ref, &self.target_ref)?;
        }

        if self.source_ref.get_type() == "relationship"
            || self.target_ref.get_type() == "relationship"
        {
            warn!("The source and target of a Relationship Object cannot be another Relationship Object. This generic SRO points from a {} to a {}.",
                self.source_ref.get_type(), self.target_ref.get_type()
            );
        }

        self.source_ref.stix_check()?;
        self.target_ref.stix_check()?;

        if let (Some(start), Some(stop)) = (&self.start_time, &self.stop_time) {
            if stop < start {
                return Err(Error::ValidationError(format!("This generic SRO has a stop timestamp of {} and a start timestamp of {}. The former cannot be earlier than or the same as the latter.",
                    stop,
                    start
                )));
            }
        }

        Ok(())
    }
}

/// Nested struct for properties only found in Sightings
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sighting {
    /// The beginning of the time window during which the SDO referenced by the `sighting_of_ref` property was sighted.
    pub first_seen: Option<Timestamp>,
    /// The end of the time window during which the SDO referenced by the `sighting_of_ref` property was sighted.
    ///
    /// If this property and the `first_seen`` property are both defined, then this property **MUST** be greater than or equal
    /// to the timestamp in the `first_seen` property.
    pub last_seen: Option<Timestamp>,
    /// If present, this **MUST** be an integer between 0 and 999,999,999 inclusive and represents the number of times the
    /// SDO referenced by the sighting_of_ref property was sighted.
    ///
    /// A sighting with a count of 0 can be used to express that an indicator was not seen at all.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub count: Option<u64>,
    /// An ID reference to the SDO that was sighted (e.g., Indicator or Malware).
    ///
    /// This property **MUST** reference only an SDO.
    pub sighting_of_ref: Identifier,
    /// A list of ID references to the Observed Data objects that contain the raw cyber data for this Sighting.
    ///
    /// This property **MUST** reference only Observed Data SDOs.
    pub observed_data_refs: Option<Vec<Identifier>>,
    /// A list of ID references to the Identity or Location objects describing the entities or types of entities that saw the sighting.
    ///
    /// This property **MUST** reference only Identity or Location SDOs.
    pub where_sighted_refs: Option<Vec<Identifier>>,
    /// The summary property indicates whether the Sighting should be considered summary data. Summary data is an aggregation of
    /// previous Sightings reports and should not be considered primary source data.
    pub summary: Option<bool>,
}

impl Stix for Sighting {
    fn stix_check(&self) -> Result<(), Error> {
        if let Some(count) = &self.count {
            count.stix_check()?;
        }
        if let (Some(start), Some(stop)) = (&self.first_seen, &self.last_seen) {
            if stop < start {
                return Err(Error::ValidationError(format!("This sighting SRO has a last seen timestamp of {} and a first seen timestamp of {}. The former cannot be earlier than or the same as the latter.",
                    stop,
                    start
                )));
            }
        }

        if let Some(count) = self.count {
            if count > 999999999 {
                return Err(Error::ValidationError(format!("This sighting SRO has a count of {}. This field cannot have a value larger than 999,999,999.",
                count
            )));
            }
        }

        if SdoTypes::iter()
            .all(|x| x.as_ref() != self.sighting_of_ref.get_type().to_case(Case::Kebab))
        {
            warn!(
                "Sighting of ref must be an SDO. Sighting of ref is type {}.",
                self.sighting_of_ref.get_type()
            );
        }
        if !ScoTypes::iter()
            .all(|x| x.as_ref() != self.sighting_of_ref.get_type().to_case(Case::Kebab))
            || !StixMetaTypes::iter()
                .all(|x| x.as_ref() != self.sighting_of_ref.get_type().to_case(Case::Kebab))
            || !SroTypes::iter()
                .all(|x| x.as_ref() != self.sighting_of_ref.get_type().to_case(Case::Kebab))
        {
            return Err(Error::ValidationError(format!(
                "Sighting of ref must be an SDO. Sighting of ref is type {}.",
                self.sighting_of_ref.get_type()
            )));
        }

        self.sighting_of_ref.stix_check()?;

        if let Some(observed_data_refs) = &self.observed_data_refs {
            let mut bad_refs = Vec::new();
            for data_ref in observed_data_refs {
                if data_ref.get_type() != "observed-data" {
                    bad_refs.push(data_ref.get_type());
                }
            }

            if !bad_refs.is_empty() {
                return Err(Error::ValidationError(format!("This sighting SRO contains 'observed' data refs of types {}. This field must reference only Observed Data SDOs.",
                    bad_refs.join(", ")
                )));
            }
        }

        if let Some(where_sighted_refs) = &self.where_sighted_refs {
            let mut bad_refs = Vec::new();
            for data_ref in where_sighted_refs {
                if ["identity", "location"].contains(&data_ref.get_type()) {
                    bad_refs.push(data_ref.get_type());
                }
            }

            if !bad_refs.is_empty() {
                return Err(Error::ValidationError(format!("This sighting SRO contains 'where sighted' refs of types {}. This field must reference only Identity or Location SDOs.",
                    bad_refs.join(", ")
                )));
            }
        }

        Ok(())
    }
}

/// Creates a new STIX 2.1 `RelationshipObject` of the given type
#[derive(Clone, Debug)]
pub struct RelationshipObjectBuilder {
    object_type: RelationshipObjectType,
    common_properties: CommonPropertiesBuilder,
    description: Option<String>,
}

impl RelationshipObjectBuilder {
    /// Creates a new STIX 2.1 RelationshipObjectBuilder of the for the given relationship type between two object Identifiers
    ///
    /// The `source`, `target`, and `relationship_type` fields must be lowercase, with words separated by `-`
    ///
    /// Automatically generates an `id`
    /// Other fields are set to their Default (which is `None`` for optional fields)
    pub fn new(
        source: Identifier,
        target: Identifier,
        relationship_type: &str,
    ) -> Result<RelationshipObjectBuilder, Error> {
        // Get the relationship type if it is in the STIX list of relationship types, or else create a custom relationship type
        let final_relationship_type =
            RelationshipType::from_str(&relationship_type.replace("-", ""))
                .unwrap_or_else(|_| RelationshipType::Custom(relationship_type.to_string()));
        // Validate that the relationship type is allowed between the source and target (this will never return an error for a custom type)
        final_relationship_type.validate(&source, &target)?;

        // Build the common properties with generated and default values
        let common_properties = CommonPropertiesBuilder::new("sro", "relationship")?;

        // The initial inner `Relationship` struct will be created with default values other than the provided relationship information
        Ok(RelationshipObjectBuilder {
            object_type: RelationshipObjectType::Relationship(Relationship {
                relationship_type: final_relationship_type,
                source_ref: source,
                target_ref: target,
                start_time: Default::default(),
                stop_time: Default::default(),
            }),
            common_properties,
            description: Default::default(),
        })
    }

    /// Creates a new STIX 2.1 RelationshipObjectBuilder for a sighting of an object Identifier
    ///
    /// The `type` field must be lowercase, with words separated by `-`
    ///
    /// Automatically generates an `id`
    /// Other fields are set to their Default (which is `None`` for optional fields)
    pub fn new_sighting(sighting_of_ref: Identifier) -> Result<RelationshipObjectBuilder, Error> {
        let common_properties = CommonPropertiesBuilder::new("sro", "sighting")?;

        // The initial inner `Sighting` struct will be created with default values other than the provided `sighting_of_ref`
        Ok(RelationshipObjectBuilder {
            object_type: RelationshipObjectType::Sighting(Sighting {
                first_seen: Default::default(),
                last_seen: Default::default(),
                count: Default::default(),
                sighting_of_ref,
                observed_data_refs: Default::default(),
                where_sighted_refs: Default::default(),
                summary: Default::default(),
            }),
            common_properties,
            description: Default::default(),
        })
    }

    /// Create a new STIX 2.1 `RelationshipObjectBuilder` by cloning the fields from an existing `RelationshipObject`
    /// When built, this will create `RelationshipObject` as a newer version of the original object.
    pub fn version(old: &RelationshipObject) -> Result<RelationshipObjectBuilder, Error> {
        if old.is_revoked() {
            return Err(Error::UnableToVersion(format!(
                "SRO {} is revoked. Versioning a revoked object is prohibited.",
                old.common_properties.id
            )));
        }

        let object_type = old.object_type.clone();
        let description = old.description.clone();
        let old_properties = old.common_properties.clone();
        let common_properties = CommonPropertiesBuilder::version("sro", &old_properties)?;

        Ok(RelationshipObjectBuilder {
            object_type,
            common_properties,
            description,
        })
    }

    // Setter functions for optional properties common to both SRO types

    /// Set the optional `created_by_ref` field for an SRO under construction.
    /// This is only allowed when creating a new SRO, not when versioning an existing one,
    /// as only the original creator of an object can version it.
    pub fn created_by_ref(mut self, id: Identifier) -> Result<Self, Error> {
        self.common_properties = self.common_properties.clone().created_by_ref(id)?;
        Ok(self)
    }

    /// Set the optional `labels` field for an SRO under construction.
    pub fn labels(mut self, labels: Vec<String>) -> Self {
        self.common_properties = self.common_properties.clone().labels(labels);
        self
    }

    /// Set the optional `confidence` field for an SRO under construction.
    pub fn confidence(mut self, confidence: u8) -> Self {
        self.common_properties = self.common_properties.clone().confidence(confidence);
        self
    }

    /// Set the optional `lang` field for an SRO under construction.
    /// If the language is English ("en"), this does not need to be set (but it can be if specificity is desired).
    pub fn lang(mut self, language: String) -> Self {
        self.common_properties = self.common_properties.clone().lang(language);
        self
    }

    /// Set the optional `external_references` field for an SRO under construction.
    pub fn external_references(mut self, references: Vec<ExternalReference>) -> Self {
        self.common_properties = self
            .common_properties
            .clone()
            .external_references(references);
        self
    }

    /// Set the optional `object_marking_refs` field for an SRO under construction.
    pub fn object_marking_refs(mut self, references: Vec<Identifier>) -> Self {
        self.common_properties = self
            .common_properties
            .clone()
            .object_marking_refs(references);
        self
    }

    /// Set the optional `granular_markings` field for an SRO under construction.
    pub fn granular_markings(mut self, markings: Vec<GranularMarking>) -> Self {
        self.common_properties = self.common_properties.clone().granular_markings(markings);
        self
    }

    /// Add an optional extension to the `extensions` field for an SRO under construction, creating the field if it does not exist
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

    /// Set the optional `description` field for an SRO under construction
    pub fn description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    // Setter functions for properties that exist only for generic "relationship" SROs
    // These functions will error if you try to set these properties for a "sighting"

    /// Set the optional `start time` field for a generic SRO under construction.
    pub fn start_time(mut self, datetime: &str) -> Result<Self, Error> {
        if let RelationshipObjectType::Relationship(ref mut relationship) = self.object_type {
            let start_time = Timestamp(datetime.parse().map_err(Error::DateTimeError)?);
            relationship.start_time = Some(start_time);
            return Ok(self);
        }

        Err(Error::IllegalBuilderProperty {
            object: "SROs".to_string(),
            object_type: self.object_type.to_string(),
            field: "start time".to_string(),
        })
    }

    /// Set the optional `stop time` field for a generic SRO under construction.
    pub fn stop_time(mut self, datetime: &str) -> Result<Self, Error> {
        if let RelationshipObjectType::Relationship(ref mut relationship) = self.object_type {
            let stop_time = Timestamp(datetime.parse().map_err(Error::DateTimeError)?);
            relationship.stop_time = Some(stop_time);
            return Ok(self);
        }

        Err(Error::IllegalBuilderProperty {
            object: "SROs".to_string(),
            object_type: self.object_type.to_string(),
            field: "stop time".to_string(),
        })
    }

    // Setter functions for properties that exist only for "sighting" SROs
    // These functions will error if you try the property for a a generic "relationship"

    /// Set the optional `first_seen` field for a sightings SRO under construction.
    pub fn first_seen(mut self, datetime: &str) -> Result<Self, Error> {
        if let RelationshipObjectType::Sighting(ref mut sighting) = self.object_type {
            let first_seen = Timestamp(datetime.parse().map_err(Error::DateTimeError)?);
            sighting.first_seen = Some(first_seen);
            return Ok(self);
        }

        Err(Error::IllegalBuilderProperty {
            object: "SROs".to_string(),
            object_type: self.object_type.to_string(),
            field: "first seen".to_string(),
        })
    }

    /// Set the optional `last_seen` field for a sightings SRO under construction.
    pub fn last_seen(mut self, datetime: &str) -> Result<Self, Error> {
        if let RelationshipObjectType::Sighting(ref mut sighting) = self.object_type {
            let last_seen = Timestamp(datetime.parse().map_err(Error::DateTimeError)?);
            sighting.last_seen = Some(last_seen);
            return Ok(self);
        }

        Err(Error::IllegalBuilderProperty {
            object: "SROs".to_string(),
            object_type: self.object_type.to_string(),
            field: "last seen".to_string(),
        })
    }

    /// Set the optional `count` field for a sightings SRO under construction.
    pub fn count(mut self, count: u64) -> Result<Self, Error> {
        if let RelationshipObjectType::Sighting(ref mut sighting) = self.object_type {
            sighting.count = Some(count);
            return Ok(self);
        }

        Err(Error::IllegalBuilderProperty {
            object: "SROs".to_string(),
            object_type: self.object_type.to_string(),
            field: "count".to_string(),
        })
    }

    /// Set the optional `observed_data_refs` field for a sightings SRO under construction.
    pub fn observed_data_refs(
        mut self,
        observed_data_refs: Vec<Identifier>,
    ) -> Result<Self, Error> {
        if let RelationshipObjectType::Sighting(ref mut sighting) = self.object_type {
            sighting.observed_data_refs = Some(observed_data_refs);
            return Ok(self);
        }

        Err(Error::IllegalBuilderProperty {
            object: "SROs".to_string(),
            object_type: self.object_type.to_string(),
            field: "observed data refs".to_string(),
        })
    }

    /// Set the optional `where_sighted_refs` field for a sightings SRO under construction.
    pub fn where_sighted_refs(
        mut self,
        where_sighted_refs: Vec<Identifier>,
    ) -> Result<Self, Error> {
        if let RelationshipObjectType::Sighting(ref mut sighting) = self.object_type {
            sighting.where_sighted_refs = Some(where_sighted_refs);
            return Ok(self);
        }

        Err(Error::IllegalBuilderProperty {
            object: "SROs".to_string(),
            object_type: self.object_type.to_string(),
            field: "where_sighted_refs".to_string(),
        })
    }

    /// Set the optional `summary` field for a sightings SRO under construction to `Some(true)`.
    pub fn set_summary(mut self) -> Result<Self, Error> {
        if let RelationshipObjectType::Sighting(ref mut sighting) = self.object_type {
            sighting.summary = Some(true);
            return Ok(self);
        }

        Err(Error::IllegalBuilderProperty {
            object: "SROs".to_string(),
            object_type: self.object_type.to_string(),
            field: "summary".to_string(),
        })
    }

    /// Builds a new SRO, using the information found in the RelationshipObjectBuilder
    ///
    /// This performs a final check that all required fields for a given SRO type are included before construction.
    /// This also runs the `stick_check()` validation method on the newly constructed SRO.
    pub fn build(self) -> Result<RelationshipObject, Error> {
        let common_properties = self.common_properties.build();

        let sro = RelationshipObject {
            object_type: self.object_type,
            common_properties,
            description: self.description,
        };

        sro.stix_check()?;

        Ok(sro)
    }
}
