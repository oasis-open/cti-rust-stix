//! Contains the implementation logic for Stix Domain Objects (SDOs).

#![allow(dead_code)]

use crate::{
    base::{CommonProperties, CommonPropertiesBuilder, Stix},
    domain_objects::{
        sdo_types::{
            AttackPattern, Campaign, CourseOfAction, Grouping, Identity, Incident, Indicator,
            Infrastructure, IntrusionSet, Location, Malware, MalwareAnalysis, Note, ObservedData,
            Opinion, Report, ThreatActor, Tool, Vulnerability,
        },
        vocab::OpinionType,
    },
    error::{add_error, return_multiple_errors, StixError as Error},
    json,
    relationship_objects::{Related, RelationshipObjectBuilder},
    types::{
        DictionaryValue, ExternalReference, GranularMarking, Identified, Identifier,
        KillChainPhase, StixDictionary, Timestamp,
    },
};

use convert_case::{Case, Casing};
use jiff::Timestamp as JiffTimestamp;
use ordered_float::OrderedFloat as ordered_float;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::str::FromStr;
use strum::{AsRefStr, Display as StrumDisplay, EnumString};

/// A STIX Domain Object (SDO) of some type.
///
/// Each of SDO type corresponds to a unique concept commonly represented in CTI.
/// These types can be categorized as tactics, techniques, and procedures (TTPs) or as adversary information.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_nrhq5e9nylke>
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainObject {
    /// Identifies the type of SDO.
    #[serde(flatten)]
    pub object_type: DomainObjectType,
    /// Common object properties
    #[serde(flatten)]
    pub common_properties: CommonProperties,
}

impl DomainObject {
    /// Deserializes an SDO from a JSON String.
    /// Checks that all fields conform to the STIX 2.1 standard
    /// If the `allow_custom` flag is flase, checks that there are no fields in the JSON String that are not in the SDO type definition
    pub fn from_json(json: &str, allow_custom: bool) -> Result<Self, Error> {
        let domain_object: Self =
            serde_json::from_str(json).map_err(|e| Error::DeserializationError(e.to_string()))?;
        domain_object.stix_check()?;

        if !allow_custom {
            json::field_check(&domain_object, json)?;
        }

        Ok(domain_object)
    }

    pub fn is_revoked(&self) -> bool {
        matches!(self.common_properties.revoked, Some(true))
    }

    pub fn add_sighting(self) -> Result<RelationshipObjectBuilder, Error> {
        let sighting_of_ref = self.get_id().to_owned();

        RelationshipObjectBuilder::new_sighting(sighting_of_ref)
    }
}

// Returns a reference to the identifier of the `DomainObject`.
// This implementation accesses the `id` field from the `common_properties`
// of the `DomainObject`, providing a way to retrieve the unique identifier
// associated with this object.
impl Identified for DomainObject {
    fn get_id(&self) -> &Identifier {
        &self.common_properties.id
    }
}

impl Related for DomainObject {
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

impl Stix for DomainObject {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Check that we have the correct common properties for an SDO
        add_error(&mut errors, check_sdo_properties(&self.common_properties));

        // Check common properties
        add_error(&mut errors, self.common_properties.stix_check());

        // Check specific SDO type constraints
        add_error(
            &mut errors,
            self.object_type.stix_check().map_err(|e| {
                Error::ValidationError(format!(
                    "Domain Object {} is not a valid {}: {}",
                    self.get_id(),
                    self.object_type.as_ref(),
                    e
                ))
            }),
        );

        return_multiple_errors(errors)
    }
}

// Checks that the required properties for an SDO are present and that the prohibited fields for an SDO are not present
pub fn check_sdo_properties(properties: &CommonProperties) -> Result<(), Error> {
    let mut errors = Vec::new();

    // Check that the `spec_version` field exists for SDOs
    if properties.spec_version.is_none() {
        errors.push(Error::ValidationError(
            "SDOs must have a `spec_version` property.".to_string(),
        ));
    }
    // Check that the `created` field exists for SDOs
    if properties.created.is_none() {
        errors.push(Error::ValidationError(
            "SDOs must have a `created` property.".to_string(),
        ));
    }
    // Check that the `modified` field exists for SDOs
    if properties.modified.is_none() {
        errors.push(Error::ValidationError(
            "SDOs must have a `modified` property.".to_string(),
        ));
    }
    // Check that the `defanged` property is `None` for SDOs
    if properties.defanged.is_some() {
        errors.push(Error::ValidationError(
            "SDOs cannot have a `defanged` property.".to_string(),
        ));
    }

    return_multiple_errors(errors)
}

/// The various SDO types represented in STIX.
#[derive(
    Clone, Debug, PartialEq, Eq, Serialize, Deserialize, AsRefStr, EnumString, StrumDisplay,
)]
#[serde(tag = "type", rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum DomainObjectType {
    AttackPattern(AttackPattern),
    Campaign(Campaign),
    CourseOfAction(CourseOfAction),
    Grouping(Grouping),
    Identity(Identity),
    Incident(Incident),
    Indicator(Indicator),
    Infrastructure(Infrastructure),
    IntrusionSet(IntrusionSet),
    Location(Location),
    Malware(Malware),
    MalwareAnalysis(MalwareAnalysis),
    Note(Note),
    ObservedData(ObservedData),
    Opinion(Opinion),
    Report(Report),
    ThreatActor(ThreatActor),
    Tool(Tool),
    Vulnerability(Vulnerability),
}

impl Stix for DomainObjectType {
    /// Calls `stix_check()` on the internal SDO type struct
    fn stix_check(&self) -> Result<(), Error> {
        match self {
            DomainObjectType::AttackPattern(attack_pattern) => attack_pattern.stix_check(),
            DomainObjectType::Campaign(campaign) => campaign.stix_check(),
            DomainObjectType::CourseOfAction(course_of_action) => course_of_action.stix_check(),
            DomainObjectType::Grouping(grouping) => grouping.stix_check(),
            DomainObjectType::Identity(identity) => identity.stix_check(),
            DomainObjectType::Incident(incident) => incident.stix_check(),
            DomainObjectType::Indicator(indicator) => indicator.stix_check(),
            DomainObjectType::Infrastructure(infrastructure) => infrastructure.stix_check(),
            DomainObjectType::IntrusionSet(intrustion_set) => intrustion_set.stix_check(),
            DomainObjectType::Location(location) => location.stix_check(),
            DomainObjectType::Note(note) => note.stix_check(),
            DomainObjectType::ObservedData(observed_data) => observed_data.stix_check(),
            DomainObjectType::Opinion(opinion) => opinion.stix_check(),
            DomainObjectType::Malware(malware) => malware.stix_check(),
            DomainObjectType::MalwareAnalysis(malware_anlaysis) => malware_anlaysis.stix_check(),
            DomainObjectType::Report(report) => report.stix_check(),
            DomainObjectType::ThreatActor(threat_actor) => threat_actor.stix_check(),
            DomainObjectType::Tool(tool) => tool.stix_check(),
            DomainObjectType::Vulnerability(vulnerability) => vulnerability.stix_check(),
        }
    }
}

/// Builder struct for SDOs.
///
/// This follows the "Rust builder pattern," where we  use a `new()` function to construct a Builder
/// with a minimum set of required fields, then set additional fields with their own setter functions.
/// Once all fields have been set, the `build()` function will take all of the fields in the Builder
/// struct and use them to create the final `DomainObject` struct.
///
/// Note: Because different types of SDOs have different fields, and fields present in multiple types
/// may be requried in some and optional in others, it is possible for a `DomainObjectBuilder` to be
/// in an incomplete state prior to constructing a `DomainObject`. The `build()` function will error
/// in such a case.
#[derive(Clone, Debug)]
pub struct DomainObjectBuilder {
    /// The SDO type
    object_type: DomainObjectType,
    /// Common STIX object properties
    common_properties: CommonPropertiesBuilder,
}

impl DomainObjectBuilder {
    /// Creates a new STIX 2.1 `DomainObjectBuilder` of the given type
    ///
    /// The `type` field must be lowercase, with words separated by `-`
    ///
    /// Automatically generates an `id`
    /// Other fields are set to their Default (which is `None`` for optional fields)
    pub fn new(type_name: &str) -> Result<DomainObjectBuilder, Error> {
        // Parses the passed type name to select a type for the SDO
        // The initial inner struct in the `DomainObjectType` enum will be created with default values, which may not be valid for constructing the final `DomainObject`
        let object_type = DomainObjectType::from_str(&type_name.to_case(Case::Kebab))
            .map_err(Error::UnrecognizedObject)?;
        // Build the common properties with generated and default values
        let common_properties = CommonPropertiesBuilder::new("sdo", type_name)?;
        Ok(DomainObjectBuilder {
            object_type,
            common_properties,
        })
    }

    /// Create a new STIX 2.1 `DomainObjectBuilder` by cloning the fields from an existing `DomainObject`
    /// When built, this will create `DomainObject` as a newer version of the original object.
    pub fn version(old: &DomainObject) -> Result<DomainObjectBuilder, Error> {
        if old.is_revoked() {
            return Err(Error::UnableToVersion(format!(
                "SDO {} is revoked. Versioning a revoked object is prohibited.",
                old.common_properties.id
            )));
        }

        let object_type = old.object_type.clone();
        let old_properties = old.common_properties.clone();
        let common_properties = CommonPropertiesBuilder::version("sdo", &old_properties)?;

        Ok(DomainObjectBuilder {
            object_type,
            common_properties,
        })
    }

    // Setter functions for optional properties common to all SDOs

    /// Set the optional `created_by_ref` field for an SDO under construction.
    /// This is only allowed when creating a new SDO, not when versioning an existing one,
    /// as only the original creator of an object can version it.
    pub fn created_by_ref(mut self, id: Identifier) -> Result<Self, Error> {
        self.common_properties = self.common_properties.clone().created_by_ref(id)?;
        Ok(self)
    }

    /// Set the optional `labels` field for an SDO under construction.
    pub fn labels(mut self, labels: Vec<String>) -> Self {
        self.common_properties = self.common_properties.clone().labels(labels);
        self
    }

    /// Set the optional `confidence` field for an SDO under construction.
    pub fn confidence(mut self, confidence: u8) -> Self {
        self.common_properties = self.common_properties.clone().confidence(confidence);
        self
    }

    /// Set the optional `lang` field for an SDO under construction.
    /// If the language is English ("en"), this does not need to be set (but it can be if specificity is desired).
    pub fn lang(mut self, language: String) -> Self {
        self.common_properties = self.common_properties.clone().lang(language);
        self
    }

    /// Set the optional `external_references` field for an SDO under construction.
    pub fn external_references(mut self, references: Vec<ExternalReference>) -> Self {
        self.common_properties = self
            .common_properties
            .clone()
            .external_references(references);
        self
    }

    /// Set the optional `object_marking_refs` field for an SDO under construction.
    pub fn object_marking_refs(mut self, references: Vec<Identifier>) -> Self {
        self.common_properties = self
            .common_properties
            .clone()
            .object_marking_refs(references);
        self
    }

    /// Set the optional `granular_markings` field for an SDO under construction.
    pub fn granular_markings(mut self, markings: Vec<GranularMarking>) -> Self {
        self.common_properties = self.common_properties.clone().granular_markings(markings);
        self
    }

    /// Add an optional extension to the `extensions` field for an SDO under construction, creating the field if it does not exist
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

    // Setter functions for properties that may not exist in all SDO types
    // These functions will error if you try to set a property that does not exist

    pub fn administrative_area(mut self, area: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Location(ref mut location) => {
                location.administrative_area = Some(area);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "administrative_area".to_string(),
                })
            }
        }
        Ok(self)
    }

    /// Set the `aliases` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn aliases(mut self, aliases: Vec<String>) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::AttackPattern(ref mut attack_pattern) => {
                attack_pattern.aliases = Some(aliases)
            }
            DomainObjectType::Campaign(ref mut campaign) => campaign.aliases = Some(aliases),
            DomainObjectType::Infrastructure(ref mut infrastructure) => {
                infrastructure.aliases = Some(aliases)
            }
            DomainObjectType::IntrusionSet(ref mut intrusion_set) => {
                intrusion_set.aliases = Some(aliases)
            }
            DomainObjectType::Malware(ref mut malware) => malware.aliases = Some(aliases),
            DomainObjectType::ThreatActor(ref mut threat_actor) => {
                threat_actor.aliases = Some(aliases)
            }
            DomainObjectType::Tool(ref mut tool) => tool.aliases = Some(aliases),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "aliases".to_string(),
                })
            }
        };
        Ok(self)
    }

    // Set the `analysis_definition_version` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn analysis_definition_version(
        mut self,
        analysis_definition_version: String,
    ) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::MalwareAnalysis(ref mut malware_analysis) => {
                malware_analysis.analysis_definition_version = Some(analysis_definition_version)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "analysis_definition_version".to_string(),
                })
            }
        };
        Ok(self)
    }

    // Set the `analysis_ended` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn analysis_ended(mut self, analysis_ended: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::MalwareAnalysis(ref mut malware_analysis) => {
                malware_analysis.analysis_ended = Some(Timestamp(
                    analysis_ended.parse().map_err(Error::DateTimeError)?,
                ));
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "analysis_ended".to_string(),
                })
            }
        };
        Ok(self)
    }

    // Set the `analysis_engine_version` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn analysis_engine_version(
        mut self,
        analysis_engine_version: String,
    ) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::MalwareAnalysis(ref mut malware_analysis) => {
                malware_analysis.analysis_engine_version = Some(analysis_engine_version)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "analysis_engine_version".to_string(),
                })
            }
        };
        Ok(self)
    }

    // Set the analysis_sco_refs field for an SDO under construction, if the SDO is of a type that has that field
    pub fn analysis_sco_refs(mut self, analysis_sco_refs: Vec<Identifier>) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::MalwareAnalysis(ref mut malware_analysis) => {
                malware_analysis.analysis_sco_refs = Some(analysis_sco_refs);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "analysis_sco_refs".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the architecture_execution_envs field for an SDO under construction, if the SDO is of a type that has that field
    pub fn architecture_execution_envs(
        mut self,
        architecture_execution_envs: Vec<String>,
    ) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Malware(ref mut malware) => {
                malware.architecture_execution_envs = Some(architecture_execution_envs);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "architecture_execution_envs".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `authors` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn authors(mut self, authors: Vec<String>) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Note(ref mut note) => note.authors = Some(authors),
            DomainObjectType::Opinion(ref mut opinion) => opinion.authors = Some(authors),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "authors".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the capabilities field for an SDO under construction, if the SDO is of a type that has that field
    pub fn capabilities(mut self, capabilities: Vec<String>) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Malware(ref mut malware) => {
                malware.capabilities = Some(capabilities);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "capabilities".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn city(mut self, city: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Location(ref mut location) => {
                location.city = Some(city);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "city".to_string(),
                })
            }
        }
        Ok(self)
    }

    /// Set the `configuration_version` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn configuration_version(mut self, configuration_version: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::MalwareAnalysis(ref mut malware_analysis) => {
                malware_analysis.configuration_version = Some(configuration_version)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "configuration_version".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `contact_information (field for an SDO under construction, if the SDO is of a type that has that field
    pub fn contact_information(mut self, contact_information: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Identity(ref mut identity) => {
                identity.contact_information = Some(contact_information)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "contact_information".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `content` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn content(mut self, content: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Note(ref mut note) => note.content = content,
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "content".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `context` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn context(mut self, context: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Grouping(ref mut grouping) => grouping.context = context,
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "context".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn country(mut self, country: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Location(ref mut location) => {
                location.country = Some(country);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "country".to_string(),
                })
            }
        }
        Ok(self)
    }

    /// Set the `description` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn description(mut self, description: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::AttackPattern(ref mut attack_pattern) => {
                attack_pattern.description = Some(description)
            }
            DomainObjectType::Campaign(ref mut campaign) => {
                campaign.description = Some(description)
            }
            DomainObjectType::CourseOfAction(ref mut course_of_action) => {
                course_of_action.description = Some(description)
            }
            DomainObjectType::Grouping(ref mut grouping) => {
                grouping.description = Some(description)
            }
            DomainObjectType::Identity(ref mut identity) => {
                identity.description = Some(description)
            }
            DomainObjectType::Incident(ref mut incident) => {
                incident.description = Some(description)
            }
            DomainObjectType::Indicator(ref mut indicator) => {
                indicator.description = Some(description)
            }
            DomainObjectType::Infrastructure(ref mut infrastructure) => {
                infrastructure.description = Some(description)
            }
            DomainObjectType::IntrusionSet(ref mut intrusion_set) => {
                intrusion_set.description = Some(description)
            }
            DomainObjectType::Location(ref mut location) => {
                location.description = Some(description)
            }
            DomainObjectType::Malware(ref mut malware) => malware.description = Some(description),
            DomainObjectType::Report(ref mut report) => report.description = Some(description),
            DomainObjectType::ThreatActor(ref mut threat_actor) => {
                threat_actor.description = Some(description)
            }
            DomainObjectType::Tool(ref mut tool) => tool.description = Some(description),
            DomainObjectType::Vulnerability(ref mut vulnerability) => {
                vulnerability.description = Some(description)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "description".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `explanation` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn explanation(mut self, explanation: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Opinion(ref mut opinion) => opinion.explanation = Some(explanation),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "explanation".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the first_observed field for an SDO under construction, if the SDO is of a type that has that field
    pub fn first_observed(mut self, first_observed: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::ObservedData(ref mut observed_data) => {
                observed_data.first_observed =
                    Timestamp(first_observed.parse().map_err(Error::DateTimeError)?);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "first_observed".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the first_seen field for an SDO under construction, if the SDO is of a type that has that field
    pub fn first_seen(mut self, first_seen: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Campaign(ref mut campaign) => {
                campaign.first_seen =
                    Some(Timestamp(first_seen.parse().map_err(Error::DateTimeError)?));
            }
            DomainObjectType::Infrastructure(ref mut infrastructure) => {
                infrastructure.first_seen =
                    Some(Timestamp(first_seen.parse().map_err(Error::DateTimeError)?));
            }
            DomainObjectType::IntrusionSet(ref mut intrusion_set) => {
                intrusion_set.first_seen =
                    Some(Timestamp(first_seen.parse().map_err(Error::DateTimeError)?));
            }
            DomainObjectType::Malware(ref mut malware) => {
                malware.first_seen =
                    Some(Timestamp(first_seen.parse().map_err(Error::DateTimeError)?));
            }
            DomainObjectType::ThreatActor(ref mut threat_actor) => {
                threat_actor.first_seen =
                    Some(Timestamp(first_seen.parse().map_err(Error::DateTimeError)?));
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "first_seen".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the roles field for an SDO under construction, if the SDO is of a type that has that field
    pub fn goals(mut self, goals: Vec<String>) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::IntrusionSet(ref mut intrusion_set) => {
                intrusion_set.goals = Some(goals);
            }
            DomainObjectType::ThreatActor(ref mut threat_actor) => threat_actor.goals = Some(goals),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "goals".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the host_vm_ref field for an SDO under construction, if the SDO is of a type that has that field
    pub fn host_vm_ref(mut self, host_vm_ref: Identifier) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::MalwareAnalysis(ref mut malware_analysis) => {
                malware_analysis.host_vm_ref = Some(host_vm_ref);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "host_vm_ref".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `identity_class` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn identity_class(mut self, identity_class: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Identity(ref mut identity) => {
                identity.identity_class = Some(identity_class)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "identity_class".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the implementation_languages field for an SDO under construction, if the SDO is of a type that has that field
    pub fn implementation_languages(
        mut self,
        implementation_languages: Vec<String>,
    ) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Malware(ref mut malware) => {
                malware.implementation_languages = Some(implementation_languages);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "implementation_languages".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `indicator_types` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn indicator_types(mut self, types: Vec<String>) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Indicator(ref mut indicator) => {
                indicator.indicator_types = Some(types)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "indicator_types".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `infrastructure_types` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn infrastructure_types(
        mut self,
        infrastructure_types: Vec<String>,
    ) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Infrastructure(ref mut infrastructure) => {
                infrastructure.infrastructure_types = Some(infrastructure_types)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "infrastructure_types".to_string(),
                })
            }
        };
        Ok(self)
    }

    // Set the installed_software_refs field for an SDO under construction, if the SDO is of a type that has that field
    pub fn installed_software_refs(
        mut self,
        installed_software_refs: Vec<Identifier>,
    ) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::MalwareAnalysis(ref mut malware_analysis) => {
                malware_analysis.installed_software_refs = Some(installed_software_refs);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "installed_software_refs".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `kill_chain_phases` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn kill_chain_phases(mut self, phases: Vec<KillChainPhase>) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::AttackPattern(ref mut attack_pattern) => {
                attack_pattern.kill_chain_phases = Some(phases)
            }
            DomainObjectType::Indicator(ref mut indicator) => {
                indicator.kill_chain_phases = Some(phases)
            }
            DomainObjectType::Infrastructure(ref mut infrastructure) => {
                infrastructure.kill_chain_phases = Some(phases)
            }
            DomainObjectType::Malware(ref mut malware) => malware.kill_chain_phases = Some(phases),
            DomainObjectType::Tool(ref mut tool) => tool.kill_chain_phases = Some(phases),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "kill_chain_phases".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the last_observed field for an SDO under construction, if the SDO is of a type that has that field
    pub fn last_observed(mut self, last_observed: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::ObservedData(ref mut observed_data) => {
                observed_data.last_observed =
                    Timestamp(last_observed.parse().map_err(Error::DateTimeError)?);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "last_observed".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the last_seen field for an SDO under construction, if the SDO is of a type that has that field
    pub fn last_seen(mut self, last_seen: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Campaign(ref mut campaign) => {
                campaign.last_seen =
                    Some(Timestamp(last_seen.parse().map_err(Error::DateTimeError)?));
            }
            DomainObjectType::Infrastructure(ref mut infrastructure) => {
                infrastructure.last_seen =
                    Some(Timestamp(last_seen.parse().map_err(Error::DateTimeError)?));
            }
            DomainObjectType::IntrusionSet(ref mut intrusion_set) => {
                intrusion_set.last_seen =
                    Some(Timestamp(last_seen.parse().map_err(Error::DateTimeError)?));
            }
            DomainObjectType::Malware(ref mut malware) => {
                malware.last_seen =
                    Some(Timestamp(last_seen.parse().map_err(Error::DateTimeError)?));
            }

            DomainObjectType::ThreatActor(ref mut threat_actor) => {
                threat_actor.last_seen =
                    Some(Timestamp(last_seen.parse().map_err(Error::DateTimeError)?));
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "last_seen".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn latitude(mut self, latitude: f64) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Location(ref mut location) => {
                location.latitude = Some(ordered_float(latitude));
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "latitude".to_string(),
                })
            }
        }
        Ok(self)
    }

    pub fn longitude(mut self, longitude: f64) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Location(ref mut location) => {
                location.longitude = Some(ordered_float(longitude));
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "longitude".to_string(),
                })
            }
        }
        Ok(self)
    }

    /// Set the malware_types field for an SDO under construction, if the SDO is of a type that has that field
    pub fn malware_types(mut self, malware_types: Vec<String>) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Malware(ref mut malware) => {
                malware.malware_types = Some(malware_types);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "malware_types".to_string(),
                })
            }
        };
        Ok(self)
    }

    // Set the modules field for an SDO under construction, if the SDO is of a type that has that field
    pub fn modules(mut self, modules: Vec<String>) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::MalwareAnalysis(ref mut malware_analysis) => {
                malware_analysis.modules = Some(modules);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "modules".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `name` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn name(mut self, name: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::AttackPattern(ref mut attack_pattern) => attack_pattern.name = name,
            DomainObjectType::Campaign(ref mut campaign) => campaign.name = name,
            DomainObjectType::CourseOfAction(ref mut course_of_action) => {
                course_of_action.name = name
            }
            DomainObjectType::Grouping(ref mut grouping) => grouping.name = Some(name),
            DomainObjectType::Identity(ref mut identity) => identity.name = name,
            DomainObjectType::Incident(ref mut incident) => incident.name = name,
            DomainObjectType::Indicator(ref mut indicator) => indicator.name = Some(name),
            DomainObjectType::Infrastructure(ref mut infrastructure) => infrastructure.name = name,
            DomainObjectType::IntrusionSet(ref mut intrusion_set) => intrusion_set.name = name,
            DomainObjectType::Location(ref mut location) => location.name = Some(name),
            DomainObjectType::Malware(ref mut malware) => malware.name = Some(name),
            DomainObjectType::Report(ref mut report) => report.name = name,
            DomainObjectType::ThreatActor(ref mut threat_actor) => threat_actor.name = name,
            DomainObjectType::Tool(ref mut tool) => tool.name = name,
            DomainObjectType::Vulnerability(ref mut vulnerability) => vulnerability.name = name,
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "name".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the number_observed field for an SDO under construction, if the SDO is of a type that has that field
    pub fn number_observed(mut self, number_observed: u64) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::ObservedData(ref mut observed_data) => {
                observed_data.number_observed = number_observed;
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "number_observed".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn objective(mut self, objective: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Campaign(ref mut campaign) => campaign.objective = Some(objective),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "objective".to_string(),
                })
            }
        };
        Ok(self)
    }
    /// Set the `object_refs` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn object_refs(mut self, object_refs: Vec<Identifier>) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Grouping(ref mut grouping) => grouping.object_refs = object_refs,
            DomainObjectType::Note(ref mut note) => note.object_refs = object_refs,
            DomainObjectType::ObservedData(ref mut observed_data) => {
                observed_data.object_refs = object_refs
            }
            DomainObjectType::Opinion(ref mut opinion) => opinion.object_refs = object_refs,
            DomainObjectType::Report(ref mut report) => report.object_refs = object_refs,
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "object_refs".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the operating_system_ref field for an SDO under construction, if the SDO is of a type that has that field
    pub fn operating_system_ref(mut self, operating_system_ref: Identifier) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::MalwareAnalysis(ref mut malware_analysis) => {
                malware_analysis.operating_system_ref = Some(operating_system_ref);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "operating_system_ref".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the operating_system_ref field for an SDO under construction, if the SDO is of a type that has that field
    pub fn operating_system_refs(
        mut self,
        operating_system_refs: Vec<Identifier>,
    ) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Malware(ref mut malware) => {
                malware.operating_system_refs = Some(operating_system_refs);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "operating_system_refs".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `opinion` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn opinion(mut self, opinion: OpinionType) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Opinion(ref mut opinion_obj) => opinion_obj.opinion = opinion,
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "opinion".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `pattern` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn pattern(mut self, pattern: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Indicator(ref mut indicator) => indicator.pattern = pattern,
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "pattern".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `pattern_type` field for an SDO under construction, if the SDO is of a type that has that field
    /// If the `pattern_type` is "stix", this also sets the `pattern_version` field to the default STIX version of "2.1"
    pub fn pattern_type(mut self, pattern_type: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Indicator(ref mut indicator) => {
                if &pattern_type == "stix" {
                    indicator.pattern_version = Some("2.1".to_string());
                }
                indicator.pattern_type = pattern_type;
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "pattern_type".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `pattern_version` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn pattern_version(mut self, pattern_version: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Indicator(ref mut indicator) => {
                indicator.pattern_version = Some(pattern_version)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "pattern_version".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the personal_motivations field for an SDO under construction, if the SDO is of a type that has that field
    pub fn personal_motivations(
        mut self,
        personal_motivations: Vec<String>,
    ) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::ThreatActor(ref mut threat_actor) => {
                threat_actor.personal_motivations = Some(personal_motivations);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "personal_motivations".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn postal_code(mut self, postal_code: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Location(ref mut location) => {
                location.postal_code = Some(postal_code);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "postal_code".to_string(),
                })
            }
        }
        Ok(self)
    }

    pub fn precision(mut self, precision: f64) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Location(ref mut location) => {
                location.precision = Some(ordered_float(precision));
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "precision".to_string(),
                })
            }
        }
        Ok(self)
    }

    /// Set the primary_motivation field for an SDO under construction, if the SDO is of a type that has that field
    pub fn primary_motivation(mut self, primary_motivation: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::IntrusionSet(ref mut intrusion_set) => {
                intrusion_set.primary_motivation = Some(primary_motivation);
            }
            DomainObjectType::ThreatActor(ref mut threat_actor) => {
                threat_actor.primary_motivation = Some(primary_motivation);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "primary_motivation".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `product` field for an MalwareAnalysis SDO under construction, if the SDO is of a type that has that field
    pub fn product(mut self, product: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::MalwareAnalysis(ref mut malware_analysis) => {
                malware_analysis.product = product
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "product".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `published` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn published(mut self, published: Timestamp) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Report(ref mut report) => report.published = published,
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "published".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn region(mut self, region: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Location(ref mut location) => {
                location.region = Some(region);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "region".to_string(),
                })
            }
        }
        Ok(self)
    }

    /// Set the report_type field for an SDO under construction, if the SDO is of a type that has that field
    pub fn report_types(mut self, report_types: Vec<String>) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Report(ref mut report) => {
                report.report_types = Some(report_types);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "report_types".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the resource_level field for an SDO under construction, if the SDO is of a type that has that field
    pub fn resource_level(mut self, resource_level: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::IntrusionSet(ref mut intrusion_set) => {
                intrusion_set.resource_level = Some(resource_level);
            }
            DomainObjectType::ThreatActor(ref mut threat_actor) => {
                threat_actor.resource_level = Some(resource_level);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "resource_level".to_string(),
                })
            }
        };
        Ok(self)
    }

    // Set the `result_name` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn result_name(mut self, result_name: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::MalwareAnalysis(ref mut malware_analysis) => {
                malware_analysis.result_name = Some(result_name)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "result_name".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `roles` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn roles(mut self, roles: Vec<String>) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Identity(ref mut identity) => identity.roles = Some(roles),
            DomainObjectType::ThreatActor(ref mut threat_actor) => threat_actor.roles = Some(roles),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "roles".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the sample_ref field for an SDO under construction, if the SDO is of a type that has that field
    pub fn sample_ref(mut self, sample_ref: Identifier) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::MalwareAnalysis(ref mut malware_analysis) => {
                malware_analysis.sample_ref = Some(sample_ref);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "sample_ref".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the secondary_motivations field for an SDO under construction, if the SDO is of a type that has that field
    pub fn secondary_motivations(
        mut self,
        secondary_motivations: Vec<String>,
    ) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::IntrusionSet(ref mut intrusion_set) => {
                intrusion_set.secondary_motivations = Some(secondary_motivations);
            }
            DomainObjectType::ThreatActor(ref mut threat_actor) => {
                threat_actor.secondary_motivations = Some(secondary_motivations);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "secondary_motivations".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `sectors ` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn sectors(mut self, identity_sector: Vec<String>) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Identity(ref mut identity) => {
                identity.sectors = Some(identity_sector); // Wrap in Some
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "sectors".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn set_abstract(mut self, set_abstract: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Note(ref mut note) => note.set_abstract = Some(set_abstract),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "abstract".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn set_family(mut self, is_family: bool) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Malware(ref mut malware) => {
                malware.is_family = is_family;
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "is_family".to_string(),
                });
            }
        };
        Ok(self)
    }

    // Set the `result` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn set_result(mut self, result: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::MalwareAnalysis(ref mut malware_analysis) => {
                malware_analysis.result = Some(result)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "result".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `version` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn set_version(mut self, version: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::MalwareAnalysis(ref mut malware_analysis) => {
                malware_analysis.version = Some(version)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "version".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the sophistication field for an SDO under construction, if the SDO is of a type that has that field
    pub fn sophistication(mut self, sophistication: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::ThreatActor(ref mut threat_actor) => {
                threat_actor.sophistication = Some(sophistication);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "sophistication".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn street_address(mut self, address: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Location(ref mut location) => {
                location.street_address = Some(address);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "street_address".to_string(),
                })
            }
        }
        Ok(self)
    }

    // Set the `submitted` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn submitted(mut self, submitted: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::MalwareAnalysis(ref mut malware_analysis) => {
                malware_analysis.submitted =
                    Some(Timestamp(submitted.parse().map_err(Error::DateTimeError)?));
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "submitted".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the threat_actor_type field for an SDO under construction, if the SDO is of a type that has that field
    pub fn threat_actor_types(mut self, threat_actor_types: Vec<String>) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::ThreatActor(ref mut threat_actor) => {
                threat_actor.threat_actor_types = Some(threat_actor_types);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "threat_actor_types".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `tool_types` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn tool_types(mut self, tool_types: Vec<String>) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Tool(ref mut tool) => tool.tool_types = Some(tool_types),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "tool_types".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `tool_version` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn tool_version(mut self, tool_version: String) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Tool(ref mut tool) => tool.tool_version = Some(tool_version),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "tool_version".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `valid_from` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn valid_from(mut self, valid_from: &str) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Indicator(ref mut indicator) => {
                indicator.valid_from = Timestamp(valid_from.parse().map_err(Error::DateTimeError)?)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "valid_from".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `valid_until` field for an SDO under construction, if the SDO is of a type that has that field
    pub fn valid_until(mut self, valid_until: &str) -> Result<Self, Error> {
        match self.object_type {
            DomainObjectType::Indicator(ref mut indicator) => {
                indicator.valid_until = Some(Timestamp(
                    valid_until.parse().map_err(Error::DateTimeError)?,
                ))
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SDOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "valid_until".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Builds a new SDO, using the information found in the DomainObjectBuilder
    ///
    /// This performs a final check that all required fields for a given SDO type are included before construction.
    /// This also runs the `stick_check()` validation method on the newly constructed SDO.
    pub fn build(self) -> Result<DomainObject, Error> {
        match self.object_type {
            DomainObjectType::AttackPattern(ref attack_pattern) => {
                if attack_pattern.name.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "name".to_string(),
                    });
                }
            }
            DomainObjectType::Campaign(ref campaign) => {
                if campaign.name.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "name".to_string(),
                    });
                }
            }
            DomainObjectType::CourseOfAction(ref course_of_action) => {
                if course_of_action.name.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "name".to_string(),
                    });
                }
            }
            DomainObjectType::Grouping(ref grouping) => {
                if grouping.object_refs.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "object_refs".to_string(),
                    });
                }
            }
            DomainObjectType::Identity(ref identity) => {
                if identity.name.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "name".to_string(),
                    });
                }
            }
            DomainObjectType::Incident(ref incident) => {
                if incident.name.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "name".to_string(),
                    });
                }
            }
            DomainObjectType::Indicator(ref indicator) => {
                if indicator.pattern.is_empty()
                    || indicator.pattern_type.is_empty()
                    || indicator.valid_from.0 == JiffTimestamp::UNIX_EPOCH
                {
                    return Err(Error::MultipleErrors(vec![
                        Error::MissingBuilderProperty {
                            object_type: self.object_type.to_string(),
                            property: "pattern".to_string(),
                        },
                        Error::MissingBuilderProperty {
                            object_type: self.object_type.to_string(),
                            property: "pattern_type".to_string(),
                        },
                        Error::MissingBuilderProperty {
                            object_type: self.object_type.to_string(),
                            property: "valid_from".to_string(),
                        },
                    ]));
                }
            }
            DomainObjectType::Infrastructure(ref infrastructure) => {
                if infrastructure.name.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "name".to_string(),
                    });
                }
            }
            DomainObjectType::IntrusionSet(ref intrusion_set) => {
                if intrusion_set.name.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "name".to_string(),
                    });
                }
            }
            DomainObjectType::Location(ref location) => {
                let _ = location.stix_check();
            }
            DomainObjectType::Malware(ref malware) => {
                let _ = malware.stix_check();
            }
            DomainObjectType::MalwareAnalysis(ref malware_analysis) => {
                if malware_analysis.product.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "product".to_string(),
                    });
                }
                if malware_analysis.result.is_none() && malware_analysis.analysis_sco_refs.is_none()
                {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "result or analysis_sco_refs".to_string(),
                    });
                }
            }
            DomainObjectType::Note(ref note) => {
                if note.content.is_empty() || note.object_refs.is_empty() {
                    return Err(Error::MultipleErrors(vec![
                        Error::MissingBuilderProperty {
                            object_type: self.object_type.to_string(),
                            property: "content".to_string(),
                        },
                        Error::MissingBuilderProperty {
                            object_type: self.object_type.to_string(),
                            property: "object_refs".to_string(),
                        },
                    ]));
                }
            }
            DomainObjectType::ObservedData(ref observed_data) => {
                if observed_data.first_observed.0 == JiffTimestamp::UNIX_EPOCH
                    || observed_data.last_observed.0 == JiffTimestamp::UNIX_EPOCH
                    || observed_data.number_observed == 0
                    || observed_data.object_refs.is_empty()
                {
                    return Err(Error::MultipleErrors(vec![
                        Error::MissingBuilderProperty {
                            object_type: self.object_type.to_string(),
                            property: "first_observed".to_string(),
                        },
                        Error::MissingBuilderProperty {
                            object_type: self.object_type.to_string(),
                            property: "last_observed".to_string(),
                        },
                        Error::MissingBuilderProperty {
                            object_type: self.object_type.to_string(),
                            property: "number_observed".to_string(),
                        },
                        Error::MissingBuilderProperty {
                            object_type: self.object_type.to_string(),
                            property: "object_refs".to_string(),
                        },
                    ]));
                }
            }
            DomainObjectType::Opinion(ref opinion) => {
                if opinion.object_refs.is_empty() || opinion.opinion.as_ref().is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "object_refs or opinion".to_string(),
                    });
                }
            }
            DomainObjectType::Report(ref report) => {
                if report.name.is_empty()
                    || report.object_refs.is_empty()
                    || report.published.0 == JiffTimestamp::UNIX_EPOCH
                {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "name, published, or object_refs".to_string(),
                    });
                }
            }
            DomainObjectType::ThreatActor(ref threat_actor) => {
                if threat_actor.name.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "name".to_string(),
                    });
                }
            }
            DomainObjectType::Tool(ref tool) => {
                if tool.name.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "name".to_string(),
                    });
                }
            }
            DomainObjectType::Vulnerability(ref vulnerability) => {
                if vulnerability.name.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "name".to_string(),
                    });
                }
            }
        }

        let common_properties = self.common_properties.build();

        let sdo = DomainObject {
            object_type: self.object_type,
            common_properties,
        };

        sdo.stix_check()?;

        Ok(sdo)
    }
}
