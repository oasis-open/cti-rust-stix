//! Defines the data structures for each specific STIX Domain Object type.

use crate::{
    base::Stix,
    domain_objects::vocab::{
        ArchitectureExecutionEnvs, AttackMotivation, AttackResourceLevel, ContextType,
        IdentitySectors, ImplementationLanguage, IndicatorPatternType, IndicatorType,
        InfrastructureType, MalwareCapability, MalwareResult, MalwareType, OpinionType, Region,
        ReportType, ThreatActorRole, ThreatActorSophistication, ThreatActorType, ToolType,
    },
    error::{add_error, return_multiple_errors, StixError as Error},
    pattern::validate_pattern,
    types::{Identifier, KillChainPhase, ScoTypes, SdoTypes, SroTypes, StixMetaTypes, Timestamp},
};
use convert_case::{Case, Casing};
use log::warn;
use ordered_float::OrderedFloat as ordered_float;
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;
use serde_with::skip_serializing_none;
use strum::IntoEnumIterator;

/// Attack Pattern SDOs
///
/// Attack Patterns are a type of TTP that describe ways that adversaries attempt to compromise targets.
/// These are used to help categorize attacks, generalize specific attacks to the patterns that they follow, and provide detailed information about how attacks are performed
///
/// An Attack Pattern SDO contains textual descriptions of the pattern along with references to externally-defined taxonomies of attacks (e.g. CAPEC)
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_axjijf603msy>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackPattern {
    /// A name used to identify the Attack Pattern.
    pub name: String,
    /// Provides more details and context about the Attack Pattern, potentially including its purpose and its key characteristics.
    pub description: Option<String>,
    /// Alternative names, if any, used to identify this Attack Pattern.
    pub aliases: Option<Vec<String>>,
    /// The list of Kill Chain Phases, if any, for which this Attack Pattern is used.
    pub kill_chain_phases: Option<Vec<KillChainPhase>>,
}
impl Stix for AttackPattern {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(kill_chain_phases) = &self.kill_chain_phases {
            add_error(&mut errors, kill_chain_phases.stix_check());
        }
        if let Some(aliases) = &self.aliases {
            add_error(&mut errors, aliases.stix_check());
        }

        return_multiple_errors(errors)
    }
}

/// Campaign SDOs
///
/// A Campaign is a grouping of adversarial behaviors that describes a set of malicious activities or attacks (sometimes called waves) that occur over a period of time against a specific
/// set of targets. Campaigns usually have well defined objectives and may be part of an Intrusion Set.
///
/// Campaigns are often attributed to an intrusion set and threat actors. The threat actors may reuse known infrastructure from the intrusion set or may set up new infrastructure specific
/// for conducting that campaign.
///
/// Campaigns can be characterized by their objectives and the incidents they cause, people or resources they target, and the resources (infrastructure, intelligence, Malware, Tools, etc.)
// they use.
///
/// For example, a Campaign could be used to describe a crime syndicate's attack using a specific variant of malware and new C2 servers against the executives of ACME Bank during the summer
/// of 2016 in order to gain secret information about an upcoming merger with another bank.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_pcpvfz4ik6d6>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Campaign {
    /// A name used to identify the Campaign.
    pub name: String,
    /// A description that provides more details and context about the Campaign, potentially including its purpose and its key characteristics.
    pub description: Option<String>,
    /// Alternative names, if any, used to identify this Campaign.
    pub aliases: Option<Vec<String>>,
    /// The time that this Campaign was first seen.
    /// A summary property of data from sightings and other data that may or may not be available in STIX. If new sightings are received that are earlier than the first seen timestamp, the object may be updated to account for the new data.
    pub first_seen: Option<Timestamp>,
    ///	The time that this Campaign was last seen.
    /// A summary property of data from sightings and other data that may or may not be available in STIX. If new sightings are received that are later than the last seen timestamp, the object may be updated to account for the new data.
    /// If this property and the first_seen property are both defined, then this property **MUST** be greater than or equal to the timestamp in the first_seen property.
    pub last_seen: Option<Timestamp>,
    /// The Campaign’s primary goal, objective, desired outcome, or intended effect — what the Threat Actor or Intrusion Set hopes to accomplish with this Campaign.
    pub objective: Option<String>,
}
impl Stix for Campaign {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let (Some(start), Some(stop)) = (&self.first_seen, &self.last_seen) {
            if stop < start {
                errors.push(Error::ValidationError(format!("The Campaign has a last seen timestamp of {} and a first seen timestamp of {}. The former cannot be earlier than or the same as the latter.",
                    stop,
                    start
                )));
            }
        }
        if let Some(aliases) = &self.aliases {
            add_error(&mut errors, aliases.stix_check());
        }

        return_multiple_errors(errors)
    }
}

/// Course of Action SDOs
///
/// A Course of Action is an action taken either to prevent an attack or to respond to an attack that is in progress. It may describe technical, automatable responses
/// (applying patches, reconfiguring firewalls) but can also describe higher level actions like employee training or policy changes. For example, a course of action
/// to mitigate a vulnerability could describe applying the patch that fixes it.
///
/// The Course of Action SDO contains a textual description of the action; a reserved `action` property also serves as a placeholder for future inclusion of machine
/// automatable courses of action.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_a925mpw39txn>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CourseOfAction {
    /// A name used to identify the Course of Action.
    pub name: String,
    /// A description that provides more details and context about the Course of Action, potentially including its purpose and its key characteristics.
    pub description: Option<String>,
}

impl Stix for CourseOfAction {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
    }
}

/// Grouping SDOs
///
/// A Grouping object explicitly asserts that the referenced STIX Objects have a shared context, unlike a STIX Bundle (which explicitly conveys no context). A Grouping
/// object should not be confused with an intelligence product, which should be conveyed via a STIX Report.
///
/// A STIX Grouping object might represent a set of data that, in time, given sufficient analysis, would mature to convey an incident or threat report as a STIX Report
/// object. For example, a Grouping could be used to characterize an ongoing investigation into a security event or incident. A Grouping object could also be used to
/// assert that the referenced STIX Objects are related to an ongoing analysis process, such as when a threat analyst is collaborating with others in their trust
/// community to examine a series of Campaigns and Indicators. The Grouping SDO contains a list of references to SDOs, SCOs, SROs, and SMOs, along with an explicit
/// statement of the context shared by the content, a textual description, and the name of the grouping.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_t56pn7elv6u7>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grouping {
    /// A name used to identify the Grouping.
    pub name: Option<String>,
    /// A description that provides more details and context about the Grouping, potentially including its purpose and its key characteristics.
    pub description: Option<String>,
    /// A short descriptor of the particular context shared by the content referenced by the Grouping.
    ///
    /// The value for this property **SHOULD** come from the `grouping-context-ov` open vocabulary.
    pub context: String,
    /// Specifies the STIX Objects that are referred to by this Grouping.
    pub object_refs: Vec<Identifier>,
}

impl Stix for Grouping {
    fn stix_check(&self) -> Result<(), Error> {
        if !ContextType::iter().any(|x| x.as_ref() == self.context.to_case(Case::Kebab)) {
            warn!(
                "The context property should come from the `grouping-context-ov` open vocabulary. grouping context '{}' is not in the vocabulary.", self.context
            );
        }

        self.object_refs.stix_check()
    }
}

/// Identity SDOs
///
/// Identities can represent actual individuals, organizations, or groups (e.g., ACME, Inc.) as well as classes of individuals, organizations, systems or groups (e.g.,
/// the finance sector).
///
/// The Identity SDO can capture basic identifying information, contact information, and the sectors that the Identity belongs to. Identity is used in STIX to represent,
/// among other things, targets of attacks, information sources, object creators, and threat actor identities.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_wh296fiwpklp>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// The name of the Identity.
    ///
    /// When referring to a specific entity (e.g., an individual or organization), this property **SHOULD** contain the canonical name of the specific entity.
    pub name: String,
    /// An optional description providing more details about the Identity.
    pub description: Option<String>,
    /// An optional list of roles that this Identity performs.
    pub roles: Option<Vec<String>>,
    /// The optional type of entity, e.g., individual or organization.
    ///
    /// The value for this property **SHOULD** come from the `identity-class-ov` open vocabulary.
    pub identity_class: Option<String>,
    /// An optional list of industry sectors this Identity belongs to.
    ///
    /// The values for this property **SHOULD** come from `the industry-sector-ov` open vocabulary.
    pub sectors: Option<Vec<String>>,
    /// The optional contact information for this Identity.
    pub contact_information: Option<String>,
}

impl Stix for Identity {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(sectors) = &self.sectors {
            add_error(&mut errors, sectors.stix_check());
            for sector in sectors {
                if IdentitySectors::iter().all(|x| x.as_ref() != sector.to_case(Case::Kebab)) {
                    warn!(
                        "A Sector should come from the STIX pattern type open vocabulary. Identity sector '{}' is not in the vocabulary.",
                        sector,
                    );
                }
            }
        }
        if let Some(roles) = &self.roles {
            add_error(&mut errors, roles.stix_check());
        }
        Ok(())
    }
}

/// Incident SDOs (**stub**)
///
/// The Incident object in STIX 2.1 is a stub. It is included to support basic use cases but does not contain properties to represent metadata about incidents.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_sczfhw64pjxt>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incident {
    /// The name of the Incident.
    pub name: String,
    /// An optional description providing more details about the Incident.
    pub description: Option<String>,
}

// The method currently returns Ok(()), indicating a successful result with no additional data.
impl Stix for Incident {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
    }
}

/// Inidicator SDOs
///
/// Indicators contain a pattern that can be used to detect suspicious or malicious cyber activity. For example, an Indicator may be used to represent a set of
/// malicious domains and use the STIX Patterning Language to specify these domains.
///
/// The Indicator SDO contains a simple textual description, the Kill Chain Phases that it detects behavior in, a time window for when the Indicator is valid or
/// useful, and a required `pattern` property to capture a structured detection pattern. Conforming STIX implementations **MUST** support the STIX Patterning Language.
///
/// Relationships from the Indicator can describe the malicious or suspicious behavior that it directly detects (Malware, Tool, and Attack Pattern). In addition,
/// it may also imply the presence of a Campaigns, Intrusion Sets, and Threat Actors, etc.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_muftrcpnf89v>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Indicator {
    /// An optional name used to identify the Indicator.
    ///
    /// Producers **SHOULD** provide this property to help products and analysts understand what this Indicator actually does.
    pub name: Option<String>,
    /// An optional description that provides more details and context about the Indicator.
    pub description: Option<String>,
    /// An optional list of open-vocab types that specify categorizations for this indicator.
    ///
    /// Producers **SHOULD** provide this property to help products and analysts understand what this Indicator actually does.
    /// This value **SHOULD** come from the `indicator-type-ov` vocabulary.
    pub indicator_types: Option<Vec<String>>,
    /// A required string that represents the detection pattern for this Indicator.
    ///
    /// The values for this property **SHOULD** come from the `indicator-type-ov` open vocabulary.
    pub pattern: String,
    /// A required open-vocab type that indicates the type of pattern used in this indicator.
    ///
    /// The value for this property **SHOULD** come from the `pattern-type-ov` open vocabulary.
    /// The value of this property **MUST** match the type of pattern data included in the `pattern` property.
    pub pattern_type: String,
    /// The optional version of the pattern language that is used for the data in the pattern property which **MUST** match the type of pattern data included in the `pattern`
    /// property.
    ///
    /// For patterns that do not have a formal specification, the build or code version that the pattern is known to work with **SHOULD** be used.
    ///
    /// For the STIX Pattern language, the default value is determined by the specification version of the object. For other languages, the default value **SHOULD** be the
    /// latest version of the patterning language at the time of this object's creation.
    pub pattern_version: Option<String>,
    /// A required timestamp indicating when this Indicator is considered valid.
    pub valid_from: Timestamp,
    /// An optional timestamp indicating when this Indicator is no longer considered valid.
    /// If omitted, there is no constraint on the latest time for which the Indicator is valid.
    ///
    /// This **MUST** be greater than the timestamp in the `valid_from` property.
    pub valid_until: Option<Timestamp>,
    /// An optional list of kill chain phases corresponding to this Indicator.
    /// This can be a vector of strings or a separate struct if more details are needed.
    pub kill_chain_phases: Option<Vec<KillChainPhase>>,
}

impl Stix for Indicator {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(kill_chain_phases) = &self.kill_chain_phases {
            add_error(&mut errors, kill_chain_phases.stix_check());
        }

        // If the pattern is a STIX Pattern, validate it using the Rust implemtation of STIX Patterning
        if self.pattern_type.to_case(Case::Kebab) == "stix" {
            add_error(&mut errors, validate_pattern(&self.pattern));
        } else if IndicatorPatternType::iter()
            .all(|x| x.as_ref() != self.pattern_type.to_case(Case::Kebab))
        {
            warn!("A pattern type should come from the STIX pattern type open vocabulary. Pattern type {} for is not in the vocabulary.",
                self.pattern_type,
            );
        }
        if let Some(indicator_types) = &self.indicator_types {
            add_error(&mut errors, indicator_types.stix_check());
            for indicator_type in indicator_types {
                if IndicatorType::iter().all(|x| x.as_ref() != indicator_type.to_case(Case::Kebab))
                {
                    warn!(
                        "A indicator Type should come from the STIX pattern type open vocabulary. Identity sector '{}' is not in the vocabulary.",
                        indicator_type,
                    );
                }
            }
        }

        return_multiple_errors(errors)
    }
}

/// Infrastructure SDOs
///
/// The Infrastructure SDO represents a type of TTP and describes any systems, software services and any associated physical or virtual resources intended to
/// support some purpose (e.g., C2 servers used as part of an attack, device or server that are part of defense, database servers targeted by an attack, etc.).
/// While elements of an attack can be represented by other SDOs or SCOs, the Infrastructure SDO represents a named group of related data that constitutes the
/// infrastructure.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_jo3k1o6lr9>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Infrastructure {
    /// A name used to identify the Infrastructure.
    pub name: String,
    /// A description that provides more details and context about the Infrastructure,
    /// potentially including its purpose, how it is being used, how it relates to other
    /// intelligence activities captured in related objects, and its key characteristics.
    pub description: Option<String>,
    /// The type of infrastructure being described.
    ///
    /// This value **SHOULD** come from the `infrastructure-type-ov` vocabulary.
    pub infrastructure_types: Option<Vec<String>>,
    /// Alternative names used to identify this Infrastructure.
    pub aliases: Option<Vec<String>>,
    /// The list of Kill Chain Phases for which this Infrastructure is used.
    pub kill_chain_phases: Option<Vec<KillChainPhase>>,
    /// The time that this Infrastructure was first seen performing malicious activities.
    pub first_seen: Option<Timestamp>,
    /// The time that this Infrastructure was last seen performing malicious activities.
    ///
    /// If this property and the first_seen property are both defined,
    /// then this property **MUST** be greater than or equal to the timestamp in the `first_seen` property.
    pub last_seen: Option<Timestamp>,
}

impl Stix for Infrastructure {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(kill_chain_phases) = &self.kill_chain_phases {
            add_error(&mut errors, kill_chain_phases.stix_check());
        }
        if let (Some(start), Some(stop)) = (&self.first_seen, &self.last_seen) {
            if stop < start {
                errors.push(Error::ValidationError(format!("The infrastructure has a last seen timestamp of {} and a first seen timestamp of {}. The former cannot be earlier than the latter.",
                    stop,
                    start
                )));
            }
        }
        if let Some(its) = &self.infrastructure_types {
            add_error(&mut errors, its.stix_check());
            for infrastructure_type in its {
                if InfrastructureType::iter()
                    .all(|x| x.as_ref() != infrastructure_type.to_case(Case::Kebab))
                {
                    warn!("An infrastructure type should come from the STIX pattern type open vocabulary. Infrastructure type {} for is not in the vocabulary.",
                infrastructure_type
                );
                }
            }
        }
        if let Some(aliases) = &self.aliases {
            add_error(&mut errors, aliases.stix_check());
        }

        return_multiple_errors(errors)
    }
}

/// Intrusion Set SDOs
///
/// An Intrusion Set is a grouped set of adversarial behaviors and resources with common properties that is believed to be orchestrated by a single organization.
/// An Intrusion Set may capture multiple Campaigns or other activities that are all tied together by shared attributes indicating a commonly known or unknown
/// Threat Actor. New activity can be attributed to an Intrusion Set even if the Threat Actors behind the attack are not known. Threat Actors can move from
/// supporting one Intrusion Set to supporting another, or they may support multiple Intrusion Sets.
///
/// Where a Campaign is a set of attacks over a period of time against a specific set of targets to achieve some objective, an Intrusion Set is the entire attack
/// package and may be used over a very long period of time in multiple Campaigns to achieve potentially multiple purposes.
///
/// While sometimes an Intrusion Set is not active, or changes focus, it is usually difficult to know if it has truly disappeared or ended. Analysts may have varying
/// level of fidelity on attributing an Intrusion Set back to Threat Actors and may be able to only attribute it back to a nation state or perhaps back to an
/// organization within that nation state.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_5ol9xlbbnrdn>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntrusionSet {
    /// A name used to identify this Threat Actor or Threat Actor group.
    pub name: String,
    /// A description that provides more details and context about the Intrusion Set,
    /// potentially including its purpose and its key characteristics.
    pub description: Option<String>,
    /// Alternative names used to identify this Intrusion Set.
    pub aliases: Option<Vec<String>>,
    /// The time that this Intrusion Set was first seen.
    pub first_seen: Option<Timestamp>,
    /// The time that this Intrusion Set was last seen.
    ///
    /// If this property and the first_seen property are both defined, then this property **MUST** be greater than or equal to the timestamp in the `first_seen` property.
    pub last_seen: Option<Timestamp>,
    /// The high-level goals of this Intrusion Set, namely, what are they trying to do.
    pub goals: Option<Vec<String>>,
    /// This property specifies the organizational level at which this Intrusion Set typically works,
    ///
    /// The value for this property **SHOULD** come from the `attack-resource-level-ov` open vocabulary.
    pub resource_level: Option<String>,
    /// The primary reason, motivation, or purpose behind this Intrusion Set.
    ///
    /// The value for this property **SHOULD** come from the `attack-motivation-ov` open vocabulary.
    pub primary_motivation: Option<String>,
    /// The secondary reasons, motivations, or purposes behind this Intrusion Set.
    ///
    /// The value for this property **SHOULD** come from the `attack-motivation-ov` open vocabulary.
    pub secondary_motivations: Option<Vec<String>>,
}

impl Stix for IntrusionSet {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(primary_motivation) = self.primary_motivation.as_deref() {
            if AttackMotivation::iter().all(|x| {
                let variant_str = x.as_ref();
                variant_str != primary_motivation
            }) {
                warn!(
                    "A primary_motivation should come from the STIX attack motivation open vocabulary. IntrusionSet primary_motivation {} is not in the vocabulary.",
                    primary_motivation,
                );
            }
        }

        if let Some(secondary_motivations) = &self.secondary_motivations {
            add_error(&mut errors, secondary_motivations.stix_check());
            for secondary_motivation in secondary_motivations {
                if AttackMotivation::iter()
                    .all(|x| x.as_ref() != secondary_motivation.as_str().to_case(Case::Kebab))
                {
                    warn!(
                        "A secondary_motivation should come from the STIX attack motivation open vocabulary. IntrusionSet secondary_motivation {} is not in the vocabulary.",
                        secondary_motivation,
                    );
                }
            }
        }

        if let Some(resource_level) = self.resource_level.as_deref() {
            if AttackResourceLevel::iter()
                .all(|x| x.as_ref() != resource_level.to_case(Case::Kebab))
            {
                warn!(
                        "A resource_level should come from the attack resource level open vocabulary. IntrusionSet resource_level {} is not in the vocabulary.",
                        resource_level,
                    );
            }
        }

        if let Some(goals) = &self.goals {
            add_error(&mut errors, goals.stix_check());
        }
        if let Some(aliases) = &self.aliases {
            add_error(&mut errors, aliases.stix_check());
        }

        return_multiple_errors(errors)
    }
}

/// Location SDOs
///
/// A Location represents a geographic location. The location may be described as any, some or all of the following: region (e.g., North America), civic address (e.g.
/// New York, US), latitude and longitude.
///
/// Locations are primarily used to give context to other SDOs. For example, a Location could be used in a relationship to describe that the Bourgeois Swallow intrusion
/// set originates from Eastern Europe. The Location SDO can be related to an Identity or Intrusion Set to indicate that the identity or intrusion set is located in that
/// location. It can also be related from a malware or attack pattern to indicate that they target victims in that location. The Location object describes geographic
/// areas, not governments, even in cases where that area might have a government. For example, a Location representing the United States describes the United States as
/// a geographic area, not the federal government of the United States.
///
/// At least one of the following properties/sets of properties **MUST** be provided: region, country, or latitude **and** longitude.
///
/// When a combination of properties is provided (e.g. a `region` and a `latitude` and `longitude`) the more precise properties are what the location describes. In other words,
/// if a location contains both a `region` of "northern-america" and a `country` of "us", then the location describes the United States, not all of North America. In cases where a
/// latitude and longitude are specified without a precision, the location describes the most precise other value.
///
/// If precision is specified, then the datum for `latitude` and `longitude` **MUST** be WGS 84 [WGS84](https://earth-info.nga.mil/php/download.php?file=coord-wgs84). Organizations
/// specifying a designated location using `latitude` and `longitude` **SHOULD** specify the precision which is appropriate for the scope of the location being identified. The scope
/// is defined by the boundary as outlined by the precision around the coordinates.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_th8nitr8jb4k>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    /// A name used to identify the Location.
    pub name: Option<String>,
    /// A textual description of the Location.
    pub description: Option<String>,
    /// The latitude of the Location in decimal degrees.
    /// Positive numbers describe latitudes north of the equator,
    /// and negative numbers describe latitudes south of the equator.
    ///
    /// The value of this property **MUST** be between -90.0 and 90.0, inclusive.
    pub latitude: Option<ordered_float<f64>>,
    /// The longitude of the Location in decimal degrees
    /// Positive numbers describe longitudes east of the prime meridian,
    /// and negative numbers describe longitudes west of the prime meridian.
    ///
    /// The value of this property **MUST** be between -180.0 and 180.0, inclusive.
    pub longitude: Option<ordered_float<f64>>,
    /// Defines the precision of the coordinates specified by the `latitude`
    /// and `longitude` properties. This is measured in meters.
    /// The actual Location may be anywhere up to precision meters from the defined point.
    ///
    /// If this property is present, the `latitude` and `longitude` properties **MUST **be present.
    pub precision: Option<ordered_float<f64>>,
    /// The region that this Location describes.
    ///
    /// This property **SHOULD** contain a value from `region-ov`.
    pub region: Option<String>,
    /// The country that this Location describes.
    ///
    /// This property **SHOULD** contain a valid ISO 3166-1 ALPHA-2 Code [ISO3166-1](https://www.iso.org/standard/63545.html).
    pub country: Option<String>,
    /// The state, province, or other sub-national administrative area
    /// that this Location describes.
    ///
    /// This property **SHOULD** contain a valid ISO 3166-2 Code [ISO3166-2](https://www.iso.org/standard/72483.html).
    pub administrative_area: Option<String>,
    /// The city that this Location describes.
    pub city: Option<String>,
    /// The street address that this Location describes.
    /// This property includes all aspects or parts of the street address.
    /// For example, some addresses may have multiple lines including a mailstop or apartment number.
    pub street_address: Option<String>,
    /// The postal code for this Location.
    pub postal_code: Option<String>,
}

impl Stix for Location {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        let min_lat = ordered_float(-90.0_f64);
        let max_lat = ordered_float(90.0_f64);
        let min_lon = ordered_float(-180.0_f64);
        let max_lon = ordered_float(180.0_f64);

        if self.precision.is_some() && (self.latitude.is_none() || self.longitude.is_none()) {
            errors.push(Error::ValidationError(
                "Latitude and longitude must be present if precision is set".to_string(),
            ));
        }

        if let Some(lat) = self.latitude {
            if lat < min_lat || lat > max_lat {
                errors.push(Error::ValidationError(
                    "Latitude should be between -90.0 and 90.0".to_string(),
                ));
            }
            if self.longitude.is_none() {
                errors.push(Error::ValidationError(
                    "Longitude must be present if latitude is set".to_string(),
                ));
            }
        }

        if let Some(lon) = self.longitude {
            if lon < min_lon || lon > max_lon {
                errors.push(Error::ValidationError(
                    "Longitude should be between -180.0 and 180.0".to_string(),
                ));
            }
            if self.latitude.is_none() {
                errors.push(Error::ValidationError(
                    "Latitude must be present if longitude is set".to_string(),
                ));
            }
        }
        if let Some(region_str) = &self.region {
            if !Region::iter().any(|x| x.as_ref() == region_str.to_case(Case::Kebab)) {
                warn!(
                    "The region property should come from the `region-ov` open vocabulary. Location region '{}' is not in the vocabulary.", region_str
                );
            }
        }
        if let Some(country) = &self.country {
            if rust_iso3166::from_alpha2(country).is_none() {
                warn!("{:?} is NOT a valid country code. This property SHOULD contain a valid ISO 3166-1 ALPHA-2 Code [ISO3166-1].", country);
            }
        }
        if let Some(administrative_area) = &self.administrative_area {
            if rust_iso3166::iso3166_2::from_code(administrative_area).is_none() {
                warn!(
                    "{:?} is NOT a valid administrative_area code. This property SHOULD contain a valid ISO 3166-2 Code.",
                    administrative_area
                );
            }
        }

        return_multiple_errors(errors)
    }
}

/// Malware SDOs
///
/// Malware is a type of TTP that represents malicious code. It generally refers to a program that is inserted into a system, usually covertly. The intent is to compromise
/// the confidentiality, integrity, or availability of the victim's data, applications, or operating system (OS) or otherwise annoy or disrupt the victim.
///
/// The Malware SDO characterizes, identifies, and categorizes malware instances and families from data that may be derived from analysis. This SDO captures detailed
/// information about how the malware works and what it does. This SDO captures contextual data relevant to sharing Malware data without requiring the full analysis provided
/// by the Malware Analysis SDO.
///
/// The Indicator SDO provides intelligence producers with the ability to define, using the STIX Pattern Grammar in a standard way to identify and detect behaviors associated
/// with malicious activities. Although the Malware SDO provides vital intelligence on a specific instance or malware family, it does not provide a standard grammar that the
/// Indicator SDO provides to identify those properties in security detection systems designed to process the STIX Pattern grammar. It is better to the use of STIX Indicators
/// for the detection of actual malware, due to its use of the STIX Patterning language and the clear semantics that it provides.
///
/// To minimize the risk of a consumer compromising their system in parsing malware samples, producers SHOULD consider sharing defanged content (archive and password-protected
/// samples) instead of raw, base64-encoded malware samples.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_s5l7katgbp09>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
/// Represents a malware instance or family.
pub struct Malware {
    /// A name used to identify the malware instance or family.
    pub name: Option<String>,
    /// A description providing more details about the malware.
    pub description: Option<String>,
    /// A set of categorizations for the malware.
    ///
    /// The values for this property **SHOULD** come from the `malware-type-ov` open vocabulary.
    pub malware_types: Option<Vec<String>>,
    /// Whether the object represents a malware family or instance.
    pub is_family: bool,
    /// Alternative names for the malware.
    pub aliases: Option<Vec<String>>,
    /// List of Kill Chain Phases for which this malware can be used.
    pub kill_chain_phases: Option<Vec<KillChainPhase>>,
    /// The time the malware was first seen.
    pub first_seen: Option<Timestamp>,
    /// The time the malware was last seen.
    ///
    /// If this property and the `first_seen` property are both defined, then this property **MUST** be greater than or equal to the timestamp in the `first_seen` property.
    pub last_seen: Option<Timestamp>,
    /// Operating systems the malware is executable on.
    ///
    /// The value of this property **MUST** be the `identifier` for a SCO `software` object.
    pub operating_system_refs: Option<Vec<Identifier>>,
    /// Processor architectures the malware is executable on.
    ///
    /// The values for this property **SHOULD** come from the `processor-architecture-ov` open vocabulary.
    pub architecture_execution_envs: Option<Vec<String>>,
    /// Programming languages used to implement the malware.
    ///
    /// The values for this property **SHOULD** come from the `implementation-language-ov` open vocabulary.
    pub implementation_languages: Option<Vec<String>>,
    /// Capabilities identified for the malware.
    ///
    /// The values for this property **SHOULD** come from the `malware-capabilities-ov` open vocabulary.
    pub capabilities: Option<Vec<String>>,
    /// Identifiers of the SCO file or artifact objects associated with the malware.
    ///
    /// If `is_family` is false, then all samples listed in sample_refs **MUST** refer to the same binary data.
    pub sample_refs: Option<Vec<Identifier>>,
}

//The method currently returns Ok(()), indicating a successful result with no additional data.
impl Stix for Malware {
    // malware_types should be from malware-type-ov
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(aliases) = &self.aliases {
            add_error(&mut errors, aliases.stix_check());
        }
        if let Some(kill_chain_phases) = &self.kill_chain_phases {
            add_error(&mut errors, kill_chain_phases.stix_check());
        }
        if let (Some(start), Some(stop)) = (&self.first_seen, &self.last_seen) {
            if stop < start {
                errors.push(Error::ValidationError(format!("Malware has a last seen timestamp of {} and a first seen timestamp of {}. The former cannot be earlier than the latter.",
                    stop,
                    start
                )));
            }
        }
        if let Some(malware_types) = &self.malware_types {
            add_error(&mut errors, malware_types.stix_check());
            for malware_type in malware_types {
                if MalwareType::iter()
                    .all(|x| x.as_ref() != malware_type.as_str().to_case(Case::Kebab))
                {
                    warn!("malware_types '{}' should come from the list", malware_type);
                }
            }
        }

        // malware operating_system_refs
        if let Some(operating_system_refs) = &self.operating_system_refs {
            add_error(&mut errors, operating_system_refs.stix_check());
            for operating_system_ref in operating_system_refs {
                if operating_system_ref.get_type().to_case(Case::Kebab) != "software" {
                    errors.push(Error::ValidationError(format!(
                        "A operating_system_refs must be a software SCO. Malware operating_system_ref is type '{}' .",
                        operating_system_ref.get_type(),
                    )));
                }
            }
        }

        // malware architecture_execution_envs
        if let Some(architecture_execution_envs) = &self.architecture_execution_envs {
            add_error(&mut errors, architecture_execution_envs.stix_check());
            for architecture_execution_env in architecture_execution_envs {
                if ArchitectureExecutionEnvs::iter()
                    .all(|x| x.as_ref() != architecture_execution_env.as_str().to_case(Case::Kebab))
                {
                    warn!(
                        "A architecture_execution_env should come from the STIX pattern type open vocabulary. Malware architecture_execution_env '{}' is not in the vocabulary.",
                        architecture_execution_env,
                    );
                }
            }
        }

        // malware implementation_languages
        if let Some(implementation_languages) = &self.implementation_languages {
            add_error(&mut errors, implementation_languages.stix_check());
            for implementation_language in implementation_languages {
                if ImplementationLanguage::iter()
                    .all(|x| x.as_ref() != implementation_language.as_str().to_case(Case::Kebab))
                {
                    warn!(
                        "A implementation_languages should come from the STIX pattern type open vocabulary. Malware implementation_languages '{}' is not in the vocabulary.",
                        implementation_language,
                    );
                }
            }
        }
        // malware capabilities (optional)
        if let Some(capabilities) = &self.capabilities {
            add_error(&mut errors, capabilities.stix_check());
            for capability in capabilities {
                if MalwareCapability::iter()
                    .all(|x| x.as_ref() != capability.as_str().to_case(Case::Kebab))
                {
                    warn!(
                        "A capability should come from the STIX pattern type open vocabulary. Malware capability '{}' is not in the vocabulary.",
                        capability,
                    );
                }
            }
        }
        // malware sample_refs
        if let Some(sample_refs) = &self.sample_refs {
            add_error(&mut errors, sample_refs.stix_check());
            for sample_ref in sample_refs {
                if !["artifact", "file"].contains(&sample_ref.get_type()) {
                    warn!(
                        "A sample_refs should come from the STIX pattern type open vocabulary. Malware sample_refs '{}' is not in the vocabulary.",
                        sample_ref,
                    );
                }
            }
        }

        return_multiple_errors(errors)
    }
}

/// Malware Analysis SDOs
///
/// Malware Analysis captures the metadata and results of a particular static or dynamic analysis performed on a malware instance or family. One of `result` or
/// `analysis_sco_refs` properties MUST be provided.
///
/// For more information, see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_6hdrixb3ua4j>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MalwareAnalysis {
    /// The name of the analysis engine or product that was used.
    pub product: String,
    /// The version of the analysis product that was used to perform the analysis.
    pub version: Option<String>,
    /// A description of the virtual machine environment used to host the guest operating system
    ///
    /// The value of this property **MUST** be the `identifier` for a SCO `software` object
    pub host_vm_ref: Option<Identifier>,
    /// The operating system used for the dynamic analysis of the malware instance or family.
    ///
    /// The value of this property **MUST** be the `identifier` for a SCO `software` object
    pub operating_system_ref: Option<Identifier>,
    /// Any non-standard software installed on the operating system
    pub installed_software_refs: Option<Vec<Identifier>>,
    /// The named configuration of additional product configuration parameters for this analysis run.
    pub configuration_version: Option<String>,
    /// The specific analysis modules that were used and configured in the product during this analysis run.
    pub modules: Option<Vec<String>>,
    /// The version of the analysis engine or product (including AV engines) that was used to perform the analysis.
    pub analysis_engine_version: Option<String>,
    /// The version of the analysis engine or product (including AV engines) that was used to perform the analysis.
    pub analysis_definition_version: Option<String>,
    /// The date and time that the malware was first submitted for scanning or analysis.
    pub submitted: Option<Timestamp>,
    /// The date and time that the malware analysis was initiated.
    pub analysis_started: Option<Timestamp>,
    /// The date and time that the malware analysis ended.
    pub analysis_ended: Option<Timestamp>,
    /// The classification result as determined by the scanner or tool analysis process.
    pub result_name: Option<String>,
    /// The classification result as determined by the scanner or tool analysis process
    ///
    /// The value for this property **SHOULD** come from the `malware-result-ov` open vocabulary.
    pub result: Option<String>,
    /// This property contains the references to the STIX Cyber-observable Objects that were captured during the analysis process.
    pub analysis_sco_refs: Option<Vec<Identifier>>,
    /// This property contains the reference to the SCO file, network traffic or artifact object that this malware analysis was performed against.
    pub sample_ref: Option<Identifier>,
}

impl Stix for MalwareAnalysis {
    // malware_types should be from malware-type-ov
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        let product = &self.product;
        if *product != product.to_case(Case::Kebab) {
            warn!("Product names SHOULD be all lowercase with words separated by a dash '-'",);
        }

        // MalwareAnalysis host_vm_ref
        if let Some(host_vm_ref) = &self.host_vm_ref {
            add_error(&mut errors, host_vm_ref.stix_check());
            if host_vm_ref.get_type() != "software" {
                errors.push(Error::ValidationError(format!(
                    "A host_vm_ref must be the identifier for a software SCO. The provided identifier has type '{}'",host_vm_ref.get_type(), 
                )));
            }
        }

        if let Some(modules) = &self.modules {
            add_error(&mut errors, modules.stix_check());
        }

        //MalwareAnalysis operating_system_ref (optional)
        if let Some(operating_system_ref) = &self.operating_system_ref {
            add_error(&mut errors, operating_system_ref.stix_check());
            if operating_system_ref.get_type() != "software" {
                errors.push(Error::ValidationError(format!(
                    "A operating_system_ref must be the identifier for a software SCO. The provided identifier has type '{}'",operating_system_ref.get_type(),
                )));
            }
        }

        // MalwareAnalysis operating_system_refs
        if let Some(installed_software_refs) = &self.installed_software_refs {
            add_error(&mut errors, installed_software_refs.stix_check());
            for installed_software_ref in installed_software_refs {
                if installed_software_ref.get_type() != "software" {
                    errors.push(Error::ValidationError(format!(
                        "An installed_software_ref must be the identifier for a software SCO. The provided identifier has type '{}'",installed_software_ref.get_type(),
                    )));
                }
            }
        }

        // MalwareAnalysis result (optional)
        if let Some(result) = &self.result {
            if !MalwareResult::iter().any(|x| x.as_ref() == result.to_case(Case::Kebab)) {
                warn!(
                    "A result should come from the malware-result-ov open vocabulary. Malware Analysis result '{}' is not in the vocabulary.",result
            );
            }
        }

        // malware analysis_sco_refs
        if let Some(analysis_sco_refs) = &self.analysis_sco_refs {
            add_error(&mut errors, analysis_sco_refs.stix_check());
            for analysis_sco_ref in analysis_sco_refs {
                if ScoTypes::iter()
                    .all(|x| x.as_ref() != analysis_sco_ref.get_type().to_case(Case::Kebab))
                {
                    warn!(
                        "An analysis_sco_ref should come from STIX Cyber-observable objects. Malware is type '{}'.",
                        analysis_sco_ref,
                    );
                }
                if !SroTypes::iter()
                    .all(|x| x.as_ref() != analysis_sco_ref.get_type().to_case(Case::Kebab))
                    || !SdoTypes::iter()
                        .all(|x| x.as_ref() != analysis_sco_ref.get_type().to_case(Case::Kebab))
                    || !StixMetaTypes::iter()
                        .all(|x| x.as_ref() != analysis_sco_ref.get_type().to_case(Case::Kebab))
                {
                    errors.push(Error::ValidationError(format!(
                        "An analysis_sco_ref should come from STIX Cyber-observable objects. Malware '{}' is not in the SCO.",
                        analysis_sco_ref,
                    )));
                }
            }
        }
        // MalwareAnalysis sample_ref
        if let Some(sample_ref) = &self.sample_ref {
            add_error(&mut errors, sample_ref.stix_check());
            if !ScoTypes::iter().any(|x| x.as_ref() == sample_ref.get_type().to_case(Case::Kebab)) {
                warn!(
                    "A sample_ref must be an SCO. Malware Analysis host_vm_ref is type '{}'.",
                    sample_ref.get_type(), // Ensure this is what you want to log
                );
            }

            if !SroTypes::iter().all(|x| x.as_ref() != sample_ref.get_type().to_case(Case::Kebab))
                || !SdoTypes::iter()
                    .all(|x| x.as_ref() != sample_ref.get_type().to_case(Case::Kebab))
                || !StixMetaTypes::iter()
                    .all(|x| x.as_ref() != sample_ref.get_type().to_case(Case::Kebab))
            {
                errors.push(Error::ValidationError(format!(
                    "A sample_ref must be an SCO. Malware Analysis host_vm_ref is type '{}'.",
                    sample_ref,
                )));
            }
        }

        // Return Ok(()) to satisfy the expected return type
        return_multiple_errors(errors)
    }
}

/// Note SDOs
///
/// A Note is intended to convey informative text to provide further context and/or to provide additional analysis not contained in the STIX Objects, Marking Definition
/// objects, or Language Content objects which the Note relates to. Notes can be created by anyone (not just the original object creator).
///
/// For example, an analyst may add a Note to a Campaign object created by another organization indicating that they've seen posts related to that Campaign on a hacker forum.
///
/// Because Notes are typically (though not always) created by human analysts and are comprised of human-oriented text, they contain an additional property to capture the
/// analyst(s) that created the Note. This is distinct from the `created_by_ref` property, which is meant to capture the organization that created the object.
///  
/// For more information, see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_gudodcg1sbb9>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    /// An optional abstract providing a summary of the note.
    #[serde(rename = "abstract")]
    pub set_abstract: Option<String>,

    /// A required string that provides the content of the note.
    pub content: String,

    /// An optional list of authors of the note.
    pub authors: Option<Vec<String>>,

    /// A list of references to other STIX objects.
    pub object_refs: Vec<Identifier>,
}

impl Stix for Note {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(authors) = &self.authors {
            add_error(&mut errors, authors.stix_check());
        }
        add_error(&mut errors, self.object_refs.stix_check());

        return_multiple_errors(errors)
    }
}

/// Observed Data SDOs
///
/// Observed Data conveys information about cyber security related entities such as files, systems, and networks using the STIX Cyber-observable Objects (SCOs). For example,
/// Observed Data can capture information about an IP address, a network connection, a file, or a registry key. Observed Data is not an intelligence assertion, it is simply
/// the raw information without any context for what it means.
///
/// Observed Data can capture that a piece of information was seen one or more times. Meaning, it can capture both a single observation of a single entity (file, network
/// connection) as well as the aggregation of multiple observations of an entity. When the `number_observed` property is 1 the Observed Data represents a single entity. When
/// the `number_observed` property is greater than 1, the Observed Data represents several instances of an entity potentially collected over a period of time. If a time window
/// is known, that can be captured using the `first_observed` and `last_observed` properties. When used to collect aggregate data, it is likely that some properties in the SCO
/// (e.g., timestamp properties) will be omitted because they would differ for each of the individual observations.
///
/// Observed Data may be used by itself (without relationships) to convey raw data collected from any source including analyst reports, sandboxes, and network and host-based
/// detection tools. An intelligence producer conveying Observed Data **SHOULD** include as much context (e.g. SCOs) as possible that supports the use of the observed data set in
/// systems expecting to utilize the Observed Data for improved security. This includes all SCOs that matched on an Indicator pattern and are represented in the collected
/// observed event (or events) being conveyed in the Observed Data object. For example, a firewall could emit a single Observed Data instance containing a single Network
/// Traffic object for each connection it sees. The firewall could also aggregate data and instead send out an Observed Data instance every ten minutes with an IP address and
/// an appropriate `number_observed` value to indicate the number of times that IP address was observed in that window. A sandbox could emit an Observed Data instance containing
/// a file hash that it discovered.
///
/// Observed Data may also be related to other SDOs to represent raw data that is relevant to those objects. For example, the Sighting Relationship object, can relate an Indicator,
/// Malware, or other SDO to a specific Observed Data to represent the raw information that led to the creation of the Sighting (e.g., what was actually seen that suggested that a
/// particular instance of malware was active).
///
/// To support backwards compatibility, related SCOs can still be specified using the `objects` properties, Either the `objects` property or the `object_refs` property **MUST** be
/// provided, but both **MUST NOT** be present at the same time.
///
/// For more information, see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_p49j1fwoxldc>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedData {
    /// The beginning of the time window during which the data was seen.
    pub first_observed: Timestamp,
    /// The end of the time window during which the data was seen.
    ///
    /// This **MUST** be greater than or equal to `first_observed`.
    pub last_observed: Timestamp,
    /// The number of times that each Cyber-observable object represented in the objects or object_ref property was seen. If present, this **MUST** be an integer between 1 and 999,999,999 inclusive.
    #[serde(default, deserialize_with = "as_u64")]
    pub number_observed: u64,
    /// A list of SCOs and SROs representing the observation. The `object_refs` **MUST** contain at least one SCO reference if defined.
    pub object_refs: Vec<Identifier>,
}

impl Stix for ObservedData {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        add_error(&mut errors, self.number_observed.stix_check());
        if self.last_observed < self.first_observed {
            errors.push(Error::ValidationError(format!(
                "The last_observed timestamp {} cannot be earlier than the first_observed timestamp {}.",
                self.last_observed,
                self.first_observed
            )));
        }

        if self.number_observed < 1 || self.number_observed > 999_999_999 {
            errors.push(Error::ValidationError(format!(
                "The number_observed {} must be an integer between 1 and 999,999,999 inclusive.",
                self.number_observed
            )));
        }

        let mut has_sco = false;
        let mut has_custom = false;
        for object_ref in self.object_refs.iter() {
            add_error(&mut errors, self.object_refs.stix_check());
            // Check for known SDOs and SMOs, which are prohibited
            if SdoTypes::iter().any(|s| s.as_ref() == object_ref.get_type().to_case(Case::Kebab))
                || StixMetaTypes::iter()
                    .any(|s| s.as_ref() == object_ref.get_type().to_case(Case::Kebab))
            {
                errors.push(Error::ValidationError(format!(
                    "The `object_refs` list must contain only SCO and SRO types. {} is neither.",
                    object_ref.get_type().to_case(Case::Kebab)
                )));
            // Check for known SCOs, which are permitted, and flag if at least one is found
            } else if ScoTypes::iter()
                .any(|s| s.as_ref() == object_ref.get_type().to_case(Case::Kebab))
            {
                has_sco = true;
            // Check for known SROs, which are permitted. If the object_ref is not that, it must be a custom type of known object_type
            } else if !SroTypes::iter()
                .any(|s| s.as_ref() == object_ref.get_type().to_case(Case::Kebab))
            {
                warn!(
                    "The `object_refs` list must contain only SCO and SRO types. Confirm that {} is one of those types.",
                    object_ref.get_type().to_case(Case::Kebab)
                );
                has_custom = true;
            }
        }

        if !has_sco {
            if !has_custom {
                errors.push(Error::ValidationError(
                    "The `object_refs` list must contain at least one SCO type.".to_string(),
                ));
            } else {
                warn!(
                    "The `object_refs` list must contain at least one SCO type. Confirm that at least one of the included custom types is an SCO."
                );
            }
        }
        return_multiple_errors(errors)
    }
}

/// Opinion SDOs
///
/// An Opinion is an assessment of the correctness of the information in a STIX Object produced by a different entity. The primary property is the opinion property, which
/// captures the level of agreement or disagreement using a fixed scale. That fixed scale also supports a numeric mapping to allow for consistent statistical operations
/// across opinions.
///
/// For example, an analyst from a consuming organization might say that they "strongly disagree" with a Campaign object and provide an explanation about why. In a more
/// automated workflow, a SOC operator might give an Indicator "one star" in their TIP (expressing "strongly disagree") because it is considered to be a false positive
/// within their environment. Opinions are subjective, and the specification does not address how best to interpret them. Sharing communities are encouraged to provide clear
/// guidelines to their constituents regarding best practice for the use of Opinion objects within the community.
///
/// Because Opinions are typically (though not always) created by human analysts and are comprised of human-oriented text, they contain an additional property to capture the
/// analyst(s) that created the Opinion. This is distinct from the `created_by_ref` property, which is meant to capture the organization that created the object.
///
/// For more information, see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ht1vtzfbtzda>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Opinion {
    /// An optional abstract providing a summary of the note.
    pub explanation: Option<String>,
    /// The name of the author(s) of this Opinion (e.g., the analyst(s) that created it).
    pub authors: Option<Vec<String>>,
    /// A required string that provides the content of the note.
    ///
    /// The value of this property **MUST** come from the `opinion-enum` open vocabulary
    pub opinion: OpinionType,
    /// A list of references to other STIX objects.
    pub object_refs: Vec<Identifier>,
}

impl Stix for Opinion {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        let opinion = &self.opinion.as_ref().to_string();
        if OpinionType::iter().all(|x| x.as_ref() != opinion.to_case(Case::Kebab)) {
            errors.push(Error::ValidationError(format!(
                "The values of opinion MUST come from the opinion-enum enumeration {}.",
                opinion,
            )));
        }
        if let Some(authors) = &self.authors {
            add_error(&mut errors, authors.stix_check());
        }

        add_error(&mut errors, self.object_refs.stix_check());
        return_multiple_errors(errors)
    }
}

/// Report SDOs
///
/// Reports are collections of threat intelligence focused on one or more topics, such as a description of a threat actor, malware, or attack technique, including context and
/// related details. They are used to group related threat intelligence together so that it can be published as a comprehensive cyber threat story.
///
/// The Report SDO contains a list of references to STIX Objects (the CTI objects included in the report) along with a textual description and the name of the report.
///
/// For example, a threat report produced by ACME Defense Corp. discussing the Glass Gazelle campaign should be represented using Report. The Report itself would contain the
/// narrative of the report while the Campaign SDO and any related SDOs (e.g., Indicators for the Campaign, Malware it uses, and the associated Relationships) would be
/// referenced in the report contents.
///
/// For more information, see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_n8bjzg1ysgdq>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// A name used to identify the Report.
    /// This field is required.
    pub name: String,

    /// A description that provides more details and context about the Report,
    /// potentially including its purpose and its key characteristics.
    /// This field is optional.
    pub description: Option<String>,

    /// This property is an open vocabulary that specifies the primary subject(s) of this report.
    /// This is an open vocabulary and values SHOULD come from the report-type-ov vocabulary.
    /// This field is required.
    pub report_types: Option<Vec<String>>,

    /// The date that this Report object was officially published by the creator of this report.
    /// The publication date (public release, legal release, etc.) may be different than the date
    /// the report was created or shared internally (the date in the created property).
    /// This field is required.
    pub published: Timestamp,

    /// Specifies the STIX Objects that are referred to by this Report.
    /// This field is required.
    /// A list of references to other STIX objects.
    pub object_refs: Vec<Identifier>,
}

impl Stix for Report {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(report_types) = &self.report_types {
            add_error(&mut errors, report_types.stix_check());
            for report_type in report_types {
                if ReportType::iter().all(|x| x.as_ref() != report_type.to_case(Case::Kebab)) {
                    warn!(
                        "A report type must be an SDO. Report is type {}.",
                        report_type,
                    );
                }
                if !ScoTypes::iter().all(|x| x.as_ref() != report_type.to_case(Case::Kebab))
                    || !SroTypes::iter().all(|x| x.as_ref() != report_type.to_case(Case::Kebab))
                    || !StixMetaTypes::iter()
                        .all(|x| x.as_ref() != report_type.to_case(Case::Kebab))
                {
                    errors.push(Error::ValidationError(format!(
                        "A report type must be an SDO. Report is type {}.",
                        report_type,
                    )));
                }
            }
            add_error(&mut errors, self.object_refs.stix_check());
        }
        return_multiple_errors(errors)
    }
}

/// ThreatActor SDOs
///
/// Threat Actors are actual individuals, groups, or organizations believed to be operating with malicious intent. A Threat Actor is not an Intrusion Set but may support or
/// be affiliated with various Intrusion Sets, groups, or organizations over time.
///
/// Threat Actors leverage their resources, and possibly the resources of an Intrusion Set, to conduct attacks and run Campaigns against targets.
///
/// Threat Actors can be characterized by their motives, capabilities, goals, sophistication level, past activities, resources they have access to, and their role in the
/// organization.
///
/// For more information, see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_k017w16zutw>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatActor {
    /// A name used to identify this Threat Actor or Threat Actor group.
    pub name: String,
    /// A description that provides more details and context about the Threat Actor.
    pub description: Option<String>,
    /// Specifies the type(s) of this threat actor.
    ///
    /// The values for this property **SHOULD** come from the `threat-actor-type-ov` open vocabulary.
    pub threat_actor_types: Option<Vec<String>>,
    /// A list of other names that this Threat Actor is believed to use.
    pub aliases: Option<Vec<String>>,
    /// The time that this Threat Actor was first seen.
    pub first_seen: Option<Timestamp>,
    /// The time that this Threat Actor was last seen.
    ///
    /// If this property and the `first_seen` property are both defined, then this property **MUST** be greater than or equal to the timestamp in the `first_seen` property.
    pub last_seen: Option<Timestamp>,
    /// A list of roles the Threat Actor plays.
    ///
    /// The values for this property **SHOULD** come from the `threat-actor-role-ov` open vocabulary.
    pub roles: Option<Vec<String>>,
    /// The high-level goals of this Threat Actor.
    pub goals: Option<Vec<String>>,
    /// The skill or expertise a Threat Actor must have to perform the attack.
    ///
    /// The value for this property **SHOULD** come from the `threat-actor-sophistication-ov` open vocabulary.
    pub sophistication: Option<String>,
    /// Defines the organizational level at which this Threat Actor typically works. This attribute is linked to the `sophistication` property — a specific resource level
    /// implies that the Threat Actor has access to at least a specific sophistication level.
    ///
    /// The value for this property **SHOULD** come from the `attack-resource-level-ov` open vocabulary.
    pub resource_level: Option<String>,
    /// The primary reason, motivation, or purpose behind this Threat Actor.
    ///
    /// The value for this property SHOULD come from the `attack-motivation-ov `open vocabulary.
    pub primary_motivation: Option<String>,
    /// The secondary reasons, motivations, or purposes behind this Threat Actor.
    ///  
    /// The value for this property SHOULD come from the `attack-motivation-ov `open vocabulary.
    pub secondary_motivations: Option<Vec<String>>,
    /// The personal reasons, motivations, or purposes of the Threat Actor.
    ///
    /// The value for this property SHOULD come from the `attack-motivation-ov `open vocabulary.
    pub personal_motivations: Option<Vec<String>>,
}

impl Stix for ThreatActor {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(actor_types) = &self.threat_actor_types {
            add_error(&mut errors, actor_types.stix_check());
            for actor_type in actor_types {
                if ThreatActorType::iter().all(|x| x.as_ref() != actor_type.to_case(Case::Kebab)) {
                    warn!(
                        "A actor type should come from the STIX pattern type open vocabulary. Threat actor type '{}' is not in the vocabulary.",
                        actor_type,
                    );
                }
            }
        }
        if let Some(aliases) = &self.aliases {
            add_error(&mut errors, aliases.stix_check());
        }
        if let (Some(start), Some(stop)) = (&self.first_seen, &self.last_seen) {
            if stop < start {
                errors.push(Error::ValidationError(format!("The threat actor has a last seen timestamp of {} and a first seen timestamp of {}. The former cannot be earlier than the latter.",
                    stop,
                    start
                )));
            }
        }
        if let Some(roles) = &self.roles {
            add_error(&mut errors, roles.stix_check());
            for role in roles {
                if ThreatActorRole::iter().all(|x| x.as_ref() != role.as_str().to_case(Case::Kebab))
                {
                    warn!(
                        "A role should come from the STIX pattern type open vocabulary. Threat actor role '{}' is not in the vocabulary.",
                        role,
                    );
                }
            }
        }
        if let Some(goals) = &self.goals {
            add_error(&mut errors, goals.stix_check());
        }

        if let Some(sophistication) = self.sophistication.as_deref() {
            if ThreatActorSophistication::iter()
                .all(|x| x.as_ref() != sophistication.to_case(Case::Kebab))
            {
                warn!(
                        "A sophistication should come from the STIX pattern type open vocabulary. Threat actor sophistication {} is not in the vocabulary.",
                        sophistication,
                    );
            }
        }
        if let Some(primary_motivation) = self.primary_motivation.as_deref() {
            if AttackMotivation::iter()
                .all(|x| x.as_ref() != primary_motivation.to_case(Case::Kebab))
            {
                warn!(
                        "A primary_motivation should come from the STIX pattern type open vocabulary. Threat actor primary_motivation {} is not in the vocabulary.",
                        primary_motivation,
                    );
            }
        }

        if let Some(secondary_motivations) = &self.secondary_motivations {
            add_error(&mut errors, secondary_motivations.stix_check());
            for secondary_motivation in secondary_motivations {
                if AttackMotivation::iter()
                    .all(|x| x.as_ref() != secondary_motivation.as_str().to_case(Case::Kebab))
                {
                    warn!(
                        "A secondary_motivation should come from the STIX pattern type open vocabulary. Threat actor secondary_motivation '{}' is not in the vocabulary.",
                        secondary_motivation,
                    );
                }
            }
        }
        if let Some(personal_motivations) = &self.personal_motivations {
            add_error(&mut errors, personal_motivations.stix_check());
            for personal_motivation in personal_motivations {
                if AttackMotivation::iter()
                    .all(|x| x.as_ref() != personal_motivation.as_str().to_case(Case::Kebab))
                {
                    warn!(
                        "A primary_motivation should come from the STIX pattern type open vocabulary. Threat actor primary_motivation '{}' is not in the vocabulary.",
                        personal_motivation,
                    );
                }
            }
        }

        return_multiple_errors(errors)
    }
}

/// Tool SDOs
///
/// Tools are legitimate software that can be used by threat actors to perform attacks. Knowing how and when threat actors use such tools can be important for understanding
/// how campaigns are executed. Unlike malware, these tools or software packages are often found on a system and have legitimate purposes for power users, system
/// administrators, network administrators, or even normal users. Remote access tools (e.g., RDP) and network scanning tools (e.g., Nmap) are examples of Tools that may be
/// used by a Threat Actor during an attack.
///
/// The Tool SDO characterizes the properties of these software tools and can be used as a basis for making an assertion about how a Threat Actor uses them during an attack.
/// It contains properties to name and describe the tool, a list of Kill Chain Phases the tool can be used to carry out, and the version of the tool.
///
/// This SDO **MUST NOT** be used to characterize malware. Further, Tool **MUST NOT** be used to characterize tools used as part of a course of action in response to an attack.
///
/// For more information, see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_z4voa9ndw8v>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tool {
    /// The name used to identify the Tool.
    pub name: String,
    /// A description that provides more details and context about the Tool, potentially including its purpose and its key characteristics.
    pub description: Option<String>,
    /// The kind(s) of tool(s) being described.
    ///
    /// The values for this property **SHOULD** come from the `tool-type-ov` open vocabulary.
    pub tool_types: Option<Vec<String>>,
    /// Alternative names used to identify this Tool.
    pub aliases: Option<Vec<String>>,
    /// The list of kill chain phases for which this Tool can be used.
    pub kill_chain_phases: Option<Vec<KillChainPhase>>,
    /// The version identifier associated with the Tool.
    pub tool_version: Option<String>,
}

impl Stix for Tool {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(kill_chain_phases) = &self.kill_chain_phases {
            add_error(&mut errors, kill_chain_phases.stix_check());
        }
        if let Some(tool_types) = &self.tool_types {
            tool_types.stix_check()?;
            for tool_type in tool_types {
                if !ToolType::iter().any(|x| x.as_ref() == tool_type.to_case(Case::Kebab)) {
                    warn!(
                        "The values of the tool_types property should come from the `tool type-ov` open vocabulary. Tool type '{}' is not in the vocabulary.", tool_type
                    );
                }
            }
        }
        if let Some(aliases) = &self.aliases {
            add_error(&mut errors, aliases.stix_check());
        }

        return_multiple_errors(errors)
    }
}

/// Vulnerability SDOs
///
/// A Vulnerability is a weakness or defect in the requirements, designs, or implementations of the computational logic (e.g., code) found in software and some hardware
/// components (e.g., firmware) that can be directly exploited to negatively impact the confidentiality, integrity, or availability of that system.
///
/// CVE is a list of information security vulnerabilities and exposures that provides common names for publicly known problems [CVE](http://cve.mitre.org/). For example, if a
/// piece of malware exploits CVE-2015-12345, a Malware object could be linked to a Vulnerability object that references CVE-2015-12345.
///
/// The Vulnerability SDO is primarily used to link to external definitions of vulnerabilities or to describe 0-day vulnerabilities that do not yet have an external definition.
/// Typically, other SDOs assert relationships to Vulnerability objects when a specific vulnerability is targeted and exploited as part of malicious cyber activity. As such,
/// Vulnerability objects can be used as a linkage to the asset management and compliance process.
///
/// For more information, see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_q5ytzmajn6re>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vulnerability {
    /// Required: The name of the Vulnerability.
    pub name: String,
    /// An optional description providing more details about the Vulnerability.
    pub description: Option<String>,
}

//The method currently returns Ok(()), indicating a successful result with no additional data.
impl Stix for Vulnerability {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
    }
}
