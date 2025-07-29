use crate::{error::StixError as Error, types::Identifier};

use serde::{Deserialize, Serialize};
use strum::{AsRefStr, Display as StrumDisplay, EnumString};

#[derive(
    Debug, PartialEq, Eq, Clone, Deserialize, Serialize, AsRefStr, StrumDisplay, EnumString,
)]
#[serde(tag = "relationship_type", rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum RelationshipType {
    // Common relationships
    DuplicateOf,
    DerivedFrom,
    RelatedTo,
    // SDO specific relationships
    AnalysisOf,
    AttributedTo,
    AuthoredBy,
    BasedOn,
    BeaconsTo,
    Characterizes,
    CommunicatesWith,
    Compromises,
    ConsistsOf,
    Controls,
    Delivers,
    Downloads,
    Drops,
    DynamicAnalysisOf,
    ExfiltratesTo,
    Exploits,
    Has,
    Hosts,
    Impersonates,
    Indicates,
    Investigates,
    LocatedAt,
    Mitigates,
    OriginatesFrom,
    Owns,
    Remediates,
    StaticAnalysisOf,
    Targets,
    Uses,
    VariantOf,
    // Custom relationship, storing the relationship name
    Custom(String),
}

impl RelationshipType {
    /// Checks that the relationship type is allowed between the provided source and target SDOs or SCOs
    /// Errors if not allowed
    pub fn validate(&self, source: &Identifier, target: &Identifier) -> Result<(), Error> {
        let source_type = source.get_type();
        let target_type = target.get_type();

        let valid = match self {
            RelationshipType::DerivedFrom => source_type == target_type,
            RelationshipType::DuplicateOf => source_type == target_type,
            RelationshipType::RelatedTo => true,
            RelationshipType::AnalysisOf => {
                source_type == "malware-analysis" && target_type == "malware"
            }
            RelationshipType::AttributedTo => {
                (source_type == "campaign"
                    && ["intrusion-set", "threat-actor"].contains(&target_type))
                    || (source_type == "intrustion-set" && target_type == "threat-actor")
                    || (source_type == "threat-actor" && target_type == "identity")
            }
            RelationshipType::AuthoredBy => {
                source_type == "malware"
                    && ["intrustion-set", "threat-actor"].contains(&target_type)
            }
            RelationshipType::BasedOn => {
                source_type == "indicator" && target_type == "observed-data"
            }
            RelationshipType::BeaconsTo => {
                source_type == "malware" && target_type == "infrastructure"
            }
            RelationshipType::Characterizes => {
                source_type == "malware-analysis" && target_type == "malware"
            }
            RelationshipType::CommunicatesWith => {
                (source_type == "infrastructure"
                    && [
                        "domain-name",
                        "infrastructure",
                        "ipv4-addr",
                        "ipv6-addr",
                        "url",
                    ]
                    .contains(&target_type))
                    || (source_type == "malware"
                        && ["domain-name", "ipv4-addr", "ipv6-addr", "url"].contains(&target_type))
            }
            RelationshipType::Compromises => {
                ["campaign", "intrusion-set", "threat-actor"].contains(&source_type)
                    && target_type == "infrastructure"
            }
            RelationshipType::ConsistsOf => {
                source_type == "infrastructure"
                    && [
                        "infrastructure",
                        "observed-data",
                        "artifact",
                        "autonomous-system",
                        "directory",
                        "domain-name",
                        "email-addr",
                        "email-message",
                        "email-mime-part-type",
                        "file",
                        "ipv4-addr",
                        "ipv6-addr",
                        "mac-addr",
                        "mutex",
                        "network-traffic",
                        "process",
                        "software",
                        "url",
                        "user-account",
                        "windows-registry-key",
                        "x509-certificate",
                    ]
                    .contains(&target_type)
            }
            RelationshipType::Controls => {
                (source_type == "infrastructure"
                    && ["infrastructure", "malware"].contains(&target_type))
                    || (source_type == "malware" && target_type == "malware")
            }
            RelationshipType::Delivers => {
                ["attack-pattern", "infrastructure", "tool"].contains(&source_type)
                    && target_type == "malware"
            }
            RelationshipType::Downloads => {
                source_type == "malware" && ["malware", "file", "tool"].contains(&target_type)
            }
            RelationshipType::Drops => {
                source_type == "malware" && ["malware", "file", "tool"].contains(&target_type)
            }
            RelationshipType::DynamicAnalysisOf => {
                source_type == "malware-analysis" && target_type == "malware"
            }
            RelationshipType::ExfiltratesTo => {
                source_type == "malware" && target_type == "infrastructure"
            }
            RelationshipType::Exploits => {
                source_type == "malware" && target_type == "vulnerability"
            }
            RelationshipType::Has => {
                ["infrastructure", "tool"].contains(&source_type) && target_type == "vulnerability"
            }
            RelationshipType::Hosts => {
                (source_type == "infrastructure" && ["malware", "tools"].contains(&target_type))
                    || (source_type == "intrusion-set" && target_type == "infrastructure")
                    || (source_type == "threat-actor" && target_type == "infrastructure")
            }
            RelationshipType::Impersonates => {
                source_type == "indicator" && target_type == "identity"
            }
            RelationshipType::Indicates => {
                source_type == "malware"
                    && [
                        "attack-pattern",
                        "campaign",
                        "infrastructure",
                        "intrusion-set",
                        "malware",
                        "threat-actor",
                        "tool",
                    ]
                    .contains(&target_type)
            }
            RelationshipType::Investigates => {
                source_type == "course-of-action" && target_type == "indicator"
            }
            RelationshipType::LocatedAt => {
                ["identity", "infrastructure", "threat-actor"].contains(&source_type)
                    && target_type == "location"
            }
            RelationshipType::Mitigates => {
                source_type == "course-of-action"
                    && [
                        "attack-pattern",
                        "infrastructure",
                        "malware",
                        "tool",
                        "vulnerability",
                    ]
                    .contains(&target_type)
            }
            RelationshipType::OriginatesFrom => {
                ["campaign", "intrustion-set", "malware"].contains(&source_type)
                    && target_type == "location"
            }
            RelationshipType::Owns => {
                ["intrusion-set", "threat-actor"].contains(&source_type)
                    && target_type == "infrastructure"
            }
            RelationshipType::Remediates => {
                source_type == "course-of-action"
                    && ["malware", "vulnerability"].contains(&target_type)
            }
            RelationshipType::StaticAnalysisOf => {
                source_type == "malware-analysis" && target_type == "malware"
            }
            RelationshipType::Targets => {
                ([
                    "attack-pattern",
                    "campaign",
                    "intrustion-set",
                    "threat-actor",
                ]
                .contains(&source_type)
                    && ["identity", "location", "vulnerability"].contains(&target_type))
                    || (["malware", "tool"].contains(&source_type)
                        && ["identity", "infrastructure", "location", "vulnerability"]
                            .contains(&target_type))
            }
            RelationshipType::Uses => {
                (source_type == "attack-pattern" && ["malware", "tool"].contains(&target_type))
                    || (["campaign", "intrusion-set", "malware", "threat-actor"]
                        .contains(&source_type)
                        && ["attack-pattern", "infrastructure", "malware", "tool"]
                            .contains(&target_type))
                    || (source_type == "infrastructure" && target_type == "infrastructure")
            }
            RelationshipType::VariantOf => source_type == "malware" && target_type == "malware",
            // Custom relationship types always pass this validation step
            RelationshipType::Custom(_) => true,
        };

        if valid {
            Ok(())
        } else {
            Err(Error::InvalidRelationship {
                relationship: self.to_string(),
                source_type: source_type.to_string(),
                target_type: target_type.to_string(),
            })
        }
    }
}
