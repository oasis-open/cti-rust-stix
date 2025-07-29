//! Contains the implementation logic for STIX Cyber-observable Objects (SCOs).
use crate::{
    base::{CommonProperties, CommonPropertiesBuilder, Stix},
    cyber_observable_objects::{
        sco_types::{
            Artifact, AutonomousSystem, Directory, DomainName, EmailAddress, EmailMessage,
            EmailMimeCompomentType, File, Ipv4Addr, Ipv6Addr, MacAddr, Mutex, NetworkTraffic,
            Process, Software, Url, UserAccount, WindowsRegistryKey, WindowsRegistryKeyType,
            X509Certificate, X509V3Extensions,
        },
        vocab::EncryptionAlgorithm,
    },
    error::{add_error, return_multiple_errors, StixError as Error},
    json,
    relationship_objects::{Related, RelationshipObjectBuilder},
    types::{
        get_field_by_name, stix_case, DictionaryValue, ExternalReference, GranularMarking, Hashes,
        Identified, Identifier, StixDictionary, Timestamp,
    },
};
use log::warn;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::{collections::HashMap, str::FromStr, sync::LazyLock};
use strum::{AsRefStr, Display as StrumDisplay, EnumString};
use url::Url as RustUrl;

// Static dictionaries of ID contributing properties for each SCO type

// ID Contributing properties that will always be present for a given SCO type
static REQUIRED_ID_PROPERTIES: LazyLock<HashMap<&'static str, Vec<&'static str>>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();
        m.insert("artifact", Vec::new());
        m.insert("autonomous-system", vec!["number"]);
        m.insert("directory", vec!["path"]);
        m.insert("domain-name", vec!["value"]);
        m.insert("email-addr", vec!["value"]);
        m.insert("email-message", Vec::new());
        m.insert("file", Vec::new());
        m.insert("ipv4-addr", vec!["value"]);
        m.insert("ipv6-addr", vec!["value"]);
        m.insert("mac-addr", vec!["value"]);
        m.insert("network-traffic", vec!["protocols"]);
        m.insert("process", Vec::new());
        m.insert("software", vec!["name"]);
        m.insert("url", vec!["value"]);
        m.insert("user-account", Vec::new());
        m.insert("windows-registry-key", Vec::new());
        m.insert("x509-certificate", Vec::new());
        m
    });

// ID Contributing properties that are not guaranteed to be present for a given SCO type, but should be used if they are
static OPTIONAL_ID_PROPERTIES: LazyLock<HashMap<&'static str, Vec<&'static str>>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();
        m.insert("artifact", vec!["hashes", "payload_bin"]);
        m.insert("autonomous-system", Vec::new());
        m.insert("directory", Vec::new());
        m.insert("domain-name", Vec::new());
        m.insert("email-addr", Vec::new());
        m.insert("email-message", vec!["from_ref", "subject", "body"]);
        m.insert(
            "file",
            vec!["hashes", "name", "extensions", "parent_directory_ref"],
        );
        m.insert("ipv4-addr", Vec::new());
        m.insert("ipv6-addr", Vec::new());
        m.insert("mac-addr", Vec::new());
        m.insert(
            "network-traffic",
            vec![
                "start",
                "end",
                "src_ref",
                "dst_ref",
                "src_port",
                "dst_poart",
                "extensions",
            ],
        );
        m.insert("process", Vec::new());
        m.insert("url", Vec::new());
        m.insert(
            "user-account",
            vec!["account_type", "user_id", "account_login"],
        );
        m.insert("windows-registry-key", vec!["key, values"]);
        m.insert("x509-certificate", vec!["hashes, serial_number"]);
        m
    });

// Static dictionary of network-traffic extension protocols
static PROTOCOLS_MAP: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
    let mut protocols_map = HashMap::new();
    protocols_map.insert("http-request-ext".to_string(), "http".to_string());
    protocols_map.insert("tcp-ext".to_string(), "tcp".to_string());
    protocols_map.insert("imcp-ext".to_string(), "imcp".to_string());
    protocols_map.insert("socket-ext".to_string(), "tcp".to_string());
    protocols_map
});

/// A STIX Cyber-observable Object (SCO) of some type.
///
/// STIX defines a set of STIX Cyber-observable Objects (SCOs) for characterizing host-based and network-based information.
///
/// SCOs are used by various STIX Domain Objects (SDOs) to provide supporting context. The Observed Data SDO, for example, indicates that the raw data was observed at a particular time.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_rosvg2qjx4h4>
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CyberObject {
    /// Identifies the SCO type of SCO.
    #[serde(flatten)]
    pub object_type: CyberObjectType,
    /// Common object properties
    #[serde(flatten)]
    pub common_properties: CommonProperties,
}
impl CyberObject {
    /// Deserializes an SCO from a JSON String.
    /// Checks that all fields conform to the STIX 2.1 standard
    /// If the `allow_custom` flag is flase, checks that there are no fields in the JSON String that are not in the SRO type definition
    pub fn from_json(json: &str, allow_custom: bool) -> Result<Self, Error> {
        let cyber_object: Self =
            serde_json::from_str(json).map_err(|e| Error::DeserializationError(e.to_string()))?;
        cyber_object.stix_check()?;

        if !allow_custom {
            json::field_check(&cyber_object, json)?;
        }

        Ok(cyber_object)
    }

    pub fn is_revoked(&self) -> bool {
        matches!(self.common_properties.revoked, Some(true))
    }
}

// Returns a reference to the identifier of the `CyberObject`.
// This implementation accesses the `id` field from the `common_properties`
// of the `CyberObject`, providing a way to retrieve the unique identifier
// associated with this object.
impl Identified for CyberObject {
    fn get_id(&self) -> &Identifier {
        &self.common_properties.id
    }
}

impl Related for CyberObject {
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

impl Stix for CyberObject {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Check that we have the correct common properties for an SCO
        add_error(&mut errors, check_sco_properties(&self.common_properties));

        // Check common properties
        add_error(&mut errors, self.common_properties.stix_check());

        // Special check for NetworkTraffic that looks at both a NetworkTraffic property and a CommonProperty
        // If a protocol extension is present for a NetworkTraffic SCO, the corresponding protocol value for that extension **SHOULD** be listed in the protocols property.
        if let (CyberObjectType::NetworkTraffic(network_traffic), Some(extensions)) =
            (&self.object_type, &self.common_properties.extensions)
        {
            for key in extensions.keys() {
                // Check if the extension key is in the list of predefined protocol extensions
                if let Some(protocol) = PROTOCOLS_MAP.get(key) {
                    // If it is, check that the corresponding protocol is in the protocols property list, otherwise warn the user
                    if !network_traffic.protocols.contains(protocol) {
                        warn!("A {} extension is present for the Network Traffic Cyber Object {}, but it is missing the protocol {} in its protocols property.", key, self.get_id(), protocol);
                    }
                }
            }
        }

        // Check SCO type specific errors
        add_error(
            &mut errors,
            self.object_type.stix_check().map_err(|e| {
                Error::ValidationError(format!(
                    "Cyber Object {} is not a valid {}: {}",
                    self.get_id(),
                    self.object_type.as_ref(),
                    e
                ))
            }),
        );

        return_multiple_errors(errors)
    }
}

/// Checks that the required properties for an SCO are present and that the prohibited fields for an SCO are not present
pub fn check_sco_properties(properties: &CommonProperties) -> Result<(), Error> {
    let mut errors = Vec::new();

    if properties.created_by_ref.is_some() {
        errors.push(Error::ValidationError(
            "SCOs cannot have a `created_by_ref` property.".to_string(),
        ));
    }
    if properties.revoked.is_some() {
        errors.push(Error::ValidationError(
            "SCOs cannot have a `revoked` property.".to_string(),
        ));
    }
    if properties.labels.is_some() {
        errors.push(Error::ValidationError(
            "SCOs cannot have a `labels` property.".to_string(),
        ));
    }
    if properties.confidence.is_some() {
        errors.push(Error::ValidationError(
            "SCOs cannot have a `confidence` property.".to_string(),
        ));
    }
    if properties.lang.is_some() {
        errors.push(Error::ValidationError(
            "SCOs cannot have a `lang` property.".to_string(),
        ));
    }
    if properties.external_references.is_some() {
        errors.push(Error::ValidationError(
            "SCOs cannot have a `external_references` property.".to_string(),
        ));
    }
    if properties.created.is_some() {
        errors.push(Error::ValidationError(
            "SCOs cannot have a `created` property.".to_string(),
        ));
    }
    if properties.modified.is_some() {
        errors.push(Error::ValidationError(
            "SCOs cannot have a `modified` property.".to_string(),
        ));
    }

    return_multiple_errors(errors)
}

impl Stix for CyberObjectType {
    fn stix_check(&self) -> Result<(), Error> {
        match self {
            CyberObjectType::Artifact(artifact) => artifact.stix_check(),
            CyberObjectType::AutonomousSystem(automomous_system) => automomous_system.stix_check(),
            CyberObjectType::Directory(directory) => directory.stix_check(),
            CyberObjectType::DomainName(domain_name) => domain_name.stix_check(),
            CyberObjectType::EmailAddress(email_address) => email_address.stix_check(),
            CyberObjectType::EmailMessage(email_message) => email_message.stix_check(),
            CyberObjectType::File(file) => file.stix_check(),
            CyberObjectType::Ipv4Addr(ipv4_addr) => ipv4_addr.stix_check(),
            CyberObjectType::Ipv6Addr(ipv6_addr) => ipv6_addr.stix_check(),
            CyberObjectType::MacAddr(mac_address) => mac_address.stix_check(),
            CyberObjectType::Mutex(mutex) => mutex.stix_check(),
            CyberObjectType::NetworkTraffic(network_traffic) => network_traffic.stix_check(),
            CyberObjectType::Process(process) => process.stix_check(),
            CyberObjectType::Software(software) => software.stix_check(),
            CyberObjectType::Url(url) => url.stix_check(),
            CyberObjectType::UserAccount(user_account) => user_account.stix_check(),
            CyberObjectType::WindowsRegistryKey(windows_registry_key) => {
                windows_registry_key.stix_check()
            }
            CyberObjectType::WindowsRegistryKeyType(windows_registry_key_type) => {
                windows_registry_key_type.stix_check()
            }
            CyberObjectType::X509Certificate(x509_certificate) => x509_certificate.stix_check(),
        }
    }
}

/// Builder struct for SCOs.
///
/// This follows the "Rust builder pattern," where we  use a `new()` function to construct a Builder
/// with a minimum set of required fields, then set additional fields with their own setter functions.
/// Once all fields have been set, the `build()` function will take all of the fields in the Builder
/// struct and use them to create the final `CyberObject` struct.
///
/// Note: Because different types of SDOs have different fields, and fields present in multiple types
/// may be requried in some and optional in others, it is possible for a `CyberObjectBuilder` to be
/// in an incomplete state prior to constructing a `CyberObject`. The `build()` function will error
/// in such a case.
// This struct derives `Serialize` only for use with the `get_field_by_name()`` function
#[derive(Clone, Debug, Serialize)]
pub struct CyberObjectBuilder {
    /// The SCO type
    // We flatten this field so the get_field_by_name() function can access an SCO type's specific fields
    #[serde(flatten)]
    object_type: CyberObjectType,
    /// Common STIX object properties
    common_properties: CommonPropertiesBuilder,
}

impl CyberObjectBuilder {
    /// Set the belongs_to_ref field for an SCO, if the SCO is of a type that has that field
    pub fn belongs_to_ref(mut self, belongs_to_ref: Identifier) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::EmailAddress(ref mut email_address) => {
                email_address.belongs_to_ref = Some(belongs_to_ref);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "belongs_to_ref".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Creates a new STIX 2.1 `CyberObjectBuilder` of the given type
    ///
    /// The `type` field must be lowercase, with words separated by `-`
    ///
    /// Automatically generates an `id`
    /// Other fields are set to their Default (which is `None`` for optional fields)
    pub fn new(type_name: &str) -> Result<CyberObjectBuilder, Error> {
        // Parses the passed type name to select a type for the SCO
        // The initial inner struct in the `CyberObjectType` enum will be created with default values, which may not be valid for constructing the final `CyberObject`
        let object_type =
            CyberObjectType::from_str(&stix_case(type_name)).map_err(Error::UnrecognizedObject)?;
        // Build the common properties with generated and default values
        let common_properties = CommonPropertiesBuilder::new("sco", type_name)?;
        Ok(CyberObjectBuilder {
            object_type,
            common_properties,
        })
    }

    // Setter functions for optional properties common to all SCOs

    /// Set the optional `created_by_ref` field for an SCO under construction.
    /// This is only allowed when creating a new SCO, not when versioning an existing one,
    /// as only the original creator of an object can version it.
    pub fn created_by_ref(mut self, id: Identifier) -> Result<Self, Error> {
        self.common_properties = self.common_properties.clone().created_by_ref(id)?;
        Ok(self)
    }

    /// Set the optional `labels` field for an SCO under construction.
    pub fn labels(mut self, labels: Vec<String>) -> Self {
        self.common_properties = self.common_properties.clone().labels(labels);
        self
    }

    /// Set the optional `confidence` field for an SCO under construction.
    pub fn confidence(mut self, confidence: u8) -> Self {
        self.common_properties = self.common_properties.clone().confidence(confidence);
        self
    }

    /// Set the optional `lang` field for an SCO under construction.
    /// If the language is English ("en"), this does not need to be set (but it can be if specificity is desired).
    pub fn lang(mut self, language: String) -> Self {
        self.common_properties = self.common_properties.clone().lang(language);
        self
    }

    /// Set the optional `external_references` field for an SCO under construction.
    pub fn external_references(mut self, references: Vec<ExternalReference>) -> Self {
        self.common_properties = self
            .common_properties
            .clone()
            .external_references(references);
        self
    }

    /// Set the optional `object_marking_refs` field for an SCO under construction.
    pub fn object_marking_refs(mut self, references: Vec<Identifier>) -> Self {
        self.common_properties = self
            .common_properties
            .clone()
            .object_marking_refs(references);
        self
    }

    /// Set the optional `granular_markings` field for an SCO under construction.
    pub fn granular_markings(mut self, markings: Vec<GranularMarking>) -> Self {
        self.common_properties = self.common_properties.clone().granular_markings(markings);
        self
    }

    /// Add an optional extension to the `extensions` field for an SCO under construction, creating the field if it does not exist
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

    /// Set the optional `additional_header_fields` property for an SCO under construction
    pub fn additional_header_fields(
        mut self,
        additional_header_fields: StixDictionary<Vec<String>>,
    ) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::EmailMessage(ref mut email_message) => {
                email_message.additional_header_fields = Some(additional_header_fields)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "additional_header_fields".to_string(),
                })
            }
        }
        Ok(self)
    }

    /// Set the `account_created` field for an SCO under construction.
    pub fn account_created(mut self, account_created: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::UserAccount(ref mut user_account) => {
                user_account.account_created = Some(Timestamp(
                    account_created.parse().map_err(Error::DateTimeError)?,
                ));
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "account_created".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `account_expires` field for an SCO under construction.
    pub fn account_expires(mut self, account_expires: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::UserAccount(ref mut user_account) => {
                user_account.account_expires = Some(Timestamp(
                    account_expires.parse().map_err(Error::DateTimeError)?,
                ));
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "account_expires".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `account_first_login` field for an SCO under construction.
    pub fn account_first_login(mut self, account_first_login: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::UserAccount(ref mut user_account) => {
                user_account.account_first_login = Some(Timestamp(
                    account_first_login.parse().map_err(Error::DateTimeError)?,
                ));
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "account_first_login".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `account_last_login` field for an SCO under construction.
    pub fn account_last_login(mut self, account_last_login: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::UserAccount(ref mut user_account) => {
                user_account.account_last_login = Some(Timestamp(
                    account_last_login.parse().map_err(Error::DateTimeError)?,
                ));
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "account_last_login".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `account_login` field for an Sso under construction.
    pub fn account_login(mut self, account_login: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::UserAccount(ref mut user_account) => {
                user_account.account_login = Some(account_login)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "account_login".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `account_type ` field for an Sso under construction.
    pub fn account_type(mut self, account_type: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::UserAccount(ref mut user_account) => {
                user_account.account_type = Some(account_type)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "account_type".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the optional `atime` property for an SCO under construction
    pub fn atime(mut self, atime: &str) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Directory(ref mut directory) => {
                directory.atime = Some(Timestamp(atime.parse().map_err(Error::DateTimeError)?))
            }
            CyberObjectType::File(ref mut file) => {
                file.atime = Some(Timestamp(atime.parse().map_err(Error::DateTimeError)?))
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "atime".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the optional `bcc_refs` property for an SCO under construction
    pub fn bcc_refs(mut self, bcc_refs: Vec<Identifier>) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::EmailMessage(ref mut email_message) => {
                email_message.bcc_refs = Some(bcc_refs)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "bcc_refs".to_string(),
                })
            }
        }
        Ok(self)
    }

    /// Set the optional `belongs_to_refs` property for an SCO under construction
    pub fn belongs_to_refs(mut self, refs: Vec<Identifier>) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Ipv4Addr(ref mut ipv4_addr) => ipv4_addr.belongs_to_refs = Some(refs),
            CyberObjectType::Ipv6Addr(ref mut ipv6_addr) => ipv6_addr.belongs_to_refs = Some(refs),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "belongs_to_refs".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the optional `body` property for an SCO under construction
    pub fn body(mut self, body: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::EmailMessage(ref mut email_message) => email_message.body = Some(body),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "body".to_string(),
                })
            }
        }
        Ok(self)
    }

    /// Set the optional `body_multipart` property for an SCO under construction
    pub fn body_multipart(
        mut self,
        body_multipart: Vec<EmailMimeCompomentType>,
    ) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::EmailMessage(ref mut email_message) => {
                email_message.body_multipart = Some(body_multipart)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "body_multipart".to_string(),
                })
            }
        }
        Ok(self)
    }

    /// Set the optional `cc_refs` property for an SCO under construction
    pub fn cc_refs(mut self, cc_refs: Vec<Identifier>) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::EmailMessage(ref mut email_message) => {
                email_message.cc_refs = Some(cc_refs)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "cc_refs".to_string(),
                })
            }
        }
        Ok(self)
    }

    /// Set the `can_escalate_privs` field for an SCO under construction.
    pub fn can_escalate_privs(mut self, can_escalate_privs: bool) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::UserAccount(ref mut user_account) => {
                user_account.can_escalate_privs = Some(can_escalate_privs);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),

                    field: "child_refs".to_string(),
                })
            }
        }
        Ok(self)
    }

    /// Set the optional `child_refs` property for an SCO under construction
    pub fn child_refs(mut self, child_refs: Vec<Identifier>) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Process(ref mut process) => process.child_refs = Some(child_refs),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "can_escalate_privs".to_string(),
                });
            }
        };
        Ok(self)
    }

    /// Set the optional `command_line` property for an SCO under construction
    pub fn command_line(mut self, command_line: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Process(ref mut process) => process.command_line = Some(command_line),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "command_line".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the optional `contains_refs` property for an SCO under construction
    pub fn contains_refs(mut self, contains_refs: Vec<Identifier>) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Directory(ref mut directory) => {
                directory.contains_refs = Some(contains_refs)
            }
            CyberObjectType::File(ref mut file) => file.contains_refs = Some(contains_refs),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "contains_refs".to_string(),
                })
            }
        }
        Ok(self)
    }

    /// Set the optional `content_ref` property for an SCO under construction
    pub fn content_ref(mut self, content_ref: Identifier) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::File(ref mut file) => file.content_ref = Some(content_ref),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "content_ref".to_string(),
                })
            }
        }
        Ok(self)
    }

    /// Set the optional `content_type` property for an SCO under construction
    pub fn content_type(mut self, content_type: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::EmailMessage(ref mut email_message) => {
                email_message.content_type = Some(content_type)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "content_type".to_string(),
                })
            }
        }
        Ok(self)
    }

    /// Set the optional `credential_last_changed` field for an SCO under construction.
    pub fn credential_last_changed(
        mut self,
        credential_last_changed: String,
    ) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::UserAccount(ref mut user_account) => {
                user_account.credential_last_changed = Some(Timestamp(
                    credential_last_changed
                        .parse()
                        .map_err(Error::DateTimeError)?,
                ));
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "credential_last_changed".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the optional `cpe` field for an sco under construction.
    pub fn cpe(mut self, cpe: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Software(ref mut software) => software.cpe = Some(cpe),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "cpe".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the optional `created_time` property for an SCO under construction
    pub fn created_time(mut self, created_time: Timestamp) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Process(ref mut process) => process.created_time = Some(created_time),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "created_time".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the optional `creator_user_ref` property for an SCO under construction
    pub fn creator_user_ref(mut self, creator_user_ref: Identifier) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::WindowsRegistryKey(ref mut windows_registry_key) => {
                windows_registry_key.creator_user_ref = Some(creator_user_ref)
            }
            CyberObjectType::Process(ref mut process) => {
                process.creator_user_ref = Some(creator_user_ref)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "creator_user_ref".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the optional `credential` field for an Sso under construction.
    pub fn credential(mut self, credential: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::UserAccount(ref mut user_account) => {
                user_account.credential = Some(credential)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "credential".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the optional `ctime` property for an SCO under construction
    pub fn ctime(mut self, ctime: &str) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Directory(ref mut directory) => {
                directory.ctime = Some(Timestamp(ctime.parse().map_err(Error::DateTimeError)?))
            }
            CyberObjectType::File(ref mut file) => {
                file.ctime = Some(Timestamp(ctime.parse().map_err(Error::DateTimeError)?))
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "ctime".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the optional `cwd` property for an SCO under construction
    pub fn cwd(mut self, cwd: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Process(ref mut process) => process.cwd = Some(cwd),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "cwd".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the optional `data` property for an SCO under construction
    pub fn data(mut self, data: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::WindowsRegistryKeyType(ref mut windows_registry_key_type) => {
                windows_registry_key_type.data = Some(data)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "data".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the optional `date` property for an SCO under construction
    pub fn date(mut self, date: Timestamp) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::EmailMessage(ref mut email_message) => email_message.date = Some(date),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "date".to_string(),
                })
            }
        }
        Ok(self)
    }

    /// Set the optional `data_type` property for an SCO under construction
    pub fn data_type(mut self, data_type: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::WindowsRegistryKeyType(ref mut windows_registry_key_type) => {
                windows_registry_key_type.data_type = Some(data_type)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "data_type".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the optional `description_key` property for an SCO under construction
    pub fn decryption_key(mut self, decryption_key: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Artifact(ref mut artifact) => {
                artifact.decryption_key = Some(decryption_key)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "decryption_key".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the optional `display_name` property for an SCO under construction
    pub fn display_name(mut self, display_name: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::EmailAddress(ref mut email_address) => {
                email_address.display_name = Some(display_name)
            }
            CyberObjectType::UserAccount(ref mut user_account) => {
                user_account.display_name = Some(display_name)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "display_name".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the optional `dst_byte_count` property for an SCO under construction
    pub fn dst_byte_count(mut self, dst_byte_count: u64) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::NetworkTraffic(ref mut nt) => nt.dst_byte_count = Some(dst_byte_count),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "dst_byte_count".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the optional `dst_packets` property for an SCO under construction
    pub fn dst_packets(mut self, dst_packets: u64) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::NetworkTraffic(ref mut nt) => nt.dst_packets = Some(dst_packets),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "dst_packets".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn dst_payload_ref(mut self, dst_payload_ref: Identifier) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::NetworkTraffic(ref mut nt) => {
                nt.dst_payload_ref = Some(dst_payload_ref)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "dst_payload_ref".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn dst_port(mut self, dst_port: u64) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::NetworkTraffic(ref mut nt) => nt.dst_port = Some(dst_port),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "dst_port".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn dst_ref(mut self, dst_ref: Identifier) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::NetworkTraffic(ref mut nt) => nt.dst_ref = Some(dst_ref),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "dst_ref".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn encapsulated_by_ref(mut self, encapsulated_by_ref: Identifier) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::NetworkTraffic(ref mut nt) => {
                nt.encapsulated_by_ref = Some(encapsulated_by_ref)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "encapsulated_by_ref".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn encapsulates_refs(mut self, encapsulates_refs: Vec<Identifier>) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::NetworkTraffic(ref mut nt) => {
                nt.encapsulates_refs = Some(encapsulates_refs)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "encapsulates_refs".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn encryption_algorithm(
        mut self,
        encryption_algorithm: EncryptionAlgorithm,
    ) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Artifact(ref mut artifact) => {
                artifact.encryption_algorithm = Some(encryption_algorithm)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "encryption_key".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn end(mut self, end: Timestamp) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::NetworkTraffic(ref mut nt) => nt.end = Some(end),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "end".to_string(),
                })
            }
        }
        Ok(self)
    }

    pub fn environment_variables(
        mut self,
        environment_variables: StixDictionary<Vec<String>>,
    ) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Process(ref mut process) => {
                process.environment_variables = Some(environment_variables)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "environment_variables".to_string(),
                })
            }
        }
        Ok(self)
    }

    pub fn from_ref(mut self, from_ref: Identifier) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::EmailMessage(ref mut email_message) => {
                email_message.from_ref = Some(from_ref)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "from_ref".to_string(),
                })
            }
        }
        Ok(self)
    }

    pub fn hashes(mut self, hashes: Hashes) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Artifact(ref mut artifact) => artifact.hashes = Some(hashes),
            CyberObjectType::File(ref mut file) => file.hashes = Some(hashes),
            CyberObjectType::X509Certificate(ref mut x509_certificate) => {
                x509_certificate.hashes = Some(hashes)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "hashes".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn ipfix(mut self, ipfix: StixDictionary<DictionaryValue>) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::NetworkTraffic(ref mut nt) => nt.ipfix = Some(ipfix),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "ipfix".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn is_active(mut self, is_active: bool) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::NetworkTraffic(ref mut nt) => nt.is_active = Some(is_active),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "is_active".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `is_disabled` field for an Sso under construction.
    pub fn is_disabled(mut self, is_disabled: bool) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::UserAccount(ref mut user_account) => {
                user_account.is_disabled = Some(is_disabled);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "is_disabled".to_string(),
                });
            }
        };
        Ok(self)
    }

    pub fn is_hidden(mut self, is_hidden: bool) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Process(ref mut process) => process.is_hidden = Some(is_hidden),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "is_hidden".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn is_self_signed(mut self, is_self_signed: bool) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::X509Certificate(ref mut x509_certificate) => {
                x509_certificate.is_self_signed = Some(is_self_signed);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "is_self_signed".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn issuer(mut self, issuer: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::X509Certificate(ref mut x509_certificate) => {
                x509_certificate.issuer = Some(issuer)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "issuer".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn image_ref(mut self, image_ref: Identifier) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Process(ref mut process) => process.image_ref = Some(image_ref),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "image_ref".to_string(),
                })
            }
        };
        Ok(self)
    }

    // defaults to false: only need to set if true
    pub fn is_multipart(mut self) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::EmailMessage(ref mut email_message) => {
                email_message.is_multipart = true
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "is_multipart".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `is_privileged` field for an Sso under construction.
    pub fn is_privileged(mut self, is_privileged: bool) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::UserAccount(ref mut user_account) => {
                user_account.is_privileged = Some(is_privileged);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "is_privileged".to_string(),
                });
            }
        };
        Ok(self)
    }

    /// Set the `is_service_account` field for an Sso under construction.
    pub fn is_service_account(mut self, is_service_account: bool) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::UserAccount(ref mut user_account) => {
                user_account.is_service_account = Some(is_service_account);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "is_service_account".to_string(),
                });
            }
        };
        Ok(self)
    }

    pub fn key(mut self, key: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::WindowsRegistryKey(ref mut windows_registy_key) => {
                windows_registy_key.key = Some(key)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "key".to_string(),
                })
            }
        }
        Ok(self)
    }

    /// Set the `languages` field for an Sso under construction.
    pub fn languages(mut self, languages: Vec<String>) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Software(ref mut software) => software.languages = Some(languages),

            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "languages".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn magic_number_hex(mut self, magic_number_hex: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::File(ref mut file) => file.magic_number_hex = Some(magic_number_hex),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "magic_number_hex".to_string(),
                })
            }
        }
        Ok(self)
    }
    pub fn message_id(mut self, message_id: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::EmailMessage(ref mut email_message) => {
                email_message.message_id = Some(message_id)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "message_id".to_string(),
                })
            }
        }
        Ok(self)
    }

    pub fn mime_type(mut self, mime_type: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Artifact(ref mut artifact) => artifact.mime_type = Some(mime_type),
            CyberObjectType::File(ref mut file) => file.mime_type = Some(mime_type),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "mime_type".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn modified_time(mut self, modified_time: Timestamp) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::WindowsRegistryKey(ref mut windows_registry_key) => {
                windows_registry_key.modified_time = Some(modified_time)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "modified_time".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn mtime(mut self, mtime: &str) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Directory(ref mut directory) => {
                directory.mtime = Some(Timestamp(mtime.parse().map_err(Error::DateTimeError)?))
            }
            CyberObjectType::File(ref mut file) => {
                file.mtime = Some(Timestamp(mtime.parse().map_err(Error::DateTimeError)?))
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "mtime".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `name` field for an sco under construction.
    pub fn name(mut self, name: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::AutonomousSystem(ref mut autonomous_system) => {
                autonomous_system.name = Some(name)
            }
            CyberObjectType::File(ref mut file) => file.name = Some(name),
            CyberObjectType::Mutex(ref mut mutex) => mutex.name = name,
            CyberObjectType::Software(ref mut software) => software.name = name,
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "name".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn name_enc(mut self, name_enc: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::File(ref mut file) => file.name_enc = Some(name_enc),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "name_enc".to_string(),
                })
            }
        }
        Ok(self)
    }

    pub fn number(mut self, number: u64) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::AutonomousSystem(ref mut autonomous_system) => {
                autonomous_system.number = number;
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "number".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn number_of_subkeys(mut self, number_of_subkeys: i64) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::WindowsRegistryKey(ref mut windows_registry_key) => {
                windows_registry_key.number_of_subkeys = Some(number_of_subkeys)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "number_of_subkeys".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn opened_connection_refs(
        mut self,
        opened_connection_refs: Vec<Identifier>,
    ) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Process(ref mut process) => {
                process.opened_connection_refs = Some(opened_connection_refs)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "opened_connection_refs".to_string(),
                })
            }
        }
        Ok(self)
    }

    pub fn parent_directory_ref(mut self, parent_directory_ref: Identifier) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::File(ref mut file) => {
                file.parent_directory_ref = Some(parent_directory_ref)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "parent_directory_ref".to_string(),
                })
            }
        }
        Ok(self)
    }

    pub fn parent_ref(mut self, parent_ref: Identifier) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Process(ref mut process) => process.parent_ref = Some(parent_ref),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "parent_ref".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn path(mut self, path: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Directory(ref mut directory) => directory.path = path,
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "path".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn path_enc(mut self, path_enc: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Directory(ref mut directory) => directory.path_enc = Some(path_enc),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "path_enc".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn payload_bin(mut self, payload_bin: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Artifact(ref mut artifact) => artifact.payload_bin = Some(payload_bin),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "payload_bin".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn pid(mut self, pid: i64) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Process(ref mut process) => process.pid = Some(pid),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "pid".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn protocols(mut self, protocols: Vec<String>) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::NetworkTraffic(ref mut nt) => nt.protocols = protocols,
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "protocols".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn raw_email_ref(mut self, raw_email_ref: Identifier) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::EmailMessage(ref mut email_message) => {
                email_message.raw_email_ref = Some(raw_email_ref)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "raw_email_ref".to_string(),
                })
            }
        }
        Ok(self)
    }

    pub fn recieved_lines(mut self, recieved_lines: Vec<String>) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::EmailMessage(ref mut email_message) => {
                email_message.recieved_lines = Some(recieved_lines)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "recieved_lines".to_string(),
                })
            }
        }
        Ok(self)
    }

    pub fn resolves_to_refs(mut self, refs: Vec<Identifier>) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::DomainName(ref mut domain_name) => {
                domain_name.resolves_to_refs = Some(refs)
            }
            CyberObjectType::Ipv4Addr(ref mut ipv4_addr) => ipv4_addr.resolves_to_refs = Some(refs),
            CyberObjectType::Ipv6Addr(ref mut ipv6_addr) => ipv6_addr.resolves_to_refs = Some(refs),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "resolves_to_refs".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn rir(mut self, rir: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::AutonomousSystem(ref mut autonomous_system) => {
                autonomous_system.rir = Some(rir)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "rir".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn sender_ref(mut self, sender_ref: Identifier) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::EmailMessage(ref mut email_message) => {
                email_message.sender_ref = Some(sender_ref)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "sender_ref".to_string(),
                })
            }
        }
        Ok(self)
    }

    pub fn serial_number(mut self, serial_number: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::X509Certificate(ref mut x509_certificate) => {
                x509_certificate.serial_number = Some(serial_number)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "serial_number".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn signature_algorithm(mut self, signature_algorithm: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::X509Certificate(ref mut x509_certificate) => {
                x509_certificate.signature_algorithm = Some(signature_algorithm)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "signature_algorithm".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn size(mut self, size: u64) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::File(ref mut file) => file.size = Some(size),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "size".to_string(),
                })
            }
        }
        Ok(self)
    }

    pub fn src_byte_count(mut self, src_byte_count: u64) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::NetworkTraffic(ref mut nt) => nt.src_byte_count = Some(src_byte_count),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "src_byte_count".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn src_packets(mut self, src_packets: u64) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::NetworkTraffic(ref mut nt) => nt.src_packets = Some(src_packets),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "src_packets".to_string(),
                })
            }
        };
        Ok(self)
    }
    pub fn src_payload_ref(mut self, src_payload_ref: Identifier) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::NetworkTraffic(ref mut nt) => {
                nt.src_payload_ref = Some(src_payload_ref)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "src_payload_ref".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn src_ref(mut self, src_ref: Identifier) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::NetworkTraffic(ref mut nt) => nt.src_ref = Some(src_ref),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "src_ref".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn src_port(mut self, src_port: u64) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::NetworkTraffic(ref mut nt) => nt.src_port = Some(src_port),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "src_port".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn start(mut self, start: Timestamp) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::NetworkTraffic(ref mut nt) => nt.start = Some(start),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "start".to_string(),
                })
            }
        }
        Ok(self)
    }

    pub fn subject(mut self, subject: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::EmailMessage(ref mut email_message) => {
                email_message.subject = Some(subject)
            }
            CyberObjectType::X509Certificate(ref mut x509_certificate) => {
                x509_certificate.subject = Some(subject);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "subject".to_string(),
                })
            }
        }
        Ok(self)
    }

    pub fn subject_public_key_algorithm(
        mut self,
        subject_public_key_algorithm: String,
    ) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::X509Certificate(ref mut x509_certificate) => {
                x509_certificate.subject_public_key_algorithm = Some(subject_public_key_algorithm);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "subject_public_key_algorithm".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn subject_public_key_exponent(
        mut self,
        subject_public_key_exponent: i64,
    ) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::X509Certificate(ref mut x509_certificate) => {
                x509_certificate.subject_public_key_exponent = Some(subject_public_key_exponent);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "subject_public_key_exponent".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn subject_public_key_modulus(
        mut self,
        subject_public_key_modulus: String,
    ) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::X509Certificate(ref mut x509_certificate) => {
                x509_certificate.subject_public_key_modulus = Some(subject_public_key_modulus);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "subject_public_key_modulus".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `swid` field for an sco under construction.
    pub fn swid(mut self, swid: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Software(ref mut software) => software.swid = Some(swid),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "swid".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn to_refs(mut self, to_refs: Vec<Identifier>) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::EmailMessage(ref mut email_message) => {
                email_message.to_refs = Some(to_refs)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "to_refs".to_string(),
                })
            }
        }
        Ok(self)
    }

    pub fn url(mut self, url_str: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Artifact(ref mut artifact) => {
                artifact.url = Some(
                    RustUrl::parse(&url_str)
                        .map_err(|e| Error::ValidationError(format!("Invalid URL: {}", e)))?,
                );
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "url".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn value(mut self, value: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::DomainName(ref mut domain_name) => domain_name.value = value,
            CyberObjectType::EmailAddress(ref mut email_address) => email_address.value = value,
            CyberObjectType::Ipv4Addr(ref mut ipv4_addr) => ipv4_addr.value = value,
            CyberObjectType::Ipv6Addr(ref mut ipv6_addr) => ipv6_addr.value = value,
            CyberObjectType::MacAddr(ref mut mac_address) => mac_address.value = value,
            CyberObjectType::Url(ref mut url) => {
                url.value = RustUrl::parse(&value)
                    .map_err(|e| Error::ValidationError(format!("Invalid URL: {}", e)))?;
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "value".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn values(mut self, values: Vec<WindowsRegistryKeyType>) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::WindowsRegistryKey(ref mut windows_registry_key) => {
                windows_registry_key.values = Some(values)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "values".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `vendor` field for an sco under construction.
    pub fn vendor(mut self, vendor: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Software(ref mut software) => software.vendor = Some(vendor),
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "vendor".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `user_id` field for an Sco under construction.
    pub fn user_id(mut self, user_id: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::UserAccount(ref mut user_account) => {
                user_account.user_id = Some(user_id)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "user_id".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn validity_not_after(mut self, validity_not_after: Timestamp) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::X509Certificate(ref mut x509_certificate) => {
                x509_certificate.validity_not_after = Some(validity_not_after)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "validity_not_after".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn validity_not_before(mut self, validity_not_before: Timestamp) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::X509Certificate(ref mut x509_certificate) => {
                x509_certificate.validity_not_before = Some(validity_not_before)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "validity_not_before".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Set the `version` field for an sco under construction.
    pub fn version(mut self, version: String) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::Software(ref mut software) => software.version = Some(version),
            CyberObjectType::X509Certificate(ref mut x509_certificate) => {
                x509_certificate.version = Some(version)
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "version".to_string(),
                })
            }
        };
        Ok(self)
    }

    pub fn x509_v3_extensions(
        mut self,
        x509_v3_extensions: X509V3Extensions,
    ) -> Result<Self, Error> {
        match self.object_type {
            CyberObjectType::X509Certificate(ref mut x509_certificate) => {
                x509_certificate.x509_v3_extensions = Some(x509_v3_extensions);
            }
            _ => {
                return Err(Error::IllegalBuilderProperty {
                    object: "SCOs".to_string(),
                    object_type: self.object_type.to_string(),
                    field: "x509_v3_extensions".to_string(),
                })
            }
        };
        Ok(self)
    }

    /// Builds a new SCO, using the information found in the DomainObjectBuilder
    ///
    /// This performs a final check that all required fields for a given SDO type are included before construction.
    /// If possible, it generates a UUIDv5 for the SCO, in place of a UUIDv4.
    /// This also runs the `stick_check()` validation method on the newly constructed SDO.
    pub fn build(self) -> Result<CyberObject, Error> {
        // Note: Many SCOs have all optional fields, but require that at least one such field be present.
        // This is checked as part of stix_check() to guarantee that an error will occur during building or deserialization.
        match self.object_type {
            CyberObjectType::AutonomousSystem(ref automomous_system) => {
                if automomous_system.number == 0 {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "number".to_string(),
                    });
                }
            }
            CyberObjectType::Directory(ref directory) => {
                if directory.path.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "path".to_string(),
                    });
                }
            }
            CyberObjectType::DomainName(ref domain_name) => {
                if domain_name.value.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "value".to_string(),
                    });
                }
            }
            CyberObjectType::EmailAddress(ref email_address) => {
                if email_address.value.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "value".to_string(),
                    });
                }
            }
            CyberObjectType::Ipv4Addr(ref ipv4_addr) => {
                if ipv4_addr.value.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "value".to_string(),
                    });
                }
            }
            CyberObjectType::Ipv6Addr(ref ipv6_addr) => {
                if ipv6_addr.value.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "value".to_string(),
                    });
                }
            }
            CyberObjectType::MacAddr(ref mac_address) => {
                if mac_address.value.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "value".to_string(),
                    });
                }
            }
            CyberObjectType::Mutex(ref mutex) => {
                if mutex.name.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "name".to_string(),
                    });
                }
            }
            CyberObjectType::Process(ref process) => {
                // A Process object MUST contain at least one property (other than type) from this object (or one of its extensions)
                if process.is_hidden.is_none()
                    && process.pid.is_none()
                    && process.created_time.is_none()
                    && process.cwd.is_none()
                    && process.command_line.is_none()
                    && process.environment_variables.is_none()
                    && process.opened_connection_refs.is_none()
                    && process.creator_user_ref.is_none()
                    && process.image_ref.is_none()
                    && process.parent_ref.is_none()
                    && process.child_refs.is_none()
                {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "extensions, is_hidden, pid, created_time, cwd, command_line, environment_variables,opened_connection_refs, creator_user_ref, image_ref, parent_ref, child_refs "
                            .to_string(),
                    });
                }
            }
            // stix_check() will fail is the `protocols` field is an empty Vec, but we check here to provide a more specific error in this situation
            CyberObjectType::NetworkTraffic(ref network_traffic) => {
                if network_traffic.protocols.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "protocols".to_string(),
                    });
                }
                if network_traffic.src_ref.is_none() && network_traffic.dst_ref.is_none() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "src_ref, dst_ref".to_string(),
                    });
                }
            }
            CyberObjectType::Software(ref software) => {
                if software.name.is_empty() {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "name".to_string(),
                    });
                }
            }
            CyberObjectType::Url(ref url) => {
                if &url.value.to_string() == "http://example.com" {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "value".to_string(),
                    });
                }
            }
            CyberObjectType::WindowsRegistryKey(ref windows_registry_key) => {
                if windows_registry_key.key.is_none()
                    && windows_registry_key.values.is_none()
                    && windows_registry_key.modified_time.is_none()
                    && windows_registry_key.creator_user_ref.is_none()
                    && windows_registry_key.number_of_subkeys.is_none()
                {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "key, values, creator_user_ref, number_of_subkeys".to_string(),
                    });
                }
            }
            CyberObjectType::X509Certificate(ref x509_certificate) => {
                if x509_certificate.is_self_signed.is_none()
                    && x509_certificate.hashes.is_none()
                    && x509_certificate.version.is_none()
                    && x509_certificate.serial_number.is_none()
                    && x509_certificate.signature_algorithm.is_none()
                    && x509_certificate.issuer.is_none()
                    && x509_certificate.validity_not_before.is_none()
                    && x509_certificate.validity_not_after.is_none()
                    && x509_certificate.subject.is_none()
                    && x509_certificate.subject_public_key_algorithm.is_none()
                    && x509_certificate.subject_public_key_modulus.is_none()
                    && x509_certificate.subject_public_key_exponent.is_none()
                    && x509_certificate.x509_v3_extensions.is_none()
                {
                    return Err(Error::MissingBuilderProperty {
                        object_type: self.object_type.to_string(),
                        property: "is_self_signed, hashes, version, serial_number, signature_algorithm, issuer, validity_not_before, validity_not_after, subject, subject_public_key_algorithm, subject_public_key_modulus, subject_public_key_exponent, x509_v3_extensions".to_string(),
                    });
                }
            }
            _ => {}
        }
        let mut common_properties = self.common_properties.build();

        // If any of the ID Contributing Properties exist for this SCO, change the ID to one that uses a generated UUIDv5. Otherwise leave it as the already generated UUIDv4.
        if let Some(contributing_properties) = self.get_uuid5_properties()? {
            let id_v5 = Identifier::new_v5(self.object_type.as_ref(), &contributing_properties)?;
            common_properties.id = id_v5;
        }

        let sco = CyberObject {
            object_type: self.object_type,
            common_properties,
        };

        sco.stix_check()?;

        Ok(sco)
    }

    /// Get the id contributing properties, if they exist, for constructing a UUIDv5
    fn get_uuid5_properties(&self) -> Result<Option<HashMap<String, IdPropertyValue>>, Error> {
        let object_type = self.object_type.as_ref();
        let mut properties = HashMap::new();

        // First check any required properties
        if let Some(required) = REQUIRED_ID_PROPERTIES.get(object_type) {
            for field in required {
                // PANIC: Safe to unwrap Option because these fields are required
                //
                // Handle special cases of non-String values
                if object_type == "autonomous-system" {
                    // AutonomousSystem.number is a u64
                    let value = get_field_by_name::<&CyberObjectBuilder, u64>(self, field)?
                        .unwrap()
                        .to_string();
                    properties.insert(field.to_string(), IdPropertyValue::String(value));
                } else if object_type == "network-traffic" {
                    // NetworkTraffic.protocols is a Vec<String>
                    let protocols =
                        get_field_by_name::<&CyberObjectBuilder, Vec<String>>(self, field)?
                            .unwrap();
                    properties.insert(field.to_string(), IdPropertyValue::List(protocols));
                } else if object_type == "url" {
                    // Url.value is a url::Url
                    let value = get_field_by_name::<&CyberObjectBuilder, RustUrl>(self, field)?
                        .unwrap()
                        .to_string();
                    properties.insert(field.to_string(), IdPropertyValue::String(value));
                } else {
                    // Everything else is a String
                    let value =
                        get_field_by_name::<&CyberObjectBuilder, String>(self, field)?.unwrap();
                    properties.insert(field.to_string(), IdPropertyValue::String(value));
                }
            }
        }

        // Then check optional properties
        if let Some(optional) = OPTIONAL_ID_PROPERTIES.get(object_type) {
            for field in optional {
                // Handle special cases of non-String values
                if *field == "hashes" {
                    // Get only the most preferred hash
                    if let Some(Some(hashes)) =
                        get_field_by_name::<&CyberObjectBuilder, Option<Hashes>>(self, field)?
                    {
                        // Check hashes in order of hash key preference
                        if let Some(value) = hashes.get("MD5") {
                            properties.insert(
                                field.to_string(),
                                IdPropertyValue::Tuple(("MD5".to_string(), value.to_string())),
                            );
                        } else if let Some(value) = hashes.get("SHA-1") {
                            properties.insert(
                                field.to_string(),
                                IdPropertyValue::Tuple(("SHA-1".to_string(), value.to_string())),
                            );
                        } else if let Some(value) = hashes.get("SHA-256") {
                            properties.insert(
                                field.to_string(),
                                IdPropertyValue::Tuple(("SHA-256".to_string(), value.to_string())),
                            );
                        } else if let Some(value) = hashes.get("SHA-512") {
                            properties.insert(
                                field.to_string(),
                                IdPropertyValue::Tuple(("SHA-512".to_string(), value.to_string())),
                            );
                        // Otherwise just use one of the hashes in the list, of any other key
                        } else {
                            // PANIC: Safe to unwrap because there must be at least one hash in the hash list
                            let (key, value) = hashes.iter().next().unwrap();
                            properties.insert(
                                field.to_string(),
                                IdPropertyValue::Tuple((key.to_string(), value.to_string())),
                            );
                        }
                    }
                } else if *field == "extensions" {
                    // extensions do not return a common type across SCOs, so we cannot use our get_field_by_name() function without generics
                    match &self.object_type {
                        CyberObjectType::File(_) => {
                            if let Some(extensions) = &self.common_properties.properties.extensions
                            {
                                for (key, extension) in extensions.iter() {
                                    properties.insert(
                                        field.to_string(),
                                        IdPropertyValue::Tuple((
                                            key.to_string(),
                                            json_canon::to_string(extension).map_err(|e| {
                                                Error::DeserializationError(e.to_string())
                                            })?,
                                        )),
                                    );
                                }
                            }
                        }
                        CyberObjectType::NetworkTraffic(_) => {
                            if let Some(extensions) = &self.common_properties.properties.extensions
                            {
                                for (key, extension) in extensions.iter() {
                                    properties.insert(
                                        field.to_string(),
                                        IdPropertyValue::Tuple((
                                            key.to_string(),
                                            json_canon::to_string(extension).map_err(|e| {
                                                Error::DeserializationError(e.to_string())
                                            })?,
                                        )),
                                    );
                                }
                            }
                        }
                        // No other SCOs have extensions as an ID contributing property
                        _ => unreachable!(),
                    }
                } else if *field == "start" || *field == "end" {
                    // NetworkTraffic.start and NetworkTraffic.end are Timestamps
                    if let Some(Some(value)) =
                        get_field_by_name::<&CyberObjectBuilder, Option<Timestamp>>(self, field)?
                    {
                        properties.insert(
                            field.to_string(),
                            IdPropertyValue::String(value.to_string()),
                        );
                    }
                } else if object_type == "windows-registry-key" {
                    // WindowsRegistryKey.values is a Vec of a custom struct
                    if let Some(Some(values)) = get_field_by_name::<
                        &CyberObjectBuilder,
                        Option<Vec<WindowsRegistryKeyType>>,
                    >(self, field)?
                    {
                        for value in values {
                            properties.insert(
                                field.to_string(),
                                IdPropertyValue::String(
                                    json_canon::to_string(&value)
                                        .map_err(|e| Error::DeserializationError(e.to_string()))?,
                                ),
                            );
                        }
                    }
                } else if *field == "src_port" || *field == "dst_port" {
                    // NetworkTraffic.src_port and NetworkTraffic.dst_port are Integers
                    if let Some(Some(value)) =
                        get_field_by_name::<&CyberObjectBuilder, Option<u64>>(self, field)?
                    {
                        properties.insert(
                            field.to_string(),
                            IdPropertyValue::String(value.to_string()),
                        );
                    }
                } else {
                    // Everything else is a String
                    if let Some(Some(value)) =
                        get_field_by_name::<&CyberObjectBuilder, Option<String>>(self, field)?
                    {
                        properties.insert(field.to_string(), IdPropertyValue::String(value));
                    }
                }
            }
        }

        // If no ID contributing properties were found, return `None`
        match properties.is_empty() {
            true => Ok(None),
            false => Ok(Some(properties)),
        }
    }
}

// Possible collections of ID contributing property strings
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum IdPropertyValue {
    // A single String (whether natively or parsed to a String)
    String(String),
    // A list of Strings
    List(Vec<String>),
    // A pair of Strings, used for hashes and extensions
    Tuple((String, String)),
}

impl Stix for IdPropertyValue {
    fn stix_check(&self) -> Result<(), Error> {
        match self {
            IdPropertyValue::String(string) => string.stix_check(),
            IdPropertyValue::List(list) => list.stix_check(),
            IdPropertyValue::Tuple((key, value)) => {
                let mut errors = Vec::new();
                add_error(&mut errors, key.stix_check());
                add_error(&mut errors, value.stix_check());
                return_multiple_errors(errors)
            }
        }
    }
}

/// The various SCO types represented in STIX.
#[derive(
    Clone, Debug, PartialEq, Eq, Serialize, Deserialize, AsRefStr, EnumString, StrumDisplay,
)]
#[serde(tag = "type", rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum CyberObjectType {
    Artifact(Artifact),
    AutonomousSystem(AutonomousSystem),
    Directory(Directory),
    DomainName(DomainName),
    EmailAddress(EmailAddress),
    EmailMessage(EmailMessage),
    File(File),
    Ipv4Addr(Ipv4Addr),
    Ipv6Addr(Ipv6Addr),
    MacAddr(MacAddr),
    Mutex(Mutex),
    NetworkTraffic(NetworkTraffic),
    Process(Process),
    Software(Software),
    Url(Url),
    UserAccount(UserAccount),
    WindowsRegistryKey(WindowsRegistryKey),
    WindowsRegistryKeyType(WindowsRegistryKeyType),
    X509Certificate(Box<X509Certificate>),
}
