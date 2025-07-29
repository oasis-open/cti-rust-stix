//! Defines the data structures for each specific STIX Cyber-observable Object type.
use crate::{
    base::Stix,
    cyber_observable_objects::vocab::{
        AccountTypeVocabulary, EncryptionAlgorithm, IanaServiceNamesEnum,
        WindowsRegistryDataTypeEnum,
    },
    error::{add_error, return_multiple_errors, StixError as Error},
    types::{DictionaryValue, Hashes, Identifier, StixDictionary, Timestamp},
};
use addr::parse_domain_name;
use base64::{engine::general_purpose, Engine};
use convert_case::{Case, Casing};
use email_address::{EmailAddress as validate_email, Options};
use iptools;
use language_tags::LanguageTag;
use log::warn;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_this_or_that::{as_opt_i64, as_opt_u64, as_u64};
use serde_with::skip_serializing_none;
use strum::IntoEnumIterator;
use url::Url as RustUrl;

/// Artifact Object
///
/// The Artifact object permits capturing an array of bytes (8-bits),
/// as a base64-encoded string, or linking to a file-like payload.
///  
/// One of payload_bin or url **MUST** be provided. It is incumbent on object
/// creators to ensure that the URL is accessible for downstream consumers.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_4jegwl6ojbes>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub mime_type: Option<String>,
    pub payload_bin: Option<String>,
    pub url: Option<RustUrl>,
    pub hashes: Option<Hashes>,
    pub encryption_algorithm: Option<EncryptionAlgorithm>,
    pub decryption_key: Option<String>,
}
impl Stix for Artifact {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(hashes) = &self.hashes {
            add_error(&mut errors, hashes.stix_check());
        }
        if self.payload_bin.is_none() && self.url.is_none() {
            errors.push(Error::ValidationError(
                "One of the optional fields, url or payload_bin, must be set".to_string(),
            ));
        }
        if self.payload_bin.is_some() && self.url.is_some() {
            errors.push(Error::ValidationError(
                "Only one of payload_bin and url may be set".to_string(),
            ));
        }
        if self.decryption_key.is_some() && self.encryption_algorithm.is_none() {
            errors.push(Error::ValidationError(
                "Encrytpion algorithm must be set when when decryption key is present".to_string(),
            ));
        }
        if let Some(payload_bin) = &self.payload_bin {
            // Try to decode the payload bin as a base-64 encoded string
            // We do not care about the value, just that it *can* be decoded
            let bytes = general_purpose::STANDARD.decode(payload_bin);
            if bytes.is_err() {
                errors.push(Error::ValidationError(
                    "A payload_bin must be a valid base-64 encoded string".to_string(),
                ));
            }
        }
        if self.url.is_some() && self.hashes.is_none() {
            errors.push(Error::ValidationError(
                "Hashes field must be present when url is set".to_string(),
            ));
        }

        return_multiple_errors(errors)
    }
}

/// Autonomous System
///
/// This object represents the properties of an Autonomous System (AS).
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_27gux0aol9e3>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutonomousSystem {
    ///Specifies the number assigned to the AS.
    #[serde(default, deserialize_with = "as_u64")]
    pub number: u64,
    ///Specifies the name of the AS
    pub name: Option<String>,
    ///Specifies the name of the Regional Internet Registry (RIR) that assigned the number to the AS.
    pub rir: Option<String>,
}
impl Stix for AutonomousSystem {
    fn stix_check(&self) -> Result<(), Error> {
        self.number.stix_check()
    }
}

/// Directory
///
/// The Directory object represents the properties common to a file system directory.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_lyvpga5hlw52>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Directory {
    pub path: String, // if not USCII path_enc must be set: not sure how we can determine
    pub path_enc: Option<String>, //supposed to be from charcter set list
    pub ctime: Option<Timestamp>,
    pub mtime: Option<Timestamp>,
    pub atime: Option<Timestamp>,
    pub contains_refs: Option<Vec<Identifier>>,
}
impl Stix for Directory {
    fn stix_check(&self) -> Result<(), Error> {
        if let Some(cr) = &self.contains_refs {
            cr.stix_check()?;
            for cref in cr {
                if cref.get_type() != "file" || cref.get_type() != "directory" {
                    return Err(Error::ValidationError(
                        "contains_refs must contain identifiers only of type file or directory"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Domain Name
///
/// The Domain Name object represents the properties of a network domain name.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_prhhksbxbg87>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainName {
    /// Specifies the value of the domain name.
    pub value: String,
    /// Specifies a list of references to one or more IP addresses or domain names that the domain name resolves to.
    pub resolves_to_refs: Option<Vec<Identifier>>,
}
impl Stix for DomainName {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Check if the domain name is in the correct format using the `addr` crate
        if parse_domain_name(&self.value).is_err() {
            errors.push(Error::ValidationError(
                "Domain name must conform to RFC1034 and RFC5890".to_string(),
            ));
        }

        // Validate resolves_to_refs if present
        if let Some(resolves_to_refs) = &self.resolves_to_refs {
            resolves_to_refs.stix_check()?;
            for reference in resolves_to_refs {
                let ref_type = reference.get_type();
                if ref_type != "ipv4-addr" && ref_type != "ipv6-addr" && ref_type != "domain-name" {
                    errors.push(Error::ValidationError(
                        "All resolves_to_refs must reference objects of type ipv4-addr, ipv6-addr, or domain-name".to_string(),
                    ));
                }
            }
        }

        return_multiple_errors(errors)
    }
}

/// Email Address
///
/// The Email Address object represents a single email address.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_wmenahkvqmgj>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailAddress {
    /// Specifies the value of the email address. This MUST NOT include the display name.
    pub value: String,
    /// Specifies a single email display name, i.e., the name that is displayed to the human user of a mail application.
    pub display_name: Option<String>,
    /// Specifies the user account that the email address belongs to, as a reference to a User Account object.
    pub belongs_to_ref: Option<Identifier>,
}
impl Stix for EmailAddress {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Check if the Email address is in the correct format
        let value = &self.value.to_string();
        let options = Options {
            minimum_sub_domains: 2,
            ..Options::default()
        };
        if validate_email::parse_with_options(value, options).is_err() {
            errors.push(Error::ValidationError(format!(
                "Email address {} is not a valid e-mail address.",
                value
            )));
        }
        if let Some(display_name) = &self.display_name {
            if value.contains(&display_name.to_string()) {
                errors.push(Error::ValidationError(format!(
                    "Email address {} must not include the display name {}.",
                    value, display_name
                )));
            }
        }
        if let Some(belongs_to_ref) = &self.belongs_to_ref {
            belongs_to_ref.stix_check()?;
            let belongs_to_ref_type = belongs_to_ref.get_type();
            if belongs_to_ref_type != "user-account" {
                errors.push(Error::ValidationError(format!(
                    "Email address belongs_to_ref type {} must be 'user-account'.",
                    belongs_to_ref_type
                )));
            }
        }

        return_multiple_errors(errors)
    }
}

/// Email Message
///
/// The Email Message object represents an instance of an email message, corresponding to the internet message
/// format described in [RFC5322](http://www.rfc-editor.org/info/rfc5322) and related RFCs.
///
/// Header field values that have been encoded as described in section 2 of [RFC2047](http://www.rfc-editor.org/info/rfc2047)
/// **MUST** be decoded before inclusion in Email Message object properties. For example, this is some text **MUST** be used instead
/// of =?iso-8859-1?q?this=20is=20some=20text?=. Any characters in the encoded value which cannot be decoded into Unicode
/// SHOULD be replaced with the 'REPLACEMENT CHARACTER' (U+FFFD). If it is necessary to capture the header value as observed,
/// this can be achieved by referencing an Artifact object through the raw_email_ref property.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_grboc7sq5514>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailMessage {
    //bools default to false: so is_multipart only needs to be set if true
    pub is_multipart: bool,
    pub date: Option<Timestamp>,
    pub content_type: Option<String>,
    pub from_ref: Option<Identifier>,
    pub sender_ref: Option<Identifier>,
    pub to_refs: Option<Vec<Identifier>>,
    pub cc_refs: Option<Vec<Identifier>>,
    pub bcc_refs: Option<Vec<Identifier>>,
    pub message_id: Option<String>,
    pub subject: Option<String>,
    pub recieved_lines: Option<Vec<String>>,
    pub additional_header_fields: Option<StixDictionary<Vec<String>>>,
    pub body: Option<String>,
    pub body_multipart: Option<Vec<EmailMimeCompomentType>>,
    pub raw_email_ref: Option<Identifier>,
}
impl Stix for EmailMessage {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(from_ref) = &self.from_ref {
            from_ref.stix_check()?;
            let ref_type = from_ref.get_type();
            if ref_type != "email-addr" {
                errors.push(Error::ValidationError(format!(
                    "Referenced addresss {} must be 'email-addr'.",
                    ref_type
                )));
            }
        }
        if let Some(sender_ref) = &self.sender_ref {
            sender_ref.stix_check()?;
            let ref_type = sender_ref.get_type();
            if ref_type != "email-addr" {
                errors.push(Error::ValidationError(format!(
                    "Referenced addresss {} must be 'email-addr'.",
                    ref_type
                )));
            }
        }
        if let Some(to_refs) = &self.to_refs {
            to_refs.stix_check()?;
            if !to_refs.iter().any(|x| x.get_type() == "email-addr") {
                errors.push(Error::ValidationError(
                    "Referenced addresses in to_refs must be 'email-addr'.".to_string(),
                ));
            }
        }

        if let Some(cc_refs) = &self.cc_refs {
            cc_refs.stix_check()?;
            if !cc_refs.iter().any(|x| x.get_type() == "email-addr") {
                errors.push(Error::ValidationError(
                    "Referenced addressses in cc_refs must be 'email-addr'.".to_string(),
                ));
            }
        }

        if let Some(bcc_refs) = &self.bcc_refs {
            bcc_refs.stix_check()?;
            if !bcc_refs.iter().any(|x| x.get_type() == "email-addr") {
                errors.push(Error::ValidationError(
                    "Referenced addressses in cc_refs must be 'email-addr'.".to_string(),
                ));
            }
        }
        if let Some(recieved_lines) = &self.recieved_lines {
            add_error(&mut errors, recieved_lines.stix_check());
        }
        if let Some(additional_header_fields) = &self.additional_header_fields {
            add_error(&mut errors, additional_header_fields.stix_check());
        }

        if self.body.is_some() && self.is_multipart {
            errors.push(Error::ValidationError(
                "The property body MUST NOT be used if is_multipart is true".to_string(),
            ));
        }

        if let Some(ref body_multipart) = self.body_multipart {
            if !self.is_multipart {
                body_multipart.stix_check()?; // Assuming stix_check() is a method on the type of body_multipart
                errors.push(Error::ValidationError(
                    "The property body_multipart MUST NOT be used if is_multipart is false"
                        .to_string(),
                ));
            }
        }

        if let Some(raw_email_ref) = &self.raw_email_ref {
            raw_email_ref.stix_check()?;
            let ref_type = raw_email_ref.get_type();
            if ref_type != "artifact" {
                errors.push(Error::ValidationError(
                    "Raw_email_ref must be an Identifier of type artifact".to_string(),
                ));
            }
        }

        return_multiple_errors(errors)
    }
}

/// Specifies one component of a multi-part email body.
///
/// One of `body` OR `body_raw_ref` MUST be included.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailMimeCompomentType {
    /// Specifies the contents of the MIME part if the content_type is not provided or starts with `text/` (e.g., in the case of plain text or HTML email).
    pub body: Option<String>,
    /// Specifies the contents of non-textual MIME parts, that is those whose content_type does not start with `text/`, as a reference to an `Artifact` object or `File` object.
    ///
    /// The object referenced in this property **MUST** be of type `artifact` or `file`.
    /// For use cases where conveying the actual data contained in the MIME part is of primary importance, `artifact` **SHOULD** be used.
    /// Otherwise, for use cases where conveying metadata about the file-like properties of the MIME part is of primary importance, `file` **SHOULD** be used.
    pub body_raw_ref: Option<Identifier>,
    /// Specifies the value of the "Content-Type" header field of the MIME part.
    ///
    /// Any additional "Content-Type" header field parameters such as `charset` **SHOULD** be included in this property.
    pub content_type: Option<String>,
    /// Specifies the value of the "Content-Disposition" header field of the MIME part.
    pub content_disposition: Option<String>,
}

impl Stix for EmailMimeCompomentType {
    fn stix_check(&self) -> Result<(), Error> {
        if self.body.is_none() == self.body_raw_ref.is_none() {
            return Err(Error::ValidationError(
                "An email MIME component type must include either a body or a body_raw_ref"
                    .to_string(),
            ));
        } else if let Some(body_raw_ref) = &self.body_raw_ref {
            body_raw_ref.stix_check()?;
            if body_raw_ref.get_type() != "artifact" && body_raw_ref.get_type() != "file" {
                return Err(Error::ValidationError(format!("An email MIME component type's `body_raw_ref` must refer to either an artifact or a file. This refers to an object of type {}", body_raw_ref.get_type())));
            }
        }
        Ok(())
    }
}

/// File
///
/// The File object represents the properties of a file. A File object **MUST** contain at least one of hashes or name.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_99bl2dibcztv>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct File {
    /// Specifies a dictionary of hashes for the file.
    pub hashes: Option<Hashes>,
    /// Specifies the size of the file, in bytes. The value of this property MUST NOT be negative.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size: Option<u64>,
    /// Specifies the name of the file.
    pub name: Option<String>,
    /// Specifies the observed encoding for the name of the file.
    pub name_enc: Option<String>,
    /// Specifies the hexadecimal constant ("magic number") associated with a specific file format that corresponds to the file, if applicable.
    pub magic_number_hex: Option<String>,
    /// Specifies the MIME type name specified for the file, e.g., application/msword.
    pub mime_type: Option<String>,
    /// Specifies the date/time the file was created.
    pub ctime: Option<Timestamp>,
    /// Specifies the date/time the file was last written to/modified.
    pub mtime: Option<Timestamp>,
    /// Specifies the date/time the file was last accessed.
    pub atime: Option<Timestamp>,
    /// Specifies the parent directory of the file, as a reference to a Directory object.
    pub parent_directory_ref: Option<Identifier>,
    /// Specifies a list of references to other Cyber-observable Objects contained within the file, such as another file that is appended to the end of the file, or an IP address that is contained somewhere in the file.
    pub contains_refs: Option<Vec<Identifier>>,
    /// Specifies the content of the file, represented as an Artifact object.
    pub content_ref: Option<Identifier>,
}
impl Stix for File {
    fn stix_check(&self) -> Result<(), Error> {
        if let Some(hashes) = &self.hashes {
            hashes.stix_check()?;
        }
        let mut errors = Vec::new();

        if let Some(size) = &self.size {
            add_error(&mut errors, size.stix_check());
        }
        if let Some(magic_number_hex) = &self.magic_number_hex {
            if hex::decode(magic_number_hex).is_err() {
                errors.push(Error::ParseHexError(
                    "magic_number_hex -- ".to_string() + magic_number_hex,
                ))
            }
        }
        if self.parent_directory_ref.is_some() {
            if let Some(parent_directory_ref) = &self.parent_directory_ref {
                parent_directory_ref.stix_check()?;
                if parent_directory_ref.get_type() != "directory" {
                    errors.push(Error::ValidationError(
                        "parent_directory_ref must be of type directory".to_string(),
                    ));
                }
            }
        };
        if let Some(contains_refs) = &self.contains_refs {
            add_error(&mut errors, contains_refs.stix_check());
        }

        if self.content_ref.is_some() {
            if let Some(content_ref) = &self.content_ref {
                content_ref.stix_check()?;
                if content_ref.get_type() != "artifact" {
                    errors.push(Error::ValidationError(
                        "content_ref must be of type artifact".to_string(),
                    ));
                }
            }
        }
        if self.name.is_none() && self.hashes.is_none() {
            errors.push(Error::ValidationError(
                "One of name or hashes muste be set".to_string(),
            ));
        }

        return_multiple_errors(errors)
    }
}

/// IPv4 Address
///
/// The IPv4 Address object represents one or more IPv4 addresses expressed using CIDR notation.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ki1ufj1ku8s0>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4Addr {
    /// Specifies the values of one or more IPv4 addresses expressed using CIDR notation.
    pub value: String,
    /// Specifies a list of references to one or more Layer 2 Media Access Control (MAC) addresses that the IPv4 address resolves to.
    pub resolves_to_refs: Option<Vec<Identifier>>,
    /// Specifies a list of references to one or more autonomous systems (AS) that the IPv4 address belongs to.
    pub belongs_to_refs: Option<Vec<Identifier>>,
}

impl Stix for Ipv4Addr {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Check if the IPv4 address is in the correct format, with or without a CIDR
        if !(iptools::ipv4::validate_cidr(&self.value) || iptools::ipv4::validate_ip(&self.value)) {
            errors.push(Error::ValidationError(
                "IPv4 address must be a valid dotted-decimal format with optional CIDR notation"
                    .to_string(),
            ));
        }

        // Validate resolves_to_refs if present
        if let Some(resolves_to_refs) = &self.resolves_to_refs {
            resolves_to_refs.stix_check()?;
            for reference in resolves_to_refs {
                if reference.get_type() != "mac-addr" {
                    errors.push(Error::ValidationError(
                        "All resolves_to_refs must reference objects of type mac-addr".to_string(),
                    ));
                }
            }
        }

        // Validate belongs_to_refs if present
        if let Some(belongs_to_refs) = &self.belongs_to_refs {
            belongs_to_refs.stix_check()?;
            for reference in belongs_to_refs {
                if reference.get_type() != "autonomous-system" {
                    errors.push(Error::ValidationError(
                        "All belongs_to_refs must reference objects of type autonomous-system"
                            .to_string(),
                    ));
                }
            }
        }

        return_multiple_errors(errors)
    }
}

/// IPv6 Address
///
/// The IPv6 Address object represents one or more IPv6 addresses expressed using CIDR notation.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_oeggeryskriq>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv6Addr {
    /// Specifies the values of one or more IPv6 addresses expressed using CIDR notation.
    pub value: String,
    /// Specifies a list of references to one or more Layer 2 Media Access Control (MAC) addresses that the IPv6 address resolves to.
    pub resolves_to_refs: Option<Vec<Identifier>>,
    /// Specifies a list of references to one or more autonomous systems (AS) that the IPv6 address belongs to.
    pub belongs_to_refs: Option<Vec<Identifier>>,
}
impl Stix for Ipv6Addr {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Check if the IPv6 address is in the correct format, with or without a CIDR
        if !(iptools::ipv6::validate_cidr(&self.value) || iptools::ipv6::validate_ip(&self.value)) {
            errors.push(Error::ValidationError(
                "IPv6 address must be a valid hexadecimal format with optional CIDR notation"
                    .to_string(),
            ));
        }

        // Validate resolves_to_refs if present
        if let Some(resolves_to_refs) = &self.resolves_to_refs {
            resolves_to_refs.stix_check()?;
            for reference in resolves_to_refs {
                if reference.get_type() != "mac-addr" {
                    errors.push(Error::ValidationError(
                        "All resolves_to_refs must reference objects of type mac-addr".to_string(),
                    ));
                }
            }
        }

        // Validate belongs_to_refs if present
        if let Some(belongs_to_refs) = &self.belongs_to_refs {
            belongs_to_refs.stix_check()?;
            for reference in belongs_to_refs {
                if reference.get_type() != "autonomous-system" {
                    errors.push(Error::ValidationError(
                        "All belongs_to_refs must reference objects of type autonomous-system"
                            .to_string(),
                    ));
                }
            }
        }

        return_multiple_errors(errors)
    }
}

/// MAC Address
///
/// The MAC Address object represents a single Media Access Control (MAC) address.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_f92nr9plf58y>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacAddr {
    /// Specifies the value of a single MAC address.
    pub value: String,
}

impl Stix for MacAddr {
    fn stix_check(&self) -> Result<(), Error> {
        // Check if the MAC address is in the correct format
        // Panic: Safe to unwrap as this is a valid regex string
        let mac_regex = regex::Regex::new(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$").unwrap();
        if !mac_regex.is_match(&self.value) {
            return Err(Error::ValidationError(
                "MAC address must be a valid colon-delimited, lowercase MAC-48 address with leading zeros".to_string(),
            ));
        }
        Ok(())
    }
}

/// Mutex
///
/// The MAC Address object represents a single Media Access Control (MAC) address.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_84hwlkdmev1w>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mutex {
    /// Specifies the name of the mutex object.
    pub name: String,
}
impl Stix for Mutex {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
    }
}

/// Network Traffic
///
/// The Network Traffic object represents arbitrary network traffic that originates \
/// from a source and is addressed to a destination. The network traffic MAY or MAY NOT
/// constitute a valid unicast, multicast, or broadcast network connection. This MAY also
/// include traffic that is not established, such as a SYN flood.
///
/// To allow for use cases where a source or destination address may be sensitive and not
/// suitable for sharing, such as addresses that are internal to an organization’s network,
/// the source and destination properties (src_ref and dst_ref, respectively) are defined
/// as optional in the properties table below. However, a Network Traffic object **MUST**
/// contain the protocols property and at least one of the src_ref or dst_ref properties
/// and SHOULD contain the src_port and dst_port properties.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_rgnc3w40xy>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkTraffic {
    pub start: Option<Timestamp>,
    pub end: Option<Timestamp>,
    pub is_active: Option<bool>,
    pub src_ref: Option<Identifier>,
    pub dst_ref: Option<Identifier>,
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub src_port: Option<u64>,
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub dst_port: Option<u64>,
    pub protocols: Vec<String>,
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub src_byte_count: Option<u64>,
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub dst_byte_count: Option<u64>,
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub src_packets: Option<u64>,
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub dst_packets: Option<u64>,
    pub ipfix: Option<StixDictionary<DictionaryValue>>,
    pub src_payload_ref: Option<Identifier>,
    pub dst_payload_ref: Option<Identifier>,
    pub encapsulates_refs: Option<Vec<Identifier>>,
    pub encapsulated_by_ref: Option<Identifier>,
}
impl Stix for NetworkTraffic {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(src_port) = &self.src_port {
            add_error(&mut errors, src_port.stix_check());
        }
        if let Some(dst_port) = &self.dst_port {
            add_error(&mut errors, dst_port.stix_check());
        }
        if let Some(src_byte_count) = &self.src_byte_count {
            add_error(&mut errors, src_byte_count.stix_check());
        }
        if let Some(dst_byte_count) = &self.dst_byte_count {
            add_error(&mut errors, dst_byte_count.stix_check());
        }
        if let Some(src_packets) = &self.src_packets {
            add_error(&mut errors, src_packets.stix_check());
        }
        if let Some(dst_packets) = &self.dst_packets {
            add_error(&mut errors, dst_packets.stix_check());
        }

        if self.src_port.is_none() && self.dst_port.is_none() {
            warn!(
                "It is recommended that network traffic contain the src_port and dst_port properties."
            );
        }
        if let Some(dst_payload_ref) = &self.dst_payload_ref {
            dst_payload_ref.stix_check()?;
            if dst_payload_ref.get_type() != "artifact" {
                errors.push(Error::ValidationError(format!(
                    "dst_payload_ref {} MUST be of type artifact.",
                    dst_payload_ref.get_type()
                )));
            }
        }
        if let Some(encapsulated_by_ref) = &self.encapsulated_by_ref {
            encapsulated_by_ref.stix_check()?;
            if encapsulated_by_ref.get_type() != "network-traffic" {
                errors.push(Error::ValidationError(format!(
                    "encapsulated_by_ref {} MUST be of type network-traffic.",
                    encapsulated_by_ref.get_type()
                )));
            }
        }
        if let Some(dst_port) = self.dst_port {
            if (0..=65535).contains(&dst_port) {
                errors.push(Error::ValidationError(
                format!("dst_port {} Specifies the source port used in the network traffic, as an integer. The port value MUST be in the range of 0 - 65535.",dst_port),
            ));
            }
        }
        if let Some(dst_ref) = &self.dst_ref {
            add_error(&mut errors, dst_ref.stix_check());
            if dst_ref.get_type() != "ipv4-addr"
                && dst_ref.get_type() != "ipv6-addr"
                && dst_ref.get_type() != "mac-addr"
                && dst_ref.get_type() != "domain-name"
            {
                errors.push(Error::ValidationError(
                    format!("dst_ref {} MUST be of type ipv4-addr, ipv6-addr, mac-addr, or domain-name (for cases where the IP address for a domain name is unknown).",dst_ref.get_type(),
                )));
            }
        }
        if let Some(encapsulates_refs) = &self.encapsulates_refs {
            encapsulates_refs.stix_check()?;
            for er in encapsulates_refs {
                if er.get_type() != "network-traffic" {
                    errors.push(Error::ValidationError(format!(
                        "encapsulates_refs {} MUST be of type network-traffic.",
                        er.get_type()
                    )));
                }
            }
        }
        if let (Some(end), Some(is_active)) = (&self.end, &self.is_active) {
            if *is_active {
                errors.push(Error::ValidationError(
                    format!("If the is_active property is true, then the end {} property MUST NOT be included. If the end property is provided, is_active MUST be false.",end)
                ));
            }
        }

        if let (Some(start), Some(stop)) = (&self.start, &self.end) {
            if stop < start {
                errors.push(Error::ValidationError(format!("Network traffic has an end timestamp of {} and a start timestamp of {}. The former cannot be earlier than the latter.",
                    stop,
                    start
                )));
            }
        }

        if let Some(src_payload_ref) = &self.src_payload_ref {
            src_payload_ref.stix_check()?;
            if src_payload_ref.get_type() != "artifact" {
                errors.push(Error::ValidationError(format!(
                    "src_payload_ref {} MUST be of type artifact.",
                    src_payload_ref.get_type()
                )));
            }
        }
        if let Some(src_ref) = &self.src_ref {
            add_error(&mut errors, src_ref.stix_check());
            if src_ref.get_type() != "ipv4-addr"
                && src_ref.get_type() != "ipv6-addr"
                && src_ref.get_type() != "mac-addr"
                && src_ref.get_type() != "domain-name"
            {
                errors.push(Error::ValidationError(
                        format!("src_ref {} MUST be of type ipv4-addr, ipv6-addr, mac-addr, or domain-name (for cases where the IP address for a domain name is unknown).",src_ref.get_type()),
                    ));
            }
        }

        add_error(&mut errors, self.protocols.stix_check());

        let protocols_joined = &self.protocols.join(",");
        if protocols_joined.contains("ip") && !protocols_joined.starts_with("ip") {
            errors.push(Error::ValidationError(
                    format!("protocols {} Protocols MUST be listed in low to high order, from outer to inner in terms of packet encapsulation. That is, the protocols in the outer level of the packet, such as IP, MUST be listed first.",protocols_joined),
                ));
        }
        for p in &self.protocols {
            if !IanaServiceNamesEnum::iter().any(|x| x.as_ref().to_case(Case::Kebab) == *p) {
                warn!(
                "The protocol names SHOULD come from the service names defined in the Service Name column of the IANA Service Name and Port Number Registry. Doublecheck that protocol name '{}' is in the registry.", p
            );
            }
        }
        if let Some(ipfix) = &self.ipfix {
            add_error(&mut errors, ipfix.stix_check());
            for (_key, val) in ipfix.iter() {
                match val {
                    DictionaryValue::String(string) => add_error(&mut errors,string.stix_check()),
                    DictionaryValue::Int(int) => add_error(&mut errors,int.stix_check()),
                    _ =>  errors.push(Error::ValidationError(
                        format!("Ipfix dictionary value {} SHOULD be a case-preserved version of the IPFIX element name, e.g., octetDeltaCount. Each dictionary value MUST be either an integer or a string, as well as a valid IPFIX property.",val)
                    )),
                };
            }
        }

        return_multiple_errors(errors)
    }
}

/// Process
///
/// The Process object represents common properties of an instance of a computer program as executed
/// on an operating system. A Process object **MUST** contain at least one property (other than type) from
/// this object (or one of its extensions).
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_hpppnm86a1jm>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Process {
    /// Specifies whether the process is hidden.
    pub is_hidden: Option<bool>,
    /// Specifies the Process ID, or PID, of the process.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub pid: Option<i64>,
    /// Specifies the date/time at which the process was created.
    pub created_time: Option<Timestamp>,
    /// Specifies the current working directory of the process.
    pub cwd: Option<String>,
    /// Specifies the full command line used in executing the process, including the process name (which may be specified individually via the image_ref.name property) and any arguments.
    pub command_line: Option<String>,
    /// Specifies the list of environment variables associated with the process as a dictionary.
    pub environment_variables: Option<StixDictionary<Vec<String>>>,
    /// Specifies the list of network connections opened by the process, as a reference to one or more Network Traffic objects.
    pub opened_connection_refs: Option<Vec<Identifier>>,
    /// Specifies the user that created the process, as a reference to a User Account object.
    pub creator_user_ref: Option<Identifier>,
    /// Specifies the executable binary that was executed as the process image, as a reference to a File object.
    pub image_ref: Option<Identifier>,
    /// Specifies the other process that spawned (i.e. is the parent of) this one, as a reference to a Process object.
    pub parent_ref: Option<Identifier>,
    /// Specifies the other processes that were spawned by (i.e. children of) this process, as a reference to one or more other Process objects.
    pub child_refs: Option<Vec<Identifier>>,
}
impl Stix for Process {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(child_refs) = &self.child_refs {
            for child_ref in child_refs {
                if child_ref.get_type() != "process" {
                    errors.push(Error::ValidationError(
                        "child_refs must be of type 'process'.".to_string(),
                    ));
                }
            }
        }
        if let Some(creator_user_ref) = &self.creator_user_ref {
            creator_user_ref.stix_check()?;
            if creator_user_ref.get_type() != "user-account" {
                errors.push(Error::ValidationError(
                    "creator_user_ref must be of type 'user-account'.".to_string(),
                ));
            }
        }
        if let Some(image_ref) = &self.image_ref {
            image_ref.stix_check()?;
            if image_ref.get_type() != "file" {
                errors.push(Error::ValidationError(
                    "image_ref must be of type 'file'.".to_string(),
                ));
            }
        }
        if let Some(opened_connection_refs) = &self.opened_connection_refs {
            opened_connection_refs.stix_check()?;
            for ocr in opened_connection_refs {
                if ocr.get_type() != "network-traffic" {
                    errors.push(Error::ValidationError(
                        "opened_connection_refs must be of type 'network-traffic'.".to_string(),
                    ));
                }
            }
        }
        if let Some(parent_ref) = &self.parent_ref {
            parent_ref.stix_check()?;
            if parent_ref.get_type() != "process" {
                errors.push(Error::ValidationError(
                    "parent_ref must be of type 'process'.".to_string(),
                ));
            }
        }
        if let Some(pid) = &self.pid {
            add_error(&mut errors, pid.stix_check());
        }
        if let Some(child_refs) = &self.child_refs {
            add_error(&mut errors, child_refs.stix_check());
        }

        if let Some(environment_variables) = &self.environment_variables {
            add_error(&mut errors, environment_variables.stix_check());
        }

        return_multiple_errors(errors)
    }
}

/// Software
///
/// The Software object represents high-level properties associated with software, including software products.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_7rkyhtkdthok>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Software {
    // name of the software.
    pub name: String,
    // Common Platform Enumeration (CPE) entry for the software
    pub cpe: Option<String>,
    // The Software Identification (SWID) Tags [SWID] entry for the software
    pub swid: Option<String>,
    //languages supported by the software.
    pub languages: Option<Vec<String>>,
    // The name of the vendor of the software.
    pub vendor: Option<String>,
    // The version of the software.
    pub version: Option<String>,
}
impl Stix for Software {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(languages) = &self.languages {
            add_error(&mut errors, languages.stix_check());
            for language in languages {
                match LanguageTag::parse(language) {
                Ok(tag) => if let Err(e) = LanguageTag::validate(&tag) {
                    errors.push(Error::ValidationError(format!("Object {:?}'s `language` is {}. A `language` must conform to RFC5646. Details: {}",
                    self,
                    language,
                    e
                )));
                }
                Err(e) => errors.push(Error::ValidationError(format!("Object {:?}'s `language` is {}. A `language` must conform to RFC5646. Details: {}",
                self,
                    language,
                    e
                ))),
            }
            }
        }

        return_multiple_errors(errors)
    }
}

/// URL
///
/// The User Account object represents an instance of any type of user account, including but not limited to
/// operating system, device, messaging service, and social media platform accounts. As all properties of this
/// object are optional, at least one of the properties defined below **MUST** be included when using this object.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ah3hict2dez0>
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Url {
    pub value: RustUrl,
}
impl Stix for Url {
    fn stix_check(&self) -> Result<(), Error> {
        // We do not need to validate the `value` field, because a `url::Url` cannot be empty or an invalid URL.
        Ok(())
    }
}

impl Default for Url {
    fn default() -> Self {
        Url {
            // Panic: Safe to unwrap as this is a valid URL string
            value: RustUrl::parse("http://example.com").unwrap(),
        }
    }
}

/// User Account
///
/// The User Account object represents an instance of any type of user account, including but not limited to
/// operating system, device, messaging service, and social media platform accounts. As all properties of this
/// object are optional, at least one of the properties defined below **MUST** be included when using this object.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_azo70vgj1vm2>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserAccount {
    // The identifier of the account.
    pub user_id: Option<String>,
    // Specifies a cleartext credential
    pub credential: Option<String>,
    //Specifies the account login string,
    pub account_login: Option<String>,
    //pecifies the type of the account.
    pub account_type: Option<String>,
    //Specifies the display name of the account
    pub display_name: Option<String>,
    //Indicates that the account is associated with a network service
    pub is_service_account: Option<bool>,
    //Specifies that the account has elevated privileges
    pub is_privileged: Option<bool>,
    //Specifies that the account has the ability to escalate privileges
    pub can_escalate_privs: Option<bool>,
    //Specifies if the account is disabled.
    pub is_disabled: Option<bool>,
    //Specifies when the account was created.
    pub account_created: Option<Timestamp>,
    //Specifies the expiration date of the account.
    pub account_expires: Option<Timestamp>,
    //Specifies when the account credential was last changed.
    pub credential_last_changed: Option<Timestamp>,
    //Specifies when the account was first accessed.
    pub account_first_login: Option<Timestamp>,
    //Specifies when the account was last accessed.
    pub account_last_login: Option<Timestamp>,
}

impl Stix for UserAccount {
    fn stix_check(&self) -> Result<(), Error> {
        if let Some(account_type_str) = &self.account_type {
            if !AccountTypeVocabulary::iter()
                .any(|x| x.as_ref() == account_type_str.to_case(Case::Kebab))
            {
                warn!(
                    "The region property should come from the `region-ov` open vocabulary. Location region '{}' is not in the vocabulary.", account_type_str
                );
            }
        }

        Ok(())
    }
}

/// Windows Regsitry Key Open
///
/// The Registry Key object represents the properties of a Windows registry key. As all properties of this object are optional,
/// at least one of the properties defined below **MUST** be included when using this object.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_luvw8wjlfo3y>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsRegistryKey {
    /// Specifies the full registry key including the hive.
    pub key: Option<String>,
    /// list of type windows-registry-value-type
    pub values: Option<Vec<WindowsRegistryKeyType>>,
    /// Specifies the last date/time that the registry key was modified.
    pub modified_time: Option<Timestamp>,
    /// Specifies a reference to the user account that created the registry key.
    pub creator_user_ref: Option<Identifier>,
    /// Specifies the number of subkeys contained under the registry key.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub number_of_subkeys: Option<i64>,
}
impl Stix for WindowsRegistryKey {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(creator_user_ref) = &self.creator_user_ref {
            creator_user_ref.stix_check()?;
            if creator_user_ref.get_type() != "user-account" {
                errors.push(Error::ValidationError(
                    "creator_user_ref must be of type 'user-account'.".to_string(),
                ));
            }
        }
        if let Some(key) = &self.key {
            // Panic: Safe to unwrap as this is a valid regex string
            let re = Regex::new(r"^(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)(\\[a-zA-Z0-9_]+)*$").unwrap();
            if !re.is_match(key) {
                errors.push(Error::ValidationError(
                    "Registry key must begin with HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, HKEY_CLASSES_ROOT, HKEY_USERS, or HKEY_CURRENT_CONFIG.".to_string(),
                ));
            }
        }
        if let Some(number_of_subkeys) = &self.number_of_subkeys {
            number_of_subkeys.stix_check()?;
        }
        if let Some(values) = &self.values {
            add_error(&mut errors, values.stix_check());
        }

        return_multiple_errors(errors)
    }
}

/// Windows Registry Value Type
///
/// The Windows Registry Value type captures the properties of a Windows Registry Key Value.
/// As all properties of this type are optional, at least one of the properties defined below MUST be included when using this type.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_u7n4ndghs3qq>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsRegistryKeyType {
    /// Specifies the name of the registry value. For specifying the default value in a registry key, an empty string MUST be used.
    pub name: Option<String>,
    /// Specifies the data contained in the registry value.
    pub data: Option<String>,
    /// Specifies the registry (REG_*) data type used in the registry value.
    pub data_type: Option<String>,
}
impl Stix for WindowsRegistryKeyType {
    fn stix_check(&self) -> Result<(), Error> {
        if let Some(data_type) = &self.data_type {
            if WindowsRegistryDataTypeEnum::iter().all(|x| x.as_ref() != data_type) {
                return Err(Error::ValidationError(
                    "data_type must come from the 'windows-registry-datatype-enum' enumeration."
                        .to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// X.509 Certificate
///
/// The X.509 Certificate object represents the properties of an X.509 certificate, as defined by ITU recommendation X.509 [X.509].
/// An X.509 Certificate object **MUST** contain at least one object specific property (other than type) from this object.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_8abcy1o5x9w1>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct X509Certificate {
    /// Specifies whether the certificate is self-signed, i.e., whether it is signed by the same entity whose identity it certifies.
    pub is_self_signed: Option<bool>,
    /// Specifies any hashes that were calculated for the entire contents of the certificate.
    pub hashes: Option<Hashes>,
    /// Specifies the version of the encoded certificate.
    pub version: Option<String>,
    /// Specifies the unique identifier for the certificate, as issued by a specific Certificate Authority.
    pub serial_number: Option<String>,
    /// Specifies the name of the algorithm used to sign the certificate.
    pub signature_algorithm: Option<String>,
    /// Specifies the name of the Certificate Authority that issued the certificate.
    pub issuer: Option<String>,
    /// Specifies the date on which the certificate validity period begins.
    pub validity_not_before: Option<Timestamp>,
    /// Specifies the date on which the certificate validity period ends.
    pub validity_not_after: Option<Timestamp>,
    /// Specifies the name of the entity associated with the public key stored in the subject public key field of the certificate.
    pub subject: Option<String>,
    /// Specifies the name of the algorithm with which to encrypt data being sent to the subject.
    pub subject_public_key_algorithm: Option<String>,
    /// Specifies the modulus portion of the subject’s public RSA key.
    pub subject_public_key_modulus: Option<String>,
    /// Specifies the exponent portion of the subject’s public RSA key, as an integer.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub subject_public_key_exponent: Option<i64>,
    /// Specifies any standard X.509 v3 extensions that may be used in the certificate.
    pub x509_v3_extensions: Option<X509V3Extensions>,
}
impl Stix for X509Certificate {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Validate subject_public_key_exponent
        if let Some(exponent) = self.subject_public_key_exponent {
            if exponent <= 0 {
                errors.push(Error::ValidationError(
                    "subject_public_key_exponent must be a positive integer".to_string(),
                ));
            }
        }

        // Validate x509_v3_extensions if present
        if let Some(extensions) = &self.x509_v3_extensions {
            add_error(&mut errors, extensions.stix_check());
        }
        if let Some(subject_public_key_exponent) = &self.subject_public_key_exponent {
            add_error(&mut errors, subject_public_key_exponent.stix_check());
        }
        return_multiple_errors(errors)
    }
}

/// X.509 v3 Extensions
///
/// The X.509 v3 Extensions object represents the properties of the X.509 v3 extensions that may be used in the certificate.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_oudvonxzdlku>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct X509V3Extensions {
    /// Specifies a multi-valued extension which indicates whether a certificate is a CA certificate.
    pub basic_constraints: Option<String>,
    /// Specifies a namespace within which all subject names in subsequent certificates in a certification path MUST be located.
    pub name_constraints: Option<String>,
    /// Specifies any constraints on path validation for certificates issued to CAs.
    pub policy_constraints: Option<String>,
    /// Specifies a multi-valued extension consisting of a list of names of the permitted key usages.
    pub key_usage: Option<String>,
    /// Specifies a list of usages indicating purposes for which the certificate public key can be used for.
    pub extended_key_usage: Option<String>,
    /// Specifies the identifier that provides a means of identifying certificates that contain a particular public key.
    pub subject_key_identifier: Option<String>,
    /// Specifies the identifier that provides a means of identifying the public key corresponding to the private key used to sign a certificate.
    pub authority_key_identifier: Option<String>,
    /// Specifies the additional identities to be bound to the subject of the certificate.
    pub subject_alternative_name: Option<String>,
    /// Specifies the additional identities to be bound to the issuer of the certificate.
    pub issuer_alternative_name: Option<String>,
    /// Specifies the identification attributes (e.g., nationality) of the subject.
    pub subject_directory_attributes: Option<String>,
    /// Specifies how CRL information is obtained.
    pub crl_distribution_points: Option<String>,
    /// Specifies the number of additional certificates that may appear in the path before anyPolicy is no longer permitted.
    pub inhibit_any_policy: Option<String>,
    /// Specifies the date on which the validity period begins for the private key, if it is different from the validity period of the certificate.
    pub private_key_usage_period_not_before: Option<Timestamp>,
    /// Specifies the date on which the validity period ends for the private key, if it is different from the validity period of the certificate.
    pub private_key_usage_period_not_after: Option<Timestamp>,
    /// Specifies a sequence of one or more policy information terms, each of which consists of an object identifier (OID) and optional qualifiers.
    pub certificate_policies: Option<String>,
    /// Specifies one or more pairs of OIDs; each pair includes an issuerDomainPolicy and a subjectDomainPolicy.
    pub policy_mappings: Option<String>,
}

impl Stix for X509V3Extensions {
    fn stix_check(&self) -> Result<(), Error> {
        // Ensure at least one property is present
        if self.basic_constraints.is_none()
            && self.name_constraints.is_none()
            && self.policy_constraints.is_none()
            && self.key_usage.is_none()
            && self.extended_key_usage.is_none()
            && self.subject_key_identifier.is_none()
            && self.authority_key_identifier.is_none()
            && self.subject_alternative_name.is_none()
            && self.issuer_alternative_name.is_none()
            && self.subject_directory_attributes.is_none()
            && self.crl_distribution_points.is_none()
            && self.inhibit_any_policy.is_none()
            && self.private_key_usage_period_not_before.is_none()
            && self.private_key_usage_period_not_after.is_none()
            && self.certificate_policies.is_none()
            && self.policy_mappings.is_none()
        {
            return Err(Error::ValidationError(
                "An X.509 v3 Extensions object must contain at least one property.".to_string(),
            ));
        }

        Ok(())
    }
}
