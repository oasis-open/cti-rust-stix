//! Core types for representing and manipulating STIX data structures.
#![allow(dead_code)]

/// STIX2 Common Data Types used by STIX Objects that cannot be reprsented by existing Rust types
use crate::{
    base::Stix,
    error::{add_error, return_multiple_errors, StixError as Error},
};
use convert_case::{Boundary, Case, Casing};
use identyhash::identify_hash;
use jiff::Timestamp as JiffTimestamp;
use language_tags::LanguageTag;
use log::warn;
use ordered_float::OrderedFloat;
use regex::Regex;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_value::Value;
use serde_with::{skip_serializing_none, DeserializeFromStr, SerializeDisplay};
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    ops::Not,
    str::{self, FromStr},
};
use strum::{AsRefStr, EnumIter, EnumString, IntoEnumIterator};
use url::Url;
use uuid::{Uuid, Version};

#[cfg(test)]
use uuid::uuid;

// Impl STIX validation for Rust types that are already valid STIX types

impl Stix for bool {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl Stix for u8 {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl Stix for u64 {
    fn stix_check(&self) -> Result<(), Error> {
        if *self > (1 << 53) - 1 {
            return Err(Error::ValidationError(
                "u64 values must be limited to within [0, (2^53) - 1] or <= 9007199254740991"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

impl Stix for i64 {
    fn stix_check(&self) -> Result<(), Error> {
        let min = -(2i64.pow(53)) + 1;
        let max = (2i64.pow(53)) - 1;
        if *self < min || *self > max {
            return Err(Error::ValidationError(
                "i64 values must be limited to within [-(2^53)+1, (2^53)-1] or within the number range [-9007199254740991, 9007199254740991]".to_string(),
            ));
        }
        Ok(())
    }
}

impl<T> Stix for OrderedFloat<T> {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl Stix for String {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
    }
}

/// Converts a raw string to kebab-case.
pub fn stix_case(raw_str: &str) -> String {
    raw_str
        .without_boundaries(&[Boundary::UPPER_DIGIT, Boundary::LOWER_DIGIT])
        .to_case(Case::Kebab)
}

// impl STIX for Rust Vec's as STIX Lists by requiring that they are non-empty and contain only valid STIX elements
impl<T: Stix> Stix for Vec<T> {
    fn stix_check(&self) -> Result<(), Error> {
        if self.is_empty() {
            return Err(Error::EmptyList);
        }
        let mut errors = Vec::new();
        for item in self.iter() {
            add_error(&mut errors, item.stix_check());
        }
        return_multiple_errors(errors)
    }
}

impl<T: Stix, U: Stix> Stix for HashMap<T, U> {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Check that the key and value of each Map entry are valid Stix objects or properties
        for (key, value) in self.iter() {
            add_error(&mut errors, key.stix_check());
            add_error(&mut errors, value.stix_check());
        }
        return_multiple_errors(errors)
    }
}

impl<T: Stix, U: Stix> Stix for BTreeMap<T, U> {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Check that the key and value of each Map entry are valid Stix objects or properties
        for (key, value) in self.iter() {
            add_error(&mut errors, key.stix_check());
            add_error(&mut errors, value.stix_check());
        }
        return_multiple_errors(errors)
    }
}

impl Stix for serde_json::Value {
    fn stix_check(&self) -> Result<(), Error> {
        match self {
            Self::Bool(bool) => bool.stix_check(),
            Self::Number(number) => {
                if let Some(unsigned) = number.as_u64() {
                    unsigned.stix_check()
                } else if let Some(signed) = number.as_i64() {
                    if signed < -9007199254740992 {
                        Err(Error::ValidationError(
                            "i64 values must be limited to within 2^53 bits".to_string(),
                        ))
                    } else {
                        Ok(())
                    }
                } else {
                    OrderedFloat(number.as_f64()).stix_check()
                }
            }
            Self::String(string) => string.stix_check(),
            Self::Array(array) => array.stix_check(),
            Self::Object(map) => {
                let mut errors = Vec::new();

                // Check that the key and value of each Map entry are valid Stix objects or properties
                for (key, value) in map.iter() {
                    add_error(&mut errors, key.stix_check());
                    add_error(&mut errors, value.stix_check());
                }
                return_multiple_errors(errors)
            }
            Self::Null => Err(Error::JsonNull),
        }
    }
}

/// A STIX 2.1 compliant dictionary that captures an set of key/value pairs.
///
/// The dictionary key is a string that must satisfy certain constraints, which are checked when a new entry is added.
/// The value can be any valid STIX type. This must be checked.
///
/// Becuase the dictionary is stored as a Rust BTreeMap, the entries will always be serialized orderd by key, not by entry order
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_f6e8afjdtrse>
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StixDictionary<T: Stix>(BTreeMap<String, T>);

impl<T: Stix> StixDictionary<T> {
    /// Creates a new Stix 2.1 compliant dictionary
    ///
    /// Note: STIX 2.1 requires that dictionaries cannot be empty,
    /// so at least one entry must be added to the dictionary with the `insert()` method or the dictionary will not pass validation
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Adds a valid key/value pair to a dictionary
    pub fn insert(&mut self, key: &str, value: T) -> Result<(), Error> {
        // Make sure the key is a valid STIX Dictionary key
        if check_dictionary_key(key) {
            // We do not allow duplicate keys
            match self.0.insert(key.to_string(), value) {
                Some(_duplicate_key) => Err(Error::ValidationError(format!(
                    "Duplicate value specified for {}",
                    key
                ))),
                None => Ok(()),
            }
        } else {
            Err(Error::ValidationError(format!("Key {} is not a valid key under STIX policies. Keys may only contain letters, numbers, '-, or '_'.", key)))
        }
    }

    /// Retrieves the value for a given key in a dictionary
    pub fn get(&self, key: &str) -> Option<&T> {
        self.0.get(key)
    }

    /// Creates an iterator for the keys of the dictionary
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.0.keys()
    }

    /// Creates an iterator for the key/value pairs of the dictionary
    pub fn iter(&self) -> impl Iterator<Item = (&String, &T)> {
        self.0.iter()
    }
}

impl<T: Stix> Default for StixDictionary<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Stix> Stix for StixDictionary<T> {
    fn stix_check(&self) -> Result<(), Error> {
        // Empty dictionaries are prohibited in STIX
        if self.0.is_empty() {
            return Err(Error::EmptyList);
        }
        // If the dicitonary is non-empty, check that each key is valid.
        let mut errors = Vec::new();
        for (key, val) in self.iter() {
            if !check_dictionary_key(key) {
                errors.push(Error::ValidationError(format!("Key {} is not a valid key under STIX policies. Keys may only contain letters, numbers, '-, or '_'.", key)))
            }
            add_error(&mut errors, val.stix_check());
        }

        return_multiple_errors(errors)
    }
}

// Checks that the provided dictionary key is STIX 2.1 compliant and provides warnings if it compliant but against recommendations
fn check_dictionary_key(key: &str) -> bool {
    let valid = key.len() <= 250
        && (key
            .chars()
            .all(|c| c.is_ascii() && (c.is_alphanumeric() || c == '-' || c == '_')));

    if key.chars().any(|c| c.is_uppercase()) {
        warn!(
            "STIX 2.1 recommends that dictionary keys should be lowercase. Key value is {}.",
            key
        );
    }

    valid
}

/// Possible primitive dictionary values
///
/// This enum is to cover the case of different primitive types being stored in the same STIX dictionary
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(untagged)]
pub enum DictionaryValue {
    String(String),
    Bool(bool),
    Int(u64),
    SInt(i64),
    Float(OrderedFloat<f64>),
    List(Vec<DictionaryValue>),
    Dict(StixDictionary<DictionaryValue>),
}

impl fmt::Display for DictionaryValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DictionaryValue::String(string) => write!(f, "{string}"),
            DictionaryValue::Bool(bool) => write!(f, "{bool}"),
            DictionaryValue::Int(int) => write!(f, "{int}"),
            DictionaryValue::SInt(signed) => write!(f, "{signed}"),
            DictionaryValue::Float(float) => write!(f, "{float}"),
            DictionaryValue::List(list) => {
                let mut vec_string = String::new();
                vec_string.push('[');

                for item in list {
                    vec_string.push_str(&item.to_string());
                    vec_string.push_str(", ");
                }

                // Remove the space after the last item in the list
                vec_string.pop();
                vec_string.pop();
                vec_string.push(']');
                write!(f, "{vec_string}")
            }
            DictionaryValue::Dict(dict) => {
                let mut dict_string = String::new();
                dict_string.push('{');

                for (key, value) in dict.iter() {
                    dict_string.push_str(&format!("{}: {}", key, value));
                    dict_string.push_str(", ");
                }

                // Remove the space after the last item in the list
                dict_string.pop();
                dict_string.pop();
                dict_string.push('}');
                write!(f, "{dict_string}")
            }
        }
    }
}

impl Stix for DictionaryValue {
    fn stix_check(&self) -> Result<(), Error> {
        match self {
            DictionaryValue::String(string) => string.stix_check(),
            DictionaryValue::Bool(bool) => bool.stix_check(),
            DictionaryValue::Int(int) => int.stix_check(),
            DictionaryValue::SInt(_signed) => Ok(()),
            DictionaryValue::Float(float) => float.stix_check(),
            DictionaryValue::List(list) => list.stix_check(),
            DictionaryValue::Dict(dict) => dict.stix_check(),
        }
    }
}

/// Gets the extension type for a general extension
pub fn get_extension_type(extension: &StixDictionary<DictionaryValue>) -> Option<ExtensionType> {
    match extension.get("extension_type") {
        Some(DictionaryValue::String(extension_type)) => {
            ExtensionType::from_str(&stix_case(extension_type)).ok()
        }
        _ => None,
    }
}

/// A STIX 2.1 compliant hash list, with a key/value pair identifying the hashing algorithm used and the hashed value.
///
/// Because hash lists have different constraints than other dictionaries, it is treated as a separate type.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_odoabbtwuxyd>
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hashes(HashMap<String, String>);

impl Hashes {
    /// Creates a new Stix 2.1 compliant hash list with a single key/value pair
    ///
    /// STIX 2.1 requires that hash lists cannot be empty, so to be extra careful we **must** have an initial key-value pair to create a new dictionary
    pub fn new(key: &str, value: &str) -> Result<Self, Error> {
        // Make sure the key is a valid STIX hash
        if check_hash_key(key) {
            let mut hashes = HashMap::new();
            hashes.insert(key.to_string(), value.to_string());

            Ok(Self(hashes))
        } else {
            Err(Error::ValidationError(format!("Key {} is not a valid key under STIX policies. Keys may only contain letters, numbers, '-, or '_'.", key)))
        }
    }

    /// Adds a valid key/value pair to a hash list
    pub fn insert(&mut self, key: &str, value: &str) -> Result<(), Error> {
        // Make sure the key is a valid STIX Dictionary key
        if check_hash_key(key) {
            // We do not allow duplicate keys
            match self.0.insert(key.to_string(), value.to_string()) {
                Some(_duplicate_key) => Err(Error::ValidationError(format!(
                    "Duplicate value specified for {}",
                    key
                ))),
                None => Ok(()),
            }
        } else {
            Err(Error::ValidationError(format!("Key {} is not a valid key under STIX policies. Keys may only contain letters, numbers, '-, or '_'.", key)))
        }
    }

    /// Retrieves the value for a given key in a hash list
    pub fn get(&self, key: &str) -> Option<&String> {
        self.0.get(key)
    }

    /// Creates an iterator for the key/value pairs of a hash list
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.0.iter()
    }
    pub fn length(&self) -> usize {
        self.0.len()
    }
}

// Checks that the provided hash key is STIX 2.1 compliant and provides warnings if it compliant but against recommendations
fn check_hash_key(key: &str) -> bool {
    let valid = key.len() >= 3
        && key.len() <= 250
        && (key
            .chars()
            .all(|c| c.is_ascii() && (c.is_alphanumeric() || c == '-' || c == '_')));

    if key != "SHA-256" {
        warn!("STIX 2.1 recommends that the SHA-256 hash should be used whenever possible");
    }

    valid
}

impl Stix for Hashes {
    fn stix_check(&self) -> Result<(), Error> {
        // Panic: Safe to unwrap as this is a valid regex string
        let ssdeep_re = Regex::new(r"^\d+:[A-Za-z0-9/+]{1,}:[A-Za-z0-9/+]{1,}$").unwrap();
        for (key, value) in self.iter() {
            let origin_hash_str = value.as_str();
            let hash_type_identity = identify_hash(origin_hash_str).to_lowercase();
            let origin_hash_type = key.as_str().to_lowercase();
            if LegalHashTypes::iter().all(|x| x.as_ref() != origin_hash_type) {
                warn!(
                    "The hash type should be from the hash-algorithm-ov open vocabulary values: MD5, SHA-1, SHA-256, SHA-512, SHA3-256, SHA3-512, SSDEEP, TLSH. Hash type '{}' does not match the vocabulary, including case and hyphen.", origin_hash_type
                );
            }
            // sha-256 and sha3-256 have same format and identyhash crate treats them the same
            if (origin_hash_type == *LegalHashTypes::SHA256.as_ref()
                || origin_hash_type == *LegalHashTypes::SHA3256.as_ref())
                && hash_type_identity != *LegalHashTypes::SHA256.as_ref()
            {
                return Err(Error::InvalidHash {
                    hash_type: origin_hash_type,
                    hash_identity: hash_type_identity,
                    hash_string: origin_hash_str.to_string(),
                });
            }
            // sha-512 and sha3-512 have same format and identyhash crate treats them the same
            if (origin_hash_type == *LegalHashTypes::SHA512.as_ref()
                || origin_hash_type == *LegalHashTypes::SHA3512.as_ref())
                && hash_type_identity != *LegalHashTypes::SHA512.as_ref()
            {
                return Err(Error::InvalidHash {
                    hash_type: origin_hash_type,
                    hash_identity: hash_type_identity,
                    hash_string: origin_hash_str.to_string(),
                });
            }
            if origin_hash_type == *LegalHashTypes::SSDEEP.as_ref()
                && !ssdeep_re.is_match(origin_hash_str)
            {
                return Err(Error::InvalidHash {
                    hash_type: origin_hash_type,
                    hash_identity: hash_type_identity,
                    hash_string: origin_hash_str.to_string(),
                });
            }
            if origin_hash_type == *LegalHashTypes::TLSH.as_ref() {
                //mimic identyhash crate
                if !origin_hash_str.len() != 70
                    && !origin_hash_str.chars().all(|c| c.is_ascii_hexdigit())
                {
                    return Err(Error::InvalidHash {
                        hash_type: origin_hash_type,
                        hash_identity: hash_type_identity,
                        hash_string: origin_hash_str.to_string(),
                    });
                }
            }
            if (origin_hash_type == *LegalHashTypes::SHA1.as_ref()
                || origin_hash_type == *LegalHashTypes::MD5.as_ref())
                && hash_type_identity != origin_hash_type
            {
                return Err(Error::InvalidHash {
                    hash_type: origin_hash_type,
                    hash_identity: hash_type_identity,
                    hash_string: origin_hash_str.to_string(),
                });
            }
        }
        Ok(())
    }
}

/// An external reference that describes pointers to information outside STIX.
///
/// A reference can be described by one or more of a human readable description, a URL, or an external id.
/// At least one of these three must be present in an external reference.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_72bcfr3t79jx>
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalReference {
    /// The name of the source that this external-reference is defined within (system, registry, organization, etc.).
    source_name: String,
    /// A human readable description.
    description: Option<String>,
    /// A URL reference to an external resource with its hashes, if any.
    #[serde(flatten)]
    url: Option<ReferenceUrl>,
    /// An identifier for the external reference content.
    external_id: Option<String>,
}

impl ExternalReference {
    /// Creates a new external reference with at least one describing field
    pub fn new(
        source_name: &str,
        description: Option<String>,
        url: Option<ReferenceUrl>,
        external_id: Option<String>,
    ) -> Result<Self, Error> {
        if description.is_none() && url.is_none() && external_id.is_none() {
            Err(Error::ValidationError(format!("External reference {} needs at least one of a description, a URL, or an external ID.", source_name)))
        } else {
            Ok(Self {
                source_name: source_name.to_string(),
                description,
                url,
                external_id,
            })
        }
    }
}

impl Stix for ExternalReference {
    fn stix_check(&self) -> Result<(), Error> {
        if let Some(url) = &self.url {
            url.stix_check()?;
        }
        Ok(())
    }
}

///The `granular-marking` type defines how the `marking-definition` object referenced by the `marking_ref` property or a language specified by the `lang` property applies to a set of
/// content identified by the list of selectors in the selectors property.
///
/// One *and only one* of the `marking_ref` and `lang` properties **MUST** be present.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_robezi5egfdr>
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GranularMarking {
    /// The lang property identifies the language of the text identified by this marking.
    ///
    /// The value of the lang property, if present, **MUST be an RFC5646 language code.
    pub lang: Option<String>,
    /// The marking_ref property specifies the ID of the marking-definition object that describes the marking.
    pub marking_ref: Option<Identifier>,
    /// The selectors property specifies a list of selectors for content contained within the STIX Object in which this property appears
    pub selectors: Vec<String>,
}

impl Stix for GranularMarking {
    fn stix_check(&self) -> Result<(), Error> {
        if self.marking_ref.is_some() && self.lang.is_some() {
            return Err(Error::ValidationError("marking_ref and lang".to_string()));
        }

        if let Some(marking_ref) = &self.marking_ref {
            if marking_ref.get_type() != "marking-definition" {
                return Err(Error::ValidationError(
                    "referenced id must be a marking definition".to_string(),
                ));
            }
        } else if let Some(ref language) = self.lang {
            match LanguageTag::parse(language) {
                Ok(tag) => if let Err(e) = LanguageTag::validate(&tag) {
                    return Err(Error::ValidationError(format!("A language granular marking has a `lang` of {}. A `lang` must conform to RFC5646. Details: {}",
                    language,
                    e
                )));
                }
                Err(e) => return Err(Error::ValidationError(format!("A language granular marking has a `lang` of {}. A `lang` must conform to RFC5646. Details: {}",
                    language,
                    e
                ))),
            }
        } else {
            return Err(Error::ValidationError(
                "A granular marking must have one and only one of a `marking _ref` or a `lang`"
                    .to_string(),
            ));
        }

        //TODO: Add validation for selectors

        Ok(())
    }
}

/// A URL with one or more hashes for the contents of the URL.
///
/// It is possible to create a URL without any hashes, but STIX 2.1 recommends against it
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceUrl {
    /// The URL itself
    url: Url,
    /// Specifies a dictionary of hashes for the contents of the url. This should be provided when the url property is present.
    ///
    /// The keys must come from one of the entries listed in the hash-algorithm-ov open vocabulary.
    /// A SHA-256 hash SHOULD be included whenever possible.
    hashes: Option<Hashes>,
}

impl ReferenceUrl {
    /// Creates an external reference URL from a provided URL string and an optional but recommended list of hashes
    pub fn new(raw_url: &str, hashes: Option<Hashes>) -> Result<Self, Error> {
        let url =
            Url::parse(raw_url).map_err(|e| Error::ValidationError(format!("invalid URL: {e}")))?;

        if hashes.is_none() {
            warn!("An external reference URL should always come with a dictionary of hashes")
        };
        Ok(Self { url, hashes })
    }

    pub fn get_url(&self) -> &Url {
        &self.url
    }
}

impl Stix for ReferenceUrl {
    /// Verifies the hash type is correct for Reference Url
    fn stix_check(&self) -> Result<(), Error> {
        if let Some(hashes) = &self.hashes {
            hashes.stix_check()?;
        }
        Ok(())
    }
}

/// Refers to the valid hash algorithms like MD5, SHA-1, and SHA-256 used for file identification.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter, Serialize, Deserialize)]
pub enum LegalHashTypes {
    #[strum(serialize = "md5")]
    MD5,
    #[strum(serialize = "sha-1")]
    SHA1,
    #[strum(serialize = "sha-256")]
    SHA256,
    #[strum(serialize = "sha-512")]
    SHA512,
    #[strum(serialize = "sha3-256")]
    SHA3256,
    #[strum(serialize = "sha3-512")]
    SHA3512,
    #[strum(serialize = "ssdeep")]
    SSDEEP,
    #[strum(serialize = "tlsh")]
    TLSH,
}

/// A STIX 2.1 compliant identifier that uniquely identifies a STIX Object.
///
/// It consists of two parts, the object-type and a UUID.
/// The object type must exactly match the type property of the object being identified or referenced.
/// The UUID is either an RFC 9562 compliant UUIDv4 or UUIDv5.
/// The latter is used only for Cyber-observable objects. All other objects use UUIDv4
///
/// `Identifier` `impl`'s `Display` and `FromStr`, and its String representation is {object-type}--{UUID}
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_64yvzeku5a5c>
#[derive(Clone, Debug, PartialEq, Eq, SerializeDisplay, Default, DeserializeFromStr)]
pub struct Identifier {
    /// The object type
    object_type: String,
    /// The UUID
    uuid: Uuid,
}

impl Identifier {
    /// Create a UUIDv4 identifier, used for any Stix Object that is not a Cyber-observable object
    pub fn new(object_type: &str) -> Result<Self, Error> {
        check_object_type(object_type)?;

        Ok(Self {
            object_type: stix_case(object_type),
            uuid: Uuid::new_v4(),
        })
    }

    /// Create a UUIDv5 identifier using the STIX 2.1 preferred namespace, used ONLY for Cyber-observable Objects
    /// The value of the name portion should be the list of "ID Contributing Properties" (property-name and property value pairs), as defined on each object.
    pub fn new_v5<T: Serialize>(
        object_type: &str,
        contributing_properties: &HashMap<String, T>,
    ) -> Result<Self, Error> {
        check_object_type(object_type)?;

        // PANIC: This function is safe to unwrap, as the provided namespace String is a valid hexidecimal string represenation of a UUID
        let namespace = Uuid::parse_str("00abedb4-aa42-466c-9c01-fed23315a9b7").unwrap();
        let names = json_canon::to_vec(contributing_properties)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;

        Ok(Self {
            object_type: stix_case(object_type),
            uuid: Uuid::new_v5(&namespace, &names),
        })
    }

    /// Returns the object-type of the identifier
    pub fn get_type(&self) -> &str {
        &self.object_type
    }

    /// Return the UUID version of the idetifier's UUID
    /// Only UUIDv4 and UUIDv5 are supported by STIX 2.1, so any other version is labeled as unsupported
    #[cfg(test)]
    pub fn get_uuid_version(&self) -> &str {
        match &self.uuid.get_version() {
            Some(Version::Random) => "UUIDv4",
            Some(Version::Sha1) => "UUIDv5",
            Some(_) => "Unsupported UUID version",
            None => "Could not determine UUID version",
        }
    }

    /// Creates a dummy identifier without a randomly generated UUID
    #[cfg(test)]
    pub fn new_test(object_type: &str) -> Self {
        Self {
            object_type: stix_case(object_type),
            uuid: uuid!("cc7fa653-c35f-43db-afdd-dce4c3a241d5"),
        }
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}--{}", self.object_type, self.uuid)
    }
}

impl str::FromStr for Identifier {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (object_type, raw_uuid) = s
            .split_once("--")
            .ok_or(Error::ParseIdentifierError(s.to_string()))?;

        let object_type_fromstr = stix_case(object_type);
        let uuid_fromstr =
            Uuid::from_str(raw_uuid).map_err(|_| Error::ParseIdentifierError(s.to_string()))?;

        Ok(Identifier {
            object_type: object_type_fromstr,
            uuid: uuid_fromstr,
        })
    }
}

impl Stix for Identifier {
    fn stix_check(&self) -> Result<(), Error> {
        check_object_type(self.get_type())?;

        //Check UUID version
        match &self.uuid.get_version() {
            Some(Version::Random) => {
                if ScoTypes::iter().any(|x| x.as_ref() == stix_case(self.get_type())) {
                    warn!("SCOs **SHOULD** use UUIDv5 in their id's, unless no ID contributing properties could be found")
                }
            }
            Some(Version::Sha1) => {
                if !ScoTypes::iter().any(|x| x.as_ref() == stix_case(self.get_type())) {
                    return Err(Error::InvalidUuid {
                        message:
                            "STIX Objects other than SCOs **MUST** only use UUIDv4's in their id's"
                                .to_string(),
                    });
                }
            }
            Some(_) => {
                return Err(Error::InvalidUuid { message: "STIX does not support UUID versions other than UUIDv4 and UUIDv5 (for SCOs) in object id's".to_string() });
            }
            None => {
                return Err(Error::InvalidUuid {
                    message: "This object's id is not a valid UUID of known type".to_string(),
                });
            }
        }

        Ok(())
    }
}

/// Check that a given object type is a valid STIX object type
fn check_object_type(object_type: &str) -> Result<(), Error> {
    if object_type
        .chars()
        .all(|c| char::is_lowercase(c) || char::is_numeric(c) || c == '-')
    {
        Ok(())
    } else {
        Err(Error::ParseIdentifierError(object_type.to_string()))
    }
}

/// A trait for objects that have an identifier, providing a method to access it.
pub trait Identified {
    fn get_id(&self) -> &Identifier;
}

///Function to get the value of a struct's field given the field name
// Function to get the value of a struct's field given the field name as a &str by serializing the struct then looking for the field name as a key
// Requires that the struct being checked be serializable and the field property be deserializable
//
// Taken from an idea originated by David Tolnay (dtolnay@gmail.com) at https://users.rust-lang.org/t/access-struct-attributes-by-string/17520/2
pub fn get_field_by_name<T, R>(data: T, field: &str) -> Result<Option<R>, Error>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let mut map = match serde_value::to_value(data) {
        Ok(Value::Map(map)) => map,
        _ => {
            return Err(Error::SerializationError(
                "Could not serialize struct for field checking".to_string(),
            ))
        }
    };

    let key = Value::String(field.to_owned());
    let value = match map.remove(&key) {
        Some(value) => value,
        // Key not found in struct
        None => return Ok(None),
    };

    match R::deserialize(value) {
        Ok(r) => Ok(Some(r)),
        Err(e) => Err(Error::DeserializationError(format!(
            "Could not deserialize value of field checked to correct type: {}",
            e
        ))),
    }
}

/// Represents a phase in a kill-chain, i.e. one of the phases an attacker may undertake to achieve their objective.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_i4tjv75ce50h>
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillChainPhase {
    /// The name of the kill chain.
    /// This should be all lowercase and should use hyphens instead of spaces or underscores as word separators.
    kill_chain_name: String,
    /// The name of the phase in the kill chain.
    /// This should be all lowercase and should use hyphens instead of spaces or underscores as word separators.
    phase_name: String,
}

impl KillChainPhase {
    /// Creates a new kill-chain phase
    /// When referencing the Lockcheed Martin Cyber Kill Chain, the kill_chain field must be "lockheed-martin-cyber-kill-chain"
    pub fn new(kill_chain: &str, phase: &str) -> Self {
        Self {
            kill_chain_name: kill_chain.to_string(),
            phase_name: phase.to_string(),
        }
    }
}

/// kill_chain_name: (required)  string  The name of the kill chain. The value of this property SHOULD be all lowercase and SHOULD use hyphens instead of spaces or underscores as word separators.
/// phase_name: (required)   string  The name of the phase in the kill chain. The value of this property SHOULD be all lowercase and SHOULD use hyphens instead of spaces or underscores as word separators.
impl Stix for KillChainPhase {
    fn stix_check(&self) -> Result<(), Error> {
        fn validate_string(kcp_string: &str, string_label: &str) -> Result<(), Error> {
            if kcp_string.contains(' ') || kcp_string.contains('_') {
                return Err(Error::ValidationError(format!(
                    "{} {} contains spaces or underscores.",
                    string_label, kcp_string
                )));
            }

            if kcp_string.split('-').any(|word| word.is_empty()) {
                return Err(Error::ValidationError(format!(
                    "{} {} contains consecutive hyphens or starts/ends with a hyphen.",
                    string_label, kcp_string
                )));
            }

            if !kcp_string.chars().all(|c| c.is_lowercase() || c == '-') {
                return Err(Error::ValidationError(format!("{} {} contains invalid characters, should be lowercase and separate words by a dash/hyphen.", string_label, kcp_string)));
            }

            Ok(())
        }

        let kill_chain_name = &self.kill_chain_name;
        let phase_name = &self.phase_name;

        validate_string(kill_chain_name, "kill_chain_name")?;
        validate_string(phase_name, "phase_name")?;

        Ok(())
    }
}

/// A custom Timestamp struct that holds a `jiff::Timestamp`.
///
/// We use this custom type because while `Timestamp` is RFC 3339 compliant, its deserializtion is *more* generous
/// than the STIX 2.1 timestamp formatting rules.
/// A timestamp will not deserialize unless it is in the format `YYYY-MM-DDTHH:mm:ss[.s+]Z` and is not in a timezone other than UTC.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ksbm2nost85y>
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(pub JiffTimestamp);

impl Timestamp {
    pub fn now() -> Self {
        Self(JiffTimestamp::now())
    }

    pub fn new(timestamp_str: &str) -> Result<Self, Error> {
        // STIX 2.1 has a stricter standard for valid timestamps than the `jiff`` crate we use.
        // Before parsing a given timestamp string, check that it matches the STIX pattern.
        //
        // Panic: Safe to unwrap because this is a valid regex pattern
        let re = Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(.\d+)?Z$").unwrap();
        if re.is_match(timestamp_str).not() {
            return Err(Error::ParseTimestampError(timestamp_str.to_string()));
        }

        let timestamp = JiffTimestamp::from_str(timestamp_str).map_err(Error::DateTimeError)?;
        Ok(Self(timestamp))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Most of the custom `impl` of `serde:Seriazlie and serde:Deserialize` are taken from `jiff::Timestamp`'s `imp` of `Deserialize`
impl serde::Serialize for Timestamp {
    #[inline]
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Timestamp {
    #[inline]
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Timestamp, D::Error> {
        use serde::de;

        struct TimestampVisitor;

        impl de::Visitor<'_> for TimestampVisitor {
            type Value = Timestamp;

            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("a timestamp string in STIX 2.1 format")
            }

            #[inline]
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Timestamp, E> {
                // STIX 2.1 has a stricter standard for valid timestamps than the `jiff`` crate we use.
                // Before parsing a given timestamp string, check that it matches the STIX pattern.
                //
                // Panic: Safe to unwrap because this is a valid regex string
                let re = Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(.\d+)?Z$").unwrap();
                if !re.is_match(value) {
                    return Err(de::Error::custom(format!(
                        "Could not parse timestamp {} as a valid STIX 2.1 Timestamp",
                        value
                    )));
                }
                // If the pattern matches, parse the string as a `jiff::Timestamp` and insert it into our custom Timestamp struct
                let ts: JiffTimestamp = value.parse().map_err(de::Error::custom)?;
                Ok(Timestamp(ts))
            }
        }

        deserializer.deserialize_str(TimestampVisitor)
    }
}

impl Stix for Timestamp {
    fn stix_check(&self) -> Result<(), Error> {
        // If a Timestamp has already been parsed from a string, then we have already checked that is a valid STIX Timestamp
        Ok(())
    }
}

/// The Extensions Type enumeration used in the Extension SMO and the `extensions` common property.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, AsRefStr, EnumIter, EnumString)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum ExtensionType {
    /// Specifies that the Extension includes a new SDO.
    NewSdo,
    /// Specifies that the Extension includes a new SCO.
    NewSco,
    /// Specifies that the Extension includes a new SRO.
    NewSro,
    /// Specifies that the Extension includes additional properties for a given STIX Object.
    PropertyExtension,
    /// Specifies that the Extension includes additional properties for a given STIX Object at the *top-level*.
    ///
    /// Organizations are encouraged to use the `property-extension` instead of this extension type.
    ToplevelPropertyExtension,
}

/// A list of all STIX Domain Objects (SDO) types found in the STIX 2.1 standard.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum SdoTypes {
    AttackPattern,
    Campaign,
    CourseOfAction,
    Grouping,
    Identity,
    Incident,
    Indicator,
    Infrastructure,
    IntrustionSet,
    Location,
    Malware,
    MalwareAnalysis,
    Note,
    ObservedData,
    Report,
    ThreatActor,
    Tool,
    Vulnerability,
}

/// A list of all STIX Cyber Observable Object (SCO) types found in the STIX 2.1 standard.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum ScoTypes {
    Artifact,
    AutonomousSystem,
    Directory,
    DomainName,
    EmailAddress,
    EmailMessage,
    EmailMimePartType,
    File,
    Ipv4Addr,
    Ipv6Addr,
    MacAddr,
    Mutex,
    NetworkTraffic,
    Process,
    Software,
    Url,
    UserAccount,
    WindowsRegistryKey,
    X509Certificate,
}

/// A list of all STIX Relationship Object (SRO) types found in the STIX 2.1 standard.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum SroTypes {
    Relationship,
    Sighting,
}

/// A list of all STIX Meta Object (SMO) types found in the STIX 2.1 standard.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum StixMetaTypes {
    LanguageContent,
    MarkingDefinition,
    ExtensionDefinition,
}

/// Function to return the STIX Object type associated with the "type" value, or return "custom" if the type is not recognized
pub fn get_object_type(sub_type: &str) -> String {
    if SdoTypes::iter().any(|s| s.as_ref() == sub_type.to_case(Case::Kebab)) {
        "sdo".to_string()
    } else if ScoTypes::iter().any(|s| s.as_ref() == sub_type.to_case(Case::Kebab)) {
        "sco".to_string()
    } else if SroTypes::iter().any(|s| s.as_ref() == sub_type.to_case(Case::Kebab)) {
        "sro".to_string()
    } else if StixMetaTypes::iter().any(|s| s.as_ref() == sub_type.to_case(Case::Kebab)) {
        sub_type.to_case(Case::Kebab).to_string()
    } else {
        "custom".to_string()
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use crate::types::{get_object_type, stix_case, JiffTimestamp, Timestamp};

    #[derive(Debug, PartialEq, Eq, Deserialize)]
    struct ExampleObject {
        created: Timestamp,
    }

    #[test]
    fn deserialize_valid_timestamp() {
        let json = r#"{
            "created": "2016-01-20T12:31:12.123Z"
        }"#;
        let result: ExampleObject = serde_json::from_str(json).unwrap();
        let ts: JiffTimestamp = "2016-01-20T12:31:12.123Z".parse().unwrap();
        let expected = ExampleObject {
            created: Timestamp(ts),
        };
        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_timestamp_with_space() {
        // The timestamp string should correctly parse as a jiff::Timestamp, without our extra deserializer
        let valid_ts: Result<JiffTimestamp, jiff::Error> = "2016-01-20 12:31:12.123Z".parse();
        assert!(valid_ts.is_ok());

        let json = r#"{
            "created": "2016-01-20 12:31:12.123Z"
        }"#;
        let result: Result<ExampleObject, serde_json::Error> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_timestamp_with_offset() {
        // The timestamp string should correctly parse as a jiff::Timestamp, without our extra deserializer
        let valid_ts: Result<JiffTimestamp, jiff::Error> = "2016-01-20T12:31:12.123+05".parse();
        assert!(valid_ts.is_ok());

        let json = r#"{
            "created": "2016-01-20T12:31:12.123+05"
        }"#;
        let result: Result<ExampleObject, serde_json::Error> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn get_sdo_from_type() {
        let sub_type = "AttackPattern";
        let result = get_object_type(sub_type);
        assert_eq!(&result, "sdo");
    }

    #[test]
    fn get_smo_from_type() {
        let sub_type = "extension_definition";
        let result = get_object_type(sub_type);
        assert_eq!(&result, "extension-definition");
    }

    #[test]
    fn get_smo_marking_from_type() {
        let sub_type = "marking_definition";
        let result = get_object_type(sub_type);
        assert_eq!(&result, "marking-definition");
    }

    #[test]
    fn get_custom_from_type() {
        let sub_type = "foo";
        let result = get_object_type(sub_type);
        assert_eq!(&result, "custom");
    }

    #[test]
    fn convert_case() {
        let raw_str = "Ipv4Addr";
        let result = stix_case(raw_str);
        assert_eq!(&result, "ipv4-addr");
    }
}
