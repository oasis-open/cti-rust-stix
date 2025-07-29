//! A custom STIX Error type, with its associated functions.
use std::num::ParseIntError;

use jiff::Error as JiffError;
use strum::ParseError;
use thiserror::Error;

use crate::types::Identifier;

/// Custom Error type for rust-stix
#[derive(Debug, Clone, Error)]
pub enum StixError {
    // For retunning multiple errors at once, e.g. during validation
    #[error("Multiple errors: {0:?}")]
    MultipleErrors(Vec<StixError>),
    // Basic parsing or validation errors
    #[error("DateTime error: {0}")]
    DateTimeError(JiffError),
    #[error("Empty lists and dictionaries are prohibted in STIX")]
    EmptyList,
    #[error("The corresponding hash string for this value MUST be a valid {hash_type} message, and it is: {hash_identity} {hash_string}")]
    InvalidHash {
        hash_type: String,
        hash_identity: String,
        hash_string: String,
    },
    #[error("Invalid UUID in object id: {message}")]
    InvalidUuid { message: String },
    #[error("{object} of type {object_type} do not have a '{field}' field.")]
    IllegalBuilderProperty {
        object: String,
        object_type: String,
        field: String,
    },
    #[error("A Relationship Object of type {relationship} cannot exist from a {source_type} to a {target_type}")]
    InvalidRelationship {
        relationship: String,
        source_type: String,
        target_type: String,
    },
    #[error("Object of type {object_type} must have the '{property}' property set.")]
    MissingBuilderProperty {
        object_type: String,
        property: String,
    },
    #[error("Could not parse String {0} as a valid hex")]
    ParseHexError(String),
    #[error("Could not parse String {0} as a valid STIX 2.1 Identifier")]
    ParseIdentifierError(String),
    #[error("Error parsing integer: {0}")]
    ParseIntegerError(ParseIntError),
    #[error("Could not parse timestamp {0} as a valid STIX 2.1 Timestamp")]
    ParseTimestampError(String),
    #[error("Failed to parse STIX Pattern {0}: {1}")]
    ParsePatternError(String, String),
    // General validation error
    #[error("STIX validation error: {0}")]
    ValidationError(String),
    // Extension errors
    #[error("Extension key is not a known predefined extension")]
    UnknownExtension,
    #[error("Wrong extension type for object")]
    WrongExtension,
    // Versioning errors
    #[error("Cannot version this object: {0}")]
    UnableToVersion(String),
    #[error("{0} is not valid version timestamp: {1}")]
    BadVersion(String, JiffError),
    // Customization errors
    #[error("Custom objects must have an extension with an appropriate new_object extension type")]
    CustomMissingExtension,
    // (De)serialization and JSON parsing related errors
    #[error("JSON nulls are not allowed in STIX 2.1")]
    JsonNull,
    #[error("Unexpected JSON format")]
    UnexpectedJsonFormat,
    #[error("Unknown fields in JSON: {0:?}")]
    UnknownFields(Vec<String>),
    #[error("Unrecognized STIX Object or Object Type")]
    UnrecognizedObject(ParseError),
    // `serde_json:Error`s are converted to Strings during error mapping because that Error type does not `impl Clone`
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    // Datastore errors
    #[error("Data source not found")]
    MissingDataSource,
    #[error("Data sink not found")]
    MissingDataSink,
    #[error("Data type {0} is not supported in rust-stix")]
    UnsupportedDataType(String),
    // Filesystem access errors
    #[error("File I/O error: {0}")]
    IoError(String),
    #[error("File {0} not found")]
    PathNotFound(String),
    #[error("Object {0} not in filesystem")]
    ObjectNotFound(Identifier),
}

/// Checks a Result to see if it is an Error. If it is, add that Error to a Vec of StixErrors
pub fn add_error<T>(errors: &mut Vec<StixError>, possible_error: Result<T, StixError>) {
    if let Err(error) = possible_error {
        errors.push(error)
    };
}

/// Return a Vec of StixErrors as a single Error, unless the Vec is empty
///
/// This is useful when checking multiple possible sources of error, such as during STIX validation
pub fn return_multiple_errors(errors: Vec<StixError>) -> Result<(), StixError> {
    if errors.is_empty() {
        return Ok(());
    }
    // If there is only one Error in the Vec, return it as itself
    if errors.len() == 1 {
        return Err(errors[0].clone());
    }
    Err(StixError::MultipleErrors(errors))
}
