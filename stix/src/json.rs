//! Functions for deserializing STIX objects from JSON strings.

use crate::{error::StixError as Error, types::get_object_type};
use serde::Serialize;
use serde_json::Value;

/// Compares fields of a deserialized struct with a JSON string, returning an error for unknown fields.
// Function that takes any *already deserialized* struct and a JSON String and compares the fields in both values.
// If any fields are unknown it errors
// Note: A fully initalized struct is necessary to do this comparision, which is why this function is called after
// deserialization as a check that returns an error as a validation check.
pub fn field_check<T: Serialize>(s: &T, json_str: &str) -> Result<(), Error> {
    // Deserialize the JSON again as a generic JSON Value and get its keys
    let json_value: Value =
        serde_json::from_str(json_str).map_err(|e| Error::DeserializationError(e.to_string()))?;
    let json_keys: Vec<String> = match &json_value {
        Value::Object(map) => map.keys().cloned().collect(),
        _ => return Err(Error::UnexpectedJsonFormat),
    };

    // Compare the keys of the JSON String to the keys of the provided struct after re-serializing it
    let keys = get_keys(s).map_err(|e| Error::SerializationError(e.to_string()))?;
    let unknown_fields = find_differences(&json_keys, &keys);

    // If there are any keys in the JSON String not in the struct, return an error
    if unknown_fields.is_empty() {
        Ok(())
    } else {
        Err(Error::UnknownFields(unknown_fields))
    }
}

/// Function to get the keys of any serializable struct passed in
pub fn get_keys<T: Serialize>(s: &T) -> Result<Vec<String>, serde_json::Error> {
    let serialized = serde_json::to_value(s)?;
    if let Value::Object(map) = serialized {
        Ok(map.keys().cloned().collect())
    } else {
        Ok(vec![])
    }
}

/// Function to find differences in two vectors.
pub fn find_differences(vec1: &[String], vec2: &[String]) -> Vec<String> {
    let unknown_fields: Vec<String> = vec1
        .iter()
        .filter(|item| !vec2.contains(item))
        .cloned()
        .collect();

    unknown_fields
}

/// Function to get the STIX object type from a generic STIX object JSON by matching the given type
///
/// If the type is not recognized, the object is considered to be a "custom" STIX object, with any number of possible unrecognized fields
pub fn get_object_type_from_json(json_str: &str) -> Result<String, Error> {
    // Deserialize the JSON string to a generic JSON value
    let json_value: Value =
        serde_json::from_str(json_str).map_err(|e| Error::DeserializationError(e.to_string()))?;

    // Confirm that the JSON has "type" and "id" fields
    let (Some(sub_type), true) = (json_value.get("type"), json_value.get("id").is_some()) else {
        return Err(Error::UnexpectedJsonFormat);
    };

    // Return the STIX Object type associated with the "type" value, or return "custom" if the type is not recognized
    Ok(get_object_type(sub_type.to_string().trim_matches('\"')))
}

#[cfg(test)]
mod tests {
    use crate::json::*;

    #[test]
    fn get_sdo_from_json() {
        let json_str = r#"{
            "type": "identity",
            "name": "Identity",
            "identity_class": "individual",
            "description": "Responsible for managing personal digital identity",
            "roles": ["User", "Administrator"],
            "sectors": ["Technology","Aerospace"],
            "spec_version": "2.1",
            "contact_information": "alex.johnson@example.com",
            "id": "identity--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "external_references": [
                {
                    "source_name": "capec",
                    "external_id": "CAPEC-163"
                }
            ]
        }"#;
        let result = get_object_type_from_json(json_str).unwrap();

        assert_eq!(&result, "sdo");
    }
}
