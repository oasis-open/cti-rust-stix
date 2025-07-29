//! Contains the implementation logic for STIX Bundles

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::{
    base::Stix,
    error::{add_error, return_multiple_errors, StixError as Error},
    object::StixObject,
    types::{Identified, Identifier},
};

/// A Bundle is a collection of arbitrary STIX Objects grouped together in a single container.
///
/// A Bundle does not have any semantic meaning and the objects contained within the Bundle are not considered related by virtue of being in the same Bundle.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_gms872kuzdmg>
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    /// The type property identifies the type of object.
    ///
    /// The value of this property **MUST** be bundle.
    #[serde(rename = "type")]
    pub object_type: String,
    /// An identifier for this Bundle
    id: Identifier,
    /// Specifies a set of one or more STIX Objects.
    ///
    /// Objects in this list **MUST** be a STIX Object.
    #[serde(deserialize_with = "deserialize_bundle_objects")]
    objects: Vec<StixObject>,
}

impl Bundle {
    /// Construct a new STIX bundle, starting with an initial STIX object (because Lists in STIX 2.1 cannot be empty)
    pub fn new(object: StixObject) -> Self {
        // Panic: Safe to unwrap becuse "bundle" is valid STIX object type
        Self {
            object_type: "bundle".to_string(),
            id: Identifier::new("bundle").unwrap(),
            objects: vec![object],
        }
    }

    /// Add an additional STIX object to an existing Stix bundle   
    pub fn add(&mut self, object: StixObject) {
        self.objects.push(object);
    }

    /// Deserialize a bundle from a JSON String and validate the contents of the bundle
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let bundle: Self =
            serde_json::from_str(json).map_err(|e| Error::DeserializationError(e.to_string()))?;
        bundle.stix_check()?;

        Ok(bundle)
    }

    /// Return a list of all objects in the bundle
    pub fn get_objects(&self) -> Vec<StixObject> {
        self.objects.clone()
    }
}

impl Identified for Bundle {
    fn get_id(&self) -> &Identifier {
        &self.id
    }
}

impl Stix for Bundle {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Bundles must be of type "bundle"
        if &self.object_type != "bundle" {
            errors.push(Error::ValidationError(format!(
                "STIX bundles must have a `type` of 'bundle'. Bundle {} has a type of {}",
                self.id, self.object_type
            )));
        }

        // Validate the id
        add_error(&mut errors, self.id.stix_check());

        // Validate all contained objects
        for object in self.objects.iter() {
            add_error(&mut errors, object.stix_check());
        }

        return_multiple_errors(errors)
    }
}

/// Custom deserializer function for a `Vec<StixObject>` to make sure each StixObject is deserialized into the correct object type
fn deserialize_bundle_objects<'de, D>(deserializer: D) -> Result<Vec<StixObject>, D::Error>
where
    D: Deserializer<'de>,
{
    let values: Vec<Value> = Vec::deserialize(deserializer)?;

    let mut objects = Vec::new();

    for raw_object in values {
        let object = StixObject::from_json(
            &serde_json::to_string(&raw_object).map_err(serde::de::Error::custom)?,
            true,
        )
        .map_err(serde::de::Error::custom)?;
        objects.push(object);
    }

    Ok(objects)
}

#[cfg(test)]
mod test {
    use crate::{
        bundles::Bundle,
        domain_objects::sdo::{DomainObjectBuilder, DomainObjectType},
        object::StixObject,
    };

    #[test]
    fn deserialize_bundle() {
        let json = r#"{
            "type": "bundle",
            "id": "bundle--5d0092c5-5f74-4287-9642-33f4c354e56d",
            "objects": [
                {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
                "created": "2016-04-29T14:09:00.000Z",
                "modified": "2016-04-29T14:09:00.000Z",
                "object_marking_refs": ["marking-definition--089a6ecb-cc15-43cc-9494-767639779123"],
                "name": "Poison Ivy Malware",
                "description": "This file is part of Poison Ivy",
                "pattern": "[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']",
                "pattern_type": "stix",
                "valid_from": "2016-01-01T00:00:00Z"
                }
            ]
        }"#;

        let bundle = Bundle::from_json(json).unwrap();
        let objects = bundle.get_objects();
        let object = &objects[0];

        assert_eq!(object.get_type(), "indicator");

        let StixObject::Sdo(sdo) = object else {
            panic!()
        };
        let DomainObjectType::Indicator(indicator) = &sdo.object_type else {
            panic!()
        };
        assert_eq!(indicator.name.as_ref().unwrap(), "Poison Ivy Malware");
    }

    #[test]
    fn construct_bundle() {
        let sdo = DomainObjectBuilder::new("indicator")
            .unwrap()
            .name("Indicator".to_string())
            .unwrap()
            .description(
                "This indicator detects connections to a known malicious IP address".to_string(),
            )
            .unwrap()
            .indicator_types(vec!["malicious-activity".to_string()])
            .unwrap()
            .pattern("[domain-name:value = 'example.com']".to_string())
            .unwrap()
            .pattern_type("stix".to_string())
            .unwrap()
            .valid_from("2016-05-12T08:17:27.000Z")
            .unwrap()
            .valid_until("2023-10-05T10:00:00.000Z")
            .unwrap()
            .build()
            .unwrap();

        let bundle = Bundle::new(StixObject::Sdo(sdo));

        let object = &bundle.get_objects()[0];
        let StixObject::Sdo(sdo) = object else {
            panic!()
        };
        let DomainObjectType::Indicator(indicator) = &sdo.object_type else {
            panic!()
        };
        assert_eq!(indicator.name.as_ref().unwrap(), "Indicator");
    }
}
