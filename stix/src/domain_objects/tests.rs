#[cfg(test)]
mod test {
    use crate::{
        domain_objects::{
            sdo::{DomainObject, DomainObjectBuilder},
            vocab::OpinionType,
        },
        error::StixError as Error,
        relationship_objects::{Related, RelationshipObject},
        types::{
            DictionaryValue, ExternalReference, Hashes, Identified, Identifier, KillChainPhase,
            ReferenceUrl, StixDictionary, Timestamp,
        },
    };
    use log::warn;
    use serde_json::Value;
    use std::str::FromStr;
    use test_log::test;

    // Functions for editing otherwise un-editable fields, for testing only
    impl DomainObject {
        fn test_id(mut self) -> Self {
            let object_type = self.object_type.as_ref();
            self.common_properties.id = Identifier::new_test(object_type);
            self
        }

        fn created(mut self, datetime: &str) -> Self {
            self.common_properties.created = Some(Timestamp(datetime.parse().unwrap()));
            self
        }

        fn modified(mut self, datetime: &str) -> Self {
            self.common_properties.modified = Some(Timestamp(datetime.parse().unwrap()));
            self
        }
    }

    impl RelationshipObject {
        fn test_id(mut self) -> Self {
            let object_type = self.object_type.as_ref();
            self.common_properties.id = Identifier::new_test(object_type);
            self
        }

        fn created(mut self, datetime: &str) -> Self {
            self.common_properties.created = Some(Timestamp(datetime.parse().unwrap()));
            self
        }

        fn modified(mut self, datetime: &str) -> Self {
            self.common_properties.modified = Some(Timestamp(datetime.parse().unwrap()));
            self
        }
    }

    #[test]
    fn try_build_with_required_field() {
        let attack_pattern = DomainObjectBuilder::new("attack-pattern")
            .unwrap()
            .name("name".to_string())
            .unwrap()
            .build();

        assert!(attack_pattern.is_ok());
    }

    #[test]
    fn try_build_without_required_field() {
        let attack_pattern = DomainObjectBuilder::new("attack-pattern").unwrap().build();

        assert!(attack_pattern.is_err());
    }

    #[test]
    fn try_build_with_correct_creator_type() {
        let identity = DomainObjectBuilder::new("identity")
            .unwrap()
            .name("identity".to_string())
            .unwrap()
            .build()
            .unwrap();

        let attack_pattern = DomainObjectBuilder::new("attack-pattern")
            .unwrap()
            .name("pattern".to_string())
            .unwrap()
            .created_by_ref(identity.get_id().clone())
            .unwrap()
            .build();

        assert!(attack_pattern.is_ok());
    }

    #[test]
    fn try_build_with_wrong_creator_type() {
        let attack_pattern_1 = DomainObjectBuilder::new("attack-pattern")
            .unwrap()
            .name("pattern 1".to_string())
            .unwrap()
            .build()
            .unwrap();

        let attack_pattern_2 = DomainObjectBuilder::new("attack-pattern")
            .unwrap()
            .name("pattern 2".to_string())
            .unwrap()
            .created_by_ref(attack_pattern_1.get_id().clone())
            .unwrap()
            .build();

        assert!(attack_pattern_2.is_err());
    }

    #[test]
    fn kebab_case_test() {
        // This should not generate a warning that "Advanced" is not in the sophistication open-vocab
        let threat_actor_result = DomainObjectBuilder::new("threatActor")
            .unwrap()
            .name("Threat Actor Group".to_string())
            .unwrap()
            .sophistication("Advanced".to_string())
            .unwrap()
            .build();
        assert!(threat_actor_result.is_ok());
        let threat_actor = threat_actor_result.unwrap();
        let threat_actor_types = threat_actor.get_id().get_type();
        assert_eq!(threat_actor_types, "threat-actor");
    }

    #[test]
    fn version() {
        let attack_pattern_1 = DomainObjectBuilder::new("attack-pattern")
            .unwrap()
            .name("name".to_string())
            .unwrap()
            .build()
            .unwrap();

        let attack_pattern_2 = DomainObjectBuilder::version(&attack_pattern_1)
            .unwrap()
            .build()
            .unwrap();

        assert_ne!(
            attack_pattern_1.common_properties.modified,
            attack_pattern_2.common_properties.modified
        );
    }

    #[test]
    fn deserialize_with_excluded_common_property() {
        let json = r#"{
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27.000Z",
            "modified": "2016-05-12T08:17:27.000Z",
            "name": "Spear Phishing",
            "description": "...",
            "external_references": [
                {
                "source_name": "capec",
                "external_id": "CAPEC-163"
                }
            ],
            "defanged": "true",
            }"#;

        let result = DomainObject::from_json(json, false);

        assert!(result.is_err());
    }

    #[test]
    fn serialize_attack_pattern() {
        let attack_pattern =
            DomainObjectBuilder::new("attack-pattern")
                .unwrap()
                .name("Spear Phishing".to_string())
                .unwrap()
                .description("...".to_string())
                .unwrap()
                .external_references(vec![ExternalReference::new(
                "capec",
                None,
                Some(ReferenceUrl::new(
                    "https://foo-bar.com/foo",
                    Some(
                        Hashes::new(
                            "SHA-256",
                            "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b",
                        )
                        .unwrap(),
                    ),
                ).unwrap()),
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
                .build()
                .unwrap()
                // Change id, created, and modified fields for test matching
                .test_id()
                .created("2016-05-12T08:17:27.000Z")
                .modified("2016-05-12T08:17:27.000Z");

        let mut result = serde_json::to_string_pretty(&attack_pattern).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
        "type": "attack-pattern",
        "name": "Spear Phishing",
        "description": "...",
        "spec_version": "2.1",
        "id": "attack-pattern--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "external_references": [
        {
        "source_name": "capec",
        "url": "https://foo-bar.com/foo",
        "hashes": {
            "SHA-256": "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b"
        },
        "external_id": "CAPEC-163"
        }
        ]
        }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected)
    }

    #[test]
    fn deserialize_attack_pattern() {
        let json = r#"{
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": "attack-pattern--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27.000Z",
        "modified": "2016-05-12T08:17:27.000Z",
        "name": "Spear Phishing",
        "description": "...",
        "external_references": [
            {
            "source_name": "capec",
            "external_id": "CAPEC-163"
            }
        ]
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();

        let expected = DomainObjectBuilder::new("attack-pattern")
            .unwrap()
            .name("Spear Phishing".to_string())
            .unwrap()
            .description("...".to_string())
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        assert_eq!(result, expected);
    }

    #[test]
    fn serialize_campaign() {
        let campaign = DomainObjectBuilder::new("campaign")
            .unwrap()
            .name("Test_Campaign".to_string())
            .unwrap()
            .objective("Test_objective_property".to_string())
            .unwrap()
            .first_seen("2024-11-14T21:05:36.309596Z".to_string())
            .unwrap()
            .last_seen("2024-11-14T21:05:36.309596Z".to_string())
            .unwrap()
            .aliases(vec!["Test_Campaign2".to_string()])
            .unwrap()
            .description("description_test".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id()
            .created("2024-11-14T21:05:36.309596Z")
            .modified("2024-11-14T21:05:36.309596Z");
        let mut result = serde_json::to_string_pretty(&campaign).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
        "type": "campaign",
        "name": "Test_Campaign",
        "description": "description_test",
        "aliases":["Test_Campaign2"],
        "first_seen":"2024-11-14T21:05:36.309596Z",
        "last_seen":"2024-11-14T21:05:36.309596Z",
        "objective": "Test_objective_property",
        "spec_version": "2.1",
        "id": "campaign--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2024-11-14T21:05:36.309596Z",
        "modified": "2024-11-14T21:05:36.309596Z"
        }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected)
    }

    #[test]
    fn deserialize_campaign() {
        let json = r#"{
        "type": "campaign",
        "name": "Test_Campaign",
        "description": "description_test",
        "aliases":["Test_Campaign2"],
        "first_seen":"2024-11-14T21:05:36.309596Z",
        "last_seen":"2024-11-14T21:05:36.309596Z",
        "objective": "Test_objective_property",
        "spec_version": "2.1",
        "id": "campaign--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2024-11-14T21:05:36.309596Z",
        "modified": "2024-11-14T21:05:36.309596Z"
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();

        let expected = DomainObjectBuilder::new("campaign")
            .unwrap()
            .name("Test_Campaign".to_string())
            .unwrap()
            .objective("Test_objective_property".to_string())
            .unwrap()
            .first_seen("2024-11-14T21:05:36.309596Z".to_string())
            .unwrap()
            .last_seen("2024-11-14T21:05:36.309596Z".to_string())
            .unwrap()
            .aliases(vec!["Test_Campaign2".to_string()])
            .unwrap()
            .description("description_test".to_string())
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2024-11-14T21:05:36.309596Z")
            .modified("2024-11-14T21:05:36.309596Z");

        assert_eq!(result, expected);
    }

    #[test]
    //checks if the first_seen, last seen check is functioning properly
    fn deserialize_campaign_invalid() {
        let json = r#"{
        "type": "campaign",
        "name": "Test_Campaign",
        "first_seen":"2024-11-14T21:05:36.309596Z",
        "last_seen":"2023-11-14T21:05:36.309596Z",
        "spec_version": "2.1",
        "id": "campaign--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2024-11-14T21:05:36.309596Z",
        "modified": "2024-11-14T21:05:36.309596Z"
        }"#;

        let result = DomainObject::from_json(json, false);

        assert!(result.is_err());
    }

    #[test]
    fn serialize_course_of_action() {
        let course_of_action = DomainObjectBuilder::new("course-of-action")
            .unwrap()
            .name("Add TCP port 80 Filter Rule to the existing Block UDP 1434 Filter".to_string())
            .unwrap()
            .description("This is how to add a filter rule to block inbound access to TCP port 80 to the existing UDP 1434 filter ...".to_string())
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-04-06T20:03:48.000Z")
            .modified("2016-04-06T20:03:48.000Z");

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(course_of_action).unwrap();

        let expected = r#"{
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": "course-of-action--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-04-06T20:03:48Z",
        "modified": "2016-04-06T20:03:48Z",
        "name": "Add TCP port 80 Filter Rule to the existing Block UDP 1434 Filter",
        "description": "This is how to add a filter rule to block inbound access to TCP port 80 to the existing UDP 1434 filter ..."
        }"#;

        //Deserialization (from_str): Converts JSON text into Value, which is an in-memory representation of JSON data
        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn deserialize_course_of_action() {
        let json = r#"{
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": "course-of-action--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-04-06T20:03:48Z",
        "modified": "2016-04-06T20:03:48Z",
        "name": "Add TCP port 80 Filter Rule to the existing Block UDP 1434 Filter",
        "description": "This is how to add a filter rule to block inbound access to TCP port 80 to the existing UDP 1434 filter ..."
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();

        let expected = DomainObjectBuilder::new("course-of-action")
        .unwrap()
            .name("Add TCP port 80 Filter Rule to the existing Block UDP 1434 Filter".to_string())
            .unwrap()
            .description("This is how to add a filter rule to block inbound access to TCP port 80 to the existing UDP 1434 filter ...".to_string())
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-04-06T20:03:48.000Z")
            .modified("2016-04-06T20:03:48.000Z");
        assert_eq!(result, expected);
    }

    #[test]
    fn serialize_grouping() {
        let grouping = DomainObjectBuilder::new("grouping")
            .unwrap()
            .name("Suspicious Activity Group".to_string())
            .unwrap()
            .description(
                "Grouping of related suspicious indicators identified in recent activity."
                    .to_string(),
            )
            .unwrap()
            .context("suspicious-activity".to_string())
            .unwrap()
            .object_refs(vec![Identifier::from_str(
                "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            )
            .unwrap()])
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&grouping).unwrap();

        let expected = r#"{
        "type": "grouping",
        "spec_version": "2.1",
        "id": "grouping--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "name": "Suspicious Activity Group",
        "description": "Grouping of related suspicious indicators identified in recent activity.",
        "object_refs": [
            "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5"
        ],
        "context": "suspicious-activity"
        }"#;

        //Deserialization (from_str): Converts JSON text into Value, which is an in-memory representation of JSON data
        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn deserialize_grouping() {
        let json = r#"{
        "type": "grouping",
        "spec_version": "2.1",
        "id": "grouping--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "name": "Suspicious Activity Group",
        "description": "Grouping of related suspicious indicators identified in recent activity.",
        "object_refs": [
            "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5"
        ],
        "context": "suspicious-activity"
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();

        let expected = DomainObjectBuilder::new("grouping")
            .unwrap()
            .name("Suspicious Activity Group".to_string())
            .unwrap()
            .description(
                "Grouping of related suspicious indicators identified in recent activity."
                    .to_string(),
            )
            .unwrap()
            .context("suspicious-activity".to_string())
            .unwrap()
            .object_refs(vec![Identifier::from_str(
                "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            )
            .unwrap()])
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");
        assert_eq!(result, expected);
    }

    #[test]
    fn serialize_identity() {
        let identity = DomainObjectBuilder::new("identity")
            .unwrap()
            .name("Identity".to_string())
            .unwrap()
            .identity_class("individual".to_string())
            .unwrap()
            .description("Responsible for managing personal digital identity".to_string())
            .unwrap()
            .roles(vec!["User".to_string(), "Administrator".to_string()])
            .unwrap()
            .sectors(vec!["Technology".to_string(), "Aerospace".to_string()])
            .unwrap()
            .contact_information("alex.johnson@example.com".to_string())
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&identity).unwrap();

        let expected = r#"{
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

        //Deserialization (from_str): Converts JSON text into Value, which is an in-memory representation of JSON data
        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(&result, &expected_value)
    }

    #[test]
    fn deserialize_identity() {
        let json = r#"{
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

        let result = DomainObject::from_json(json, false).unwrap();

        let expected = DomainObjectBuilder::new("identity")
            .unwrap()
            .name("Identity".to_string())
            .unwrap()
            .identity_class("individual".to_string())
            .unwrap()
            .description("Responsible for managing personal digital identity".to_string())
            .unwrap()
            .roles(vec!["User".to_string(), "Administrator".to_string()])
            .unwrap()
            .sectors(vec!["Technology".to_string(), "Aerospace".to_string()])
            .unwrap()
            .contact_information("alex.johnson@example.com".to_string())
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");
        assert_eq!(result, expected);
    }

    #[test]
    fn serialize_incident() {
        let incident = DomainObjectBuilder::new("incident")
            .unwrap()
            .name("incident".to_string())
            .unwrap()
            .description("incident desc".to_string())
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&incident).unwrap();

        let expected = r#"{
            "type": "incident",
            "name": "incident",
            "description": "incident desc",
            "spec_version": "2.1",
            "id": "incident--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "external_references": [
            {
            "source_name": "capec",
            "external_id": "CAPEC-163"
            }
        ]
        }"#;

        //Deserialization (from_str): Converts JSON text into Value, which is an in-memory representation of JSON data
        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(&result, &expected_value)
    }

    #[test]
    fn deserialize_incident() {
        let json = r#"{
            "type": "incident",
            "name": "incident",
            "description": "incident desc",
            "spec_version": "2.1",
            "id": "incident--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "external_references": [
            {
            "source_name": "capec",
            "external_id": "CAPEC-163"
            }
        ]
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();

        let expected = DomainObjectBuilder::new("incident")
            .unwrap()
            .name("incident".to_string())
            .unwrap()
            .description("incident desc".to_string())
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        assert_eq!(result, expected);
    }

    #[test]
    fn serialize_indicator() {
        let mut general_extension = StixDictionary::new();
        general_extension
            .insert(
                "extension_type",
                DictionaryValue::String("property-extension".to_string()),
            )
            .unwrap();
        general_extension
            .insert("rank", DictionaryValue::Int(5))
            .unwrap();
        general_extension
            .insert("toxicity", DictionaryValue::Int(8))
            .unwrap();

        let indicator = DomainObjectBuilder::new("indicator")
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
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .add_extension(
                "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e",
                general_extension,
            )
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&indicator).unwrap();

        let expected = r#"{
    "type": "indicator",
    "name": "Indicator",
    "description": "This indicator detects connections to a known malicious IP address",
    "indicator_types": [
            "malicious-activity"
        ],
    "pattern": "[domain-name:value = 'example.com']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
    "valid_from": "2016-05-12T08:17:27Z",
    "valid_until":"2023-10-05T10:00:00Z",
    "spec_version": "2.1",
    "id": "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
    "created": "2016-05-12T08:17:27Z",
    "modified": "2016-05-12T08:17:27Z",
    "external_references": [
        {
        "source_name": "capec",
        "external_id": "CAPEC-163"
        }
    ],
    "extensions": {
        "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e" : {
            "extension_type": "property-extension",
            "rank": 5,
            "toxicity": 8
        }
    }
    }"#;

        //Deserialization (from_str): Converts JSON text into Value, which is an in-memory representation of JSON data
        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(&result, &expected_value)
    }

    #[test]
    fn deserialize_indicator() {
        let json = r#"{
    "type": "indicator",
    "name": "Indicator",
    "description": "This indicator detects connections to a known malicious IP address",
    "indicator_types": [
            "malicious-activity"
        ],
    "pattern": "[domain-name:value = 'example.com']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
    "valid_from": "2016-05-12T08:17:27Z",
    "valid_until":"2023-10-05T10:00:00Z",
    "spec_version": "2.1",
    "id": "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
    "created": "2016-05-12T08:17:27Z",
    "modified": "2016-05-12T08:17:27Z",
    "external_references": [
        {
        "source_name": "capec",
        "external_id": "CAPEC-163"
        }
    ],
    "extensions": {
        "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e" : {
            "extension_type": "property-extension",
            "rank": 5,
            "toxicity": 8
        }
    }
    }"#;

        let result = DomainObject::from_json(json, false).unwrap();

        let mut general_extension = StixDictionary::new();
        general_extension
            .insert(
                "extension_type",
                DictionaryValue::String("property-extension".to_string()),
            )
            .unwrap();
        general_extension
            .insert("rank", DictionaryValue::Int(5))
            .unwrap();
        general_extension
            .insert("toxicity", DictionaryValue::Int(8))
            .unwrap();

        let expected = DomainObjectBuilder::new("indicator")
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
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .add_extension(
                "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e",
                general_extension,
            )
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");
        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_indicator_invalid() {
        let json = r#"{
    "type": "indicator",
    "name": "Indicator",
    "description": "This indicator detects connections to a known malicious IP address",
    "indicator_types": [
            "malicious-activity"
        ],
    "pattern": "[type=domain-name,value='example.com']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
    "valid_from": "2016-05-12T08:17:27Z",
    "valid_until":"2023-10-05T10:00:00Z",
    "spec_version": "2.1",
    "id": "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
    "created": "2016-05-12T08:17:27Z",
    "modified": "2016-05-12T08:17:27Z",
    "junk":"junk",
    "external_references": [
        {
        "source_name": "capec",
        "external_id": "CAPEC-163"
        }
    ]
    }"#;

        let result = DomainObject::from_json(json, false);

        assert!(result.is_err());
    }

    #[test]
    fn serialize_infrastructure() {
        let infrastructure = DomainObjectBuilder::new("infrastructure")
            .unwrap()
            .name("Infrastructure test".to_string())
            .unwrap()
            .description("Infrastructure description".to_string())
            .unwrap()
            .first_seen("2023-10-01T00:00:00.000Z".to_string())
            .unwrap()
            .infrastructure_types(vec!["amplification".to_string(), "botnet".to_string()])
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&infrastructure).unwrap();

        let expected = r#"{
        "type": "infrastructure",
        "spec_version": "2.1",
        "id": "infrastructure--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "name": "Infrastructure test",
        "description": "Infrastructure description",
        "first_seen": "2023-10-01T00:00:00Z",
        "infrastructure_types": [
            "amplification","botnet"
        ]
        }"#;

        //Deserialization (from_str): Converts JSON text into Value, which is an in-memory representation of JSON data
        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn deserialize_infrastructure() {
        let json = r#"{
        "type": "infrastructure",
        "spec_version": "2.1",
        "id": "infrastructure--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "name": "Infrastructure test",
        "description": "Infrastructure description",
        "first_seen": "2023-10-01T00:00:00Z",
        "infrastructure_types": [
            "amplification","botnet"
        ]
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();

        let expected = DomainObjectBuilder::new("infrastructure")
            .unwrap()
            .name("Infrastructure test".to_string())
            .unwrap()
            .description("Infrastructure description".to_string())
            .unwrap()
            .first_seen("2023-10-01T00:00:00.000Z".to_string())
            .unwrap()
            .infrastructure_types(vec!["amplification".to_string(), "botnet".to_string()])
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");
        assert_eq!(result, expected);
    }

    #[test]
    fn serialize_intrusion_set() {
        let intrusion_set = DomainObjectBuilder::new("intrusion-set")
            .unwrap()
            .name("APT28".to_string())
            .unwrap()
            .description("Fancy Bear".to_string())
            .unwrap()
            .aliases(vec!["Sofacy, Sednit".to_string()])
            .unwrap()
            .first_seen("2023-10-01T00:00:00.000Z".to_string())
            .unwrap()
            .last_seen("2023-10-01T00:00:00.000Z".to_string())
            .unwrap()
            .goals(vec!["disrupt communications".to_string()])
            .unwrap()
            .resource_level("team".to_string())
            .unwrap()
            .primary_motivation("organizational-gain".to_string())
            .unwrap()
            .secondary_motivations(vec!["organizational-gain".to_string()])
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        let result = serde_json::to_value(&intrusion_set).unwrap();

        let expected = r#"{
            "type": "intrusion-set",
            "name" : "APT28",
            "description": "Fancy Bear",
            "aliases": ["Sofacy, Sednit"],
            "first_seen": "2023-10-01T00:00:00Z",
            "last_seen": "2023-10-01T00:00:00Z",
            "goals" : ["disrupt communications"],
            "resource_level" : "team",
            "primary_motivation": "organizational-gain",
            "secondary_motivations": ["organizational-gain"],
            "spec_version": "2.1",
            "id": "intrusion-set--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "external_references": [
                {
                "source_name": "capec",
                 "external_id": "CAPEC-163"
                }
            ]
   }"#
        .to_string();

        let expected_value: Value = serde_json::from_str(&expected).unwrap();

        assert_eq!(result, expected_value);
    }

    #[test]
    fn deserialize_intrusion_set() {
        let json = r#"{
            "type": "intrusion-set",
            "name" : "APT28",
            "description": "Fancy Bear",
            "aliases": ["Sofacy, Sednit"],
            "first_seen": "2023-10-01T00:00:00Z",
            "last_seen": "2023-10-01T00:00:00Z",
            "goals" : ["disrupt communications"],
            "resource_level" : "team",
            "primary_motivation": "organizational-gain",
            "secondary_motivations": ["organizational-gain"],
            "spec_version": "2.1",
            "id": "intrusion-set--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "external_references": [
                {
                "source_name": "capec",
                 "external_id": "CAPEC-163"
                }
            ]
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();

        let expected = DomainObjectBuilder::new("intrusion-set")
            .unwrap()
            .name("APT28".to_string())
            .unwrap()
            .description("Fancy Bear".to_string())
            .unwrap()
            .aliases(vec!["Sofacy, Sednit".to_string()])
            .unwrap()
            .first_seen("2023-10-01T00:00:00.000Z".to_string())
            .unwrap()
            .last_seen("2023-10-01T00:00:00.000Z".to_string())
            .unwrap()
            .goals(vec!["disrupt communications".to_string()])
            .unwrap()
            .resource_level("team".to_string())
            .unwrap()
            .primary_motivation("organizational-gain".to_string())
            .unwrap()
            .secondary_motivations(vec!["organizational-gain".to_string()])
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        assert_eq!(result, expected);
    }

    #[test]
    fn serialize_location() {
        let location = DomainObjectBuilder::new("location")
            .unwrap()
            .name("Test Location".to_string())
            .unwrap()
            .description("A test location".to_string())
            .unwrap()
            .latitude(37.7749)
            .unwrap()
            .longitude(-122.4194)
            .unwrap()
            .precision(10.0)
            .unwrap()
            .region("northern-america".to_string())
            .unwrap()
            .country("US".to_string())
            .unwrap()
            .administrative_area("SE-O".to_string())
            .unwrap()
            .city("San Francisco".to_string())
            .unwrap()
            .street_address("1 Market St".to_string())
            .unwrap()
            .postal_code("94105".to_string())
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        let result = serde_json::to_value(&location).unwrap();

        let expected = r#"{
            "type": "location",
            "name": "Test Location",
            "description": "A test location",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "precision": 10.0,
            "region": "northern-america",
            "country": "US",
            "administrative_area": "SE-O",
            "city": "San Francisco",
            "street_address": "1 Market St",
            "postal_code": "94105",
            "spec_version": "2.1",
            "id": "location--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z"
        }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(result, expected_value);
    }

    #[test]
    fn serialize_location_invalid_latitude() {
        let location = DomainObjectBuilder::new("location")
            .unwrap()
            .name("Test Location".to_string())
            .unwrap()
            .description("A test location".to_string())
            .unwrap()
            .latitude(97.7749)
            .unwrap()
            .longitude(-122.4194)
            .unwrap()
            .precision(10.0)
            .unwrap()
            .region("northern-america".to_string())
            .unwrap()
            .country("US".to_string())
            .unwrap()
            .administrative_area("SE-O".to_string())
            .unwrap()
            .city("San Francisco".to_string())
            .unwrap()
            .street_address("1 Market St".to_string())
            .unwrap()
            .postal_code("94105".to_string())
            .unwrap()
            .build();

        assert!(location.is_err());
    }

    #[test]
    fn serialize_location_invalid_precision() {
        // lat and long should be present but are not
        let location = DomainObjectBuilder::new("location")
            .unwrap()
            .name("Test Location".to_string())
            .unwrap()
            .description("A test location".to_string())
            .unwrap()
            .precision(10.0)
            .unwrap()
            .region("northern-america".to_string())
            .unwrap()
            .country("us".to_string())
            .unwrap()
            .administrative_area("se-o".to_string())
            .unwrap()
            .city("San Francisco".to_string())
            .unwrap()
            .street_address("1 Market St".to_string())
            .unwrap()
            .postal_code("94105".to_string())
            .unwrap()
            .build();

        assert!(location.is_err());
    }

    #[test]
    fn deserialize_location() {
        let json = r#"{
            "type": "location",
            "name": "Test Location",
            "description": "A test location",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "precision": 10.0,
            "region": "northern-america",
            "country": "US",
            "administrative_area": "SE-O",
            "city": "San Francisco",
            "street_address": "1 Market St",
            "postal_code": "94105",
            "spec_version": "2.1",
            "id": "location--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z"
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();

        let expected = DomainObjectBuilder::new("location")
            .unwrap()
            .name("Test Location".to_string())
            .unwrap()
            .description("A test location".to_string())
            .unwrap()
            .latitude(37.7749)
            .unwrap()
            .longitude(-122.4194)
            .unwrap()
            .precision(10.0)
            .unwrap()
            .region("northern-america".to_string())
            .unwrap()
            .country("US".to_string())
            .unwrap()
            .administrative_area("SE-O".to_string())
            .unwrap()
            .city("San Francisco".to_string())
            .unwrap()
            .street_address("1 Market St".to_string())
            .unwrap()
            .postal_code("94105".to_string())
            .unwrap()
            .build()
            .unwrap() // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        assert_eq!(result, expected);
    }
    // test that if report_type is either in known STIX language as an SDO or unknown from STIX language, object passes
    #[test]
    fn try_ok_report_types() {
        let report = DomainObjectBuilder::new("report")
            .unwrap()
            .name("Test_Report".to_string())
            .unwrap()
            .description("A simple report with an indicator and campaign".to_string())
            .unwrap()
            .published(Timestamp("2016-05-12T08:17:27.000Z".parse().unwrap()))
            .unwrap()
            .created_by_ref(Identifier::new_test("identity"))
            .unwrap()
            .report_types(vec!["attack-pattern".to_string()])
            .unwrap()
            .object_refs(vec![Identifier::from_str(
                "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
            )
            .unwrap()])
            .unwrap()
            .build();
        assert!(report.is_ok());
        let report = DomainObjectBuilder::new("report")
            .unwrap()
            .name("Test_Report".to_string())
            .unwrap()
            .description("A simple report with an indicator and campaign".to_string())
            .unwrap()
            .published(Timestamp("2016-05-12T08:17:27.000Z".parse().unwrap()))
            .unwrap()
            .created_by_ref(Identifier::new_test("identity"))
            .unwrap()
            .report_types(vec!["CUSTOM_REPORT".to_string()])
            .unwrap()
            .object_refs(vec![Identifier::from_str(
                "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
            )
            .unwrap()])
            .unwrap()
            .build();
        assert!(report.is_ok());
    }
    // test that if report_type is in language, but not a report, gives an error
    #[test]
    fn try_error_report_types() {
        let report = DomainObjectBuilder::new("report")
            .unwrap()
            .name("Test_Report".to_string())
            .unwrap()
            .description("A simple report with an indicator and campaign".to_string())
            .unwrap()
            .published(Timestamp("2016-05-12T08:17:27.000Z".parse().unwrap()))
            .unwrap()
            .created_by_ref(Identifier::new_test("identity"))
            .unwrap()
            .report_types(vec!["artifact".to_string()])
            .unwrap()
            .object_refs(vec![Identifier::from_str(
                "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
            )
            .unwrap()])
            .unwrap()
            .build();
        assert!(report.is_err());
        let report = DomainObjectBuilder::new("report")
            .unwrap()
            .name("Test_Report".to_string())
            .unwrap()
            .description("A simple report with an indicator and campaign".to_string())
            .unwrap()
            .published(Timestamp("2016-05-12T08:17:27.000Z".parse().unwrap()))
            .unwrap()
            .created_by_ref(Identifier::new_test("identity"))
            .unwrap()
            .report_types(vec!["sighting".to_string()])
            .unwrap()
            .object_refs(vec![Identifier::from_str(
                "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
            )
            .unwrap()])
            .unwrap()
            .build();
        assert!(report.is_err());
        let report = DomainObjectBuilder::new("report")
            .unwrap()
            .name("Test_Report".to_string())
            .unwrap()
            .description("A simple report with an indicator and campaign".to_string())
            .unwrap()
            .created_by_ref(Identifier::new_test("identity"))
            .unwrap()
            .report_types(vec!["language-content".to_string()])
            .unwrap()
            .object_refs(vec![Identifier::from_str(
                "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
            )
            .unwrap()])
            .unwrap()
            .build();
        assert!(report.is_err());
    }

    #[test]
    fn deserialize_location_invalid() {
        //lat and long should be present
        let json = r#"{
            "type": "location",
            "name": "Test Location",
            "description": "A test location",
            "precision": 10.0,
            "region": "northern-america",
            "country": "US",
            "administrative_area": "SE-O",
            "city": "San Francisco",
            "street_address": "1 Market St",
            "postal_code": "94105",
            "spec_version": "2.1",
            "id": "location--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z"
        }"#;

        let result = DomainObject::from_json(json, false);
        assert!(result.is_err());
    }

    #[test]
    fn serialize_malware() {
        let malware = DomainObjectBuilder::new("malware")
            .unwrap()
            .name("malware".to_string())
            .unwrap()
            .description("A ransomware trojan".to_string())
            .unwrap()
            .malware_types(vec!["Adware".to_string(), "ExploitKit".to_string()])
            .unwrap()
            .set_family(true)
            .unwrap()
            .aliases(vec!["CryptoDefense".to_string(), "WannaCry".to_string()])
            .unwrap()
            .first_seen("2023-10-01T00:00:00.00Z".to_string())
            .unwrap()
            .last_seen("2023-10-01T00:00:00.00Z".to_string())
            .unwrap()
            .operating_system_refs(vec![Identifier::from_str(
                "software--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            )
            .unwrap()])
            .unwrap()
            .architecture_execution_envs(vec!["Arm".to_string(), "PowerPC".to_string()])
            .unwrap()
            .implementation_languages(vec!["AppleScript".to_string(), "Bash".to_string()])
            .unwrap()
            .capabilities(vec!["AntiDebugging".to_string(), "AntiSandbox".to_string()])
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        let result = serde_json::to_value(&malware).unwrap();

        let json = r#"{
            "type": "malware",
            "name": "malware",
            "description": "A ransomware trojan",
            "malware_types": ["Adware","ExploitKit"],
            "is_family": true,
            "aliases": ["CryptoDefense", "WannaCry"],
            "first_seen": "2023-10-01T00:00:00Z",
            "last_seen": "2023-10-01T00:00:00Z",
            "operating_system_refs":["software--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"],
            "architecture_execution_envs" : ["Arm", "PowerPC"],
            "implementation_languages": ["AppleScript","Bash"],
            "capabilities" : ["AntiDebugging","AntiSandbox"],
            "spec_version": "2.1",
            "id": "malware--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "external_references": [
            {
            "source_name": "capec",
            "external_id": "CAPEC-163"
            }
        ]
        }"#;

        let expected_value: Value = serde_json::from_str(json).unwrap();

        assert_eq!(&result, &expected_value)
    }

    #[test]
    fn deserialize_malware() {
        let json = r#"{
            "type": "malware",
            "name": "malware",
            "description": "A ransomware trojan",
            "malware_types": ["Adware","ExploitKit"],
            "is_family": true,
            "aliases": ["CryptoDefense", "WannaCry"],
            "first_seen": "2023-10-01T00:00:00Z",
            "last_seen": "2023-10-01T00:00:00Z",
            "operating_system_refs":["software--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"],
            "architecture_execution_envs" : ["Arm", "PowerPC"],
            "implementation_languages": ["AppleScript","Bash"],
            "capabilities" : ["AntiDebugging","AntiSandbox"],
            "spec_version": "2.1",
            "id": "malware--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "external_references": [
            {
            "source_name": "capec",
            "external_id": "CAPEC-163"
            }
        ]
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();

        let expected = DomainObjectBuilder::new("malware")
            .unwrap()
            .name("malware".to_string())
            .unwrap()
            .description("A ransomware trojan".to_string())
            .unwrap()
            .malware_types(vec!["Adware".to_string(), "ExploitKit".to_string()])
            .unwrap()
            .set_family(true)
            .unwrap()
            .aliases(vec!["CryptoDefense".to_string(), "WannaCry".to_string()])
            .unwrap()
            .first_seen("2023-10-01T00:00:00.000Z".to_string())
            .unwrap()
            .last_seen("2023-10-01T00:00:00.000Z".to_string())
            .unwrap()
            .operating_system_refs(vec![Identifier::from_str(
                "software--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            )
            .unwrap()])
            .unwrap()
            .architecture_execution_envs(vec!["Arm".to_string(), "PowerPC".to_string()])
            .unwrap()
            .implementation_languages(vec!["AppleScript".to_string(), "Bash".to_string()])
            .unwrap()
            .capabilities(vec!["AntiDebugging".to_string(), "AntiSandbox".to_string()])
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        assert_eq!(&result, &expected);
    }

    #[test]
    fn try_ok_malware_operating_system_refs() {
        let malware = DomainObjectBuilder::new("malware")
            .unwrap()
            .name("malware".to_string())
            .unwrap()
            .description("A ransomware trojan".to_string())
            .unwrap()
            .malware_types(vec!["Adware".to_string(), "ExploitKit".to_string()])
            .unwrap()
            .operating_system_refs(vec![Identifier::new("software").unwrap()])
            .unwrap()
            .build();
        assert!(malware.is_ok());
    }

    #[test]
    fn try_err_malware_operating_system_refs() {
        let malware = DomainObjectBuilder::new("malware")
            .unwrap()
            .name("malware".to_string())
            .unwrap()
            .description("A ransomware trojan".to_string())
            .unwrap()
            .malware_types(vec!["Adware".to_string(), "ExploitKit".to_string()])
            .unwrap()
            .operating_system_refs(vec![Identifier::new("attack-pattern").unwrap()])
            .unwrap()
            .build();
        assert!(malware.is_err());
        let malware = DomainObjectBuilder::new("malware")
            .unwrap()
            .name("malware".to_string())
            .unwrap()
            .description("A ransomware trojan".to_string())
            .unwrap()
            .malware_types(vec!["Adware".to_string(), "ExploitKit".to_string()])
            .unwrap()
            .operating_system_refs(vec![Identifier::new("sighting").unwrap()])
            .unwrap()
            .build();
        assert!(malware.is_err());
        let malware = DomainObjectBuilder::new("malware")
            .unwrap()
            .name("malware".to_string())
            .unwrap()
            .description("A ransomware trojan".to_string())
            .unwrap()
            .malware_types(vec!["Adware".to_string(), "ExploitKit".to_string()])
            .unwrap()
            .operating_system_refs(vec![Identifier::new("language-content").unwrap()])
            .unwrap()
            .build();
        assert!(malware.is_err());
    }

    #[test]
    fn serialize_malware_analysis() {
        let malware_analysis = DomainObjectBuilder::new("malware-analysis")
            .unwrap()
            .set_result("benign".to_string())
            .unwrap()
            .product("malware-analysis".to_string())
            .unwrap()
            .host_vm_ref(
                Identifier::from_str("software--5b7f978f-7299-47f5-b5ff-f043f6b3cf8d").unwrap(),
            )
            .unwrap()
            .operating_system_ref(
                Identifier::from_str("software--2a40a042-e9d3-429d-b029-7a9a3c4e7b79").unwrap(),
            )
            .unwrap()
            .installed_software_refs(vec![Identifier::from_str(
                "software--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            )
            .unwrap()])
            .unwrap()
            .configuration_version("v1.3.2".to_string())
            .unwrap()
            .modules(vec!["Dridex".to_string(), "Ransomware".to_string()])
            .unwrap()
            .analysis_engine_version("v1.1.1".to_string())
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        let json = r#"{
                "type": "malware-analysis",
                "result": "benign",
                "product": "malware-analysis",
                "host_vm_ref": "software--5b7f978f-7299-47f5-b5ff-f043f6b3cf8d",
                "operating_system_ref":"software--2a40a042-e9d3-429d-b029-7a9a3c4e7b79",
                "installed_software_refs":["software--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"],
                "configuration_version":"v1.3.2",
                "modules":["Dridex", "Ransomware"],
                "analysis_engine_version":"v1.1.1",
                "spec_version": "2.1",
                "id": "malware-analysis--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
                "created": "2016-05-12T08:17:27Z",
                "modified": "2016-05-12T08:17:27Z",
                "external_references": [
                {
                "source_name": "capec",
                "external_id": "CAPEC-163"
                }
            ]
            }"#;

        let result = serde_json::to_value(&malware_analysis).unwrap();
        let expected_value: Value = serde_json::from_str(json).unwrap();

        assert_eq!(&result, &expected_value)
    }

    #[test]
    fn deserialize_malware_analysis() {
        let json = r#"{
                "type": "malware-analysis",
                "result": "benign",
                "product": "malware-analysis",
                "host_vm_ref": "software--5b7f978f-7299-47f5-b5ff-f043f6b3cf8d",
                "operating_system_ref":"software--2a40a042-e9d3-429d-b029-7a9a3c4e7b79",
                "installed_software_refs":["software--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"],
                "configuration_version":"v1.3.2",
                "modules":["Dridex", "Ransomware"],
                "analysis_engine_version":"v1.1.1",
                "spec_version": "2.1",
                "id": "malware-analysis--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
                "created": "2016-05-12T08:17:27Z",
                "modified": "2016-05-12T08:17:27Z",
                "external_references": [
                {
                "source_name": "capec",
                "external_id": "CAPEC-163"
                }
            ]
            }"#;

        let expected = DomainObjectBuilder::new("malware-analysis")
            .unwrap()
            .set_result("benign".to_string())
            .unwrap()
            .product("malware-analysis".to_string())
            .unwrap()
            .host_vm_ref(
                Identifier::from_str("software--5b7f978f-7299-47f5-b5ff-f043f6b3cf8d").unwrap(),
            )
            .unwrap()
            .operating_system_ref(
                Identifier::from_str("software--2a40a042-e9d3-429d-b029-7a9a3c4e7b79").unwrap(),
            )
            .unwrap()
            .installed_software_refs(vec![Identifier::from_str(
                "software--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            )
            .unwrap()])
            .unwrap()
            .configuration_version("v1.3.2".to_string())
            .unwrap()
            .modules(vec!["Dridex".to_string(), "Ransomware".to_string()])
            .unwrap()
            .analysis_engine_version("v1.1.1".to_string())
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        let result = DomainObject::from_json(json, false).unwrap();
        assert_eq!(&result, &expected);
    }

    #[test]
    fn serialize_note() {
        let note = DomainObjectBuilder::new("note")
            .unwrap()
            .set_abstract("Tracking Team Note#1".to_string())
            .unwrap()
            .content("This note indicates the various steps taken by the threat analyst team to investigate this specific campaign. Step 1) Do a scan 2) Review scanned results for identified hosts not known by external intel….etc".to_string())
            .unwrap()
            .authors(vec!["John Doe".to_string()])
            .unwrap()
            .object_refs(vec![Identifier::from_str("campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").unwrap()])
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "job-tracker",
                None,
                None,
                Some("job-id-1234".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&note).unwrap();

        let expected = r#"{
        "type": "note",
        "spec_version": "2.1",
        "id": "note--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "external_references": [
            {
            "source_name": "job-tracker",
            "external_id": "job-id-1234"
            }
        ],
        "abstract": "Tracking Team Note#1",
        "content": "This note indicates the various steps taken by the threat analyst team to investigate this specific campaign. Step 1) Do a scan 2) Review scanned results for identified hosts not known by external intel….etc",
        "authors": ["John Doe"],
        "object_refs": ["campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"]
        }"#;

        //Deserialization (from_str): Converts JSON text into Value, which is an in-memory representation of JSON data
        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn deserialize_note() {
        let json = r#"{
        "type": "note",
        "spec_version": "2.1",
        "id": "note--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "external_references": [
            {
            "source_name": "job-tracker",
            "external_id": "job-id-1234"
            }
        ],
        "abstract": "Tracking Team Note#1",
        "content": "This note indicates the various steps taken by the threat analyst team to investigate this specific campaign. Step 1) Do a scan 2) Review scanned results for identified hosts not known by external intel….etc",
        "authors": ["John Doe"],
        "object_refs": ["campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"]
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();

        let expected = DomainObjectBuilder::new("note")
        .unwrap()
        .set_abstract("Tracking Team Note#1".to_string())
        .unwrap()
        .content("This note indicates the various steps taken by the threat analyst team to investigate this specific campaign. Step 1) Do a scan 2) Review scanned results for identified hosts not known by external intel….etc".to_string())
        .unwrap()
        .authors(vec!["John Doe".to_string()])
        .unwrap()
        .object_refs(vec![Identifier::from_str("campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").unwrap()])
        .unwrap()
        .external_references(vec![ExternalReference::new(
            "job-tracker",
            None,
            None,
            Some("job-id-1234".to_string()),
        )
        .unwrap()])
        .build()
        .unwrap()
        // Change id, created, and modified fields for test matching
        .test_id()
        .created("2016-05-12T08:17:27.000Z")
        .modified("2016-05-12T08:17:27.000Z");
        assert_eq!(result, expected);
    }

    #[test]
    fn serialize_observed_data() {
        let observed_data = DomainObjectBuilder::new("observed-data")
            .unwrap()
            .first_observed("2015-12-21T19:00:00Z".to_string())
            .unwrap()
            .last_observed("2015-12-21T19:00:00Z".to_string())
            .unwrap()
            .number_observed(50)
            .unwrap()
            .object_refs(vec![
                Identifier::from_str("ipv4-addr--efcd5e80-570d-4131-b213-62cb18eaa6a8").unwrap(),
                Identifier::from_str("domain-name--ecb120bf-2694-4902-a737-62b74539a41b").unwrap(),
            ])
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-04-06T20:03:48.000Z")
            .modified("2016-04-06T20:03:48.000Z");

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&observed_data).unwrap();

        let expected = r#"{
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-04-06T20:03:48Z",
        "modified": "2016-04-06T20:03:48Z",
        "first_observed": "2015-12-21T19:00:00Z",
        "last_observed": "2015-12-21T19:00:00Z",
        "number_observed": 50,
        "object_refs": [
            "ipv4-addr--efcd5e80-570d-4131-b213-62cb18eaa6a8",
            "domain-name--ecb120bf-2694-4902-a737-62b74539a41b"
        ]
        }"#;

        //Deserialization (from_str): Converts JSON text into Value, which is an in-memory representation of JSON data
        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn observed_data_test_number_observed_as_json_string() {
        let observed_data = DomainObjectBuilder::new("observed-data")
            .unwrap()
            .first_observed("2015-12-21T19:00:00Z".to_string())
            .unwrap()
            .last_observed("2015-12-21T19:00:00Z".to_string())
            .unwrap()
            .number_observed(50)
            .unwrap()
            .object_refs(vec![
                Identifier::from_str("ipv4-addr--efcd5e80-570d-4131-b213-62cb18eaa6a8").unwrap(),
                Identifier::from_str("domain-name--ecb120bf-2694-4902-a737-62b74539a41b").unwrap(),
            ])
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-04-06T20:03:48.000Z")
            .modified("2016-04-06T20:03:48.000Z");

        let json = r#"{
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-04-06T20:03:48Z",
        "modified": "2016-04-06T20:03:48Z",
        "first_observed": "2015-12-21T19:00:00Z",
        "last_observed": "2015-12-21T19:00:00Z",
        "number_observed": "50",
        "object_refs": [
            "ipv4-addr--efcd5e80-570d-4131-b213-62cb18eaa6a8",
            "domain-name--ecb120bf-2694-4902-a737-62b74539a41b"
        ]
        }"#;

        //Deserialization (from_str): Converts JSON text into Value, which is an in-memory representation of JSON data
        let expected_value = DomainObject::from_json(json, false).unwrap();

        assert_eq!(&observed_data, &expected_value);
    }

    #[test]
    fn deserialize_observed_data() {
        let json = r#"{
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-04-06T20:03:48Z",
        "modified": "2016-04-06T20:03:48Z",
        "first_observed": "2015-12-21T19:00:00Z",
        "last_observed": "2015-12-21T19:00:00Z",
        "number_observed": 50,
        "object_refs": [
            "ipv4-addr--efcd5e80-570d-4131-b213-62cb18eaa6a8",
            "domain-name--ecb120bf-2694-4902-a737-62b74539a41b"
        ]
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();

        let expected = DomainObjectBuilder::new("observed-data")
            .unwrap()
            .first_observed("2015-12-21T19:00:00Z".to_string())
            .unwrap()
            .last_observed("2015-12-21T19:00:00Z".to_string())
            .unwrap()
            .number_observed(50)
            .unwrap()
            .object_refs(vec![
                Identifier::from_str("ipv4-addr--efcd5e80-570d-4131-b213-62cb18eaa6a8").unwrap(),
                Identifier::from_str("domain-name--ecb120bf-2694-4902-a737-62b74539a41b").unwrap(),
            ])
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-04-06T20:03:48.000Z")
            .modified("2016-04-06T20:03:48.000Z");
        assert_eq!(result, expected);
    }

    #[test]
    fn observed_data_sdo_fail() {
        // tests for sdo in object_refs
        let expected = DomainObjectBuilder::new("observed-data")
            .unwrap()
            .first_observed("2015-12-21T19:00:00Z".to_string())
            .unwrap()
            .last_observed("2015-12-21T19:00:00Z".to_string())
            .unwrap()
            .number_observed(50)
            .unwrap()
            .object_refs(vec![
                Identifier::from_str("ipv4-addr--efcd5e80-570d-4131-b213-62cb18eaa6a8").unwrap(),
                Identifier::from_str("note--ecb120bf-2694-4902-a737-62b74539a41b").unwrap(),
            ])
            .unwrap()
            .build();

        assert!(expected.is_err());
    }

    #[test]
    fn observed_data_no_sco_fail() {
        // tests for no sco in object_refs
        let expected = DomainObjectBuilder::new("observed-data")
            .unwrap()
            .first_observed("2015-12-21T19:00:00Z".to_string())
            .unwrap()
            .last_observed("2015-12-21T19:00:00Z".to_string())
            .unwrap()
            .number_observed(50)
            .unwrap()
            .object_refs(vec![
                Identifier::from_str("relationship--efcd5e80-570d-4131-b213-62cb18eaa6a8").unwrap(),
                Identifier::from_str("relationship--ecb120bf-2694-4902-a737-62b74539a41b").unwrap(),
            ])
            .unwrap()
            .build();

        assert!(expected.is_err());
    }

    #[test]
    fn observed_data_custom_pass() {
        // tests for no sco in object_refs
        let expected = DomainObjectBuilder::new("observed-data")
            .unwrap()
            .first_observed("2015-12-21T19:00:00Z".to_string())
            .unwrap()
            .last_observed("2015-12-21T19:00:00Z".to_string())
            .unwrap()
            .number_observed(50)
            .unwrap()
            .object_refs(vec![
                Identifier::from_str("relationship--efcd5e80-570d-4131-b213-62cb18eaa6a8").unwrap(),
                Identifier::from_str("foo--ecb120bf-2694-4902-a737-62b74539a41b").unwrap(),
            ])
            .unwrap()
            .build();

        assert!(expected.is_ok());
    }

    #[test]
    fn observed_data_none_fail() {
        // tests for none on object_refs
        let json = r#"{
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-04-06T20:03:48Z",
        "modified": "2016-04-06T20:03:48Z",
        "first_observed": "2015-12-21T19:00:00Z",
        "last_observed": "2015-12-21T19:00:00Z",
        "number_observed": 50
        }"#;

        let result = DomainObject::from_json(json, false);

        assert!(result.is_err());
    }

    #[test]
    fn serialize_opinion() {
        let opinion = DomainObjectBuilder::new("opinion")
            .unwrap()
            .explanation("The analyst team believes this campaign is related to previous malicious activity based on identified patterns.".to_string())
            .unwrap()
            .authors(vec!["Jane Smith".to_string()])
            .unwrap()
            .opinion(OpinionType::StronglyAgree)
            .unwrap()
            .object_refs(vec![Identifier::from_str("campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").unwrap()])
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "incident-reporter",
                None,
                None,
                Some("incident-id-5678".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&opinion).unwrap();

        let expected = r#"{
        "type": "opinion",
        "spec_version": "2.1",
        "id": "opinion--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "object_refs": [
            "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
        ],
        "opinion": "strongly-agree",
        "explanation": "The analyst team believes this campaign is related to previous malicious activity based on identified patterns.",
        "authors": ["Jane Smith"],
        "external_references": [
            {
                "source_name": "incident-reporter",
                "external_id": "incident-id-5678"
            }
        ]
        }"#;

        //Deserialization (from_str): Converts JSON text into Value, which is an in-memory representation of JSON data
        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn opinion_enum_fail() {
        let expected = r#"{
        "type": "opinion",
        "spec_version": "2.1",
        "id": "opinion--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "object_refs": [
            "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
        ],
        "opinion": "strongly-agreeXX",
        "explanation": "The analyst team believes this campaign is related to previous malicious activity based on identified patterns.",
        "authors": ["Jane Smith"],
        "external_references": [
            {
                "source_name": "incident-reporter",
                "external_id": "incident-id-5678"
            }
        ]
        }"#;

        let expected_value = DomainObject::from_json(expected, false);

        assert!(expected_value.is_err());
    }

    #[test]
    fn deserialize_opinion() {
        let json = r#"{
        "type": "opinion",
        "spec_version": "2.1",
        "id": "opinion--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "object_refs": [
            "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
        ],
        "opinion": "strongly-agree",
        "explanation": "The analyst team believes this campaign is related to previous malicious activity based on identified patterns.",
        "authors": ["Jane Smith"],
        "external_references": [
            {
                "source_name": "incident-reporter",
                "external_id": "incident-id-5678"
            }
        ]
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();

        let expected = DomainObjectBuilder::new("opinion")
        .unwrap()
        .explanation("The analyst team believes this campaign is related to previous malicious activity based on identified patterns.".to_string())
        .unwrap()
        .authors(vec!["Jane Smith".to_string()])
        .unwrap()
        .opinion(OpinionType::StronglyAgree)
        .unwrap()
        .object_refs(vec![Identifier::from_str("campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").unwrap()])
        .unwrap()
        .external_references(vec![ExternalReference::new(
            "incident-reporter",
            None,
            None,
            Some("incident-id-5678".to_string()),
        )
        .unwrap()])
        .build()
        .unwrap()
        // Change id, created, and modified fields for test matching
        .test_id()
        .created("2016-05-12T08:17:27.000Z")
        .modified("2016-05-12T08:17:27.000Z");
        assert_eq!(result, expected);
    }

    fn relationship(relationship_type: String) -> Result<RelationshipObject, Error> {
        let attack_pattern = DomainObjectBuilder::new("attack-pattern")
            ?
            .name("Spear Phishing as Practiced by Adversary X".to_string())
            ?
            .description("A particular form of spear phishing where the attacker claims that the target had won a contest, including personal details, to get them to click on a link.".to_string())
            ?
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            ?])
            .build()
            ?
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        let identity = DomainObjectBuilder::new("identity")?
            .name("John Smith".to_string())?
            .identity_class("individual".to_string())?
            .description("An employee who might click on a link".to_string())?
            .contact_information("john.smith@example.com".to_string())?
            .build()?
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-03-15T09:00:00.000Z")
            .modified("2016-03-15T09:00:00.000Z");

        let relationship = attack_pattern
            .add_relationship(identity, relationship_type)?
            .description("The employee targeted by the spear phishing attempt".to_string())
            .build()?
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-07-01T11:35:00.000Z")
            .modified("2016-07-01T11:35:00.000Z");

        Ok(relationship)
    }

    #[test]
    fn create_relationship() {
        let relationship = relationship("targets".to_string()).unwrap();

        assert_eq!(relationship.get_id().get_type(), "relationship");
        assert_eq!(relationship.get_relationship_type(), "targets");
    }

    #[test]
    fn prohibited_relationship() {
        let relationship = relationship("uses".to_string());
        assert!(relationship.is_err());
    }

    #[test]
    fn serialize_relationship() {
        let relationship = relationship("targets".to_string()).unwrap();

        let mut result = serde_json::to_string_pretty(&relationship).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
            "type": "relationship",            
            "relationship_type": "targets",
            "source_ref": "attack-pattern--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "target_ref": "identity--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "spec_version": "2.1",
            "id": "relationship--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-07-01T11:35:00Z",
            "modified": "2016-07-01T11:35:00Z",
            "description": "The employee targeted by the spear phishing attempt"
        }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_relationship() {
        let json = r#"{
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-07-01T11:35:00Z",
            "modified": "2016-07-01T11:35:00Z",
            "relationship_type": "targets",
            "description": "The employee targeted by the spear phishing attempt",
            "source_ref": "attack-pattern--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "target_ref": "identity--cc7fa653-c35f-43db-afdd-dce4c3a241d5"
        }"#;
        let result = RelationshipObject::from_json(json, false).unwrap();

        let expected = relationship("targets".to_string()).unwrap();

        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_invalid_relationship() {
        let json = r#"{
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-07-01T11:35:00Z",
            "modified": "2016-07-01T11:35:00Z",
            "relationship_type": "targets",
            "description": "The employee targeted by the spear phishing attempt",
            "source_ref": "attack-pattern--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "target_ref": "malware--cc7fa653-c35f-43db-afdd-dce4c3a241d5"
        }"#;
        let result = RelationshipObject::from_json(json, false);
        assert!(result.is_err());
    }

    #[test]
    fn serialize_report() {
        let location = DomainObjectBuilder::new("report")
            .unwrap()
            .name("The Black Vine Cyberespionage Group".to_string())
            .unwrap()
            .description("A simple report with an indicator and campaign".to_string())
            .unwrap()
            .created_by_ref(Identifier::new_test("identity"))
            .unwrap()
            .published(Timestamp("2016-05-12T08:17:27.000Z".parse().unwrap()))
            .unwrap()
            .report_types(vec!["campaign".to_string(), "attack-pattern".to_string()])
            .unwrap()
            .object_refs(vec![
                Identifier::from_str("indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2").unwrap(),
                Identifier::from_str("campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c").unwrap(),
                Identifier::from_str("relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a").unwrap(),
            ])
            .unwrap()
            .build()
            .unwrap() // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        let result = serde_json::to_value(&location).unwrap();

        let expected = r#"{
            "type": "report",
            "name": "The Black Vine Cyberespionage Group",
            "description": "A simple report with an indicator and campaign",
            "created_by_ref": "identity--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "published": "2016-05-12T08:17:27Z",
            "report_types": ["campaign","attack-pattern"],
            "object_refs": [
                "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
                "campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c",
                "relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a"
             ],
            "spec_version": "2.1",
            "id": "report--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z"
           }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(result, expected_value);
    }

    #[test]
    fn deserialize_report() {
        let json = r#"{
            "type": "report",
            "name": "The Black Vine Cyberespionage Group",
            "description": "A simple report with an indicator and campaign",
            "created_by_ref": "identity--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "published": "2016-05-12T08:17:27Z",
            "report_types": ["campaign","attack-pattern"],
            "object_refs": [
                "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
                "campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c",
                "relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a"
             ],
            "spec_version": "2.1",
            "id": "report--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z"
           }"#;

        let result = DomainObject::from_json(json, false).unwrap();

        let expected = DomainObjectBuilder::new("report")
            .unwrap()
            .name("The Black Vine Cyberespionage Group".to_string())
            .unwrap()
            .description("A simple report with an indicator and campaign".to_string())
            .unwrap()
            .created_by_ref(Identifier::new_test("identity"))
            .unwrap()
            .published(Timestamp("2016-05-12T08:17:27.000Z".parse().unwrap()))
            .unwrap()
            .report_types(vec!["campaign".to_string(), "attack-pattern".to_string()])
            .unwrap()
            .object_refs(vec![
                Identifier::from_str("indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2").unwrap(),
                Identifier::from_str("campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c").unwrap(),
                Identifier::from_str("relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a").unwrap(),
            ])
            .unwrap()
            .build()
            .unwrap() // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        assert_eq!(result, expected);
    }

    fn sighting() -> Result<RelationshipObject, Error> {
        let indicator = DomainObjectBuilder::new("indicator")
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
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        let sighting = indicator
            .add_sighting()?
            .description("Sighting of malicious IP indicator".to_string())
            .last_seen("2016-08-15T14:00:00.000Z")
            .unwrap()
            .build()?
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-07-01T11:35:00.000Z")
            .modified("2016-07-01T11:35:00.000Z");

        Ok(sighting)
    }

    #[test]
    fn serialize_sighting() {
        let sighting = sighting().unwrap();

        let mut result = serde_json::to_string_pretty(&sighting).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
            "type": "sighting",            
            "last_seen": "2016-08-15T14:00:00Z",
            "sighting_of_ref": "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "spec_version": "2.1",
            "id": "sighting--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-07-01T11:35:00Z",
            "modified": "2016-07-01T11:35:00Z",
            "description": "Sighting of malicious IP indicator"
        }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_sighting() {
        let json = r#"{
            "type": "sighting",            
            "last_seen": "2016-08-15T14:00:00Z",
            "sighting_of_ref": "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "spec_version": "2.1",
            "id": "sighting--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-07-01T11:35:00Z",
            "modified": "2016-07-01T11:35:00Z",
            "description": "Sighting of malicious IP indicator"
        }"#;
        let result = RelationshipObject::from_json(json, false).unwrap();

        let expected = sighting().unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_invalid_sighting() {
        let json = r#"{
            "type": "sighting",            
            "last_seen": "2016-08-15T14:00:00Z",
            "sighting_of_ref": "file--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "spec_version": "2.1",
            "id": "sighting--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-07-01T11:35:00Z",
            "modified": "2016-07-01T11:35:00Z",
            "description": "Sighting of malicious IP indicator"
        }"#;
        let result = RelationshipObject::from_json(json, false);

        assert!(result.is_err());
    }

    #[test]
    fn serialize_threat_actor() {
        let threat_actor = DomainObjectBuilder::new("threat-actor")
            .unwrap()
            .name("Threat Actor Group".to_string())
            .unwrap()
            .description("A group known for cyber espionage".to_string())
            .unwrap()
            .threat_actor_types(vec!["activist".to_string(), "crime-syndicate".to_string()])
            .unwrap()
            .aliases(vec!["TA123, Cyber Espionage Group".to_string()])
            .unwrap()
            .first_seen("2023-10-01T00:00:00.000Z".to_string())
            .unwrap()
            .last_seen("2023-10-01T00:00:00.000Z".to_string())
            .unwrap()
            .roles(vec!["agent".to_string(), "malware author".to_string()])
            .unwrap()
            .goals(vec!["disrupt communications".to_string()])
            .unwrap()
            .sophistication("advanced".to_string())
            .unwrap()
            .resource_level("government".to_string())
            .unwrap()
            .primary_motivation("ideology".to_string())
            .unwrap()
            .secondary_motivations(vec!["organizational-gain".to_string()])
            .unwrap()
            .personal_motivations(vec!["personal-gain".to_string()])
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        let mut result = serde_json::to_string_pretty(&threat_actor).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected_value = r#"{
            "type": "threat-actor",
            "name" : "Threat Actor Group",
            "description": "A group known for cyber espionage",
            "threat_actor_types": ["activist","crime-syndicate"],
            "aliases": ["TA123, Cyber Espionage Group"],
            "first_seen": "2023-10-01T00:00:00Z",
            "last_seen": "2023-10-01T00:00:00Z",
            "roles": ["agent", "malware author"],
            "goals" : ["disrupt communications"],
            "sophistication": "advanced",
            "resource_level" : "government",
            "primary_motivation": "ideology",
            "secondary_motivations": ["organizational-gain"],
            "personal_motivations": ["personal-gain"],
            "spec_version": "2.1",
            "id": "threat-actor--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "external_references": [
                {
                "source_name": "capec",
                 "external_id": "CAPEC-163"
                }
            ]
   }"#
        .to_string();
        expected_value.retain(|c| !c.is_whitespace());

        assert_eq!(&result, &expected_value)
    }

    #[test]
    fn deserialize_threat_actor() {
        let json = r#"{
            "type": "threat-actor",
            "name" : "Threat Actor Group",
            "description": "A group known for cyber espionage",
            "threat_actor_types": ["activist","crime-syndicate"],
            "aliases": ["TA123, Cyber Espionage Group"],
            "first_seen": "2023-10-01T00:00:00Z",
            "last_seen": "2023-10-01T00:00:00Z",
            "roles": ["agent", "malware author"],
            "goals" : ["disrupt communications"],
            "sophistication": "advanced",
            "resource_level" : "government",
            "primary_motivation": "ideology",
           "secondary_motivations": ["organizational-gain"],
            "personal_motivations": ["personal-gain"],
            "spec_version": "2.1",
            "id": "threat-actor--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "external_references": [
                {
                "source_name": "capec",
                 "external_id": "CAPEC-163"
                }
            ]
        }"#
        .to_string();

        let result = DomainObject::from_json(&json, false).unwrap();

        let expected = DomainObjectBuilder::new("threat-actor")
            .unwrap()
            .name("Threat Actor Group".to_string())
            .unwrap()
            .description("A group known for cyber espionage".to_string())
            .unwrap()
            .threat_actor_types(vec!["activist".to_string(), "crime-syndicate".to_string()])
            .unwrap()
            .aliases(vec!["TA123, Cyber Espionage Group".to_string()])
            .unwrap()
            .first_seen("2023-10-01T00:00:00.000Z".to_string())
            .unwrap()
            .last_seen("2023-10-01T00:00:00.000Z".to_string())
            .unwrap()
            .roles(vec!["agent".to_string(), "malware author".to_string()])
            .unwrap()
            .goals(vec!["disrupt communications".to_string()])
            .unwrap()
            .sophistication("advanced".to_string())
            .unwrap()
            .resource_level("government".to_string())
            .unwrap()
            .primary_motivation("ideology".to_string())
            .unwrap()
            .secondary_motivations(vec!["organizational-gain".to_string()])
            .unwrap()
            .personal_motivations(vec!["personal-gain".to_string()])
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        assert_eq!(result, expected);
    }

    #[test]
    fn serialize_tool() {
        let tool = DomainObjectBuilder::new("tool")
            .unwrap()
            .name("Network Scanner".to_string())
            .unwrap()
            .description("A tool used for scanning and identifying network assets.".to_string())
            .unwrap()
            .tool_types(vec!["credential-exploitation".to_string()])
            .unwrap()
            .aliases(vec!["NetScan".to_string(), "Asset Mapper".to_string()])
            .unwrap()
            .kill_chain_phases(vec![KillChainPhase::new(
                "mitre-attack",
                "credential-access",
            )])
            .unwrap()
            .tool_version("1.0.3".to_string())
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&tool).unwrap();

        let expected = r#"{
        "type": "tool",
        "spec_version": "2.1",
        "id": "tool--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "name": "Network Scanner",
        "aliases": ["NetScan", "Asset Mapper"],
        "tool_types": ["credential-exploitation"],
        "description": "A tool used for scanning and identifying network assets.",
        "kill_chain_phases": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "credential-access"
            }
        ],
        "tool_version": "1.0.3"
        }"#;

        //Deserialization (from_str): Converts JSON text into Value, which is an in-memory representation of JSON data
        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn tool_invalid_kill_chain() {
        let test_vals = vec![
            "With Uppercase",
            "with_underscores",
            "with spaces",
            "double--hyphen",
            "-leading-hyphen",
            "trailing-hyphen-",
        ];

        let mut all_invalid = true;

        for val in test_vals {
            let tool = DomainObjectBuilder::new("tool")
                .unwrap()
                .name("Network Scanner".to_string())
                .unwrap()
                .description("A tool used for scanning and identifying network assets.".to_string())
                .unwrap()
                .tool_types(vec!["credential-exploitation".to_string()])
                .unwrap()
                .aliases(vec!["NetScan".to_string(), "Asset Mapper".to_string()])
                .unwrap()
                .kill_chain_phases(vec![KillChainPhase::new(val, val)])
                .unwrap()
                .tool_version("1.0.3".to_string())
                .unwrap()
                .build();
            if tool.is_ok() {
                all_invalid = false;
                warn!(
                    "Test String Value in Kill Chain '{}' should be invalid but passed",
                    val
                );
            }
        }
        assert!(
            all_invalid,
            "Not all Test String Value in Kill Chain were invalid"
        );
    }

    #[test]
    fn tool_valid_kill_chain() {
        let test_vals = vec!["all-lowercase", "no-underscores", "no-spaces-here"];

        let mut all_valid = true;

        for val in test_vals {
            let tool = DomainObjectBuilder::new("tool")
                .unwrap()
                .name("Network Scanner".to_string())
                .unwrap()
                .description("A tool used for scanning and identifying network assets.".to_string())
                .unwrap()
                .tool_types(vec!["credential-exploitation".to_string()])
                .unwrap()
                .aliases(vec!["NetScan".to_string(), "Asset Mapper".to_string()])
                .unwrap()
                .kill_chain_phases(vec![KillChainPhase::new(val, val)])
                .unwrap()
                .tool_version("1.0.3".to_string())
                .unwrap()
                .build();
            if tool.is_err() {
                all_valid = false;
                warn!(
                    "Test String Value in Kill Chain '{}' should be valid but failed",
                    val
                );
            }
        }
        assert!(all_valid, "All Test String Value in Kill Chain were valid");
    }

    #[test]
    fn deserialize_tool() {
        let json = r#"{
        "type": "tool",
        "spec_version": "2.1",
        "id": "tool--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "name": "Network Scanner",
        "aliases": ["NetScan", "Asset Mapper"],
        "tool_types": ["credential-exploitation"],
        "description": "A tool used for scanning and identifying network assets.",
        "kill_chain_phases": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "credential-access"
            }
        ],
        "tool_version": "1.0.3"
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();

        let expected = DomainObjectBuilder::new("tool")
            .unwrap()
            .name("Network Scanner".to_string())
            .unwrap()
            .description("A tool used for scanning and identifying network assets.".to_string())
            .unwrap()
            .tool_types(vec!["credential-exploitation".to_string()])
            .unwrap()
            .aliases(vec!["NetScan".to_string(), "Asset Mapper".to_string()])
            .unwrap()
            .kill_chain_phases(vec![KillChainPhase::new(
                "mitre-attack",
                "credential-access",
            )])
            .unwrap()
            .tool_version("1.0.3".to_string())
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");
        assert_eq!(result, expected);
    }

    #[test]
    fn serialize_vulnerability() {
        let vulnerabililty = DomainObjectBuilder::new("vulnerability")
            .unwrap()
            .name("vulnerability".to_string())
            .unwrap()
            .description("vulnerability desc".to_string())
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&vulnerabililty).unwrap();

        let expected = r#"{
            "type": "vulnerability",
            "name": "vulnerability",
            "description": "vulnerability desc",
            "spec_version": "2.1",
            "id": "vulnerability--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "external_references": [
            {
            "source_name": "capec",
            "external_id": "CAPEC-163"
            }
        ]
        }"#;

        //Deserialization (from_str): Converts JSON text into Value, which is an in-memory representation of JSON data
        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(&result, &expected_value)
    }

    #[test]
    fn deserialize_vulnerability() {
        let json = r#"{
            "type": "vulnerability",
            "name": "vulnerability",
            "description": "vulnerability desc",
            "spec_version": "2.1",
            "id": "vulnerability--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "external_references": [
            {
            "source_name": "capec",
            "external_id": "CAPEC-163"
            }
        ]
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();

        let expected = DomainObjectBuilder::new("vulnerability")
            .unwrap()
            .name("vulnerability".to_string())
            .unwrap()
            .description("vulnerability desc".to_string())
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        assert_eq!(result, expected);
    }

    // tests for managing unknown fields in json as it is serialized/deserialized
    #[test]
    fn test_get_keys() {
        let example = DomainObjectBuilder::new("indicator")
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
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        let keys = crate::json::get_keys(&example).unwrap();
        assert_eq!(
            keys,
            vec![
                "created".to_string(),
                "description".to_string(),
                "external_references".to_string(),
                "id".to_string(),
                "indicator_types".to_string(),
                "modified".to_string(),
                "name".to_string(),
                "pattern".to_string(),
                "pattern_type".to_string(),
                "pattern_version".to_string(),
                "spec_version".to_string(),
                "type".to_string(),
                "valid_from".to_string(),
                "valid_until".to_string(),
            ]
        );
    }

    #[test]
    fn test_find_differences() {
        let json_str = r#"{
        "type": "indicator",
        "name": "Indicator",
        "description": "This indicator detects connections to a known malicious IP address",
        "indicator_types": [
                "malicious-activity"
            ],
        "pattern": "[type=domain-name,value='example.com']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2016-05-12T08:17:27Z",
        "valid_until":"2023-10-05T10:00:00Z",
        "spec_version": "2.1",
        "id": "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "banana":"banana",
        "junk":"junk",
        "apple":"apple",
        "external_references": [
            {
            "source_name": "capec",
            "external_id": "CAPEC-163"
            }
        ]
        }"#;

        let example: Value = serde_json::from_str(json_str).unwrap();
        let check_fields = crate::json::get_keys(&example).unwrap();
        let correct_fields = vec![
            String::from("apple"),
            String::from("fig"),
            String::from("orange"),
        ];
        let unknown_fields = vec![
            "banana".to_string(),
            "created".to_string(),
            "description".to_string(),
            "external_references".to_string(),
            "id".to_string(),
            "indicator_types".to_string(),
            "junk".to_string(),
            "modified".to_string(),
            "name".to_string(),
            "pattern".to_string(),
            "pattern_type".to_string(),
            "pattern_version".to_string(),
            "spec_version".to_string(),
            "type".to_string(),
            "valid_from".to_string(),
            "valid_until".to_string(),
        ];

        let result = crate::json::find_differences(&check_fields, &correct_fields);

        assert_eq!(result, unknown_fields);
    }

    #[test]
    fn test_field_check_valid() {
        let json_str_valid = r#"{
        "type": "indicator",
        "name": "Indicator",
        "description": "This indicator detects connections to a known malicious IP address",
        "indicator_types": [
                "malicious-activity"
            ],
        "pattern": "[domain-name:value = 'example.com']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2016-05-12T08:17:27Z",
        "valid_until":"2023-10-05T10:00:00Z",
        "spec_version": "2.1",
        "id": "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "external_references": [
            {
            "source_name": "capec",
            "external_id": "CAPEC-163"
            }
        ]
        }"#;

        let expected: DomainObject = serde_json::from_str(json_str_valid).unwrap();
        let deserialized_valid = DomainObject::from_json(json_str_valid, false).unwrap();
        assert_eq!(deserialized_valid, expected);
    }

    #[test]
    fn test_field_check_invalid() {
        let json_str_invalid = r#"{
        "type": "indicator",
        "name": "Indicator",
        "description": "This indicator detects connections to a known malicious IP address",
        "indicator_types": [
                "malicious-activity"
            ],
        "pattern": "[type=domain-name,value='example.com']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2016-05-12T08:17:27Z",
        "valid_until":"2023-10-05T10:00:00Z",
        "spec_version": "2.1",
        "id": "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "junk":"junk",
        "external_references": [
            {
            "source_name": "capec",
            "external_id": "CAPEC-163"
            }
        ]
        }"#;

        let deserialized_invalid = DomainObject::from_json(json_str_invalid, false);
        assert!(deserialized_invalid.is_err());
    }

    #[test]
    fn test_custom_field_check_invalid() {
        let json_str_invalid = r#"{
        "type": "indicator",
        "name": "Indicator",
        "description": "This indicator detects connections to a known malicious IP address",
        "indicator_types": [
                "malicious-activity"
            ],
        "pattern": "[domain-name:value = 'example.com']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2016-05-12T08:17:27Z",
        "valid_until":"2023-10-05T10:00:00Z",
        "spec_version": "2.1",
        "id": "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "junk":"junk",
        "external_references": [
            {
            "source_name": "capec",
            "external_id": "CAPEC-163"
            }
        ]
        }"#;

        let deserialized_invalid = DomainObject::from_json(json_str_invalid, true);
        assert!(deserialized_invalid.is_ok());
    }
}
