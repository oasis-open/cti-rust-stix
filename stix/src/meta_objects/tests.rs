#[cfg(test)]
mod test {
    use crate::{
        meta_objects::{
            extension_definition::{ExtensionDefinition, ExtensionDefinitionBuilder},
            language_content::{ContentType, LanguageContent, LanguageContentBuilder},
            marking_definition::{
                MarkingDefinition, MarkingDefinitionBuilder, MarkingTypes, Statement,
            },
        },
        types::{ExtensionType, Identifier, StixDictionary, Timestamp},
    };

    // Functions for editing otherwise un-editable fields, for testing only
    impl LanguageContent {
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

    fn german_content() -> StixDictionary<ContentType> {
        let mut content = StixDictionary::new();
        content
            .insert("name", ContentType::String("Böse Org".to_string()))
            .unwrap();
        content
            .insert(
                "description",
                ContentType::String("Die Bedrohungsakteursgruppe 'Böse Org'".to_string()),
            )
            .unwrap();
        content
            .insert(
                "goals",
                ContentType::List(vec![
                    "Bankgeld stehlen".to_string(),
                    "Kreditkarten stehlen".to_string(),
                ]),
            )
            .unwrap();
        content
    }

    fn french_content() -> StixDictionary<ContentType> {
        let mut content = StixDictionary::new();
        content
            .insert(
                "name",
                ContentType::String("Organisation maléfique".to_string()),
            )
            .unwrap();
        content
            .insert(
                "description",
                ContentType::String(
                    "Le groupe d'acteurs de la menace Organisation maléfique".to_string(),
                ),
            )
            .unwrap();
        content
            .insert(
                "goals",
                ContentType::List(vec![
                    "Voler de l'argent en banque".to_string(),
                    "".to_string(),
                ]),
            )
            .unwrap();
        content
    }

    #[test]
    fn serialize_language_content() {
        let language_content =
            LanguageContentBuilder::new("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
                .unwrap()
                .object_modified("2017-02-08T21:31:22.007Z")
                .unwrap()
                .insert_content("de", german_content())
                .unwrap()
                .insert_content("fr", french_content())
                .unwrap()
                .build()
                .unwrap()
                // Change id, created, and modified fields for test matching
                .test_id()
                .created("2019-06-08T21:31:22.007Z")
                .modified("2019-07-08T21:31:22.007Z");

        let mut result = serde_json::to_string_pretty(&language_content).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
            "type": "language-content",
            "spec_version": "2.1",
            "id": "language-content--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2019-06-08T21:31:22.007Z",
            "modified": "2019-07-08T21:31:22.007Z",
            "object_ref": "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "object_modified": "2017-02-08T21:31:22.007Z",
            "contents": {
            "de": {
            "description": "Die Bedrohungsakteursgruppe 'Böse Org'",
            "goals": ["Bankgeld stehlen", "Kreditkarten stehlen"],
            "name": "Böse Org"
            },
            "fr": {
            "description": "Le groupe d'acteurs de la menace Organisation maléfique",
            "goals": ["Voler de l'argent en banque", ""],
            "name": "Organisation maléfique"
            }
            }
            }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_language_content() {
        let json = r#"{
            "type": "language-content",
            "spec_version": "2.1",
            "id": "language-content--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2019-06-08T21:31:22.007Z",
            "modified": "2019-07-08T21:31:22.007Z",
            "object_ref": "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "object_modified": "2017-02-08T21:31:22.007Z",
            "contents": {
            "de": {
            "description": "Die Bedrohungsakteursgruppe 'Böse Org'",
            "goals": ["Bankgeld stehlen", "Kreditkarten stehlen"],
            "name": "Böse Org"
            },
            "fr": {
            "description": "Le groupe d'acteurs de la menace Organisation maléfique",
            "goals": ["Voler de l'argent en banque", ""],
            "name": "Organisation maléfique"
            }
            }
            }"#;

        let result = LanguageContent::from_json(json, false).unwrap();

        let expected =
            LanguageContentBuilder::new("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
                .unwrap()
                .object_modified("2017-02-08T21:31:22.007Z")
                .unwrap()
                .insert_content("de", german_content())
                .unwrap()
                .insert_content("fr", french_content())
                .unwrap()
                .build()
                .unwrap()
                // Change id, created, and modified fields for test matching
                .test_id()
                .created("2019-06-08T21:31:22.007Z")
                .modified("2019-07-08T21:31:22.007Z");

        assert_eq!(result, expected);
    }

    #[test]
    fn serialize_language_content_bad_ref() {
        let language_content = LanguageContentBuilder::new("foo--12345");
        assert!(language_content.is_err())
    }

    #[test]
    fn serialize_language_content_invalid_lang() {
        let language_content =
            LanguageContentBuilder::new("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
                .unwrap()
                .insert_content("ger", german_content())
                .unwrap()
                .build();

        assert!(language_content.is_err())
    }

    impl ExtensionDefinition {
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
    fn serialize_extension_definition() {
        let extension_definition = ExtensionDefinitionBuilder::new("Extension My Favorite SDO and Sub-Comp")
            .unwrap()
            .created_by_ref(Identifier::new_test("identity"))
            .unwrap()
            .description("This schema adds a new object my-favorite-sdo and some sub-component to existing objects".to_string())
            .schema("https://www.example.com/schema-newobj-subcomp/v1/schema.json".to_string())
            .set_version("1.2.1".to_string())
            .extension_types(vec![ExtensionType::NewSdo, ExtensionType::NewSco, ExtensionType::PropertyExtension])
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2019-06-08T21:31:22.007Z")
            .modified("2019-07-08T21:31:22.007Z");

        let mut result = serde_json::to_string_pretty(&extension_definition).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
            "type": "extension-definition",
            "spec_version": "2.1",
            "id": "extension-definition--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created_by_ref": "identity--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2019-06-08T21:31:22.007Z",
            "modified": "2019-07-08T21:31:22.007Z",
            "name": "Extension My Favorite SDO and Sub-Comp",
            "description": "This schema adds a new object my-favorite-sdo and some sub-component to existing objects",
            "schema": "https://www.example.com/schema-newobj-subcomp/v1/schema.json",
            "version": "1.2.1",
            "extension_types": [ "new-sdo", "new-sco", "property-extension" ]
            }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_extension_definition() {
        let json = r#"{
            "type": "extension-definition",
            "spec_version": "2.1",
            "id": "extension-definition--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created_by_ref": "identity--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2019-06-08T21:31:22.007Z",
            "modified": "2019-07-08T21:31:22.007Z",
            "name": "Extension My Favorite SDO and Sub-Comp",
            "description": "This schema adds a new object my-favorite-sdo and some sub-component to existing objects",
            "schema": "https://www.example.com/schema-newobj-subcomp/v1/schema.json",
            "version": "1.2.1",
            "extension_types": [ "new-sdo", "new-sco", "property-extension" ]
            }"#;

        let result = ExtensionDefinition::from_json(json, false).unwrap();

        let expected = ExtensionDefinitionBuilder::new("Extension My Favorite SDO and Sub-Comp")
            .unwrap()
            .created_by_ref(Identifier::new_test("identity"))
            .unwrap()
            .description("This schema adds a new object my-favorite-sdo and some sub-component to existing objects".to_string())
            .schema("https://www.example.com/schema-newobj-subcomp/v1/schema.json".to_string())
            .set_version("1.2.1".to_string())
            .extension_types(vec![ExtensionType::NewSdo, ExtensionType::NewSco, ExtensionType::PropertyExtension])
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2019-06-08T21:31:22.007Z")
            .modified("2019-07-08T21:31:22.007Z");

        assert_eq!(result, expected);
    }

    impl MarkingDefinition {
        fn test_id(mut self) -> Self {
            let object_type = self.object_type.as_ref();
            self.common_properties.id = Identifier::new_test(object_type);
            self
        }

        fn created(mut self, datetime: &str) -> Self {
            self.common_properties.created = Some(Timestamp(datetime.parse().unwrap()));
            self
        }
    }
    #[test]
    fn serialize_marking_definition() {
        let marking_definition = MarkingDefinitionBuilder::new()
            .unwrap()
            .definition_type("statement".to_string())
            .definition(MarkingTypes::Statement(Statement {
                statement: "Copyright 2019, Example Corp".to_string(),
            }))
            .build()
            .unwrap()
            .test_id()
            .created("2016-08-01T00:00:00.000Z");
        let mut result = serde_json::to_string_pretty(&marking_definition).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": "marking-definition--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-08-01T00:00:00Z",
            "definition_type": "statement",
            "definition": {
              "statement": "Copyright 2019, Example Corp"
            }
          }"#
        .to_string();

        expected.retain(|c| !c.is_whitespace());
        assert_eq!(result, expected);
    }
    #[test]
    fn deserialize_marking_definition() {
        let json = r#"{
      "type": "marking-definition",
      "spec_version": "2.1",
      "id": "marking-definition--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
      "created": "2016-08-01T00:00:00.000Z",
      "definition_type": "statement",
      "definition": {
        "statement": "Copyright 2019, Example Corp"
      }
    }"#;
        let result = MarkingDefinition::from_json(json, false).unwrap();
        let expected = MarkingDefinitionBuilder::new()
            .unwrap()
            .definition_type("statement".to_string())
            .definition(MarkingTypes::Statement(Statement {
                statement: "Copyright 2019, Example Corp".to_string(),
            }))
            .build()
            .unwrap()
            .test_id()
            .created("2016-08-01T00:00:00.000Z");
        assert_eq!(result, expected);
    }
}
