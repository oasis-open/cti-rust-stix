#[cfg(test)]
mod test {
    // use std::any::Any;
    use crate::{
        cyber_observable_objects::{
            sco::{CyberObject, CyberObjectBuilder},
            sco_types::{EmailMimeCompomentType, X509V3Extensions},
            vocab::EncryptionAlgorithm,
        },
        extensions::{
            ArchiveExtension, FileExtensions, HttpRequestExtension, IcmpExtension,
            NetworkTrafficExtensions, ProcessExtensions, SocketExtenion, SpecialExtensions,
            UnixAccountExtension, UserAccountExtensions, WindowsProcessExtension,
        },
        types::{DictionaryValue, Hashes, Identifier, StixDictionary, Timestamp},
    };
    use log::warn;
    use serde_json::Value;
    use std::{collections::HashMap, str::FromStr};
    use test_log::test;

    // Functions for editing otherwise un-editable fields, for testing only
    impl CyberObject {
        fn test_id(mut self) -> Self {
            let object_type = self.object_type.as_ref();
            self.common_properties.id = Identifier::new_test(object_type);
            self
        }
    }

    #[test]
    fn try_build_with_required_field() {
        let artifact = CyberObjectBuilder::new("artifact")
            .unwrap()
            .mime_type("test".to_string())
            .unwrap()
            .url("https://www.test.com".to_string())
            .unwrap()
            .hashes(
                Hashes::new(
                    "SHA-256",
                    "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b",
                )
                .unwrap(),
            )
            .unwrap()
            .encryption_algorithm(EncryptionAlgorithm::MimeTypeIndicated)
            .unwrap()
            .decryption_key("test".to_string())
            .unwrap()
            .build();
        assert!(artifact.is_ok());
    }
    #[test]
    fn try_build_without_required_field() {
        let artifact = CyberObjectBuilder::new("artifact").unwrap().build();
        assert!(artifact.is_err());
    }

    #[test]
    fn create_uuidv5_with_required_field() {
        // `number` is a required ID contributing property for an AutonomuousSystem SCO
        let autonomous_system = CyberObjectBuilder::new("autonomous-system")
            .unwrap()
            .number(50)
            .unwrap()
            .build()
            .unwrap();

        let uuid_version = autonomous_system.common_properties.id.get_uuid_version();

        assert_eq!(uuid_version, "UUIDv5");
    }

    #[test]
    fn u64_max_test() {
        let limit: u64 = 1 << 53;
        let autonomous_system = CyberObjectBuilder::new("autonomous-system")
            .unwrap()
            .number(limit)
            .unwrap()
            .build();
        assert!(autonomous_system.is_err());
        let autonomous_system = CyberObjectBuilder::new("autonomous-system")
            .unwrap()
            .number(limit - 1)
            .unwrap()
            .build();
        assert!(autonomous_system.is_ok());
    }

    #[test]
    fn create_uuidv5_with_optional_fields() {
        // `payload_bin` and `hashes` are both optional ID contributing properties for an Artifact SCO
        let artifact = CyberObjectBuilder::new("artifact")
            .unwrap()
            .payload_bin("aGVsbG8gd29ybGR+Cg==".to_string())
            .unwrap()
            .hashes(
                Hashes::new(
                    "SHA-256",
                    "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b",
                )
                .unwrap(),
            )
            .unwrap()
            .build()
            .unwrap();

        let uuid_version = artifact.common_properties.id.get_uuid_version();

        assert_eq!(uuid_version, "UUIDv5");
    }

    #[test]
    fn create_uuidv4_with_missing_optional_fields() {
        let multipart = EmailMimeCompomentType {
            body: Some("Cats are funny!".to_string()),
            body_raw_ref: None,
            content_type: Some("text/plain; charset=utf-8".to_string()),
            content_disposition: Some("inline".to_string()),
        };

        // `from_ref`, `subject`, and `body` are the only ID contributing properties to an EmailMessage SCO
        // Because they are all optinonal, it is possible to have such an SCO with no properties to generate a UUIDv5
        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .is_multipart()
            .unwrap()
            .body_multipart(vec![multipart.clone()])
            .unwrap()
            .build()
            .unwrap();

        let uuid_version = email_message.common_properties.id.get_uuid_version();

        assert_eq!(uuid_version, "UUIDv4");
    }

    #[test]
    fn artifact_hash_valid() {
        // test hash values that are intentionally correct
        let mut test_strings = HashMap::new();
        test_strings.insert("d41d8cd98f00b204e9800998ecf8427e", "MD-5");
        test_strings.insert("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "SHA-1");
        test_strings.insert(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA-256",
        );
        test_strings.insert(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA3-256",
        );
        test_strings.insert("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "SHA-512");
        test_strings.insert("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "SHA3-512");
        // using hash example from https://ssdeep-project.github.io/ssdeep/usage.html
        test_strings.insert("96:s4Ud1Lj96tHHlZDrwciQmA+4uy1I0G4HYuL8N3TzS8QsO/wqWXLcMSx:sF1LjEtHHlZDrJzrhuyZvHYm8tKp/RWO", "SSDEEP");
        test_strings.insert(
            "dd0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123",
            "TLSH",
        );

        let mut all_valid = true;

        for (hash, hash_type) in test_strings {
            let artifact = CyberObjectBuilder::new("artifact")
                .unwrap()
                .payload_bin("aGVsbG8gd29ybGR+Cg==".to_string())
                .unwrap()
                .hashes(Hashes::new(hash_type, hash).unwrap())
                .unwrap()
                .build();
            if artifact.is_err() {
                all_valid = false;
                eprintln!(
                    "Artifiact hashes '{}' should be valid but failed as invalid {}",
                    hash, hash_type
                );
            }
        }

        assert!(all_valid, "Not all hashes were valid");
    }

    #[test]
    fn artifact_hash_invalid() {
        // test hash values that are intentionally incorrect
        let mut test_strings = HashMap::new();
        test_strings.insert("d41d8cd98f00b204e9800998ecf8427e", "SHA-1");
        test_strings.insert("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "MD5");
        test_strings.insert(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA-512",
        );
        test_strings.insert(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA3-512",
        );
        test_strings.insert("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "SHA-256");
        test_strings.insert("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "SHA3-256");
        test_strings.insert("3:abc:def", "TLSH");
        test_strings.insert(
            "dd0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123",
            "SSDEEP",
        );

        let mut all_invalid = true;

        for (hash, hash_type) in test_strings {
            let artifact = CyberObjectBuilder::new("artifact")
                .unwrap()
                .payload_bin("VBORw0KGgoAAAANSUhEUgAAADI== ...".to_string())
                .unwrap()
                .hashes(Hashes::new(hash_type, hash).unwrap())
                .unwrap()
                .build();
            if artifact.is_ok() {
                all_invalid = false;
                eprintln!(
                    "Artifiact hashes '{}' should be invalid but passed as valid {}",
                    hash, hash_type
                );
            }
        }

        assert!(all_invalid, "Not all hashes were valid");
    }

    #[test]
    fn deserialize_artifact() {
        let json = r#"{"type":"artifact","mime_type":"test","url":"https://www.test.com","hashes":{"SHA-256":"6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b"},"encryption_algorithm":{"type": "mime-type-indicated"},"decryption_key":"test","spec_version":"2.1","id":"artifact--cc7fa653-c35f-43db-afdd-dce4c3a241d5"}"#;
        let result = CyberObject::from_json(json, false).unwrap();
        let artifact = CyberObjectBuilder::new("artifact")
            .unwrap()
            .mime_type("test".to_string())
            .unwrap()
            .url("https://www.test.com".to_string())
            .unwrap()
            .hashes(
                Hashes::new(
                    "SHA-256",
                    "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b",
                )
                .unwrap(),
            )
            .unwrap()
            .encryption_algorithm(EncryptionAlgorithm::MimeTypeIndicated)
            .unwrap()
            .decryption_key("test".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();
        assert_eq!(result, artifact)
    }

    #[test]
    fn deserialize_autonomous_system() {
        let json = r#"{
        "type":"autonomous-system",
        "number":50,
        "name":"Slime Industries",
        "rir":"ARIN",
        "spec_version":"2.1",
        "id":"autonomous-system--cc7fa653-c35f-43db-afdd-dce4c3a241d5"
        }"#;

        let result = CyberObject::from_json(json, false).unwrap();

        let autonomous_system = CyberObjectBuilder::new("autonomous-system")
            .unwrap()
            .number(50)
            .unwrap()
            .name("Slime Industries".to_string())
            .unwrap()
            .rir("ARIN".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        assert_eq!(result, autonomous_system)
    }

    #[test]
    fn serialize_autonomous_system() {
        let autonomous_system = CyberObjectBuilder::new("autonomous-system")
            .unwrap()
            .number(50)
            .unwrap()
            .name("Slime Industries".to_string())
            .unwrap()
            .rir("ARIN".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let mut result = serde_json::to_string_pretty(&autonomous_system).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
        "type":"autonomous-system",
        "number":50,
        "name":"Slime Industries",
        "rir":"ARIN",
        "spec_version":"2.1",
        "id":"autonomous-system--cc7fa653-c35f-43db-afdd-dce4c3a241d5"
        }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected)
    }

    #[test]
    fn deserialize_autonomous_system_number_quote_test() {
        let autonomous_system = CyberObjectBuilder::new("autonomous-system")
            .unwrap()
            .number(50)
            .unwrap()
            .name("Slime Industries".to_string())
            .unwrap()
            .rir("ARIN".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let json = r#"{
        "type":"autonomous-system",
        "number":"50",
        "name":"Slime Industries",
        "rir":"ARIN",
        "spec_version":"2.1",
        "id":"autonomous-system--cc7fa653-c35f-43db-afdd-dce4c3a241d5"
        }"#
        .to_string();
        let expected = CyberObject::from_json(&json, false).unwrap();

        assert_eq!(autonomous_system, expected)
    }

    #[test]
    fn deserialize_autonomous_system_number_no_quote_test() {
        let autonomous_system = CyberObjectBuilder::new("autonomous-system")
            .unwrap()
            .number(50)
            .unwrap()
            .name("Slime Industries".to_string())
            .unwrap()
            .rir("ARIN".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let json = r#"{
        "type":"autonomous-system",
        "number":50,
        "name":"Slime Industries",
        "rir":"ARIN",
        "spec_version":"2.1",
        "id":"autonomous-system--cc7fa653-c35f-43db-afdd-dce4c3a241d5"
        }"#
        .to_string();
        let expected = CyberObject::from_json(&json, false).unwrap();

        assert_eq!(autonomous_system, expected)
    }

    #[test]
    fn deserialize_directory() {
        let json = r#"{
            "type": "directory",
            "spec_version": "2.1",  
            "id": "directory--cc7fa653-c35f-43db-afdd-dce4c3a241d5", 
            "path": "C:\\Windows\\System32"
        }"#;
        let result = CyberObject::from_json(json, false).unwrap();
        let directory = CyberObjectBuilder::new("directory")
            .unwrap()
            .path("C:\\Windows\\System32".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();
        assert_eq!(result, directory)
    }
    #[test]
    fn serialize_directory() {
        let directory = CyberObjectBuilder::new("directory")
            .unwrap()
            .path("C:\\Windows\\System32".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let mut result = serde_json::to_string_pretty(&directory).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
            "type": "directory",
            "path": "C:\\Windows\\System32",
            "spec_version": "2.1",
            "id": "directory--cc7fa653-c35f-43db-afdd-dce4c3a241d5"
        }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected)
    }

    #[test]
    fn serialize_emailaddress() {
        let email_address = CyberObjectBuilder::new("email-address")
            .unwrap()
            .value("john@example.com".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&email_address).unwrap();

        let expected = r#"{
            "type": "email-address",
            "spec_version": "2.1",
            "id": "email-address--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "value": "john@example.com"
        }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn deserialize_emailaddress() {
        let json = r#"{
            "type": "email-address",
            "spec_version": "2.1",
            "id": "email-address--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "value": "john@example.com"
        }"#;
        let result = CyberObject::from_json(json, false).unwrap();
        let email_address = CyberObjectBuilder::new("email-address")
            .unwrap()
            .value("john@example.com".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();
        assert_eq!(result, email_address)
    }

    #[test]
    fn email_display_nameinvalid() {
        let email_address = CyberObjectBuilder::new("email-address")
            .unwrap()
            .value("john@example.com".to_string())
            .unwrap()
            .display_name("john@example.com".to_string())
            .unwrap()
            .build();
        assert!(email_address.is_err());
    }

    #[test]
    fn email_belongs_to_ref() {
        let email_address = CyberObjectBuilder::new("email-address")
            .unwrap()
            .value("john@example.com".to_string())
            .unwrap()
            .display_name("john doe".to_string())
            .unwrap()
            .belongs_to_ref(Identifier::new("user-account").unwrap())
            .unwrap()
            .build();
        assert!(email_address.is_ok());
    }

    #[test]
    fn try_email_invalid() {
        let test_addresses = vec![
            "foobar",       // invalid email
            "john@example", // invalid email
            "foo-bar.com",  // invalid email
        ];

        let mut all_invalid = true;

        for address in test_addresses {
            let email_address = CyberObjectBuilder::new("email-address")
                .unwrap()
                .value(address.to_string())
                .unwrap()
                .build();
            if email_address.is_ok() {
                all_invalid = false;
                warn!("Email Address '{}' should be invalid but passed", address);
            }
        }
        assert!(all_invalid, "Not all email addresses were invalid");
    }

    #[test]
    fn try_email_valid() {
        let test_addresses = vec![
            "foobar@foobar.edu",        // valid email
            "john.doe@example.com",     // valid email
            "username-test@foo-bar.au", // valid email
        ];

        let mut all_valid = true;

        for address in test_addresses {
            let email_address = CyberObjectBuilder::new("email-address")
                .unwrap()
                .value(address.to_string())
                .unwrap()
                .build();
            if email_address.is_err() {
                all_valid = false;
                warn!("Email Address '{}' should be valid but failed", address);
            }
        }
        assert!(all_valid, "All email addresses were valid");
    }

    #[test]
    fn deserialize_emailmessage() {
        let json = r#"{
            "type": "email-message",
            "spec_version": "2.1",
            "id": "email-message--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "from_ref": "email-addr--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "to_refs": ["email-addr--cc7fa653-c35f-43db-afdd-dce4c3a241d5"],
            "is_multipart": false,
            "date": "1997-11-21T15:55:06Z",
            "subject": "Saying Hello"
        }"#;
        let result = CyberObject::from_json(json, false).unwrap();
        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .from_ref(Identifier::new_test("email-addr"))
            .unwrap()
            .to_refs([Identifier::new_test("email-addr")].to_vec())
            .unwrap()
            .date(Timestamp("1997-11-21T15:55:06Z".parse().unwrap()))
            .unwrap()
            .subject("Saying Hello".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();
        assert_eq!(result, email_message)
    }
    #[test]
    fn serialize_emailmessage() {
        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .from_ref(Identifier::new_test("email-addr"))
            .unwrap()
            .to_refs([Identifier::new_test("email-addr")].to_vec())
            .unwrap()
            .date(Timestamp("1997-11-21T15:55:06Z".parse().unwrap()))
            .unwrap()
            .subject("Saying Hello".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();
        let mut result = serde_json::to_string_pretty(&email_message).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
            "type": "email-message",
            "is_multipart": false,
            "date": "1997-11-21T15:55:06Z",
            "from_ref": "email-addr--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "to_refs": ["email-addr--cc7fa653-c35f-43db-afdd-dce4c3a241d5"],
            "subject": "Saying Hello",
            "spec_version": "2.1",
            "id": "email-message--cc7fa653-c35f-43db-afdd-dce4c3a241d5"
        }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected)
    }

    #[test]
    //checks multipart funtionality with body and body_multipart
    fn emailmessage_multipart_checks() {
        let multipart = EmailMimeCompomentType {
            body: Some("Cats are funny!".to_string()),
            body_raw_ref: None,
            content_type: Some("text/plain; charset=utf-8".to_string()),
            content_disposition: Some("inline".to_string()),
        };

        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .is_multipart()
            .unwrap()
            .body("test".to_string())
            .unwrap()
            .build();
        assert!(email_message.is_err());
        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .body("test".to_string())
            .unwrap()
            .build();
        assert!(email_message.is_ok());
        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .is_multipart()
            .unwrap()
            .body_multipart(vec![multipart.clone()])
            .unwrap()
            .build();
        assert!(email_message.is_ok());
        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .body_multipart(vec![multipart])
            .unwrap()
            .build();
        assert!(email_message.is_err());
    }

    #[test]
    fn emailmessage_referece_check_failure() {
        let multipart = EmailMimeCompomentType {
            body: Some("Cats are funny!".to_string()),
            body_raw_ref: None,
            content_type: Some("text/plain; charset=utf-8".to_string()),
            content_disposition: Some("inline".to_string()),
        };

        // checking from_ref failure positive is in serialization, same as sender_ref
        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .body_multipart(vec![multipart.clone()])
            .unwrap()
            .from_ref(Identifier::new_test("artifact"))
            .unwrap()
            .build();
        assert!(email_message.is_err());
        //check cc_refs: same as to_refs and bcc_refs so only checking the one-positive case is checked in serialization
        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .body_multipart(vec![multipart])
            .unwrap()
            .cc_refs([Identifier::new_test("artifact")].to_vec())
            .unwrap()
            .build();
        assert!(email_message.is_err());
    }

    #[test]
    fn check_raw_email_ref() {
        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .raw_email_ref(Identifier::new_test("artifact"))
            .unwrap()
            .build();
        assert!(email_message.is_ok());
        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .raw_email_ref(Identifier::new_test("email-addr"))
            .unwrap()
            .build();
        assert!(email_message.is_err());
    }
    #[test]
    fn deserialize_file() {
        let json = r#"{
            "type": "file",
            "spec_version": "2.1",
            "id": "file--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "name": "foo.zip",
            "hashes": {
              "SHA-256": "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f"
            },
            "extensions": {
              "archive-ext": {
                "contains_refs": [
                  "file--cc7fa653-c35f-43db-afdd-dce4c3a241d5"
                ],
                "comment": "test"
              },
              "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
                "extension_type": "property-extension",
                "rank": 5,
                "toxicity": 8
              }
            }
        }"#;
        let result = CyberObject::from_json(json, false).unwrap();
        let archive =
            SpecialExtensions::FileExtensions(FileExtensions::ArchiveExt(ArchiveExtension {
                contains_refs: [Identifier::new_test("file")].to_vec(),
                comment: Some("test".to_string()),
            }));
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
        let file = CyberObjectBuilder::new("file")
            .unwrap()
            .hashes(
                Hashes::new(
                    "SHA-256",
                    "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f",
                )
                .unwrap(),
            )
            .unwrap()
            .name("foo.zip".to_string())
            .unwrap()
            .add_extension(
                "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e",
                general_extension,
            )
            .unwrap()
            .add_extension("archive-ext", archive.extension_to_dict().unwrap())
            .unwrap()
            .build()
            .unwrap()
            .test_id();
        assert_eq!(result, file)
    }

    #[test]
    fn serialize_file() {
        let archive =
            SpecialExtensions::FileExtensions(FileExtensions::ArchiveExt(ArchiveExtension {
                contains_refs: [Identifier::new_test("file")].to_vec(),
                comment: Some("test".to_string()),
            }));
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
        let file = CyberObjectBuilder::new("file")
            .unwrap()
            .hashes(
                Hashes::new(
                    "SHA3-256",
                    "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
                )
                .unwrap(),
            )
            .unwrap()
            .name("foo.zip".to_string())
            .unwrap()
            .add_extension(
                "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e",
                general_extension,
            )
            .unwrap()
            .add_extension("archive-ext", archive.extension_to_dict().unwrap())
            .unwrap()
            .build()
            .unwrap()
            .test_id();
        let mut result = serde_json::to_string_pretty(&file).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
            "type": "file",
            "hashes": {
              "SHA3-256": "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"
            },
            "name": "foo.zip",
            "spec_version": "2.1",
            "id": "file--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "extensions": {
              "archive-ext": {
                "comment": "test",
                "contains_refs": [
                  "file--cc7fa653-c35f-43db-afdd-dce4c3a241d5"
                ]
              },
              "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
                "extension_type": "property-extension",
                "rank": 5,
                "toxicity": 8
              }
            }
        }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected)
    }

    #[test]
    fn serialize_macaddress() {
        let mac_address = CyberObjectBuilder::new("mac-addr")
            .unwrap()
            .value("d2:fb:49:24:37:18".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&mac_address).unwrap();

        let expected = r#"{
            "type": "mac-addr",
            "spec_version": "2.1",
            "id": "mac-addr--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "value": "d2:fb:49:24:37:18"
        }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn deserialize_macaddress() {
        let json = r#"{
            "type": "mac-addr",
            "spec_version": "2.1",
            "id": "mac-addr--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "value": "d2:fb:49:24:37:18"
        }"#;
        let result = CyberObject::from_json(json, false).unwrap();
        let mac_address = CyberObjectBuilder::new("mac-addr")
            .unwrap()
            .value("d2:fb:49:24:37:18".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();
        assert_eq!(result, mac_address)
    }

    #[test]
    fn try_mac_without_leading_zeros() {
        let test_addresses = vec![
            "00:1A:2B:3C:4D:5E", // uppercase letters
            "0:fb:49:24:37:18",  // no leading zeroes
            "00-1A-2B-3C-4D-5E", // incorrect delimiter
            "001A.2B3C.4D5E",    // This format and delimiter won't match
            "00:1A:2B:3C:4D:5G", // Invalid character
        ];

        let mut all_invalid = true;

        for address in test_addresses {
            let mac_address = CyberObjectBuilder::new("mac-addr")
                .unwrap()
                .value(address.to_string())
                .unwrap()
                .build();
            if mac_address.is_ok() {
                all_invalid = false;
                eprintln!("Address '{}' should be invalid but passed", address);
            }
        }

        assert!(all_invalid, "Not all addresses were invalid");
    }

    #[test]
    fn serialize_url() {
        let url = CyberObjectBuilder::new("url")
            .unwrap()
            .value(String::from("https://new-url.com/"))
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&url).unwrap();

        let expected = r#"{
            "type": "url",
            "spec_version": "2.1",
            "id": "url--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "value": "https://new-url.com/"
        }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn deserialize_url() {
        let json = r#"{
            "type": "url",
            "spec_version": "2.1",
            "id": "url--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "value": "https://new-url.com/"
        }"#;
        let result = CyberObject::from_json(json, false).unwrap();
        let url = CyberObjectBuilder::new("url")
            .unwrap()
            .value(String::from("https://new-url.com/"))
            .unwrap()
            .build()
            .unwrap()
            .test_id();
        assert_eq!(result, url)
    }

    #[test]
    fn serialize_software() {
        let software = CyberObjectBuilder::new("software")
            .unwrap()
            .name("Word".to_string())
            .unwrap()
            .cpe("cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*".to_string())
            .unwrap()
            .swid("com.example.software-1.0.0".to_string())
            .unwrap()
            .languages(vec!["en-US".to_string(), "ja-JP".to_string()])
            .unwrap()
            .vendor("Microsoft".to_string())
            .unwrap()
            .version("Word for Microsoft 365".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&software).unwrap();

        let expected = r#"{
            "name": "Word",
            "cpe":"cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*",
            "id": "software--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "swid": "com.example.software-1.0.0",
            "languages": ["en-US","ja-JP"],
            "vendor": "Microsoft",
            "version": "Word for Microsoft 365",
            "spec_version": "2.1",
             "type": "software"
        }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();
        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn deserialize_software() {
        let json = r#"{
            "name": "Word",
            "cpe":"cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*",
            "id": "software--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "swid": "com.example.software-1.0.0",
            "languages": ["en-US","ja-JP"],
            "vendor": "Microsoft",
            "version": "Word for Microsoft 365",
            "spec_version": "2.1",
             "type": "software"
        }"#;

        let result = CyberObject::from_json(json, false).unwrap();

        let software = CyberObjectBuilder::new("software")
            .unwrap()
            .name("Word".to_string())
            .unwrap()
            .cpe("cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*".to_string())
            .unwrap()
            .swid("com.example.software-1.0.0".to_string())
            .unwrap()
            .languages(vec!["en-US".to_string(), "ja-JP".to_string()])
            .unwrap()
            .vendor("Microsoft".to_string())
            .unwrap()
            .version("Word for Microsoft 365".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        assert_eq!(result, software)
    }

    #[test]
    fn serialize_ipv4address() {
        let mac_addr1 = Identifier::new("mac-addr").unwrap();
        let mac_addr2 = Identifier::new("mac-addr").unwrap();
        let autonomous_system = Identifier::new("autonomous-system").unwrap();

        let ipv4_address = CyberObjectBuilder::new("ipv4-addr")
            .unwrap()
            .value("198.51.100.3".to_string())
            .unwrap()
            .resolves_to_refs(vec![mac_addr1.clone(), mac_addr2.clone()])
            .unwrap()
            .belongs_to_refs(vec![autonomous_system.clone()])
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let result = serde_json::to_string_pretty(&ipv4_address).unwrap();
        let result_value: serde_json::Value = serde_json::from_str(&result).unwrap();

        let expected = format!(
            r#"{{
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": "ipv4-addr--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "value": "198.51.100.3",
            "resolves_to_refs": [
                "{}",
                "{}"
            ],
            "belongs_to_refs": [
                "{}"
            ]
        }}"#,
            mac_addr1, mac_addr2, autonomous_system
        );
        let expected_value: serde_json::Value = serde_json::from_str(&expected).unwrap();

        assert_eq!(result_value, expected_value);
    }

    #[test]
    fn deserialize_ipv4address() {
        let mac_addr1 = Identifier::new("mac-addr").unwrap();
        let mac_addr2 = Identifier::new("mac-addr").unwrap();
        let autonomous_system = Identifier::new("autonomous-system").unwrap();

        let json = format!(
            r#"{{
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": "ipv4-addr--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "value": "198.51.100.3",
            "resolves_to_refs": [
                "{}",
                "{}"
            ],
            "belongs_to_refs": [
                "{}"
            ]
        }}"#,
            mac_addr1, mac_addr2, autonomous_system
        );

        let result = CyberObject::from_json(&json, false).unwrap();

        let ipv4_address = CyberObjectBuilder::new("ipv4-addr")
            .unwrap()
            .value("198.51.100.3".to_string())
            .unwrap()
            .resolves_to_refs(vec![mac_addr1.clone(), mac_addr2.clone()])
            .unwrap()
            .belongs_to_refs(vec![autonomous_system.clone()])
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        assert_eq!(result, ipv4_address);
    }

    #[test]
    fn ipv4_cidr() {
        let mac_addr1 = Identifier::new("mac-addr").unwrap();
        let mac_addr2 = Identifier::new("mac-addr").unwrap();
        let autonomous_system = Identifier::new("autonomous-system").unwrap();

        let ipv4_address = CyberObjectBuilder::new("ipv4-addr")
            .unwrap()
            .value("198.51.100.0/24".to_string())
            .unwrap()
            .resolves_to_refs(vec![mac_addr1.clone(), mac_addr2.clone()])
            .unwrap()
            .belongs_to_refs(vec![autonomous_system.clone()])
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let result = serde_json::to_string_pretty(&ipv4_address).unwrap();
        let result_value: serde_json::Value = serde_json::from_str(&result).unwrap();

        let expected = format!(
            r#"{{
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": "ipv4-addr--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "value": "198.51.100.0/24",
            "resolves_to_refs": [
                "{}",
                "{}"
            ],
            "belongs_to_refs": [
                "{}"
            ]
        }}"#,
            mac_addr1, mac_addr2, autonomous_system
        );
        let expected_value: serde_json::Value = serde_json::from_str(&expected).unwrap();

        assert_eq!(result_value, expected_value);
    }

    #[test]
    fn invalid_ipv4s() {
        let test_ips = vec![
            "198.51.100.x",    // invalid ipv4
            "xC6.51.100.0",    // invalid ipv4
            "198.51.100.0/50", // invalid CIDR
        ];

        let mut all_invalid = true;

        for ip in test_ips {
            let ipv4 = CyberObjectBuilder::new("ipv4-addr")
                .unwrap()
                .value(ip.to_string())
                .unwrap()
                .build();
            if ipv4.is_ok() {
                all_invalid = false;
                warn!("Ipv4Address '{}' should be invalid but passed", ip);
            }
        }
        assert!(all_invalid, "Not all ipvv4 addresses were invalid");
    }

    #[test]
    fn serialize_ipv6address() {
        let mac_addr1 = Identifier::new("mac-addr").unwrap();
        let mac_addr2 = Identifier::new("mac-addr").unwrap();
        let autonomous_system = Identifier::new("autonomous-system").unwrap();

        let ipv6_address = CyberObjectBuilder::new("ipv6-addr")
            .unwrap()
            .value("2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string())
            .unwrap()
            .resolves_to_refs(vec![mac_addr1.clone(), mac_addr2.clone()])
            .unwrap()
            .belongs_to_refs(vec![autonomous_system.clone()])
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let result = serde_json::to_string_pretty(&ipv6_address).unwrap();
        let result_value: serde_json::Value = serde_json::from_str(&result).unwrap();

        let expected = format!(
            r#"{{
            "type": "ipv6-addr",
            "spec_version": "2.1",
            "id": "ipv6-addr--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "resolves_to_refs": [
                "{}",
                "{}"
            ],
            "belongs_to_refs": [
                "{}"
            ]
        }}"#,
            mac_addr1, mac_addr2, autonomous_system
        );
        let expected_value: serde_json::Value = serde_json::from_str(&expected).unwrap();

        assert_eq!(result_value, expected_value);
    }

    #[test]
    fn deserialize_ipv6address() {
        let mac_addr1 = Identifier::new("mac-addr").unwrap();
        let mac_addr2 = Identifier::new("mac-addr").unwrap();
        let autonomous_system = Identifier::new("autonomous-system").unwrap();

        let json = format!(
            r#"{{
            "type": "ipv6-addr",
            "spec_version": "2.1",
            "id": "ipv6-addr--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "resolves_to_refs": [
                "{}",
                "{}"
            ],
            "belongs_to_refs": [
                "{}"
            ]
        }}"#,
            mac_addr1, mac_addr2, autonomous_system
        );

        let result = CyberObject::from_json(&json, false).unwrap();

        let ipv6_address = CyberObjectBuilder::new("ipv6-addr")
            .unwrap()
            .value("2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string())
            .unwrap()
            .resolves_to_refs(vec![mac_addr1.clone(), mac_addr2.clone()])
            .unwrap()
            .belongs_to_refs(vec![autonomous_system.clone()])
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        assert_eq!(result, ipv6_address);
    }

    #[test]
    fn ipv6_cidr() {
        let mac_addr1 = Identifier::new("mac-addr").unwrap();
        let mac_addr2 = Identifier::new("mac-addr").unwrap();
        let autonomous_system = Identifier::new("autonomous-system").unwrap();

        let ipv6_address = CyberObjectBuilder::new("ipv6-addr")
            .unwrap()
            .value("2001:0db8::/96".to_string())
            .unwrap()
            .resolves_to_refs(vec![mac_addr1.clone(), mac_addr2.clone()])
            .unwrap()
            .belongs_to_refs(vec![autonomous_system.clone()])
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let result = serde_json::to_string_pretty(&ipv6_address).unwrap();
        let result_value: serde_json::Value = serde_json::from_str(&result).unwrap();

        let expected = format!(
            r#"{{
            "type": "ipv6-addr",
            "spec_version": "2.1",
            "id": "ipv6-addr--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "value": "2001:0db8::/96",
            "resolves_to_refs": [
                "{}",
                "{}"
            ],
            "belongs_to_refs": [
                "{}"
            ]
        }}"#,
            mac_addr1, mac_addr2, autonomous_system
        );
        let expected_value: serde_json::Value = serde_json::from_str(&expected).unwrap();

        assert_eq!(result_value, expected_value);
    }

    #[test]
    fn invalid_ipv6s() {
        let test_ips = vec![
            "::ffff:192.0.2.300", // invalid ipv6
            "2001:0dh8::",        // invalid ipv6
            "2001:0db8::/150",    // invalid CIDR
        ];

        let mut all_invalid = true;

        for ip in test_ips {
            let ipv6 = CyberObjectBuilder::new("ipv6-addr")
                .unwrap()
                .value(ip.to_string())
                .unwrap()
                .build();
            if ipv6.is_ok() {
                all_invalid = false;
                warn!("Ipv6Address '{}' should be invalid but passed", ip);
            }
        }
        assert!(all_invalid, "Not all ipvv4 addresses were invalid");
    }

    #[test]
    fn serialize_domain_name() {
        let ipv4_addr = Identifier::new("ipv4-addr").unwrap();

        let domain_name_obj = CyberObjectBuilder::new("domain-name")
            .unwrap()
            .value("example.com".to_string())
            .unwrap()
            .resolves_to_refs(vec![ipv4_addr.clone()])
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let result = serde_json::to_string_pretty(&domain_name_obj).unwrap();
        let result_value: serde_json::Value = serde_json::from_str(&result).unwrap();

        let expected = format!(
            r#"{{
            "type": "domain-name",
            "spec_version": "2.1",
            "id": "domain-name--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "value": "example.com",
            "resolves_to_refs": [
                "{}"
            ]
        }}"#,
            ipv4_addr
        );
        let expected_value: serde_json::Value = serde_json::from_str(&expected).unwrap();

        assert_eq!(result_value, expected_value);
    }

    #[test]
    fn deserialize_domain_name() {
        let ipv4_addr = Identifier::new("ipv4-addr").unwrap();

        let json = format!(
            r#"{{
            "type": "domain-name",
            "spec_version": "2.1",
            "id": "domain-name--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "value": "example.com",
            "resolves_to_refs": [
                "{}"
            ]
        }}"#,
            ipv4_addr
        );

        let result = CyberObject::from_json(&json, false).unwrap();

        let domain_name_obj = CyberObjectBuilder::new("domain-name")
            .unwrap()
            .value("example.com".to_string())
            .unwrap()
            .resolves_to_refs(vec![ipv4_addr.clone()])
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        assert_eq!(result, domain_name_obj);
    }

    #[test]
    fn invalid_domain_name() {
        let result = CyberObjectBuilder::new("domain-name")
            .unwrap()
            .value("invalid_domain_name".to_string())
            .unwrap()
            .build();

        assert!(
            result.is_err(),
            "Invalid domain name should result in an error"
        );
    }

    #[test]
    fn incorrect_reference_type() {
        let autonomous_system = Identifier::new("autonomous-system").unwrap();

        let result = CyberObjectBuilder::new("domain-name")
            .unwrap()
            .value("example.com".to_string())
            .unwrap()
            .resolves_to_refs(vec![autonomous_system.clone()])
            .unwrap()
            .build();

        assert!(
            result.is_err(),
            "Incorrect reference type should result in an error"
        );
    }

    #[test]
    fn serialize_mutex() {
        let mutex = CyberObjectBuilder::new("mutex")
            .unwrap()
            .name("mutex name foo bar object name here".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let result_value = serde_json::to_value(&mutex).unwrap();

        let expected = r#"{
            "type": "mutex",
            "spec_version": "2.1",
            "id": "mutex--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "name": "mutex name foo bar object name here"
        }"#;
        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(result_value, expected_value);
    }

    #[test]
    fn deserialize_mutex() {
        let json = r#"{
            "type": "mutex",
            "spec_version": "2.1",
            "id": "mutex--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "name": "mutex name foo bar object name here"
        }"#;

        let result = CyberObject::from_json(json, false).unwrap();

        let expected = CyberObjectBuilder::new("mutex")
            .unwrap()
            .name("mutex name foo bar object name here".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_network_traffic_se() {
        let json = r#"{
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": "network-traffic--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "src_ref": "ipv4-addr--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "src_port": 223,
            "protocols": [
                "ip",
                "tcp"
            ],
            "extensions": {
                "socket-ext": {
                "address_family": "AF_INET",
                "is_listening": true,
                "socket_type": "SOCK_STREAM"
                }
            }
        }"#;

        let result = CyberObject::from_json(json, false).unwrap();

        let se = SpecialExtensions::NetworkTrafficExtensions(NetworkTrafficExtensions::SocketExt(
            SocketExtenion {
                address_family: Some("AF_INET".to_string()),
                is_blocking: None,
                is_listening: Some(true),
                options: None,
                socket_type: Some("SOCK_STREAM".to_string()),
                socket_descriptor: None,
                socket_handle: None,
            },
        ));

        let expected = CyberObjectBuilder::new("network-traffic")
            .unwrap()
            .src_ref(Identifier::new_test("ipv4-addr"))
            .unwrap()
            .src_port(223)
            .unwrap()
            .protocols(vec!["ip".to_string(), "tcp".to_string()])
            .unwrap()
            .add_extension("socket-ext", se.extension_to_dict().unwrap())
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id();

        assert_eq!(result, expected);
    }

    #[test]
    fn serialize_network_traffic_se() {
        let mut se = r#"{
            "type": "network-traffic",
            "src_ref": "ipv4-addr--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "src_port": 223,
            "is_active":false,
            "end":"2016-05-12T08:17:27Z",
            "protocols": [
                "ip",
                "tcp"
            ],
            "spec_version": "2.1",
            "id": "network-traffic--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "extensions": {
                "socket-ext": {
                "address_family": "AF_INET",
                "is_listening": true,
                "socket_type": "SOCK_STREAM"
                }
            }
        }"#
        .to_string();
        se.retain(|c| !c.is_whitespace());

        let expected: Value = serde_json::from_str(&se).unwrap();

        let se = SpecialExtensions::NetworkTrafficExtensions(NetworkTrafficExtensions::SocketExt(
            SocketExtenion {
                address_family: Some("AF_INET".to_string()),
                is_listening: Some(true),
                socket_type: Some("SOCK_STREAM".to_string()),
                is_blocking: None,
                options: None,

                socket_descriptor: None,
                socket_handle: None,
            },
        ));

        let nt = CyberObjectBuilder::new("network-traffic")
            .unwrap()
            .src_ref(Identifier::new_test("ipv4-addr"))
            .unwrap()
            .src_port(223)
            .unwrap()
            .is_active(false)
            .unwrap()
            .end(Timestamp("2016-05-12T08:17:27.000Z".parse().unwrap()))
            .unwrap()
            .protocols(vec!["ip".to_string(), "tcp".to_string()])
            .unwrap()
            .add_extension("socket-ext", se.extension_to_dict().unwrap())
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id();
        let result = serde_json::to_value(&nt).unwrap();

        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_network_traffic_http_err() {
        let json = r#"{
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": "network-traffic--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "dst_ref": "ipv4x-addr--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "protocols": [
                "tcp",
                "http"
            ],
            "extensions": {
                "http-request-ext": {
                "request_method": "get",
                "request_value": "/download.html",
                "request_version": "http/1.1"
                }
            }             
        }"#;

        let result = CyberObject::from_json(json, false);

        assert!(result.is_err());
    }

    #[test]
    fn deserialize_network_traffic_http_dict() {
        let json = r#"{
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": "network-traffic--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "dst_ref": "ipv4-addr--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "protocols": [
                "tcp",
                "http"
            ],
            "extensions": {
                    "http-request-ext": {
                    "request_method": "get",
                    "request_value": "/download.html",
                    "request_version": "http/1.1",
                    "request_header": {
                        "Accept-Encoding": "gzip,deflate",
                        "User-Agent": "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6) Gecko/20040113",
                        "Host": "www.example.com"
                    }
                }
            }             
        }"#;

        let result = CyberObject::from_json(json, false).unwrap();

        let mut rh = StixDictionary::new();
        rh.insert("Accept-Encoding", "gzip,deflate".to_string())
            .unwrap();
        rh.insert(
            "User-Agent",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6) Gecko/20040113".to_string(),
        )
        .unwrap();
        rh.insert("Host", "www.example.com".to_string()).unwrap();

        let hre = SpecialExtensions::NetworkTrafficExtensions(
            NetworkTrafficExtensions::HttpRequestExt(HttpRequestExtension {
                request_method: "get".to_string(),
                request_value: "/download.html".to_string(),
                request_version: Some("http/1.1".to_string()),
                request_header: Some(rh),
                message_body_length: None,
                message_body_data_ref: None,
            }),
        );

        let expected = CyberObjectBuilder::new("network-traffic")
            .unwrap()
            .dst_ref(Identifier::new_test("ipv4-addr"))
            .unwrap()
            .protocols(vec!["tcp".to_string(), "http".to_string()])
            .unwrap()
            .add_extension("http-request-ext", hre.extension_to_dict().unwrap())
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id();

        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_network_traffic_icmp() {
        let json = r#"{
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": "network-traffic--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "src_ref": "ipv4-addr--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "dst_ref": "ipv4-addr--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "ipfix": {
                "minimumIpTotalLength": 32,
                "maximumIpTotalLength": 2556
            },
            "protocols": [
                "icmp"
            ],
            "extensions": {
                "icmp-ext": {
                "icmp_type_hex": "08",
                "icmp_code_hex": "00"
                }
            }
        }"#;

        let mut ipfix = StixDictionary::new();
        ipfix
            .insert("minimumIpTotalLength", DictionaryValue::Int(32))
            .unwrap();
        ipfix
            .insert("maximumIpTotalLength", DictionaryValue::Int(2556))
            .unwrap();

        let result = CyberObject::from_json(json, false).unwrap();

        let icmp = SpecialExtensions::NetworkTrafficExtensions(NetworkTrafficExtensions::IcmpExt(
            IcmpExtension {
                icmp_type_hex: "08".to_string(),
                icmp_code_hex: "00".to_string(),
            },
        ));

        let expected = CyberObjectBuilder::new("network-traffic")
            .unwrap()
            .src_ref(Identifier::new_test("ipv4-addr"))
            .unwrap()
            .dst_ref(Identifier::new_test("ipv4-addr"))
            .unwrap()
            .ipfix(ipfix)
            .unwrap()
            .protocols(vec!["icmp".to_string()])
            .unwrap()
            .add_extension("icmp-ext", icmp.extension_to_dict().unwrap())
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id();

        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_network_traffic_icmp_invalid() {
        //using invalid icmp_type_hex
        let json = r#"{
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": "network-traffic--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "src_ref": "ipv4-addr--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "dst_ref": "ipv4-addr--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "ipfix": {
                "minimumIpTotalLength": 32,
                "maximumIpTotalLength": 2556
            },
            "protocols": [
                "icmp"
            ],
            "extensions": {
                "icmp-ext": {
                "icmp_type_hex": "081",
                "icmp_code_hex": "00"
                }
            }
        }"#;

        let result = CyberObject::from_json(json, false);

        assert!(result.is_err());
    }

    #[test]
    fn deserialize_process() {
        let json = r#"{
            "type": "process",
            "pid": 314,
            "spec_version": "2.1",
            "id": "process--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "extensions": {
                "windows-process-ext": {
                "aslr_enabled": true,
                "dep_enabled": true,                
                "owner_sid": "S-1-5-21-186985262-1144665072-74031268-1309",
                "priority": "HIGH_PRIORITY_CLASS"
                }
            }
        }"#;

        let result = CyberObject::from_json(json, false).unwrap();

        let wpe = SpecialExtensions::ProcessExtensions(ProcessExtensions::WindowsProcessExt(
            WindowsProcessExtension {
                aslr_enabled: Some(true),
                dep_enabled: Some(true),
                priority: Some("HIGH_PRIORITY_CLASS".to_string()),
                owner_sid: Some("S-1-5-21-186985262-1144665072-74031268-1309".to_string()),
                window_title: None,
                startup_info: None,
                integrity_level: None,
            },
        ));

        let expected = CyberObjectBuilder::new("process")
            .unwrap()
            .pid(314.into())
            .unwrap()
            .add_extension("windows-process-ext", wpe.extension_to_dict().unwrap())
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id();

        assert_eq!(result, expected);
    }

    #[test]
    fn serialize_process() {
        let wpe = SpecialExtensions::ProcessExtensions(ProcessExtensions::WindowsProcessExt(
            WindowsProcessExtension {
                aslr_enabled: Some(true),
                dep_enabled: Some(true),
                priority: Some("HIGH_PRIORITY_CLASS".to_string()),
                owner_sid: Some("S-1-5-21-186985262-1144665072-74031268-1309".to_string()),
                window_title: None,
                startup_info: None,
                integrity_level: None,
            },
        ));

        let process = CyberObjectBuilder::new("process")
            .unwrap()
            .pid(314.into())
            .unwrap()
            .add_extension("windows-process-ext", wpe.extension_to_dict().unwrap())
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id();
        let mut result = serde_json::to_string_pretty(&process).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
            "type": "process",
            "pid": 314,
            "spec_version": "2.1",
            "id": "process--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "extensions": {
                "windows-process-ext": {
                "aslr_enabled": true,
                "dep_enabled": true,                
                "owner_sid": "S-1-5-21-186985262-1144665072-74031268-1309",
                "priority": "HIGH_PRIORITY_CLASS"
                }
            }
        }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected)
    }

    #[test]
    fn serialize_process_invalid_integrity() {
        let wpe = SpecialExtensions::ProcessExtensions(ProcessExtensions::WindowsProcessExt(
            WindowsProcessExtension {
                aslr_enabled: Some(true),
                dep_enabled: Some(true),
                priority: Some("HIGH_PRIORITY_CLASS".to_string()),
                owner_sid: Some("S-1-5-21-186985262-1144665072-74031268-1309".to_string()),
                window_title: None,
                startup_info: None,
                integrity_level: Some("FOO".to_string()),
            },
        ));

        let process = CyberObjectBuilder::new("process")
            .unwrap()
            .pid(314.into())
            .unwrap()
            .add_extension("windows-process-ext", wpe.extension_to_dict().unwrap())
            .unwrap()
            .build();

        assert!(process.is_err());
    }

    #[test]
    fn serialize_process_valid_integrity() {
        let wpe = SpecialExtensions::ProcessExtensions(ProcessExtensions::WindowsProcessExt(
            WindowsProcessExtension {
                aslr_enabled: Some(true),
                dep_enabled: Some(true),
                priority: Some("HIGH_PRIORITY_CLASS".to_string()),
                owner_sid: Some("S-1-5-21-186985262-1144665072-74031268-1309".to_string()),
                window_title: None,
                startup_info: None,
                integrity_level: Some("high".to_string()),
            },
        ));

        let process = CyberObjectBuilder::new("process")
            .unwrap()
            .pid(314.into())
            .unwrap()
            .add_extension("windows-process-ext", wpe.extension_to_dict().unwrap())
            .unwrap()
            .build();

        assert!(process.is_ok());
    }

    #[test]
    fn serialize_process_invalid_image_ref() {
        //image ref shuold be of type file
        let process = CyberObjectBuilder::new("process")
            .unwrap()
            .pid(314.into())
            .unwrap()
            .image_ref(Identifier::new_test("FOO"))
            .unwrap()
            .build();

        assert!(process.is_err());
    }

    #[test]
    fn serialize_windows_registry_key() {
        let windows_registry_key = CyberObjectBuilder::new("windows-registry-key")
            .unwrap()
            .key("HKEY_LOCAL_MACHINE".to_string())
            .unwrap()
            .number_of_subkeys(10000000.into())
            .unwrap()
            .creator_user_ref(
                Identifier::from_str("user-account--cc7fa653-c35f-43db-afdd-dce4c3a241d5").unwrap(),
            )
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&windows_registry_key).unwrap();

        let expected = r#"{
            "key":"HKEY_LOCAL_MACHINE",
            "id": "windows-registry-key--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "number_of_subkeys": 10000000,
            "creator_user_ref": "user-account--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "spec_version": "2.1",
             "type": "windows-registry-key"
        }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();
        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn deserialize_windows_registry_key() {
        let json = r#"{
            "key":"HKEY_LOCAL_MACHINE",
            "id": "windows-registry-key--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "number_of_subkeys": 10000000,
            "creator_user_ref": "user-account--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "spec_version": "2.1",
             "type": "windows-registry-key"
        }"#;

        let result = CyberObject::from_json(json, false).unwrap();

        let windows_registry_key = CyberObjectBuilder::new("windows-registry-key")
            .unwrap()
            .key("HKEY_LOCAL_MACHINE".to_string())
            .unwrap()
            .number_of_subkeys(10000000.into())
            .unwrap()
            .creator_user_ref(
                Identifier::from_str("user-account--cc7fa653-c35f-43db-afdd-dce4c3a241d5").unwrap(),
            )
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        assert_eq!(result, windows_registry_key)
    }

    #[test]
    fn windows_registry_key_i64_invalid1() {
        // using subkey value 1 num out of 2^53 ramge
        let json = r#"{
            "key":"HKEY_LOCAL_MACHINE",
            "id": "windows-registry-key--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "number_of_subkeys": -9007199254740992,
            "creator_user_ref": "user-account--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "spec_version": "2.1",
             "type": "windows-registry-key"
        }"#;

        let result = CyberObject::from_json(json, false);

        assert!(result.is_err())
    }

    #[test]
    fn windows_registry_key_i64_valid() {
        // using subkey value at -1 value from max
        let json = r#"{
            "key":"HKEY_LOCAL_MACHINE",
            "id": "windows-registry-key--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "number_of_subkeys": 9007199254740990,
            "creator_user_ref": "user-account--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "spec_version": "2.1",
             "type": "windows-registry-key"
        }"#;

        let result = CyberObject::from_json(json, false);
        assert!(result.is_ok());
    }

    #[test]
    fn windows_registry_key_invalid() {
        let windows_registry_key = CyberObjectBuilder::new("windows-registry-key")
            .unwrap()
            .key("HKEY_LOCAL_MACHINExx\\foo\\bar".to_string())
            .unwrap()
            .number_of_subkeys(10000000.into())
            .unwrap()
            .creator_user_ref(
                Identifier::from_str("user-account--cc7fa653-c35f-43db-afdd-dce4c3a241d5").unwrap(),
            )
            .unwrap()
            .build();

        assert!(windows_registry_key.is_err())
    }
    #[test]
    fn serialize_user_account() {
        let unix_extension = UnixAccountExtension {
            gid: Some(1000.into()),
            groups: Some(vec!["users".to_string(), "admins".to_string()]),
            home_dir: Some("/home/user".to_string()),
            shell: None,
        };

        let user_extension = SpecialExtensions::UserAccountExtensions(
            UserAccountExtensions::UnixAccountExt(unix_extension),
        );

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

        let user_account = CyberObjectBuilder::new("user-account")
            .unwrap()
            .user_id("1001".to_string())
            .unwrap()
            .account_login("jdoe".to_string())
            .unwrap()
            .account_type("unix".to_string())
            .unwrap()
            .display_name("John Doe".to_string())
            .unwrap()
            .is_service_account(false)
            .unwrap()
            .is_privileged(false)
            .unwrap()
            .can_escalate_privs(true)
            .unwrap()
            .is_disabled(true)
            .unwrap()
            .account_created("2023-10-01T00:00:00.00Z".to_string())
            .unwrap()
            .credential_last_changed("2023-10-01T00:00:00.00Z".to_string())
            .unwrap()
            .account_first_login("2023-10-01T00:00:00.00Z".to_string())
            .unwrap()
            .account_last_login("2023-10-01T00:00:00.00Z".to_string())
            .unwrap()
            .add_extension(
                "unix-account-ext",
                user_extension.extension_to_dict().unwrap(),
            )
            .unwrap()
            .add_extension(
                "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e",
                general_extension,
            )
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&user_account).unwrap();

        let expected = r#"{
        "user_id": "1001",
        "account_login": "jdoe",
        "account_type": "unix",
        "display_name": "John Doe",
        "is_service_account": false,
        "is_privileged": false,
        "can_escalate_privs": true,
        "is_disabled": true,
        "account_created": "2023-10-01T00:00:00Z",
        "credential_last_changed": "2023-10-01T00:00:00Z",
        "account_first_login": "2023-10-01T00:00:00Z",
        "account_last_login": "2023-10-01T00:00:00Z",
        "id": "user-account--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "spec_version": "2.1",
        "type": "user-account",
        "extensions": 
        {
            "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
                "extension_type": "property-extension",
                "rank": 5,
                "toxicity": 8
             },
            "unix-account-ext": {
                "gid": 1000,
                "groups": ["users", "admins"],
                "home_dir": "/home/user"
            }
        }
    }"#;
        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn deserialize_user_account() {
        let json = r#"{
        "user_id": "1001",
        "account_login": "jdoe",
        "account_type": "unix",
        "display_name": "John Doe",
        "is_service_account": false,
        "is_privileged": false,
        "can_escalate_privs": true,
        "is_disabled": true,
        "account_created": "2023-10-01T00:00:00Z",
        "credential_last_changed": "2023-10-01T00:00:00Z",
        "account_first_login": "2023-10-01T00:00:00Z",
        "account_last_login": "2023-10-01T00:00:00Z",
        "id": "user-account--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "spec_version": "2.1",
        "type": "user-account",
        "extensions":
        {
            "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
                "extension_type": "property-extension",
                "rank": 5,
                "toxicity": 8
             },
            "unix-account-ext": {
                "gid": 1000,
                "groups": ["users", "admins"],
                "home_dir": "/home/user"
            }
        }
    }"#;

        let result = CyberObject::from_json(json, false).unwrap();

        let unix_extension = UnixAccountExtension {
            gid: Some(1000.into()),
            groups: Some(vec!["users".to_string(), "admins".to_string()]),
            home_dir: Some("/home/user".to_string()),
            shell: None,
        };

        let user_extension = SpecialExtensions::UserAccountExtensions(
            UserAccountExtensions::UnixAccountExt(unix_extension),
        );

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

        let user_account = CyberObjectBuilder::new("user-account")
            .unwrap()
            .user_id("1001".to_string())
            .unwrap()
            .account_login("jdoe".to_string())
            .unwrap()
            .account_type("unix".to_string())
            .unwrap()
            .display_name("John Doe".to_string())
            .unwrap()
            .is_service_account(false)
            .unwrap()
            .is_privileged(false)
            .unwrap()
            .can_escalate_privs(true)
            .unwrap()
            .is_disabled(true)
            .unwrap()
            .account_created("2023-10-01T00:00:00.00Z".to_string())
            .unwrap()
            .credential_last_changed("2023-10-01T00:00:00.00Z".to_string())
            .unwrap()
            .account_first_login("2023-10-01T00:00:00.00Z".to_string())
            .unwrap()
            .account_last_login("2023-10-01T00:00:00.00Z".to_string())
            .unwrap()
            .add_extension(
                "unix-account-ext",
                user_extension.extension_to_dict().unwrap(),
            )
            .unwrap()
            .add_extension(
                "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e",
                general_extension,
            )
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        assert_eq!(result, user_account);
    }

    #[test]
    fn serialize_x509_certificate() {
        let x509_certificate = CyberObjectBuilder::new("x509-certificate")
            .unwrap()
            .issuer("C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com".to_string())
            .unwrap()
            .validity_not_before(Timestamp("2016-03-12T12:00:00Z".parse().unwrap()))
            .unwrap()
            .validity_not_after(Timestamp("2016-08-21T12:00:00Z".parse().unwrap()))
            .unwrap()
            .subject("C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org".to_string())
            .unwrap()
            .serial_number("36:f7:d4:32:f4:ab:70:ea:d3:ce:98:6e:ea:99:93:49:32:0a:b7:06".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let result = serde_json::to_string_pretty(&x509_certificate).unwrap();
        let result_value: serde_json::Value = serde_json::from_str(&result).unwrap();

        let expected = r#"
        {
            "type": "x509-certificate",
            "spec_version": "2.1",
            "id": "x509-certificate--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "issuer": "C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com",
            "validity_not_before": "2016-03-12T12:00:00Z",
            "validity_not_after": "2016-08-21T12:00:00Z",
            "subject": "C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org",
            "serial_number": "36:f7:d4:32:f4:ab:70:ea:d3:ce:98:6e:ea:99:93:49:32:0a:b7:06"
        }"#;
        let expected_value: serde_json::Value = serde_json::from_str(expected).unwrap();

        assert_eq!(result_value, expected_value);
    }

    #[test]
    fn deserialize_x509_certificate() {
        let json = r#"
        {
            "type": "x509-certificate",
            "spec_version": "2.1",
            "id": "x509-certificate--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "issuer": "C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com",
            "validity_not_before": "2016-03-12T12:00:00Z",
            "validity_not_after": "2016-08-21T12:00:00Z",
            "subject": "C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org",
            "serial_number": "36:f7:d4:32:f4:ab:70:ea:d3:ce:98:6e:ea:99:93:49:32:0a:b7:06"
        }"#;

        let result = CyberObject::from_json(json, false).unwrap();
        let expected = CyberObjectBuilder::new("x509-certificate")
            .unwrap()
            .issuer("C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com".to_string())
            .unwrap()
            .validity_not_before(Timestamp("2016-03-12T12:00:00Z".parse().unwrap()))
            .unwrap()
            .validity_not_after(Timestamp("2016-08-21T12:00:00Z".parse().unwrap()))
            .unwrap()
            .subject("C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org".to_string())
            .unwrap()
            .serial_number("36:f7:d4:32:f4:ab:70:ea:d3:ce:98:6e:ea:99:93:49:32:0a:b7:06".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        assert_eq!(result, expected);
    }

    #[test]
    fn serialize_x509_certificate_with_v3_extensions() {
        let certificate_extension = X509V3Extensions {
            basic_constraints: Some("critical,CA:TRUE, pathlen:0".to_string()),
            name_constraints: Some("permitted;IP:192.168.0.0/255.255.0.0".to_string()),
            policy_constraints: Some("requireExplicitPolicy:3".to_string()),
            key_usage: Some("critical, keyCertSign".to_string()),
            extended_key_usage: Some("critical,codeSigning,1.2.3.4".to_string()),
            subject_key_identifier: Some("hash".to_string()),
            authority_key_identifier: Some("keyid,issuer".to_string()),
            subject_alternative_name: Some("email:my@other.address,RID:1.2.3.4".to_string()),
            issuer_alternative_name: Some("issuer:copy".to_string()),
            subject_directory_attributes: None,
            crl_distribution_points: Some("URI:http://myhost.com/myca.crl".to_string()),
            inhibit_any_policy: Some("2".to_string()),
            private_key_usage_period_not_before: Some(Timestamp(
                "2016-03-12T12:00:00Z".parse().unwrap(),
            )),
            private_key_usage_period_not_after: Some(Timestamp(
                "2018-03-12T12:00:00Z".parse().unwrap(),
            )),
            certificate_policies: Some("1.2.4.5, 1.1.3.4".to_string()),
            policy_mappings: None,
        };

        let x509_certificate = CyberObjectBuilder::new("x509-certificate")
            .unwrap()
            .issuer("C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com".to_string())
            .unwrap()
            .validity_not_before(Timestamp("2016-03-12T12:00:00Z".parse().unwrap()))
            .unwrap()
            .validity_not_after(Timestamp("2016-08-21T12:00:00Z".parse().unwrap()))
            .unwrap()
            .subject("C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org".to_string())
            .unwrap()
            .serial_number("36:f7:d4:32:f4:ab:70:ea:d3:ce:98:6e:ea:99:93:49:32:0a:b7:06".to_string())
            .unwrap()
            .x509_v3_extensions(certificate_extension)
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let result = serde_json::to_value(&x509_certificate).unwrap();

        let expected = r#"
        {
            "type": "x509-certificate",
            "spec_version": "2.1",
            "id": "x509-certificate--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "issuer": "C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com",
            "validity_not_before": "2016-03-12T12:00:00Z",
            "validity_not_after": "2016-08-21T12:00:00Z",
            "subject": "C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org",
            "serial_number": "36:f7:d4:32:f4:ab:70:ea:d3:ce:98:6e:ea:99:93:49:32:0a:b7:06",
            "x509_v3_extensions":{
                "basic_constraints":"critical,CA:TRUE, pathlen:0",
                "name_constraints":"permitted;IP:192.168.0.0/255.255.0.0",
                "policy_constraints":"requireExplicitPolicy:3",
                "key_usage":"critical, keyCertSign",
                "extended_key_usage":"critical,codeSigning,1.2.3.4",
                "subject_key_identifier":"hash",
                "authority_key_identifier":"keyid,issuer",
                "subject_alternative_name":"email:my@other.address,RID:1.2.3.4",
                "issuer_alternative_name":"issuer:copy",
                "crl_distribution_points":"URI:http://myhost.com/myca.crl",
                "inhibit_any_policy":"2",
                "private_key_usage_period_not_before":"2016-03-12T12:00:00Z",
                "private_key_usage_period_not_after":"2018-03-12T12:00:00Z",
                "certificate_policies":"1.2.4.5, 1.1.3.4"
            }
        }"#;
        let expected: serde_json::Value = serde_json::from_str(expected).unwrap();

        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_x509_certificate_with_v3_extensions() {
        let json = r#"
        {
            "type": "x509-certificate",
            "spec_version": "2.1",
            "id": "x509-certificate--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "issuer": "C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com",
            "validity_not_before": "2016-03-12T12:00:00Z",
            "validity_not_after": "2016-08-21T12:00:00Z",
            "subject": "C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org",
            "serial_number": "36:f7:d4:32:f4:ab:70:ea:d3:ce:98:6e:ea:99:93:49:32:0a:b7:06",
            "x509_v3_extensions":{
                "basic_constraints":"critical,CA:TRUE, pathlen:0",
                "name_constraints":"permitted;IP:192.168.0.0/255.255.0.0",
                "policy_constraints":"requireExplicitPolicy:3",
                "key_usage":"critical, keyCertSign",
                "extended_key_usage":"critical,codeSigning,1.2.3.4",
                "subject_key_identifier":"hash",
                "authority_key_identifier":"keyid,issuer",
                "subject_alternative_name":"email:my@other.address,RID:1.2.3.4",
                "issuer_alternative_name":"issuer:copy",
                "crl_distribution_points":"URI:http://myhost.com/myca.crl",
                "inhibit_any_policy":"2",
                "private_key_usage_period_not_before":"2016-03-12T12:00:00Z",
                "private_key_usage_period_not_after":"2018-03-12T12:00:00Z",
                "certificate_policies":"1.2.4.5, 1.1.3.4"
            }
        }"#;

        let result = CyberObject::from_json(json, false).unwrap();
        let certificate_extension = X509V3Extensions {
            basic_constraints: Some("critical,CA:TRUE, pathlen:0".to_string()),
            name_constraints: Some("permitted;IP:192.168.0.0/255.255.0.0".to_string()),
            policy_constraints: Some("requireExplicitPolicy:3".to_string()),
            key_usage: Some("critical, keyCertSign".to_string()),
            extended_key_usage: Some("critical,codeSigning,1.2.3.4".to_string()),
            subject_key_identifier: Some("hash".to_string()),
            authority_key_identifier: Some("keyid,issuer".to_string()),
            subject_alternative_name: Some("email:my@other.address,RID:1.2.3.4".to_string()),
            issuer_alternative_name: Some("issuer:copy".to_string()),
            subject_directory_attributes: None,
            crl_distribution_points: Some("URI:http://myhost.com/myca.crl".to_string()),
            inhibit_any_policy: Some("2".to_string()),
            private_key_usage_period_not_before: Some(Timestamp(
                "2016-03-12T12:00:00Z".parse().unwrap(),
            )),
            private_key_usage_period_not_after: Some(Timestamp(
                "2018-03-12T12:00:00Z".parse().unwrap(),
            )),
            certificate_policies: Some("1.2.4.5, 1.1.3.4".to_string()),
            policy_mappings: None,
        };

        let expected = CyberObjectBuilder::new("x509-certificate")
            .unwrap()
            .issuer("C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com".to_string())
            .unwrap()
            .validity_not_before(Timestamp("2016-03-12T12:00:00Z".parse().unwrap()))
            .unwrap()
            .validity_not_after(Timestamp("2016-08-21T12:00:00Z".parse().unwrap()))
            .unwrap()
            .subject("C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org".to_string())
            .unwrap()
            .serial_number("36:f7:d4:32:f4:ab:70:ea:d3:ce:98:6e:ea:99:93:49:32:0a:b7:06".to_string())
            .unwrap()
            .x509_v3_extensions(certificate_extension)
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        assert_eq!(result, expected);
    }
}
