# README

## OASIS TC Open Repository: cti-rust-stix

This GitHub public repository [cti-rust-stix](https://github.com/oasis-open/cti-rust-stix/) was created at the request of the [CTI TC](https://groups.oasis-open.org/communities/tc-community-home2?CommunityKey=c6c33da0-d1ee-42dd-9427-018dc7d32277) as an [OASIS TC Open Repository](https://www.oasis-open.org/resources/open-repositories/) to support development of open source resources related to Technical Committee work.

While this TC Open Repository remains associated with the sponsor TC, its development priorities, leadership, intellectual property terms, participation rules, and other matters of governance are [separate and distinct](https://github.com/oasis-open/cti-rust-stix/blob/master/CONTRIBUTING.md) from the OASIS TC Process and related policies.

All contributions made to this TC Open Repository are subject to open source license terms expressed in the [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause). That license was selected as the declared [applicable license](https://www.oasis-open.org/resources/open-repositories/licenses) when the TC Open Repository was created.

As documented in [CONTRIBUTING](https://github.com/oasis-open/cti-rust-stix/blob/master/CONTRIBUTING.md), contributions to this OASIS TC Open Repository are invited from all parties, whether affiliated with OASIS or not. Participants must have a GitHub account, but no fees or OASIS membership obligations are required. Participation is expected to be consistent with the [OASIS TC Open Repository Guidelines and Procedures](https://www.oasis-open.org/policies-guidelines/open-repositories), the open source [LICENSE](https://github.com/oasis-open/cti-rust-stix/blob/master/LICENSE) designated for this particular repository, and the requirement for an [Individual Contributor License Agreement](https://www.oasis-open.org/resources/open-repositories/cla/individual-cla) that governs intellectual property.

## Statement of Purpose

OASIS TC Open Repository: OASIS Rust STIX API: a repository containing the MVP implementation of the Rust STIX API

This library crate provides RUST APIs for serializing and de-serializing STIX2 JSON content, along with higher-level APIs for common tasks, including data markings, versioning, and for accessing STIX Objects in filesystems. It also includes a complete Rust implementation of a STIX2 Patterning parser.

For more information, you can view the crate's rust-docs by cloning the repo and opening `/docs/rust_stix2/index.html` in a browser. In the future, a web version of the rust-docs will be available on [docs.rs](https://docs.rs/).

## Installation

This library is not currently hosted on `crates.io`. As such, you can add it to your project by adding 

```
[dependencies]
rust-stix2 = { git = <GIT_REPOSITORY_URL> }
```

to your crate's `Cargo.toml` file

or by installing with `cargo` from inside your project's workspace.

```
cargo add rust-stix2 --git <GIT_REPOSITORY_URL>
```

## Usage

A STIX object is one of several Rust structs contained in the `StixObject` Rust enum (each struct type represents a different kind of STIX object).

To create a STIX object, use the Rust builder pattern with a STIX Object's Builder struct. Certain required attributes of all objects, such as `id`, will be set automatically if not provided as keyword arguments. Because different types of STIX Objects have different requirements, it is possible for the builder to error if required properties are not provided before building.

For example, to create a new `Indicator` StixDomainObject, do the following.

```rust
use rust-stix2::{domain_objects::sdo::DomainObjectBuilder, object::StixObject};

let indicator = StixObject::Sdo(
    DomainObjectBuilder::new("indicator")?
        .name("File hash for malware variant".to_string())?
        .indicator_types(vec!["malicious-activity".to_string()])?
        .pattern("[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']".to_string())?
        .pattern_type("stix".to_string())?
        .build()?
);
```

All rust-stix2 types implement `serde` serializers and deserializers as needed. To parse a STIX object from JSON, use the custom `from_json` function. To serialize a STIX object to JSON, use a preffered `serde` serialization function.


```rust
use rust-stix2::object::StixObject;
use serde_json::to_string_pretty;

let json_str = r#"{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--dbcbd659-c927-4f9a-994f-0a2632274394",
    "created": "2017-09-26T23:33:39.829Z",
    "modified": "2017-09-26T23:33:39.829Z",
    "name": "File hash for malware variant",
    "indicator_types": [
        "malicious-activity"
    ],
    "pattern_type": "stix",
    "pattern_version": "2.1",
    "pattern": "[file:hashes.md5 ='d41d8cd98f00b204e9800998ecf8427e']",
    "valid_from": "2017-09-26T23:33:39.829952Z"
            }"#;

let indicator = StixObject::from_json(json_str, false)?;

let indicator_string = to_string_pretty(&indicator)?;

println!("{indicator_string}");

``` 

## Extensions

STIX 2.0 style "custom" content is not supported.  This means that it is not possible to add arbitrary custom top-level properties to a registered object type, in the absence of a toplevel property extension.  Additional 2.0 style markings can't be registered (tlp 1.0 and statement markings are supported).

STIX 2.1 style extensions are supported, however. To define an extension, create an `ExtensionDefinition` struct, either by using the builder pattern or by deserializing one from JSON. For new properties added to an existing object as an extension, add that Extension Definitions's id and type as a dictionary entry to an existing object's `common_properties.extensions` field.

To create a new object as an extension, either build a new `CustomObject` struct using its builder pattern or deserialize one from JSON. New object extensions must include a `common_properties.extensions` dictionary containing an extension with an `extension_type` of "new-sdo", "new-sro", or "new-sco".

New object extensions are always stored in the `StixObject::Custom` enum option. The `common_properties` fields of these objects are validated as for any other object, but any properties specific to that object are stored as simple Strings and are not validated at this time.

## Patterning
This crate also includes a complete implementation of the STIX Patterning grammar, and an accompanying validation function. This implementation was written using the [nom](https://crates.io/crates/nom) crate. The data structures and functions for STIX Patterning are found in the `stix/pattern` folder.

## STIX 2 Technical Specification Support

This version of cti-rust-stix brings support to STIX Version 2.1 published on 10 June 2021 currently at the Committee Specification (CS) 03 level, also known as the "OASIS Standard".

The stix2 Rust library does not currently support older versions of the STIX 2 Technical Specification.

### Maintainers

TC Open Repository [Maintainers](https://www.oasis-open.org/resources/open-repositories/maintainers-guide) are responsible for oversight of this project's community development activities, including evaluation of GitHub [pull requests](https://github.com/oasis-open/cti-rust-stix/blob/master/CONTRIBUTING.md#fork-and-pull-collaboration-model) and [preserving](https://www.oasis-open.org/policies-guidelines/open-repositories#repositoryManagement) open source principles of openness and fairness. Maintainers are recognized and trusted experts who serve to implement community goals and consensus design preferences.

Initially, the TC members have designated one or more persons to serve as Maintainer(s); subsequently, participating community members may select additional or substitute Maintainers, by [consensus agreements](https://www.oasis-open.org/resources/open-repositories/maintainers-guide#additionalMaintainers). 

### Current Maintainers of this TC Open Repository

- [Rich Piazza](rpiazza@mitre.org), [rpiazza](https://github.com/rpiazza), [MITRE](https://www.mitre.org/) 
- [Marlon Taylor](Marlon.Taylor@mail.cisa.dhs.gov), GHID, [DHS CISA](https://www.cisa.gov/)

## About OASIS TC Open Repositories

- [TC Open Repositories: Overview and Resources](https://www.oasis-open.org/resources/open-repositories/)

- [Frequently Asked Questions](https://www.oasis-open.org/faq-tc-repo/)

- [Open Source Licenses](https://www.oasis-open.org/resources/open-repositories/licenses)

- [Contributor License Agreements (CLAs)](https://www.oasis-open.org/policies-guidelines/open-projects-process/#CLAs-license-notices)

- [Maintainers' Guidelines and Agreement](https://www.oasis-open.org/resources/open-repositories/maintainers-guide)

## Feedback

Questions or comments about this TC Open Repository's activities should be composed as GitHub issues or comments. If use of an issue/comment is not possible or appropriate, questions may be directed by email to the Maintainer(s) listed above. 

Please send general questions about TC Open Repository participation to OASIS Staff at repository-admin@oasis-open.org and any specific CLA-related questions to repository-cla@oasis-open.org.