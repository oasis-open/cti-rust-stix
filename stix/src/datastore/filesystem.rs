//!Filesystem includes FilesystemSink to add and FilesystemSource for retrieving STIX objects
use crate::{bundles::Bundle, error::StixError as Error, object::StixObject, types::Identifier};
use jiff::Timestamp;
use pathbuf::pathbuf;
use serde_json;
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

/// A wrapper for a `FilesystemSink` and `FilesystemSource`, useful for creating both as a pair with shared attributes
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemStore {
    sink: FilesystemSink,
    source: FilesystemSource,
}

impl FilesystemStore {
    /// Simultaneously create a `FilesystemSink` and a `FilesystemSource` with a shared directory and custom flag.
    pub fn new(
        stix_dir: &Path,
        allow_custom: bool,
        bundlify: bool,
        encoding: String,
    ) -> Result<Self, Error> {
        let sink = FilesystemSink::new(stix_dir, allow_custom, bundlify)?;
        let source = FilesystemSource::new(stix_dir, allow_custom, encoding)?;

        Ok(FilesystemStore { sink, source })
    }
}

/// A `DataSink` used to add STIX objects to a filesystem
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemSink {
    /// Path to directory of STIX objects.
    stix_dir: PathBuf,
    /// Whether to allow custom STIX content to be added to the `FilesystemSource` (default `false`).
    allow_custom: bool,
    /// Whether to wrap objects in bundles when saving them (default `false`).
    bundlify: bool,
}

impl FilesystemSink {
    /// Create a new `FilesystemSink` with a given directory path
    pub fn new(stix_dir: &Path, allow_custom: bool, bundlify: bool) -> Result<Self, Error> {
        if stix_dir.exists() {
            Ok(FilesystemSink {
                stix_dir: stix_dir.to_path_buf(),
                allow_custom,
                bundlify,
            })
        } else {
            Err(Error::PathNotFound(stix_dir.to_string_lossy().to_string()))
        }
    }

    /// Return the path to the directory of STIX objects
    pub fn stix_dir(&self) -> String {
        self.stix_dir.to_string_lossy().to_string()
    }

    /// Add one or more STIX objects from JSON or bundles to the filesystem from a list of JSON string files
    pub fn add(&self, objects: Vec<PathBuf>) -> Result<(), Error> {
        for path in objects {
            // Check that the file exists
            if !path.exists() {
                return Err(Error::PathNotFound(path.to_string_lossy().to_string()));
            }

            // Read the JSON file
            let data = fs::read_to_string(&path).map_err(|e| Error::IoError(format!("{e}")))?;

            // Check if the JSON string deserializes to a STIX Bundle. If it does, add each object in the bundle to the filesystem
            if let Ok(bundle) = Bundle::from_json(&data) {
                self.add_objects(bundle.get_objects())?;
            } else {
                // Otherwise deserialize the JSON string to a STIX Object and add that single object to the filesystem
                let object = StixObject::from_json(&data, self.allow_custom)?;
                self.add_object(object)?;
            }
        }

        Ok(())
    }

    /// Add multiple STIX objects to the filesystem
    pub fn add_objects(&self, objects: Vec<StixObject>) -> Result<(), Error> {
        for object in objects {
            self.add_object(object)?;
        }

        Ok(())
    }

    /// Add a single STIX object to the filesystem
    pub fn add_object(&self, object: StixObject) -> Result<(), Error> {
        let stix_dir = &self.stix_dir;
        let object_type = object.get_type();
        let id = &object.get_id();

        // Create the directory {stix_dir}/{type}, if it does not already exist.
        // An error here means either we do not have write permsission, which will cause a reportable error below,
        // or that the directory already exists, in which case, we are fine. Either way, we can ignore the error.
        let _ = std::fs::create_dir(pathbuf![stix_dir, object_type]);

        // Get the appropriate path to save the STIX Object
        let file_path = match object.get_modified() {
            // If the object is versionable, the path is {stix_dir}/{type}/{id}/{modified}.json
            Some(modified) => {
                // Create the directory {stix_dir}/{type}/{id}, if it does not already exist.
                // See above about why we can ignore errors.
                let _ = std::fs::create_dir(pathbuf![stix_dir, object_type, id]);
                &pathbuf![stix_dir, object_type, id, &clean_modified(&modified)]
            }
            // Otherwise, the path is {stix_dir}/{type}/{id}.json
            None => &pathbuf![&self.stix_dir, object_type, &format!("{}.json", id)],
        };

        // Serialize the STIX object to JSON
        // If `bundlify` is `true`, wrap the object in a Bundle before serializing
        let contents = match self.bundlify {
            true => serde_json::to_string(&Bundle::new(object))
                .map_err(|e| Error::IoError(format!("{e}")))?,
            false => serde_json::to_string(&object).map_err(|e| Error::IoError(format!("{e}")))?,
        };

        // Write the JSON file, if it does not already exist
        let mut file = File::create_new(file_path).map_err(|e| Error::IoError(e.to_string()))?;
        file.write_all(contents.as_bytes())
            .map_err(|e| Error::IoError(e.to_string()))
    }
}

/// A `DataSource` used to search for or retrieve STIX objects from the filesystem
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemSource {
    /// Path to directory of STIX objects.
    stix_dir: PathBuf,
    /// Whether to allow custom STIX content to be added to the `FilesystemSource` (default `true`).
    allow_custom: bool,
    /// The encoding to use when reading a file from the filesystem.
    encoding: String,
}

impl FilesystemSource {
    /// Create a new `FilesystemSource` with a given directory path
    pub fn new(stix_dir: &Path, allow_custom: bool, encoding: String) -> Result<Self, Error> {
        if stix_dir.exists() {
            Ok(FilesystemSource {
                stix_dir: stix_dir.to_path_buf(),
                allow_custom,
                encoding,
            })
        } else {
            Err(Error::PathNotFound(stix_dir.to_string_lossy().to_string()))
        }
    }

    /// Return the path to the directory of STIX objects
    pub fn stix_dir(&self) -> String {
        self.stix_dir.to_string_lossy().to_string()
    }

    /// Retreive an object from the filesystem by its STIX id.
    ///
    /// If the object is versionable and no version is given, the latest version is retrieved
    pub fn get(&self, identifier: &Identifier, version: Option<&str>) -> Result<StixObject, Error> {
        // This ensures that the stix_id String is a valid STIX Identifier, which cannot contain potentially dangerous special characters
        let stix_id = &identifier.to_string();

        // If a version is given, get only that version of the object
        // If the object is not versionable, this will fail with a "Path not found" error
        if let Some(object_version) = version {
            // Get the object's type and the path to that type's directory
            let object_type = identifier.get_type();
            let type_path = pathbuf![&self.stix_dir, object_type];

            // Check that the version is a valid Timestamp (and remove trailing 0s from the decimal portion, if any)
            let file_version = clean_modified(
                &Timestamp::from_str(object_version)
                    .map_err(|e| Error::BadVersion(object_version.to_string(), e))?
                    .to_string(),
            );

            // Get the path to the given version of the object
            let path = pathbuf![&type_path, stix_id, &file_version];

            // Get the specific version of the object
            self.get_single_object(path)
        } else {
            // Otherwise, get all versions of the object and return the most recent version, if more than one version exists
            let objects = self.all_versions(identifier)?;
            objects
                .last()
                .ok_or(Error::ObjectNotFound(identifier.to_owned()))
                .cloned()
        }
    }

    /// Retrieve all versions of an object from the filesystem by its id
    ///
    /// This will only return one object in the list if the object is not versionable
    pub fn all_versions(&self, identifier: &Identifier) -> Result<Vec<StixObject>, Error> {
        // This ensures that the stix_id String is a valid STIX Identifier, which cannot contain potentially dangerous special characters
        let stix_id = &identifier.to_string();

        // Get the object's type and the path to that type's directory
        let object_type = identifier.get_type();
        let type_path = pathbuf![&self.stix_dir, object_type];

        // If the object's id is a sub-directory, the object is a versionable type
        if pathbuf![&type_path, stix_id].is_dir() {
            let dir = pathbuf![&type_path, stix_id];
            self.get_all_object_versions(dir)
        } else {
            // If the object does not have an id sub-directory, try the path format for a non-versionable object
            let path = pathbuf![&type_path, &format!("{}.json", stix_id)];
            if path.exists() {
                // The object exists but is not versionable
                Ok(vec![self.get_single_object(path)?])
            } else {
                // The object does not exist, whether it is versionable or not
                Err(Error::ObjectNotFound(identifier.to_owned()))
            }
        }
    }

    /// Get a single object given the exact path to it in the filesystem
    fn get_single_object(&self, path: PathBuf) -> Result<StixObject, Error> {
        // Check that the object exists in the filesystem
        if !path.exists() {
            return Err(Error::PathNotFound(path.to_string_lossy().to_string()));
        }

        // Read the JSON file and derserialize it to a STIX Object
        let data = fs::read_to_string(&path).map_err(|e| Error::IoError(format!("{e}")))?;
        let object = StixObject::from_json(&data, self.allow_custom)?;

        Ok(object)
    }

    /// Get all versions of an object in a given ID directory in the filesystem, sorted by modified timestamp.
    pub fn get_all_object_versions(&self, dir: PathBuf) -> Result<Vec<StixObject>, Error> {
        let mut objects = Vec::new();

        // Confirm that the object's id directory exists in the filesystem (this is checked already in `FilesystemSource::get()`, but we check again here for safety)
        if !dir.is_dir() {
            return Err(Error::PathNotFound(dir.to_string_lossy().to_string()));
        }

        for entry in fs::read_dir(dir).map_err(|e| Error::IoError(format!("{e}")))? {
            let path = entry.map_err(|e| Error::IoError(format!("{e}")))?.path();
            // Read the JSON file and derserialize it to a STIX Object
            let data = fs::read_to_string(&path).map_err(|e| Error::IoError(format!("{e}")))?;
            let object = StixObject::from_json(&data, self.allow_custom)?;

            //Confirm that the object is versionable
            if object.get_modified().is_none() {
                return Err(Error::UnableToVersion(object.get_type().to_string()));
            }

            objects.push(object);
        }

        // Sort objects by modified property
        // PANIC: Safe to unwrap because we have confirmed all objects have a `modified` property
        objects.sort_by_key(|o| o.get_modified().unwrap());

        Ok(objects)
    }
}

/// Remove non-numeric characters from a `modified` datetime String, then add ".json" to the end.
fn clean_modified(modified: &str) -> String {
    format!("{}.json", modified.replace(['-', '.', ':', 'T', 'Z'], ""))
}

#[cfg(test)]
mod test {
    use std::env::current_dir;

    use crate::{
        cyber_observable_objects::sco::CyberObjectType, datastore::filesystem::*,
        domain_objects::sdo::DomainObjectType,
    };

    #[test]
    fn add_versioned_object() {
        let stix_dir = pathbuf![&current_dir().unwrap(), "src", "datastore", "test"];

        let fs_store = FilesystemStore::new(&stix_dir, false, false, "utf-8".to_string()).unwrap();
        let fs_sink = fs_store.sink;
        let fs_source = fs_store.source;

        let old_file_path_1 = pathbuf![&stix_dir, "attack_pattern_v1.json"];
        let old_file_path_2 = pathbuf![&stix_dir, "attack_pattern_v2.json"];
        fs_sink.add(vec![old_file_path_1, old_file_path_2]).unwrap();

        let object = fs_source
            .get(
                &Identifier::from_str("attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061")
                    .unwrap(),
                None,
            )
            .unwrap();

        let description = match &object {
            StixObject::Sdo(sdo) => match &sdo.object_type {
                DomainObjectType::AttackPattern(attack_pattern) => {
                    attack_pattern.description.as_ref().unwrap()
                }
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };

        assert_eq!(description, "Updated description");

        let old_object = fs_source
            .get(
                &Identifier::from_str("attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061")
                    .unwrap(),
                Some("2016-05-12T08:17:27.000Z"),
            )
            .unwrap();

        let old_description = match &old_object {
            StixObject::Sdo(sdo) => match &sdo.object_type {
                DomainObjectType::AttackPattern(attack_pattern) => {
                    attack_pattern.description.as_ref().unwrap()
                }
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };

        assert_eq!(old_description, "Old description");

        let objects = fs_source
            .all_versions(
                &Identifier::from_str("attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061")
                    .unwrap(),
            )
            .unwrap();

        assert_eq!(old_object, objects[0]);
        assert_eq!(object, objects[1]);

        // Clean up
        fs::remove_dir_all(&pathbuf![&stix_dir, "attack-pattern"]).unwrap();
    }

    #[test]
    fn add_unversioned_object() {
        let stix_dir = pathbuf![&current_dir().unwrap(), "src", "datastore", "test"];

        let fs_store = FilesystemStore::new(&stix_dir, false, false, "utf-8".to_string()).unwrap();
        let fs_sink = fs_store.sink;
        let fs_source = fs_store.source;

        let old_file_path = pathbuf![&stix_dir, "artifact.json"];
        fs_sink.add(vec![old_file_path]).unwrap();

        let object = &fs_source
            .get(
                &Identifier::from_str("artifact--ca17bcf8-9846-5ab4-8662-75c1bf6e63ee").unwrap(),
                None,
            )
            .unwrap();

        let payload_bin = match object {
            StixObject::Sco(sco) => match &sco.object_type {
                CyberObjectType::Artifact(artifact) => artifact.payload_bin.as_ref().unwrap(),
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };

        assert_eq!(payload_bin, "aGVsbG8gd29ybGR+Cg==");

        let versioned_object = &fs_source.get(
            &Identifier::from_str("artifact--ca17bcf8-9846-5ab4-8662-75c1bf6e63ee").unwrap(),
            Some("2016-05-12T08:17:27.000Z"),
        );

        assert!(versioned_object.is_err());

        // Clean up
        fs::remove_dir_all(&pathbuf![&stix_dir, "artifact"]).unwrap();
    }
}
