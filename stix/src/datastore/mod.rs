//! The datastore is a top-level component that includes filesystem, filters, structs, and enums.
#![allow(dead_code)]

pub mod filesystem;
pub mod filters;

use crate::{error::StixError as Error, object::StixObject, types::Identifier};
use filesystem::{FilesystemSink, FilesystemSource};
use filters::Filter;

use std::{path::PathBuf, str::FromStr};
use strum::Display;
use uuid::Uuid;

/// A wrapper for a `DataSource` and `DataSource`, providing combined mechanisms for storing and retrieving STIX data from a datastore
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataStore {
    id: Uuid,
    source: Option<DataSource>,
    sink: Option<DataSink>,
}

impl DataStore {
    /// Create a new `DataStore` from a given `DataSource` and `DataSink`
    pub fn new(source: Option<DataSource>, sink: Option<DataSink>) -> Self {
        let id = Uuid::new_v4();
        Self { id, source, sink }
    }

    /// Add one or more STIX objects to the datasystem from a list of JSON string files using the associated `DataSink`
    pub fn add(&self, objects: Vec<PathBuf>) -> Result<(), Error> {
        if let Some(sink) = &self.sink {
            sink.add(objects)
        } else {
            Err(Error::MissingDataSink)
        }
    }

    /// Add one or more STIX objects to the datasystem using the associated `DataSink`
    pub fn add_obects(&self, objects: Vec<StixObject>) -> Result<(), Error> {
        if let Some(sink) = &self.sink {
            sink.add_obects(objects)
        } else {
            Err(Error::MissingDataSink)
        }
    }

    /// Retrieve a STIX object by given ID from the datasystem using the associated `DataSource`
    ///
    /// If the object is versionable and no version is given, the latest version is retrieved
    pub fn get(&self, stix_id: &str, version: Option<&str>) -> Result<StixObject, Error> {
        if let Some(source) = &self.source {
            source.get(stix_id, version)
        } else {
            Err(Error::MissingDataSource)
        }
    }

    /// Retrieve all versions of an object with a given ID in the datastore using the associated `DataSource`, sorted by modified timestamp.
    pub fn all_versions(&self, stix_id: &str) -> Result<Vec<StixObject>, Error> {
        if let Some(source) = &self.source {
            source.all_versions(stix_id)
        } else {
            Err(Error::MissingDataSource)
        }
    }
}

/// A `DataSink` is used to add STIX objects to the datastore
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSink {
    id: Uuid,
    pub data_type: DataSinkType,
    pub filters: Vec<Filter>,
}

impl DataSink {
    /// Create a `DataSink` for a given datastore type
    pub fn new(data_type: DataSinkType, filters: Vec<Filter>) -> Self {
        let id = Uuid::new_v4();
        Self {
            id,
            data_type,
            filters,
        }
    }

    /// Add one or more STIX objects to the datasystem from a list of JSON string files to the datastore
    pub fn add(&self, objects: Vec<PathBuf>) -> Result<(), Error> {
        match &self.data_type {
            DataSinkType::FileSystem(fs) => fs.add(objects),
            _ => Err(Error::UnsupportedDataType(self.data_type.to_string())),
        }
    }

    /// Add one or more STIX objects to the datastore
    pub fn add_obects(&self, objects: Vec<StixObject>) -> Result<(), Error> {
        match &self.data_type {
            DataSinkType::FileSystem(fs) => fs.add_objects(objects),
            _ => Err(Error::UnsupportedDataType(self.data_type.to_string())),
        }
    }
}

/// `DataSinks` for each datastore type
#[derive(Debug, Clone, PartialEq, Eq, Display)]
pub enum DataSinkType {
    /// A `DataSink` for a filesystem datastore
    FileSystem(FilesystemSink),
    /// Currently not supported
    Memory,
    /// Currently not supported
    Taxii,
}

/// A `DataSource` is used to search for or retrieve STIX objects from the datastore
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSource {
    id: Uuid,
    pub data_type: DataSourceType,
    pub filters: Vec<Filter>,
}

impl DataSource {
    /// Create a `DataSource` for a given datastore type
    pub fn new(data_type: DataSourceType, filters: Vec<Filter>) -> Self {
        let id = Uuid::new_v4();
        Self {
            id,
            data_type,
            filters,
        }
    }

    /// Retrieve a STIX object by given ID from the datastore
    ///
    /// If the object is versionable and no version is given, the latest version is retrieved
    pub fn get(&self, stix_id: &str, version: Option<&str>) -> Result<StixObject, Error> {
        let identifier = Identifier::from_str(stix_id)?;
        match &self.data_type {
            DataSourceType::FileSystem(fs) => fs.get(&identifier, version),
            _ => Err(Error::UnsupportedDataType(self.data_type.to_string())),
        }
    }

    /// Retrieve all versions of an object with a given ID in the datastore, sorted by modified timestamp.
    pub fn all_versions(&self, stix_id: &str) -> Result<Vec<StixObject>, Error> {
        let identifier = Identifier::from_str(stix_id)?;
        match &self.data_type {
            DataSourceType::FileSystem(fs) => fs.all_versions(&identifier),
            _ => Err(Error::UnsupportedDataType(self.data_type.to_string())),
        }
    }
}

/// `DataSource` for each datastore type
#[derive(Debug, Clone, PartialEq, Eq, Display)]
pub enum DataSourceType {
    /// A `DataSource` for a filesystem datastore
    FileSystem(FilesystemSource),
    /// Currently not supported
    Memory,
    /// Currently not supported
    Taxii,
}
