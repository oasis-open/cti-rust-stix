//! The Filter struct enables operations on properties with various value types for flexible filtering.
use crate::types::Timestamp;
use std::collections::HashMap;

/// The Filter struct to apply conditional logic to data retrieval
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    property: String,
    op: FilterOp,
    value: String,
}

/// The FilterOp enum represents different operators
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterOp {
    Eq,
    Ne,
    In,
    Gt,
    Lt,
    Gre,
    Lte,
    Contains,
}

/// The FilterValue enum encapsulates various data types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterValue {
    Bool(bool),
    Dict(HashMap<String, String>),
    Int(u64),
    List(Vec<String>),
    Tuple,
    Str(String),
    DateTime(Timestamp),
}
