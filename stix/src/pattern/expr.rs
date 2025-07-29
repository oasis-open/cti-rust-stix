//! Data structures used by the STIX Patterning parser

use std::{collections::HashSet, ops::Not};

use crate::{
    base::Stix,
    error::{add_error, return_multiple_errors, StixError as Error},
    types::Timestamp,
};
use log::warn;
use ordered_float::OrderedFloat;
use pcre2::bytes::RegexBuilder;

/// A STIX Pattern Constant
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Constant {
    Boolean(bool),
    Binary(String),
    Hex(String),
    Integer(i64),
    Float(OrderedFloat<f64>),
    String(String),
    Timestamp(Timestamp),
    Set(Vec<Constant>),
}

/// A STIX Pattern Observation Expression
///
/// Fpr more information, see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_e8slinrhxcc9> for details of the STIX Patterning grammar
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservationExpression {
    Comparison(ComparisonComponent),
    ObservationOp(
        Box<ObservationExpression>,
        ObservationOperator,
        Box<ObservationExpression>,
    ),
    Qualification(Box<ObservationExpression>, Qualifier),
}
impl ObservationExpression {
    fn validate(
        &self,
        errors: &mut Vec<Error>,
        qualifiers: &mut HashSet<String>,
    ) -> Result<(), Error> {
        match self {
            // Validate an observation expression that is only one or more connected comparision expressions
            Self::Comparison(comparison) => add_error(errors, comparison.validate()),
            // Validate two observation expressions joined by an observation operator
            Self::ObservationOp(lhs, _, rhs) => {
                add_error(errors, lhs.validate(&mut errors.clone(), qualifiers));
                add_error(errors, rhs.validate(&mut errors.clone(), qualifiers));
            }
            // Validate an observation expression followed by a qualifier
            Self::Qualification(observation, qualifier) => {
                add_error(
                    errors,
                    observation.validate(&mut errors.clone(), qualifiers),
                );
                add_error(errors, qualifier.check_qualifier(qualifiers));
            }
        };

        return_multiple_errors(errors.clone())
    }
}

impl Stix for ObservationExpression {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();
        let mut qualifiers = HashSet::new();

        self.validate(&mut errors, &mut qualifiers)
    }
}
/// Left-associative Boolean comparison of one or more Comparison Expressions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComparisonComponent {
    ComparisonExpression(ComparisonExpression),
    BooleanOp(
        Box<ComparisonComponent>,
        BooleanOperator,
        ComparisonExpression,
    ),
}

impl ComparisonComponent {
    /// Get the object type from one or more comparison expressions, **if** those object types are all identical
    fn get_matching_object(&self) -> Option<&str> {
        match self {
            Self::ComparisonExpression(expression) => Some(expression.get_object()),
            Self::BooleanOp(lhs, _, rhs) => lhs
                .get_matching_object()
                .filter(|&lhs_object| lhs_object == rhs.get_object()),
        }
    }

    fn validate(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        match self {
            Self::ComparisonExpression(comparison) => add_error(&mut errors, comparison.validate()),
            Self::BooleanOp(_, operator, rhs) => {
                add_error(&mut errors, rhs.validate());
                // Check that if comparison expressions are connect by an AND, both of them refer to the same object type
                if let BooleanOperator::And = operator {
                    if self.get_matching_object().is_none() {
                        errors.push(Error::ValidationError("A pair of Comparison Expressions in the pattern has an AND Boolean Operator between different objects".to_string()));
                    }
                }
            }
        }

        return_multiple_errors(errors)
    }
}

/// A STIX Pattern Comparison Expression
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparisonExpression {
    pub object_path: ObjectPath,
    pub operator: ComparisonOperator,
    pub constant: Option<Constant>,
}

impl ComparisonExpression {
    fn get_object(&self) -> &str {
        &self.object_path.sco
    }

    fn validate(&self) -> Result<(), Error> {
        if let ComparisonOperator::Exists = self.operator {
            if self.constant.is_some() {
                return Err(Error::ValidationError("A comparison expression in the pattern has an 'EXISTS' Comparison Operator but contains a constant".to_string()));
            }
        } else {
            let Some(ref constant) = self.constant else {
                return Err(Error::ValidationError("A comparison expression in the pattern has a Comparison Operator other than `EXISTS` but is missing a constant".to_string()));
            };

            match self.operator {
                ComparisonOperator::In => {
                    let Constant::Set(_) = constant else {
                        return Err(Error::ValidationError("A comparison expression in the pattern has an 'IN' Comparison Operator that is not applied to a set of constants".to_string()));
                    };
                }
                ComparisonOperator::Like
                | ComparisonOperator::IsSubset
                | ComparisonOperator::IsSuperset => {
                    let Constant::String(_) = constant else {
                        return Err(Error::ValidationError("A comparison expression in the pattern has a Comparison Operator that expects a string but is not applied to a string".to_string()));
                    };
                }
                ComparisonOperator::Matches => {
                    // First check that the constant is a String of any kind
                    let Constant::String(pattern) = constant else {
                        return Err(Error::ValidationError("A comparison expression in the pattern has a `MATCHES` Comparison Operator that expects a regular expression string but is not applied to a string".to_string()));
                    };
                    // Define an accepted PCRE regex pattern according to the STIX 2.1 standard (DOTALL enabled; UNICODE disabled if matching a binary or hex property)
                    let mut builder = RegexBuilder::new();
                    builder.dotall(true);
                    if self.object_path.sco.ends_with("_bin").not()
                        && self.object_path.sco.ends_with("_hex").not()
                    {
                        builder.ucp(true);
                    }
                    // Warn the user if the constant is not a valid PCRE regex.
                    // We warn instead of error because the pcre2 crate is still in beta and is not guaranteed to cover all possible PCRE regex patterns at this time
                    if let Err(e) = builder.build(pattern) {
                        warn!("A comparison expression in the pattern has a `MATCHES` Comparison Operator that expects a regular expression string, but the string {} may not be valid PCRE regular expression: {}", pattern, e.to_string());
                    }
                }
                _ => (),
            }
        }

        Ok(())
    }
}

/// A STIX Pattern Object Path
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectPath {
    pub sco: String,
    pub property: String,
}

/// A STIX Pattern Comparison Operator
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComparisonOperator {
    Eq,
    Neq,
    Gt,
    Lt,
    Gte,
    Lte,
    In,
    Like,
    Matches,
    IsSubset,
    IsSuperset,
    Exists,
}

/// A STIX Pattern Boolean Operator
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BooleanOperator {
    Or,
    And,
}

/// A STIX Pattern Observation Operator
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservationOperator {
    Or,
    And,
    FollowedBy,
}

/// A STIX Pattern Observation Expression Qualifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Qualifier {
    Repeats(i64),
    Within(OrderedFloat<f64>),
    StartStop(Timestamp, Timestamp),
}

impl Qualifier {
    fn check_qualifier(&self, qualifiers: &mut HashSet<String>) -> Result<(), Error> {
        match self {
            Qualifier::Repeats(_) => check_insert_qualifier("Repeats", qualifiers),
            Qualifier::Within(_) => check_insert_qualifier("Within", qualifiers),
            Qualifier::StartStop(..) => check_insert_qualifier("Start Stop", qualifiers),
        }
    }
}

/// Add a qualifier of a given type to a set of qualifiers, erroring if that type is already in the set
fn check_insert_qualifier(qualifier: &str, qualifiers: &mut HashSet<String>) -> Result<(), Error> {
    if qualifiers.contains(qualifier) {
        Err(Error::ValidationError("An Observation Expression in the pattern has more than one Qualifier of the same type.".to_string()))
    } else {
        qualifiers.insert(qualifier.to_string());
        Ok(())
    }
}
