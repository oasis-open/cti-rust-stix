//! A Rust implementaiton of STIX Patterning grammar that use the nom combinator parser

pub mod expr;
mod util;

use std::ops::Not;

use crate::{base::Stix, error::StixError, types::Timestamp};
use base64::{engine::general_purpose, Engine};
use expr::*;
use nom::{
    branch::alt,
    bytes::complete::{is_not, tag},
    character::complete::{alphanumeric1, char, digit1, multispace0, multispace1},
    combinator::{complete, fail, map, opt},
    error::{Error, ErrorKind},
    multi::separated_list1,
    number::complete::double,
    sequence::{delimited, pair, preceded, separated_pair, terminated},
    IResult, Parser,
};
use nom_language::precedence::{binary_op, precedence, unary_op, Assoc, Operation};
use ordered_float::OrderedFloat;
use util::*;

/// Validate a STIX Pattern string
pub fn validate_pattern(pattern: &str) -> Result<(), StixError> {
    // Parse the string into a STIX Pattern data structure, or else error it the pattern does not follow the grammar
    let (remains, observation) = parse_observation(pattern)
        .map_err(|e| StixError::ParsePatternError(pattern.to_string(), e.to_string()))?;
    if remains.is_empty().not() {
        return Err(StixError::ParsePatternError(
            pattern.to_string(),
            "Remaining characters at the end of pattern after parsing".to_string(),
        ));
    }

    println!("Observation: {:?}", observation);

    // Check that the STIX Pattern does not violate any additional rules
    observation.stix_check()
}

fn parse_observation(input: &str) -> IResult<&str, ObservationExpression> {
    precedence(
        fail(),
        unary_op(1, preceded(multispace1, parse_qualifier)),
        alt((
            binary_op(
                2,
                Assoc::Left,
                delimited(multispace1, tag("AND"), multispace0),
            ),
            binary_op(
                3,
                Assoc::Left,
                delimited(multispace1, tag("OR"), multispace0),
            ),
            binary_op(
                4,
                Assoc::Left,
                delimited(multispace1, tag("FOLLOWEDBY"), multispace0),
            ),
        )),
        alt((parse_comparison_observation, parse_nested_observation)),
        |op: Operation<&str, Qualifier, &str, ObservationExpression>| {
            use nom_language::precedence::Operation::*;
            match op {
                Postfix(o, qualifier) => {
                    Ok(ObservationExpression::Qualification(Box::new(o), qualifier))
                }
                Binary(lhs, "AND", rhs) => Ok(ObservationExpression::ObservationOp(
                    Box::new(lhs),
                    ObservationOperator::And,
                    Box::new(rhs),
                )),
                Binary(lhs, "OR", rhs) => Ok(ObservationExpression::ObservationOp(
                    Box::new(lhs),
                    ObservationOperator::Or,
                    Box::new(rhs),
                )),
                Binary(lhs, "FOLLOWEDBY", rhs) => Ok(ObservationExpression::ObservationOp(
                    Box::new(lhs),
                    ObservationOperator::FollowedBy,
                    Box::new(rhs),
                )),
                _ => Err("Invalid combination"),
            }
        },
    )(input)
}

fn parse_nested_observation(input: &str) -> IResult<&str, ObservationExpression> {
    let (remains, nested) =
        delimited(char('('), take_until_unbalanced('(', ')'), char(')')).parse(input)?;
    let (_, observation) = parse_observation.parse(nested)?;
    Ok((remains, observation))
}

fn parse_comparison_observation(input: &str) -> IResult<&str, ObservationExpression> {
    let (rest, first_comparison) = preceded(char('['), parse_comparison_expression).parse(input)?;

    let (remains, observation) = parse_next_comparison(
        rest,
        ComparisonComponent::ComparisonExpression(first_comparison),
    )?;

    Ok((remains, ObservationExpression::Comparison(observation)))
}

fn parse_next_comparison(
    input: &str,
    component: ComparisonComponent,
) -> IResult<&str, ComparisonComponent> {
    if let Ok((remains, _)) = char::<&str, Error<&str>>(']')(input) {
        Ok((remains, component.to_owned()))
    } else {
        let boolean_parser = map(terminated(alt((tag("AND"), tag("OR"))), multispace1), |o| {
            match_boolean_operator(o)
        });

        let (remains, (boolean, comparison2)) =
            (boolean_parser, parse_comparison_expression).parse(input)?;

        let next_component =
            ComparisonComponent::BooleanOp(Box::new(component), boolean, comparison2);
        parse_next_comparison(remains, next_component)
    }
}

fn parse_comparison_expression(input: &str) -> IResult<&str, ComparisonExpression> {
    // First check if this is an "EXISTS" comparison expression, which has a unique syntax
    if let Ok((remains, object_path)) =
        preceded(pair(tag("EXISTS"), multispace1), parse_object_path).parse(input)
    {
        let comparison_expression = ComparisonExpression {
            object_path,
            operator: ComparisonOperator::Exists,
            constant: None,
        };

        Ok((remains, comparison_expression))
    } else {
        let object_parser = terminated(parse_object_path, multispace1);
        let operator_parser = map(
            terminated(
                alt((
                    tag::<&str, &str, Error<&str>>("="),
                    tag("!="),
                    tag(">"),
                    tag("<"),
                    tag(">="),
                    tag("<="),
                    tag("IN"),
                    tag("LIKE"),
                    tag("MATCHES"),
                    tag("ISSUBSET"),
                    tag("ISSUPERSET"),
                )),
                multispace1,
            ),
            match_comparison_operator,
        );
        let constant_parser = terminated(alt((parse_set, parse_constant)), multispace0);

        let (remains, (object_path, operator, constant)) =
            (object_parser, operator_parser, constant_parser).parse(input)?;

        let comparsion_expression = ComparisonExpression {
            object_path,
            operator,
            constant: Some(constant),
        };

        Ok((remains, comparsion_expression))
    }
}

fn parse_object_path(input: &str) -> IResult<&str, ObjectPath> {
    let mut parser = complete(separated_pair(
        alphanumeric_dash0,
        char(':'),
        is_not(" \t\r\n"),
    ));

    let (remains, (sco, property)) = parser.parse(input)?;

    let object_path = ObjectPath {
        sco: sco.to_string(),
        property: property.to_string(),
    };

    Ok((remains, object_path))
}

fn parse_qualifier(input: &str) -> IResult<&str, Qualifier> {
    let (remains, qualifier) = alt((
        map(
            delimited(
                terminated(tag("REPEATS"), multispace1),
                parse_integer,
                preceded(multispace1, tag("TIMES")),
            ),
            Qualifier::Repeats,
        ),
        map(
            delimited(
                terminated(tag("WITHIN"), multispace1),
                parse_float,
                preceded(multispace1, tag("SECONDS")),
            ),
            Qualifier::Within,
        ),
        map(
            pair(
                preceded(terminated(tag("STARTS"), multispace1), parse_timestamp),
                preceded(
                    delimited(multispace1, tag("STOPS"), multispace1),
                    parse_timestamp,
                ),
            ),
            |(a, b)| Qualifier::StartStop(a, b),
        ),
    ))
    .parse(input)?;

    // Check that Qualifier values fall within the allowed ranges
    match &qualifier {
        Qualifier::Repeats(int) => {
            if *int <= 0 {
                return Err(nom::Err::Error(Error::new(input, ErrorKind::Alt)));
            }
        }
        Qualifier::Within(float) => {
            if float <= &OrderedFloat(0.0) {
                return Err(nom::Err::Error(Error::new(input, ErrorKind::Alt)));
            }
        }
        Qualifier::StartStop(start, stop) => {
            if stop <= start {
                return Err(nom::Err::Error(Error::new(input, ErrorKind::Alt)));
            }
        }
    }

    Ok((remains, qualifier))
}

fn match_boolean_operator(operator: &str) -> BooleanOperator {
    match operator {
        "AND" => BooleanOperator::And,
        "OR" => BooleanOperator::Or,
        _ => unreachable!(),
    }
}

fn match_comparison_operator(operator: &str) -> ComparisonOperator {
    match operator {
        "=" => ComparisonOperator::Eq,
        "!=" => ComparisonOperator::Neq,
        ">" => ComparisonOperator::Gt,
        "<" => ComparisonOperator::Lt,
        ">=" => ComparisonOperator::Gte,
        "<=" => ComparisonOperator::Lte,
        "IN" => ComparisonOperator::In,
        "LIKE" => ComparisonOperator::Eq,
        "MATCHES" => ComparisonOperator::Matches,
        "ISSUBSET" => ComparisonOperator::IsSubset,
        "ISSUPERSET" => ComparisonOperator::IsSuperset,
        _ => unreachable!(),
    }
}

fn parse_constant(input: &str) -> IResult<&str, Constant> {
    // parse_set is not included in the list of possible parsers to avoid recursive sets
    alt((
        map(parse_integer, Constant::Integer),
        map(parse_float, Constant::Float),
        map(parse_bool, Constant::Boolean),
        map(parse_binary, Constant::Binary),
        map(parse_hex, Constant::String),
        map(parse_timestamp, Constant::Timestamp),
        map(parse_string, Constant::String),
    ))
    .parse(input)
}

fn parse_set(input: &str) -> IResult<&str, Constant> {
    let (remains, set) = delimited(
        char('('),
        separated_list1(pair(char(','), multispace0), parse_constant),
        char(')'),
    )
    .parse(input)?;

    Ok((remains, Constant::Set(set)))
}

fn parse_integer(input: &str) -> IResult<&str, i64> {
    let (number, sign) = opt(char('-')).parse(input)?;
    let (remains, int_str) = digit1.parse(number)?;

    let mut integer = int_str
        .parse()
        .map_err(|_| nom::Err::Error(Error::new(input, ErrorKind::Digit)))?;
    if sign.is_some() {
        integer *= -1;
    }

    Ok((remains, integer))
}

fn parse_float(input: &str) -> IResult<&str, OrderedFloat<f64>> {
    let (remains, number) = double.parse(input)?;
    Ok((remains, OrderedFloat(number)))
}

fn parse_bool(input: &str) -> IResult<&str, bool> {
    let (remains, boolean) = alt((tag("true"), tag("false"))).parse(input)?;
    match boolean {
        "true" => Ok((remains, true)),
        "false" => Ok((remains, false)),
        _ => unreachable!(),
    }
}

fn parse_binary(input: &str) -> IResult<&str, String> {
    let (remains, binary_str) = delimited(tag("b\'"), alphanumeric1, char('\'')).parse(input)?;
    // Confirm that this is a valid base64 encoded string
    general_purpose::STANDARD
        .decode(format!("b\"{}\"", binary_str))
        .map_err(|_| nom::Err::Error(Error::new(input, ErrorKind::AlphaNumeric)))?;

    Ok((remains, format!("b\'{}\'", binary_str)))
}

fn parse_hex(input: &str) -> IResult<&str, String> {
    let (remains, hex_str) = delimited(tag("h\'"), alphanumeric1, char('\'')).parse(input)?;
    // Confirm that this is a valid hex string
    hex::decode(hex_str).map_err(|_| nom::Err::Error(Error::new(input, ErrorKind::HexDigit)))?;

    Ok((remains, format!("h\'{}\'", hex_str)))
}

fn parse_timestamp(input: &str) -> IResult<&str, Timestamp> {
    let (remains, timestamp_str) = delimited(tag("t\'"), nonspace0, char('\'')).parse(input)?;
    let timestamp = Timestamp::new(timestamp_str)
        .map_err(|_| nom::Err::Error(Error::new(input, ErrorKind::Tag)))?;

    Ok((remains, timestamp))
}

fn parse_string(input: &str) -> IResult<&str, String> {
    let (remains, input_str) = delimited(tag("\'"), nonspace0, char('\'')).parse(input)?;
    Ok((remains, input_str.to_string()))
}

#[cfg(test)]
mod test {
    use ordered_float::OrderedFloat;

    use crate::{
        base::Stix,
        pattern::{
            expr::*, parse_comparison_expression, parse_observation, parse_qualifier,
            validate_pattern,
        },
    };

    #[test]
    fn parse_comp_expr() {
        let pattern = "user-account:value = \'Peter\']";
        let (remains, result) = parse_comparison_expression(pattern).unwrap();

        let expected = ComparisonExpression {
            object_path: ObjectPath {
                sco: "user-account".to_string(),
                property: "value".to_string(),
            },
            operator: super::expr::ComparisonOperator::Eq,
            constant: Some(Constant::String("Peter".to_string())),
        };

        assert_eq!(remains, "]");
        assert_eq!(result, expected);
    }

    #[test]
    fn parse_invalid_constant() {
        let pattern = "user-account:value = Peter]";
        let comparison = parse_comparison_expression(pattern);

        assert!(comparison.is_err());
    }

    #[test]
    fn parse_exists() {
        let pattern = "EXISTS windows-registry-key:values";
        let result = parse_comparison_expression(pattern).unwrap().1;

        let expected = ComparisonExpression {
            object_path: ObjectPath {
                sco: "windows-registry-key".to_string(),
                property: "values".to_string(),
            },
            operator: super::expr::ComparisonOperator::Exists,
            constant: None,
        };

        assert_eq!(result, expected);
    }

    #[test]
    fn parse_comp_obsv() {
        let pattern = "[ipv4-addr:value = \'203.0.113.1\' OR ipv4-addr:value = \'203.0.113.2\' AND ipv4-addr:resolves-to-refs = (\'mac-addr--ff26c055-6336-5bc5-b98d-13d6226742dd\', \'mac-addr--5853f6a4-638f-5b4e-9b0f-ded361ae3812\')]";
        let result = parse_observation(pattern).unwrap().1;

        let comparison1 = ComparisonExpression {
            object_path: ObjectPath {
                sco: "ipv4-addr".to_string(),
                property: "value".to_string(),
            },
            operator: super::expr::ComparisonOperator::Eq,
            constant: Some(Constant::String("203.0.113.1".to_string())),
        };

        let comparison2 = ComparisonExpression {
            object_path: ObjectPath {
                sco: "ipv4-addr".to_string(),
                property: "value".to_string(),
            },
            operator: super::expr::ComparisonOperator::Eq,
            constant: Some(Constant::String("203.0.113.2".to_string())),
        };

        let comparison3 = ComparisonExpression {
            object_path: ObjectPath {
                sco: "ipv4-addr".to_string(),
                property: "resolves-to-refs".to_string(),
            },
            operator: super::expr::ComparisonOperator::Eq,
            constant: Some(Constant::Set(vec![
                Constant::String("mac-addr--ff26c055-6336-5bc5-b98d-13d6226742dd".to_string()),
                Constant::String("mac-addr--5853f6a4-638f-5b4e-9b0f-ded361ae3812".to_string()),
            ])),
        };

        let component1 = ComparisonComponent::BooleanOp(
            Box::new(ComparisonComponent::ComparisonExpression(comparison1)),
            BooleanOperator::Or,
            comparison2,
        );

        let expected = ObservationExpression::Comparison(ComparisonComponent::BooleanOp(
            Box::new(component1),
            BooleanOperator::And,
            comparison3,
        ));

        assert_eq!(result, expected);
    }

    #[test]
    fn parse_no_brackets() {
        let pattern = "ipv4-addr:value = \'203.0.113.1\' OR ipv4-addr:value = \'203.0.113.2\'";
        let observation = parse_observation(pattern);

        assert!(observation.is_err());
    }

    #[test]
    fn parse_quali() {
        let pattern = "WITHIN 600 SECONDS";
        let result = parse_qualifier(pattern).unwrap().1;

        let expected = Qualifier::Within(OrderedFloat(600_f64));
        assert_eq!(result, expected);

        let bad_pattern = "WITHIN -300 SECONDS";
        let bad_result = parse_qualifier(bad_pattern);
        assert!(bad_result.is_err());
    }

    #[test]
    fn multiple_qualis() {
        let good_pattern =
            "[domain-name:value = \'example.com\'] WITHIN 600 SECONDS REPEATS 5 TIMES";
        let good_validated = validate_pattern(good_pattern);

        let bad_pattern =
            "[domain-name:value = \'example.com\'] WITHIN 600 SECONDS WITHIN 300 SECONDS";
        let bad_validated = validate_pattern(bad_pattern);

        assert!(good_validated.is_ok());
        assert!(bad_validated.is_err());
    }

    #[test]
    fn parse_obsv() {
        let pattern = "([ipv4-addr:value = \'198.51.100.1/32\' OR ipv4-addr:value = \'203.0.113.33/32\' AND ipv6-addr:value = \'2001:0db8:dead:beef:dead:beef:dead:0001/128\'] FOLLOWEDBY [domain-name:value = \'example.com\']) WITHIN 600 SECONDS";
        let result = parse_observation(pattern).unwrap().1;

        let comparison1 = ComparisonExpression {
            object_path: ObjectPath {
                sco: "ipv4-addr".to_string(),
                property: "value".to_string(),
            },
            operator: super::expr::ComparisonOperator::Eq,
            constant: Some(Constant::String("198.51.100.1/32".to_string())),
        };

        let comparison2 = ComparisonExpression {
            object_path: ObjectPath {
                sco: "ipv4-addr".to_string(),
                property: "value".to_string(),
            },
            operator: super::expr::ComparisonOperator::Eq,
            constant: Some(Constant::String("203.0.113.33/32".to_string())),
        };

        let comparison3 = ComparisonExpression {
            object_path: ObjectPath {
                sco: "ipv6-addr".to_string(),
                property: "value".to_string(),
            },
            operator: super::expr::ComparisonOperator::Eq,
            constant: Some(Constant::String(
                "2001:0db8:dead:beef:dead:beef:dead:0001/128".to_string(),
            )),
        };

        let component1 = ComparisonComponent::BooleanOp(
            Box::new(ComparisonComponent::ComparisonExpression(comparison1)),
            BooleanOperator::Or,
            comparison2,
        );

        let observation1 = ObservationExpression::Comparison(ComparisonComponent::BooleanOp(
            Box::new(component1),
            BooleanOperator::And,
            comparison3,
        ));

        let observation2 = ObservationExpression::Comparison(
            ComparisonComponent::ComparisonExpression(ComparisonExpression {
                object_path: ObjectPath {
                    sco: "domain-name".to_string(),
                    property: "value".to_string(),
                },
                operator: super::expr::ComparisonOperator::Eq,
                constant: Some(Constant::String("example.com".to_string())),
            }),
        );

        let observation3 = ObservationExpression::ObservationOp(
            Box::new(observation1),
            ObservationOperator::FollowedBy,
            Box::new(observation2),
        );

        let expected = ObservationExpression::Qualification(
            Box::new(observation3),
            Qualifier::Within(ordered_float::OrderedFloat(600_f64)),
        );

        assert_eq!(result, expected);
    }

    #[test]
    fn parse_and_different_objects() {
        let pattern = "[ipv4-addr:value = \'198.51.100.1/32\' AND ipv6-addr:value = \'2001:0db8:dead:beef:dead:beef:dead:0001/128\']";
        let observation = parse_observation(pattern).unwrap().1.stix_check();
        assert!(observation.is_err());
    }
}
