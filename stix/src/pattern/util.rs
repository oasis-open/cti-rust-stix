//! Additional nom parser functions for use in the Patterning parser

use nom::{
    error::{Error, ErrorKind},
    IResult, Input,
};

/// Custom version of `nom::character::complete::alphanumeric0()` that also includes the '-' character
pub fn alphanumeric_dash0(input: &str) -> IResult<&str, &str> {
    input.split_at_position_complete(|item| !item.is_alphanumeric() && (item != '-'))
}

/// Custom version of `nom::character::complete::multispace0()` that includes any character that is *not* whitespace *or* a quotation mark and works only on &str
pub fn nonspace0(input: &str) -> IResult<&str, &str> {
    input.split_at_position_complete(|item| {
        item == ' ' || item == '\t' || item == '\r' || item == '\n' || item == '\'' || item == '\"'
    })
}

/// Code mostly taken from the `take_until_unbalanced` function from the `parse-hyperlinks` crate by Jens Getreu, updated for nom 8.0
/// Source: https://gitlab.com/getreu/parse-hyperlinks
pub fn take_until_unbalanced(
    opening_bracket: char,
    closing_bracket: char,
) -> impl Fn(&str) -> IResult<&str, &str> {
    move |i: &str| {
        let mut index = 0;
        let mut bracket_counter = 0;
        while let Some(n) = &i[index..].find(&[opening_bracket, closing_bracket, '\\'][..]) {
            index += n;
            let mut it = i[index..].chars();
            match it.next() {
                Some('\\') => {
                    // Skip the escape char `\`.
                    index += '\\'.len_utf8();
                    // Skip also the following char.
                    if let Some(c) = it.next() {
                        index += c.len_utf8();
                    }
                }
                Some(c) if c == opening_bracket => {
                    bracket_counter += 1;
                    index += opening_bracket.len_utf8();
                }
                Some(c) if c == closing_bracket => {
                    // Closing bracket.
                    bracket_counter -= 1;
                    index += closing_bracket.len_utf8();
                }
                // Can not happen.
                _ => unreachable!(),
            };
            // We found the unmatched closing bracket.
            if bracket_counter == -1 {
                // We do not consume it.
                index -= closing_bracket.len_utf8();
                return Ok((&i[index..], &i[0..index]));
            };
        }

        if bracket_counter == 0 {
            Ok(("", i))
        } else {
            Err(nom::Err::Error(Error::new(i, ErrorKind::TakeUntil)))
        }
    }
}
