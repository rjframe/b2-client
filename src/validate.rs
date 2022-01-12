//! Validation functions used throughout the crate.

use std::collections::HashMap;

use crate::{
    bucket::LifecycleRule,
    error::ValidationError,
};

use http_types::{
    cache::{CacheControl, Expires},
    Trailers,
};

use percent_encoding::{AsciiSet, CONTROLS};


// TODO: This doesn't really belong here; it's a transformation of valid data
// rather than a validator.
// We can ignore control characters; they will fail the filename validator.
// But the percent_encoded library won't let us create an empty set, so we're
// starting with the set of ASCII control characters anyway.
pub(crate) const QUERY_ENCODE_SET: AsciiSet = CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b',')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b']')
    .add(b'\\')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

#[deprecated(note = "Use QUERY_ENCODE_SET instead")]
pub(crate) const FILENAME_ENCODE_SET: AsciiSet = QUERY_ENCODE_SET;

/// Returns the provided HTTP header if it's valid; otherwise ValidationError.
///
/// An HTTP header:
///
/// * must be valid ASCII.
/// * must not include whitespace.
/// * must not include ASCII codes outside alphanumeric codes or any of
///   "!" "#" "$" "%" "&" "'" "*" "+" "-" "." "^" "_" "`" "|" or "~".
///
/// # Notes
///
/// We validate headers according to
/// [RFC 7230](https://www.rfc-editor.org/rfc/rfc7230), notably
/// [Section 3.2.6](https://www.rfc-editor.org/rfc/rfc7230#section-3.2.6). It is
/// possible that the B2 API is more lenient.
pub(crate) fn validated_http_header(header: &str)
-> Result<&str, ValidationError> {
    let is_valid = |c: char| "!#$%&'*+-.^_`|~".contains(c);

    let invalid = header.chars()
        .find(|c| !(c.is_ascii_alphanumeric() || is_valid(*c)));

    if let Some(ch) = invalid {
        Err(ValidationError::BadFormat(
            format!("Invalid character in header: {}", ch)
        ))
    } else {
        Ok(header)
    }
}

pub(crate) fn validated_bucket_name(name: impl Into<String>)
-> Result<String, ValidationError> {
    let name = name.into();

    if name.len() < 6 || name.len() > 50 {
        return Err(ValidationError::OutOfBounds(
            "Bucket name must be be between 6 and 50 characters, inclusive"
                .into()
        ));
    }

    let invalid_char = |c: &char| !(c.is_ascii_alphanumeric() || *c == '-');

    match name.chars().find(invalid_char) {
        None => Ok(name),
        Some(ch) => Err(
            ValidationError::BadFormat(format!("Unexpected character: {}", ch))
        ),
    }
}

/// Ensure a filename is valid.
///
/// Note that B2 disallows ASCII control characters, but other control
/// characters defined by Unicode are allowed.
pub(crate) fn validated_file_name<'a>(name: &'a str)
-> Result<&'a str, ValidationError> {
    for ch in name.chars() {
        if ch.is_ascii_control() {
            return Err(ValidationError::BadFormat(format!(
                "The filename \"{}\" cannot include the character '{}'",
                name,
                ch,
            )));
        }
    }

    if name.len() > 1024 {
        return Err(ValidationError::BadFormat(format!(
            "The filename cannot be above 1024 bytes, but is {}", name.len()
        )));
    }

    Ok(name)
}

pub(crate) fn validated_cors_rule_name(name: impl Into<String>)
-> Result<String, ValidationError> {
    // The rules are the same as for bucket names.
    validated_bucket_name(name)
}

/// Ensure the keys and values of file metadata is correct.
///
/// We do not check the byte length limit since the limit applies to both the
/// file info and the name.
// TODO: Check limit anyway? If we exceed the limit here we can fail faster.
pub(crate) fn validated_file_info(info: serde_json::Value)
-> Result<serde_json::Value, ValidationError> {
    let obj = info.as_object()
        .ok_or_else(||
            ValidationError::BadFormat("file_info is not an object".into())
        )?;

    if obj.len() > 10 {
        return Err(ValidationError::BadFormat(
            "file_info cannot contain more than 10 items".into()
        ));
    }

    for (key, val) in obj {
        validate_info_key_val(key, val)?;
    }

    Ok(info)
}

fn validate_info_key_val(key: &str, val: &serde_json::Value)
-> Result<(), ValidationError> {
    if key.len() > 50 {
        return Err(ValidationError::BadFormat(format!(
            "Key cannot exceed 50 bytes, but is {}", key.len()
        )));
    }

    if key.starts_with("b2-") {
        validate_info_val(key, val)?
    }

    let is_valid = |c: char| c.is_alphanumeric()
        || ['-', '_', '.', '`', '~', '!', '#', '$', '%', '^', '&', '*', '\'',
            '|', '+'].contains(&c);

    for ch in key.chars() {
        if ! is_valid(ch) {
            return Err(ValidationError::BadFormat(format!(
                "Invalid character in key: '{}'", ch
            )));
        }
    }

    Ok(())
}

/// Validate the file_info for B2-specific metadata.
pub fn validate_info_val(key: &str, val: &serde_json::Value)
-> Result<(), ValidationError> {
    let val = val.as_str().ok_or_else(||
        ValidationError::BadFormat(format!("{} value must be a string", key))
    )?;

    // TODO: We can likely validate the stuff I'm using http_types to validate
    // more efficiently by doing it manually.
    match key {
        "b2-content-disposition" => {
            validate_content_disposition(val, false)
        },
        "b2-content-language" => {
            for ch in val.chars() {
                if ! (ch.is_ascii_alphabetic() || ch == '-') {
                    return Err(ValidationError::BadFormat(format!(
                        "Invalid character in Content-Language: {}", ch
                    )));
                }
            }
            Ok(())
        },
        "b2-expires" => {
            let mut hdr = Trailers::new();
            hdr.insert("Expires", val);

            Expires::from_headers(hdr.as_ref())
                .map_err(|_| ValidationError::BadFormat(format!(
                    "Invalid Expires value: {}", val
                )))?;

            Ok(())
        },
        "b2-cache-control" => {
            // TODO: CacheControl type doesn't seem to validate cache-extension
            // properly. See
            // https://datatracker.ietf.org/doc/html/rfc2616#section-14.9
            let mut hdr = Trailers::new();
            hdr.insert("CacheControl", val);

            CacheControl::from_headers(hdr.as_ref())
                .map_err(|_| ValidationError::BadFormat(format!(
                    "Invalid CacheControl value: {}", val
                )))?;

            Ok(())
        },
        "b2-content-encoding" => {
            // B2 documentation says this must conform to RFC 2616, which seems
            // to be more restrictive than RFC 7231, which supercedes it. We're
            // going to validate that the value is a valid token, but not worry
            // about the value itself.
            if is_valid_token(val) {
                Ok(())
            } else {
                Err(ValidationError::BadFormat(format!(
                    "Invalid ContentEncoding: {}", val
                )))
            }
        },
        _ => Err(ValidationError::BadFormat(format!(
            "Invalid key name: {}", key
        ))),
    }
}

pub fn validate_content_disposition(text: &str, allow_star: bool)
-> Result<(), ValidationError> {
    let sep_idx = text.find(';');

    if sep_idx.is_none() {
        // Lack of a ';' means the value is a simple token.
        return if is_valid_token(text) {
            Ok(())
        } else {
            Err(ValidationError::BadFormat(format!(
                "Illegal Content-Disposition type: {}", text
            )))
        };
    } else if text.ends_with(';') {
        return Err(ValidationError::BadFormat(
            "Content-Disposition cannot end with a semicolon".into()
        ));
    }
    let sep_idx = sep_idx.unwrap();

    for param in text[sep_idx+1..].split(';') {
        if let Some((field, value)) = param.split_once('=') {
            let field = field.trim();

            if ! is_valid_token(field) {
                return Err(ValidationError::BadFormat(format!(
                    "Illegal character in field name: {}", field
                )));
            }

            if ! allow_star && field == "*" {
                return Err(ValidationError::BadFormat(
                    "Asterisk ('*') is not allowed in a field name".into()
                ));
            }

            let value = value.trim();

            // TODO: We need to also verify that if the value is an ext-value as
            // defined at
            // https://datatracker.ietf.org/doc/html/rfc5987#section-3.2 that it
            // is valid. We currently assume it's valid. Also see restrictions
            // listed at https://www.backblaze.com/b2/docs/files.html
            if ! (is_valid_token(value) || is_valid_quoted_string(value)) {
                return Err(ValidationError::BadFormat(
                    "Invalid field value".into()
                ));
            }
        }
    }

    Ok(())
}

fn is_valid_token(s: &str) -> bool {
    let separators = [
        '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?',
        '=', '{', '}', ' ', '\t',
    ];

    if s.is_empty() { return false; }

    for ch in s.chars() {
        if ! ch.is_ascii_alphanumeric() || ch.is_control()
            || separators.contains(&ch)
        {
            return false;
        }
    }

    true
}

fn is_valid_quoted_string(s: &str) -> bool {
    if ! (s.starts_with('"') && s.ends_with('"'))
    {
        return false;
    }

    let s = s.as_bytes();

    for i in 1..s.len() - 1 {
        if ! s[i].is_ascii() || s[i].is_ascii_control()
            || (s[i] == b'"' && s[i-1] != b'\\')
        {
            return false;
        }
    }

    true
}

/// Return the provided list of [LifecycleRule]s or a map of errors.
///
/// No file within a bucket can be subject to multiple lifecycle rules. If any
/// of the rules provided apply to multiple files or folders, we return the
/// conflicting rules. The map's key is the broadest rule (highest in the
/// hierarchy).
///
/// There can be duplicate entries when subfolders are involved.
///
/// The empty string (`""`) matches all paths, so if provided it must be the
/// only lifecycle rule. If it is provided along with other rules, all of those
/// rules will be listed as a conflict.
// TODO: The current implementation clones all conflicting rule paths twice.
// Three times if the initial into() requires cloning them.
pub(crate) fn validated_lifecycle_rules(rules: impl Into<Vec<LifecycleRule>>)
-> Result<Vec<LifecycleRule>, ValidationError> {
    let mut rules = rules.into();
    rules.sort();

    let mut checked: Vec<Vec<String>> = vec![];

    if rules.is_empty() {
        // There is nothing particularly wrong about having no lifecycle rules,
        // but we assume that if a list of rules is provided that it should
        // contain at least one object.
        Err(ValidationError::MissingData(
            "No lifecycle rules were specified".into()
        ))
    } else if rules.len() > 100 {
        Err(ValidationError::OutOfBounds(
            "There can be no more than 100 lifecycle rules on a bucket".into()
        ))
    } else if rules.len() == 1 {
        Ok(rules)
    } else {
        let first_rule = &rules[0].file_name_prefix;
        checked.push(vec![first_rule.to_owned()]);

        for rule in rules.iter().map(|r| &r.file_name_prefix).skip(1) {
            for i in 0 .. checked.len() {
                let root = &checked[i][0];

                if rule.starts_with(root) {
                    checked[i].push(rule.to_owned());
                }  else {
                    checked.push(vec![rule.to_owned()]);
                }
            }
        }

        let mut map = HashMap::new();

        checked.into_iter()
            .filter(|l| l.len() > 1) // Keep only conflicts.
            // TODO: We're cloning all elements here. See if the optimizer takes
            // care of it.
            .for_each(|l| {
                let key = l[0].to_owned();
                let val = Vec::from(&l[1..]);
                map.insert(key, val);
            });

        if ! map.is_empty() {
            Err(ValidationError::ConflictingRules(map))
        } else {
            Ok(rules)
        }
    }
}

/// Validate a list of origins for a CORS rule.
///
/// See [CorsRuleBuilder::with_allowed_origins] for the rules concerning a valid
/// origin.
pub(crate) fn validated_origins(origins: impl Into<Vec<String>>)
-> Result<Vec<String>, ValidationError> {
    let origins = origins.into();

    if origins.is_empty() {
        return Err(ValidationError::MissingData(
            "There must be at least one origin covered by the rule".into()
        ));
    }

    if ! (origins.len() == 1 && origins[0] == "*") {
        let mut found_https = false;

        for origin in origins.iter() {
            // `http` and `https` are valid origins, but `Url::parse()` won't
            // parse them, so we check them separately.
            if origin == "https" {
                if found_https {
                    return Err(ValidationError::Incompatible(
                        "There can only be one HTTPS rule".into()
                    ));
                }
                found_https = true;
            } else if origin != "http" {
                if origin.chars().filter(|c| *c == '*').count() > 1 {
                    return Err(ValidationError::BadFormat(
                        "A URL cannot have more than one '*'".into()
                    ));
                }

                let url = url::Url::parse(origin)?;

                if url.scheme() == "https" {
                    if found_https {
                        return Err(ValidationError::Incompatible(
                            "There can only be one HTTPS rule".into()
                        ));
                    }
                    found_https = true;
                }

                if ! (url.scheme() == "https" || url.scheme() == "http") {
                    return Err(ValidationError::BadUrl(url.to_string()));
                }
            }
        }
    }

    Ok(origins)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;


    fn make_rule(prefix: &str) -> LifecycleRule {
        LifecycleRule::builder()
            .filename_prefix(prefix).unwrap()
            .delete_after_hide(chrono::Duration::days(3)).unwrap()
            .build().unwrap()
    }

    #[test]
    fn validate_good_lifecycle_rules() {
        let rules = vec![
            make_rule("Docs/Photos/"),
            make_rule("Legal/"),
            make_rule("Archive/"),
        ];

        let rules = validated_lifecycle_rules(rules).unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].file_name_prefix, "Archive/");
        assert_eq!(rules[1].file_name_prefix, "Docs/Photos/");
        assert_eq!(rules[2].file_name_prefix, "Legal/");
    }

    #[test]
    fn validate_single_rule() {
        let rules = vec![
            make_rule("Docs/Photos/"),
        ];

        let rules = validated_lifecycle_rules(rules).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].file_name_prefix, "Docs/Photos/");
    }

    #[test]
    fn validate_one_lifecycle_rule_conflicts() {
        let rules = vec![
            make_rule("Docs/Photos/"),
            make_rule("Legal/"),
            make_rule("Legal/Taxes/"),
            make_rule("Archive/"),
        ];

        match validated_lifecycle_rules(rules).unwrap_err() {
            ValidationError::ConflictingRules(conflicts) => {
                assert_eq!(conflicts.len(), 1);
                assert_eq!(conflicts["Legal/"],
                    vec!["Legal/Taxes/".to_owned()]);
            },
            e => panic!("Unexpected error: {}", e),
        }
    }

    #[test]
    fn validate_many_lifecycle_rules_conflict() {
        let rules = vec![
            make_rule("Docs/Photos/"),
            make_rule("Docs/"),
            make_rule("Docs/Documents/"),
            make_rule("Archive/Temporary/"),
            make_rule("Legal/Taxes/"),
            make_rule("Legal/Other/"),
            make_rule("Docs/Photos/Vacations/"),
            make_rule("Archive/"),
        ];

        match validated_lifecycle_rules(rules).unwrap_err() {
            ValidationError::ConflictingRules(c) => {
                assert_eq!(c.len(), 3);
                assert_eq!(c["Docs/"],
                    vec![
                        "Docs/Documents/".to_owned(),
                        "Docs/Photos/".to_owned(),
                        "Docs/Photos/Vacations/".to_owned(),
                    ]
                );

                // This is a duplicated record owing its existence to the way
                // we've happened to implement the loops. I don't want to
                // iterate the vectors yet again to eliminate it, and I think
                // I'm OK with the duplication.
                assert_eq!(c["Docs/Photos/"],
                    vec!["Docs/Photos/Vacations/".to_owned()]
                );
                assert_eq!(c["Archive/"],
                    vec!["Archive/Temporary/".to_owned()]);
            },
            e => panic!("Unexpected error: {}", e),
        }
    }

    #[test]
    fn validate_many_lifecycle_rules_multiple_conflicts() {
        let rules = vec![
            make_rule("Docs/Photos/Vacations/"),
            make_rule("Docs/Photos/Buildings/"),
            make_rule("Docs/Photos/"),
            make_rule("Docs/"),
            make_rule("Docs/Documents/"),
        ];

        match validated_lifecycle_rules(rules).unwrap_err() {
            ValidationError::ConflictingRules(c) => {
                assert_eq!(c.len(), 1);
                assert_eq!(c["Docs/"],
                    vec![
                        "Docs/Documents/".to_owned(),
                        "Docs/Photos/".to_owned(),
                        "Docs/Photos/Buildings/".to_owned(),
                        "Docs/Photos/Vacations/".to_owned(),
                    ]
                );
            },
            e => panic!("Unexpected error: {}", e),
        }
    }

    #[test]
    fn validate_empty_lifecycle_rule_alone_is_good() {
        let rules = vec![
            make_rule(""),
        ];

        let rules = validated_lifecycle_rules(rules).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].file_name_prefix, "");
    }

    #[test]
    fn validate_empty_lifecycle_rule_with_others_is_error() {
        let rules = vec![
            make_rule("Docs/Photos/"),
            make_rule(""),
            make_rule("Legal/"),
            make_rule("Legal/Taxes/"),
            make_rule("Archive/"),
        ];

        match validated_lifecycle_rules(rules).unwrap_err() {
            ValidationError::ConflictingRules(conflicts) => {
                assert_eq!(conflicts.len(), 1);
                assert_eq!(conflicts[""],
                    vec![
                        "Archive/".to_owned(),
                        "Docs/Photos/".to_owned(),
                        "Legal/".to_owned(),
                        "Legal/Taxes/".to_owned(),
                    ]
                );
            },
            e => panic!("Unexpected error: {}", e),
        }
    }

    #[test]
    fn validate_quoted_string() {
        assert!(is_valid_quoted_string("\"\""));
        assert!(is_valid_quoted_string("\"a\""));
        assert!(is_valid_quoted_string("\"abcde\""));
        assert!(is_valid_quoted_string("\"ab\\\"cde\""));

        assert!(! is_valid_quoted_string("\"ab\"cd\""));
    }

    #[test]
    fn validate_info_key_val_filters_disallowed_chars() {
        validate_info_key_val("good-sep", &json!("asdf")).unwrap();
        validate_info_key_val("good#sep", &json!("asdf")).unwrap();
        validate_info_key_val("$goodsep", &json!("asdf")).unwrap();
        validate_info_key_val("good-sep%", &json!("asdf")).unwrap();

        validate_info_key_val("bad@sep", &json!("asdf")).unwrap_err();
        validate_info_key_val("bad(sep", &json!("asdf")).unwrap_err();
        validate_info_key_val("{badsep", &json!("asdf")).unwrap_err();
        validate_info_key_val("badsep]", &json!("asdf")).unwrap_err();
    }

    #[test]
    fn validate_content_disposition_fields() {
        validate_info_val("b2-content-disposition", &json!("inline")).unwrap();
        validate_info_val(
            "b2-content-disposition",
            &json!("attachment; filename=\"myfile.txt\"")
        ).unwrap();
        validate_info_val(
            "b2-content-disposition",
            &json!("attachment; something=value")
        ).unwrap();
        validate_info_val(
            "b2-content-disposition",
            &json!("attachment; filename=\"myfile.txt\"; something=value")
        ).unwrap();

        // RFC 6266 says that the semicolon without at least one field is
        // illegal. It wouldn't surprise me if many clients allow it, but we're
        // going to enforce the standard.
        validate_info_val("b2-content-disposition", &json!("inline;"))
            .unwrap_err();
        validate_info_val("b2-content-disposition", &json!("inline; f="))
            .unwrap_err();
    }

    #[test]
    fn validate_content_language() {
        validate_info_val("b2-content-language", &json!("en")).unwrap();
        validate_info_val("b2-content-language", &json!("lang-dialect"))
            .unwrap();

        validate_info_val("b2-content-language", &json!("bad-lang/text"))
            .unwrap_err();
        validate_info_val("b2-content-language", &json!("bad+lang"))
            .unwrap_err();
    }

    #[test]
    fn validate_expires() {
        validate_info_val("b2-expires", &json!("Thu, 01 Dec 1994 16:00:00 GMT"))
            .unwrap();

        validate_info_val("b2-expires", &json!("2021-1-1")).unwrap_err();
    }

    #[test]
    fn validate_cache_control() {
        validate_info_val("b2-cache-control", &json!("no-store")).unwrap();

        // TODO: Implement cache-extension validation to test:
        //validate_info_val("b2-cache-control", &json!("(not-valid-token)"))
        //    .unwrap_err();
    }

    #[test]
    fn b2_filename_encoding_tests() {
        use percent_encoding::utf8_percent_encode;

        // These tests come from
        // https://www.backblaze.com/b2/docs/string_encoding.html
        let tests = serde_json::json!([
            {"fullyEncoded": "%20", "minimallyEncoded": "+", "string": " "},
            {"fullyEncoded": "%21", "minimallyEncoded": "!", "string": "!"},
            {"fullyEncoded": "%22", "minimallyEncoded": "%22", "string": "\""},
            {"fullyEncoded": "%23", "minimallyEncoded": "%23", "string": "#"},
            {"fullyEncoded": "%24", "minimallyEncoded": "$", "string": "$"},
            {"fullyEncoded": "%25", "minimallyEncoded": "%25", "string": "%"},
            {"fullyEncoded": "%26", "minimallyEncoded": "%26", "string": "&"},
            {"fullyEncoded": "%27", "minimallyEncoded": "'", "string": "'"},
            {"fullyEncoded": "%28", "minimallyEncoded": "(", "string": "("},
            {"fullyEncoded": "%29", "minimallyEncoded": ")", "string": ")"},
            {"fullyEncoded": "%2A", "minimallyEncoded": "*", "string": "*"},
            {"fullyEncoded": "%2B", "minimallyEncoded": "%2B", "string": "+"},
            {"fullyEncoded": "%2C", "minimallyEncoded": "%2C", "string": ","},
            {"fullyEncoded": "%2D", "minimallyEncoded": "-", "string": "-"},
            {"fullyEncoded": "%2E", "minimallyEncoded": ".", "string": "."},
            {"fullyEncoded": "/", "minimallyEncoded": "/", "string": "/"},
            {"fullyEncoded": "%30", "minimallyEncoded": "0", "string": "0"},
            {"fullyEncoded": "%31", "minimallyEncoded": "1", "string": "1"},
            {"fullyEncoded": "%32", "minimallyEncoded": "2", "string": "2"},
            {"fullyEncoded": "%33", "minimallyEncoded": "3", "string": "3"},
            {"fullyEncoded": "%34", "minimallyEncoded": "4", "string": "4"},
            {"fullyEncoded": "%35", "minimallyEncoded": "5", "string": "5"},
            {"fullyEncoded": "%36", "minimallyEncoded": "6", "string": "6"},
            {"fullyEncoded": "%37", "minimallyEncoded": "7", "string": "7"},
            {"fullyEncoded": "%38", "minimallyEncoded": "8", "string": "8"},
            {"fullyEncoded": "%39", "minimallyEncoded": "9", "string": "9"},
            {"fullyEncoded": "%3A", "minimallyEncoded": ":", "string": ":"},
            {"fullyEncoded": "%3B", "minimallyEncoded": ";", "string": ";"},
            {"fullyEncoded": "%3C", "minimallyEncoded": "%3C", "string": "<"},
            {"fullyEncoded": "%3D", "minimallyEncoded": "=", "string": "="},
            {"fullyEncoded": "%3E", "minimallyEncoded": "%3E", "string": ">"},
            {"fullyEncoded": "%3F", "minimallyEncoded": "%3F", "string": "?"},
            {"fullyEncoded": "%40", "minimallyEncoded": "@", "string": "@"},
            {"fullyEncoded": "%41", "minimallyEncoded": "A", "string": "A"},
            {"fullyEncoded": "%42", "minimallyEncoded": "B", "string": "B"},
            {"fullyEncoded": "%43", "minimallyEncoded": "C", "string": "C"},
            {"fullyEncoded": "%44", "minimallyEncoded": "D", "string": "D"},
            {"fullyEncoded": "%45", "minimallyEncoded": "E", "string": "E"},
            {"fullyEncoded": "%46", "minimallyEncoded": "F", "string": "F"},
            {"fullyEncoded": "%47", "minimallyEncoded": "G", "string": "G"},
            {"fullyEncoded": "%48", "minimallyEncoded": "H", "string": "H"},
            {"fullyEncoded": "%49", "minimallyEncoded": "I", "string": "I"},
            {"fullyEncoded": "%4A", "minimallyEncoded": "J", "string": "J"},
            {"fullyEncoded": "%4B", "minimallyEncoded": "K", "string": "K"},
            {"fullyEncoded": "%4C", "minimallyEncoded": "L", "string": "L"},
            {"fullyEncoded": "%4D", "minimallyEncoded": "M", "string": "M"},
            {"fullyEncoded": "%4E", "minimallyEncoded": "N", "string": "N"},
            {"fullyEncoded": "%4F", "minimallyEncoded": "O", "string": "O"},
            {"fullyEncoded": "%50", "minimallyEncoded": "P", "string": "P"},
            {"fullyEncoded": "%51", "minimallyEncoded": "Q", "string": "Q"},
            {"fullyEncoded": "%52", "minimallyEncoded": "R", "string": "R"},
            {"fullyEncoded": "%53", "minimallyEncoded": "S", "string": "S"},
            {"fullyEncoded": "%54", "minimallyEncoded": "T", "string": "T"},
            {"fullyEncoded": "%55", "minimallyEncoded": "U", "string": "U"},
            {"fullyEncoded": "%56", "minimallyEncoded": "V", "string": "V"},
            {"fullyEncoded": "%57", "minimallyEncoded": "W", "string": "W"},
            {"fullyEncoded": "%58", "minimallyEncoded": "X", "string": "X"},
            {"fullyEncoded": "%59", "minimallyEncoded": "Y", "string": "Y"},
            {"fullyEncoded": "%5A", "minimallyEncoded": "Z", "string": "Z"},
            {"fullyEncoded": "%5B", "minimallyEncoded": "%5B", "string": "["},
            {"fullyEncoded": "%5C", "minimallyEncoded": "%5C", "string": "\\"},
            {"fullyEncoded": "%5D", "minimallyEncoded": "%5D", "string": "]"},
            {"fullyEncoded": "%5E", "minimallyEncoded": "%5E", "string": "^"},
            {"fullyEncoded": "%5F", "minimallyEncoded": "_", "string": "_"},
            {"fullyEncoded": "%60", "minimallyEncoded": "%60", "string": "`"},
            {"fullyEncoded": "%61", "minimallyEncoded": "a", "string": "a"},
            {"fullyEncoded": "%62", "minimallyEncoded": "b", "string": "b"},
            {"fullyEncoded": "%63", "minimallyEncoded": "c", "string": "c"},
            {"fullyEncoded": "%64", "minimallyEncoded": "d", "string": "d"},
            {"fullyEncoded": "%65", "minimallyEncoded": "e", "string": "e"},
            {"fullyEncoded": "%66", "minimallyEncoded": "f", "string": "f"},
            {"fullyEncoded": "%67", "minimallyEncoded": "g", "string": "g"},
            {"fullyEncoded": "%68", "minimallyEncoded": "h", "string": "h"},
            {"fullyEncoded": "%69", "minimallyEncoded": "i", "string": "i"},
            {"fullyEncoded": "%6A", "minimallyEncoded": "j", "string": "j"},
            {"fullyEncoded": "%6B", "minimallyEncoded": "k", "string": "k"},
            {"fullyEncoded": "%6C", "minimallyEncoded": "l", "string": "l"},
            {"fullyEncoded": "%6D", "minimallyEncoded": "m", "string": "m"},
            {"fullyEncoded": "%6E", "minimallyEncoded": "n", "string": "n"},
            {"fullyEncoded": "%6F", "minimallyEncoded": "o", "string": "o"},
            {"fullyEncoded": "%70", "minimallyEncoded": "p", "string": "p"},
            {"fullyEncoded": "%71", "minimallyEncoded": "q", "string": "q"},
            {"fullyEncoded": "%72", "minimallyEncoded": "r", "string": "r"},
            {"fullyEncoded": "%73", "minimallyEncoded": "s", "string": "s"},
            {"fullyEncoded": "%74", "minimallyEncoded": "t", "string": "t"},
            {"fullyEncoded": "%75", "minimallyEncoded": "u", "string": "u"},
            {"fullyEncoded": "%76", "minimallyEncoded": "v", "string": "v"},
            {"fullyEncoded": "%77", "minimallyEncoded": "w", "string": "w"},
            {"fullyEncoded": "%78", "minimallyEncoded": "x", "string": "x"},
            {"fullyEncoded": "%79", "minimallyEncoded": "y", "string": "y"},
            {"fullyEncoded": "%7A", "minimallyEncoded": "z", "string": "z"},
            {"fullyEncoded": "%7B", "minimallyEncoded": "%7B", "string": "{"},
            {"fullyEncoded": "%7C", "minimallyEncoded": "%7C", "string": "|"},
            {"fullyEncoded": "%7D", "minimallyEncoded": "%7D", "string": "}"},
            {"fullyEncoded": "%7E", "minimallyEncoded": "~", "string": "~"},
            {
                "fullyEncoded": "%7F",
                "minimallyEncoded": "%7F",
                "string": "\u{007f}"
            },
            {
                "fullyEncoded": "%E8%87%AA%E7%94%B1",
                "minimallyEncoded": "%E8%87%AA%E7%94%B1",
                "string": "\u{81ea}\u{7531}"
            },
            /* TODO: Invalid string.
            {
                "fullyEncoded": "%F0%90%90%80",
                "minimallyEncoded": "%F0%90%90%80",
                "string": "\u{d801}\u{dc00}"
            }
            */
        ]);

        let tests = tests.as_array().unwrap();

        for test in tests.iter() {
            let encoded = utf8_percent_encode(
                test["string"].as_str().unwrap(),
                &FILENAME_ENCODE_SET
            ).to_string();

            assert!(
                encoded == test["fullyEncoded"]
                    || encoded == test["minimallyEncoded"],
                "Failed test: {}. Actual: `{}`", test.to_string(), encoded
            );
        }
    }
}
