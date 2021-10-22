//! Validation functions used throughout the crate.

use std::collections::HashMap;

use crate::{
    bucket::LifecycleRule,
    error::ValidationError,
};


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

pub(crate) fn validated_cors_rule_name(name: impl Into<String>)
-> Result<String, ValidationError> {
    // The rules are the same as for bucket names.
    validated_bucket_name(name)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(prefix: &str) -> LifecycleRule {
        LifecycleRule::builder()
            .with_filename_prefix(prefix)
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
}
