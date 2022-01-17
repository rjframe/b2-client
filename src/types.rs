//! Collection of internal, general-purpose types used throughout the crate.

use std::fmt;
use super::error::{B2Error, Error};

use percent_encoding::{AsciiSet, CONTROLS};
use serde::{Serialize, Deserialize};


// This gives us nicer error handling when deserializing JSON responses.
// TODO: If/when Try trait is stable, impl it here.
#[derive(serde::Deserialize)]
#[serde(untagged)]
#[must_use]
pub(crate) enum B2Result<T> {
    Ok(T),
    Err(B2Error),
}

impl<T, E> From<B2Result<T>> for std::result::Result<T, Error<E>>
    where E: fmt::Debug + fmt::Display,
{
    fn from(r: B2Result<T>) -> std::result::Result<T, Error<E>> {
        match r {
            B2Result::Ok(v) => Ok(v),
            B2Result::Err(e) => Err(crate::error::Error::B2(e)),
        }
    }
}

impl<T> B2Result<T> {
    pub fn map<U, F>(self, op: F) -> B2Result<U>
        where F: FnOnce(T) -> U,
    {
        match self {
            B2Result::Ok(v) => B2Result::Ok(op(v)),
            B2Result::Err(e) => B2Result::Err(e),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Duration(pub(crate) chrono::Duration);

impl std::ops::Deref for Duration {
    type Target = chrono::Duration;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl From<chrono::Duration> for Duration {
    fn from(d: chrono::Duration) -> Self {
        Self(d)
    }
}

impl From<Duration> for chrono::Duration {
    fn from(d: Duration) -> Self { d.0 }
}

impl Serialize for Duration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: serde::Serializer,
    {
        serializer.serialize_i64(self.num_milliseconds())
    }
}

struct DurationVisitor;

impl<'de> serde::de::Visitor<'de> for DurationVisitor {
    type Value = i64;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "the number of milliseconds representing the duration"
        )
    }

    fn visit_i64<E>(self, s: i64) -> Result<Self::Value, E>
        where E: serde::de::Error,
    {
        Ok(s)
    }
}

impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D>(deserializer: D) -> Result<Duration, D::Error>
        where D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_i64(DurationVisitor)
            .map(|i| Duration(chrono::Duration::milliseconds(i)))
    }
}

/// Set of characters to percent-encode in GET requests and headers.
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

#[cfg(test)]
mod tests {
    #[test]
    fn b2_filename_encoding_tests() {
        use crate::types::QUERY_ENCODE_SET;
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
                &QUERY_ENCODE_SET
            ).to_string();

            assert!(
                encoded == test["fullyEncoded"]
                    || encoded == test["minimallyEncoded"],
                "Failed test: {}. Actual: `{}`", test.to_string(), encoded
            );
        }
    }
}
