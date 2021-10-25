//! Collection of internal, general-purpose types used throughout the crate.

use std::fmt;

use serde::{Serialize, Deserialize};


// This gives us nicer error handling when deserializing JSON responses.
// TODO: If/when Try trait is stable, impl it here.
#[derive(serde::Deserialize)]
#[serde(untagged)]
pub(crate) enum B2Result<T> {
    Ok(T),
    Err(super::error::B2Error),
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
