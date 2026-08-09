//! Versioned wire codecs for events and the authority-bearing head.
//!
//! Decoders reject unknown versions, invalid domain values, and alternate byte
//! representations before returning domain types. Public errors expose only
//! data-free categories so object contents and keys do not enter diagnostics.

use std::{error::Error, fmt};

pub mod event;
pub mod head;

pub(crate) const WIRE_VERSION: u64 = 1;

/// Fail-closed category produced by a durable wire codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    InvalidEncoding,
    NonCanonical,
    LimitExceeded,
    InvalidValue,
    ReferenceMismatch,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "invalid wire encoding",
            Self::NonCanonical => "noncanonical wire encoding",
            Self::LimitExceeded => "wire size limit exceeded",
            Self::InvalidValue => "invalid wire value",
            Self::ReferenceMismatch => "event reference mismatch",
        })
    }
}

impl Error for WireError {}
