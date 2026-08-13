use std::{error::Error, fmt};

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
