//! The store retains immutable event and artifact objects and updates one head
//! conditionally.
//!
//! Publication witnesses prevent unverified immutable bytes from entering head
//! transitions. Ambiguous mutations resolve from the current head and retained event
//! chain. No protocol path deletes objects. S3 ETags are opaque compare-and-swap
//! tokens.

pub mod domain {
    pub mod artifact;
    pub mod validation;
    pub mod work;
}

pub mod distributed;

pub mod storage {
    pub mod artifacts;
    pub mod s3;
}

pub mod scope;
pub mod sync;
