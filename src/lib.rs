//! The store retains immutable event and artifact objects and updates one head
//! conditionally.
//!
//! Publication witnesses prevent unverified immutable bytes from entering head
//! transitions. Ambiguous mutations resolve from the current head and retained event
//! chain. No protocol path deletes objects. S3 ETags are opaque compare-and-swap
//! tokens.

pub mod db {
    pub mod projections;
    pub mod worker;
}

pub mod domain {
    pub mod artifact;
    pub mod proposal;
    pub mod validation;
    pub mod work;
}

pub mod dispatch;

pub mod distributed;

pub mod invocation;

pub mod provider;

pub mod sandbox;

pub mod storage {
    pub mod artifacts;
    pub mod s3;
}

pub mod scope;
pub mod sync;
