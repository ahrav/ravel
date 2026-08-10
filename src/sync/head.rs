//! The v1 head encoding is frozen.
//!
//! Head bytes are compact UTF-8 JSON with no whitespace or trailing newline.
//! Field order is part of v1's canonical encoding: `version`, `authority`,
//! `tail`, then `operation_id`. Authority is `{"state":"unowned"}` or an
//! owned map with `owner`, `instance`, `lease_until`, and `controller_fence`.
//! Tail contains `sequence`, `digest`, then `key`. The decoder compares input
//! bytes with the production re-encoding before domain conversion; this rejects
//! extra fields on internally tagged unowned unit variants.

use serde::{Deserialize, Serialize};

use crate::domain::campaign::{Authority, AuthorityState, EventRef, Head};

use super::{WIRE_VERSION, WireError};

const MAX_HEAD_BYTES: usize = 4 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireHead {
    version: u64,
    authority: WireAuthority,
    tail: WireEventRef,
    operation_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "state", rename_all = "snake_case")]
enum WireAuthority {
    Unowned,
    Owned {
        owner: String,
        instance: String,
        lease_until: u64,
        controller_fence: u64,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireEventRef {
    sequence: u64,
    digest: String,
    key: String,
}

pub fn encode(head: &Head) -> Result<Vec<u8>, WireError> {
    serde_json::to_vec(&WireHead::from(head)).map_err(|_| WireError::InvalidEncoding)
}

pub fn decode(bytes: &[u8]) -> Result<Head, WireError> {
    if bytes.is_empty() || bytes.len() > MAX_HEAD_BYTES {
        return Err(WireError::LimitExceeded);
    }
    let wire: WireHead = serde_json::from_slice(bytes).map_err(|_| WireError::InvalidEncoding)?;
    let canonical = serde_json::to_vec(&wire).map_err(|_| WireError::InvalidEncoding)?;
    if canonical != bytes {
        return Err(WireError::NonCanonical);
    }
    wire.try_into()
}

impl From<&Head> for WireHead {
    fn from(head: &Head) -> Self {
        Self {
            version: WIRE_VERSION,
            authority: WireAuthority::from(head.authority()),
            tail: WireEventRef::from(head.tail()),
            operation_id: head.operation_id().to_owned(),
        }
    }
}

impl From<&Authority> for WireAuthority {
    fn from(authority: &Authority) -> Self {
        match authority.state() {
            AuthorityState::Unowned => Self::Unowned,
            AuthorityState::Owned {
                owner,
                instance,
                lease_until,
                controller_fence,
            } => Self::Owned {
                owner: owner.clone(),
                instance: instance.clone(),
                lease_until: *lease_until,
                controller_fence: *controller_fence,
            },
        }
    }
}

impl From<&EventRef> for WireEventRef {
    fn from(event_ref: &EventRef) -> Self {
        Self {
            sequence: event_ref.sequence(),
            digest: event_ref.digest().to_owned(),
            key: event_ref.key().to_owned(),
        }
    }
}

impl TryFrom<WireHead> for Head {
    type Error = WireError;

    fn try_from(wire: WireHead) -> Result<Self, Self::Error> {
        if wire.version != WIRE_VERSION {
            return Err(WireError::InvalidValue);
        }
        let authority = Authority::try_from(wire.authority)?;
        let tail = EventRef::new(wire.tail.sequence, wire.tail.digest, wire.tail.key)
            .map_err(|_| WireError::InvalidValue)?;
        Head::new(authority, tail, wire.operation_id).map_err(|_| WireError::InvalidValue)
    }
}

impl TryFrom<WireAuthority> for Authority {
    type Error = WireError;

    fn try_from(authority: WireAuthority) -> Result<Self, Self::Error> {
        match authority {
            WireAuthority::Unowned => Ok(Self::unowned()),
            WireAuthority::Owned {
                owner,
                instance,
                lease_until,
                controller_fence,
            } => Self::owned(owner, instance, lease_until, controller_fence)
                .map_err(|_| WireError::InvalidValue),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNED_HEAD: &[u8] = include_bytes!("../../tests/fixtures/v1/head-owned.json");

    fn digest() -> String {
        "0".repeat(64)
    }

    fn key() -> String {
        format!("{:016}-{}.cbor.zst", 1, digest())
    }

    fn valid_wire() -> WireHead {
        WireHead {
            version: WIRE_VERSION,
            authority: WireAuthority::Unowned,
            tail: WireEventRef {
                sequence: 1,
                digest: digest(),
                key: key(),
            },
            operation_id: "op".into(),
        }
    }

    fn bytes(wire: &WireHead) -> Vec<u8> {
        serde_json::to_vec(wire).unwrap()
    }

    #[test]
    fn production_json_uses_frozen_field_order() {
        assert_eq!(
            String::from_utf8(bytes(&valid_wire())).unwrap(),
            format!(
                "{{\"version\":1,\"authority\":{{\"state\":\"unowned\"}},\"tail\":{{\"sequence\":1,\"digest\":\"{}\",\"key\":\"{}\"}},\"operation_id\":\"op\"}}",
                digest(),
                key()
            )
        );
    }

    #[test]
    fn rejects_unknown_version_and_invalid_values() {
        let mut wire = valid_wire();
        wire.version = 2;
        assert_eq!(decode(&bytes(&wire)), Err(WireError::InvalidValue));

        wire.version = WIRE_VERSION;
        wire.tail.key = "bad".into();
        assert_eq!(decode(&bytes(&wire)), Err(WireError::InvalidValue));

        wire.tail.key = key();
        wire.operation_id = "x".repeat(129);
        assert_eq!(decode(&bytes(&wire)), Err(WireError::InvalidValue));

        wire.operation_id = "op".into();
        wire.authority = WireAuthority::Owned {
            owner: "x".repeat(129),
            instance: "instance".into(),
            lease_until: 1,
            controller_fence: 1,
        };
        assert_eq!(decode(&bytes(&wire)), Err(WireError::InvalidValue));
    }

    #[test]
    fn rejects_noncanonical_and_unrecognized_json() {
        let canonical = String::from_utf8(bytes(&valid_wire())).unwrap();
        assert_eq!(
            decode(format!("{canonical}\n").as_bytes()),
            Err(WireError::NonCanonical)
        );
        assert_eq!(
            decode(canonical.replace("\"version\":1,", "").as_bytes()),
            Err(WireError::InvalidEncoding)
        );
        assert_eq!(
            decode(
                canonical
                    .replace("{\"version\":1", "{\"version\":1,\"version\":1")
                    .as_bytes()
            ),
            Err(WireError::InvalidEncoding)
        );
        assert_eq!(
            decode(canonical.replace("\"unowned\"", "\"future\"").as_bytes()),
            Err(WireError::InvalidEncoding)
        );

        let root_extra = canonical.strip_suffix('}').unwrap().to_owned() + ",\"extra\":null}";
        assert_eq!(
            decode(root_extra.as_bytes()),
            Err(WireError::InvalidEncoding)
        );
        let authority_extra = canonical.replace(
            "{\"state\":\"unowned\"}",
            "{\"state\":\"unowned\",\"owner\":\"x\"}",
        );
        assert_eq!(
            decode(authority_extra.as_bytes()),
            Err(WireError::NonCanonical)
        );
        let tail_extra = canonical.replace("\"tail\":{", "\"tail\":{\"extra\":null,");
        assert_eq!(
            decode(tail_extra.as_bytes()),
            Err(WireError::InvalidEncoding)
        );

        let reordered = canonical.replacen("{\"version\":1,\"authority\":", "{\"authority\":", 1);
        let reordered = reordered.replacen("},\"tail\":", "},\"version\":1,\"tail\":", 1);
        assert_eq!(decode(reordered.as_bytes()), Err(WireError::NonCanonical));
    }

    #[test]
    fn rejects_alternate_scalar_representations() {
        let canonical = String::from_utf8(bytes(&valid_wire())).unwrap();
        assert_eq!(
            decode(
                canonical
                    .replace("\"version\":1", "\"version\":1.0")
                    .as_bytes()
            ),
            Err(WireError::InvalidEncoding)
        );
        assert_eq!(
            decode(
                canonical
                    .replace("\"version\":1", "\"version\":1e0")
                    .as_bytes()
            ),
            Err(WireError::InvalidEncoding)
        );
        assert_eq!(
            decode(
                canonical
                    .replace("\"operation_id\":\"op\"", "\"operation_id\":\"\\u006fp\"")
                    .as_bytes()
            ),
            Err(WireError::NonCanonical)
        );
        assert_eq!(
            decode(canonical.replace(&digest(), &"A".repeat(64)).as_bytes()),
            Err(WireError::InvalidValue)
        );

        let owned = String::from_utf8(OWNED_HEAD.to_vec()).unwrap();
        assert_eq!(
            decode(
                owned
                    .replace("\"lease_until\":1750000000000", "\"lease_until\":-1")
                    .as_bytes()
            ),
            Err(WireError::InvalidEncoding)
        );
    }

    #[test]
    fn bounds_head_input_before_parsing() {
        assert!(OWNED_HEAD.len() < MAX_HEAD_BYTES);
        assert!(decode(OWNED_HEAD).is_ok());
        assert_eq!(decode(&[]), Err(WireError::LimitExceeded));
        assert_eq!(
            decode(&vec![b' '; MAX_HEAD_BYTES + 1]),
            Err(WireError::LimitExceeded)
        );
    }
}
