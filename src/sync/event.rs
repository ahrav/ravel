//! Immutable event reads and publication witnesses.
//!
//! Production publication registers root genesis and plan admission; test-only successors exercise CAS and retained-chain behavior.

use std::{error::Error, fmt};

use ciborium::Value;

use crate::{
    scope::{
        DecodedScopeEvent, EncodedScopeEvent, EventEnvelope, MAX_COMPRESSED_BYTES,
        ROOT_GENESIS_PAYLOAD_TYPE, RootEvent, ScopeEventRef, ScopeIdentity, decode_scope_event,
        encode_root_event, scope_event_key,
    },
    storage::s3::{AttemptHistory, GetError, GetOutcome, PublicationError, S3Store},
};

use super::WireError;

/// Proves canonical event bytes exist in one object-store namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedScopeEventPublication {
    scope: ScopeIdentity,
    envelope: EventEnvelope,
    reference: ScopeEventRef,
    bytes: Vec<u8>,
    namespace: String,
}

impl ResolvedScopeEventPublication {
    pub fn scope(&self) -> &ScopeIdentity {
        &self.scope
    }

    pub fn envelope(&self) -> &EventEnvelope {
        &self.envelope
    }

    pub fn event_ref(&self) -> &ScopeEventRef {
        &self.reference
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    #[cfg(test)]
    pub(crate) fn attributed_to(mut self, namespace: &str) -> Self {
        self.namespace = namespace.to_owned();
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeEventPublicationError {
    UnsupportedPayload,
    Invalid(WireError),
    Storage(PublicationError),
}

impl fmt::Display for ScopeEventPublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedPayload => "scoped event payload is unsupported",
            Self::Invalid(_) => "scoped event is invalid",
            Self::Storage(_) => "scoped event publication failed",
        })
    }
}

impl Error for ScopeEventPublicationError {}

#[derive(Debug)]
pub enum ScopeEventReadError {
    Storage(GetError),
    Invalid(WireError),
}

impl fmt::Display for ScopeEventReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Storage(_) => "scoped event read failed",
            Self::Invalid(_) => "scoped event encoding is invalid",
        })
    }
}

impl Error for ScopeEventReadError {}

pub async fn publish_root(
    store: &S3Store,
    scope: &ScopeIdentity,
    event: &RootEvent,
    history: &mut AttemptHistory,
) -> Result<ResolvedScopeEventPublication, ScopeEventPublicationError> {
    let encoded = encode_root_event(event).map_err(ScopeEventPublicationError::Invalid)?;
    publish_encoded(store, scope, event.envelope(), encoded, history).await
}

pub(crate) async fn publish_encoded(
    store: &S3Store,
    scope: &ScopeIdentity,
    envelope: &EventEnvelope,
    encoded: EncodedScopeEvent,
    history: &mut AttemptHistory,
) -> Result<ResolvedScopeEventPublication, ScopeEventPublicationError> {
    let key = scope_event_key(scope, encoded.event_ref());
    validate_registered(scope, envelope, &encoded, &key)?;
    store
        .publish_with_history(
            &key,
            encoded.stored_bytes().to_vec(),
            encoded.event_ref().digest().as_str(),
            history,
        )
        .await
        .map_err(ScopeEventPublicationError::Storage)?;
    Ok(ResolvedScopeEventPublication {
        scope: scope.clone(),
        envelope: envelope.clone(),
        reference: encoded.event_ref().clone(),
        bytes: encoded.stored_bytes().to_vec(),
        namespace: store.namespace().to_owned(),
    })
}

pub(crate) async fn read_opaque(
    store: &S3Store,
    scope: &ScopeIdentity,
    reference: &ScopeEventRef,
) -> Result<Option<(DecodedScopeEvent<Value>, Vec<u8>)>, ScopeEventReadError> {
    let key = scope_event_key(scope, reference);
    let outcome =
        store
            .get_object(&key, MAX_COMPRESSED_BYTES)
            .await
            .map_err(|error| match error {
                GetError::TooLarge => ScopeEventReadError::Invalid(WireError::LimitExceeded),
                other => ScopeEventReadError::Storage(other),
            })?;
    match outcome {
        GetOutcome::NotFound => Ok(None),
        GetOutcome::Found { bytes, .. } => {
            let decoded = decode_scope_event(&bytes, &key, scope, None)
                .map_err(ScopeEventReadError::Invalid)?;
            Ok(Some((decoded, bytes)))
        }
    }
}

pub(crate) fn payload_registered(envelope: &EventEnvelope) -> bool {
    crate::scope::payload_type_registered(envelope.payload_type())
}

/// Root genesis requires sequence 1 and no parent event.
pub(crate) fn root_domain_valid(envelope: &EventEnvelope) -> bool {
    envelope.payload_type() != ROOT_GENESIS_PAYLOAD_TYPE
        || (envelope.sequence() == 1 && envelope.parent_event().is_none())
}

pub(crate) fn root_payload_valid(
    decoded: &DecodedScopeEvent<Value>,
    scope: &ScopeIdentity,
) -> bool {
    decoded.envelope().payload_type() != ROOT_GENESIS_PAYLOAD_TYPE
        || crate::scope::root_event_from_decoded(decoded.clone(), scope).is_ok()
}

fn validate_registered(
    scope: &ScopeIdentity,
    envelope: &EventEnvelope,
    encoded: &EncodedScopeEvent,
    key: &str,
) -> Result<(), ScopeEventPublicationError> {
    if !payload_registered(envelope) {
        return Err(ScopeEventPublicationError::UnsupportedPayload);
    }
    if envelope.payload_type() == ROOT_GENESIS_PAYLOAD_TYPE {
        let root = crate::scope::decode_root_event(encoded.stored_bytes(), key, scope)
            .map_err(ScopeEventPublicationError::Invalid)?;
        return if root.envelope() == envelope {
            Ok(())
        } else {
            Err(ScopeEventPublicationError::Invalid(WireError::InvalidValue))
        };
    }
    if envelope.payload_type() == crate::scope::PLAN_ADMITTED_PAYLOAD_TYPE {
        let admitted = crate::scope::decode_plan_admitted_event(encoded.stored_bytes(), key, scope)
            .map_err(ScopeEventPublicationError::Invalid)?;
        return if admitted.envelope() == envelope {
            Ok(())
        } else {
            Err(ScopeEventPublicationError::Invalid(WireError::InvalidValue))
        };
    }
    if envelope.payload_type() == crate::scope::GRANT_ACTIVATED_PAYLOAD_TYPE {
        let activated =
            crate::scope::decode_grant_activated_event(encoded.stored_bytes(), key, scope)
                .map_err(ScopeEventPublicationError::Invalid)?;
        return if activated.envelope() == envelope {
            Ok(())
        } else {
            Err(ScopeEventPublicationError::Invalid(WireError::InvalidValue))
        };
    }
    if envelope.payload_type() == crate::scope::PROJECTION_CHECKPOINT_PAYLOAD_TYPE {
        let checkpoint =
            crate::scope::decode_projection_checkpoint_event(encoded.stored_bytes(), key, scope)
                .map_err(ScopeEventPublicationError::Invalid)?;
        return if checkpoint.envelope() == envelope {
            Ok(())
        } else {
            Err(ScopeEventPublicationError::Invalid(WireError::InvalidValue))
        };
    }
    #[cfg(test)]
    if envelope.payload_type() == crate::scope::TEST_SUCCESSOR_PAYLOAD_TYPE {
        let decoded = decode_scope_event::<Value>(encoded.stored_bytes(), key, scope, None)
            .map_err(ScopeEventPublicationError::Invalid)?;
        return if decoded.envelope() == envelope && decoded.event_ref() == encoded.event_ref() {
            Ok(())
        } else {
            Err(ScopeEventPublicationError::Invalid(WireError::InvalidValue))
        };
    }
    Err(ScopeEventPublicationError::Invalid(WireError::InvalidValue))
}

#[cfg(test)]
mod tests {
    use aws_sdk_s3::primitives::SdkBody;
    use ciborium::Value;

    use crate::{
        distributed::identity::WorkspaceId,
        scope::{
            AdmittedCampaignConfig, CampaignId, EventEnvelope, encode_scope_event, root_genesis,
        },
        storage::s3::test_support::{replay_store, response},
    };

    use super::*;

    fn genesis() -> crate::scope::RootGenesis {
        root_genesis(
            &AdmittedCampaignConfig::new(
                WorkspaceId::new("workspace-a".into()).unwrap(),
                CampaignId::new("campaign-a".into()).unwrap(),
                b"admitted".to_vec(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn publishes_root_bytes_and_retains_dispatch_history() {
        let genesis = genesis();
        let root = crate::scope::decode_root_event(
            genesis.event_bytes(),
            genesis.event_key(),
            genesis.identity(),
        )
        .unwrap();
        let (store, client) = replay_store(vec![response(200, &[], SdkBody::empty())]);
        let published = publish_root(
            &store,
            genesis.identity(),
            &root,
            &mut AttemptHistory::default(),
        )
        .await
        .unwrap();
        assert_eq!(published.canonical_bytes(), genesis.event_bytes());
        assert_eq!(client.actual_requests().count(), 1);

        let (store, client) = replay_store(vec![
            response(500, &[], SdkBody::empty()),
            response(404, &[], SdkBody::empty()),
            response(412, &[], SdkBody::empty()),
        ]);
        let mut history = AttemptHistory::default();
        assert_eq!(
            publish_root(&store, genesis.identity(), &root, &mut history).await,
            Err(ScopeEventPublicationError::Storage(
                PublicationError::Unresolved
            ))
        );
        assert!(history.may_have_been_sent());
        assert_eq!(client.actual_requests().count(), 3);
    }

    #[tokio::test]
    async fn encoded_bytes_must_match_the_supplied_envelope() {
        let genesis = genesis();
        let envelope_a = EventEnvelope::new(
            genesis.identity().scope_id().clone(),
            2,
            Some(genesis.event_ref().clone()),
            1,
            "operation-a".into(),
            crate::scope::TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
        )
        .unwrap();
        let envelope_b = EventEnvelope::new(
            genesis.identity().scope_id().clone(),
            2,
            Some(genesis.event_ref().clone()),
            1,
            "operation-b".into(),
            crate::scope::TEST_SUCCESSOR_PAYLOAD_TYPE.into(),
        )
        .unwrap();
        let encoded = encode_scope_event(&envelope_b, &Value::Null).unwrap();
        let (store, client) = replay_store(vec![]);
        assert!(matches!(
            publish_encoded(
                &store,
                genesis.identity(),
                &envelope_a,
                encoded,
                &mut AttemptHistory::default(),
            )
            .await,
            Err(ScopeEventPublicationError::Invalid(_))
        ));
        assert_eq!(client.actual_requests().count(), 0);
    }

    #[tokio::test]
    async fn unsupported_payload_never_reaches_storage() {
        let genesis = genesis();
        let envelope = EventEnvelope::new(
            genesis.identity().scope_id().clone(),
            2,
            Some(genesis.event_ref().clone()),
            1,
            "artifact-op".into(),
            "artifact".into(),
        )
        .unwrap();
        let encoded = encode_scope_event(&envelope, &Value::Null).unwrap();
        let (store, client) = replay_store(vec![]);
        assert_eq!(
            publish_encoded(
                &store,
                genesis.identity(),
                &envelope,
                encoded,
                &mut AttemptHistory::default(),
            )
            .await,
            Err(ScopeEventPublicationError::UnsupportedPayload)
        );
        assert_eq!(client.actual_requests().count(), 0);

        let envelope = EventEnvelope::new(
            genesis.identity().scope_id().clone(),
            2,
            Some(genesis.event_ref().clone()),
            1,
            "fake-root".into(),
            ROOT_GENESIS_PAYLOAD_TYPE.into(),
        )
        .unwrap();
        let encoded = encode_scope_event(&envelope, &Value::Null).unwrap();
        let (store, client) = replay_store(vec![]);
        assert!(matches!(
            publish_encoded(
                &store,
                genesis.identity(),
                &envelope,
                encoded,
                &mut AttemptHistory::default(),
            )
            .await,
            Err(ScopeEventPublicationError::Invalid(_))
        ));
        assert_eq!(client.actual_requests().count(), 0);
    }
}
