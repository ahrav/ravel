//! Dispatch evidence shared by every remote boundary.
//!
//! An attempt's history is not an object-store or model concept: it records only whether a
//! request for one logical operation may already have reached a remote service. It lives
//! here so each boundary depends on the evidence rather than on another boundary.

/// Dispatch history for one logical operation across all resubmissions.
///
/// Replacing this value between attempts discards evidence that an earlier
/// request may have been sent.
///
/// One history belongs to exactly one operation identity — an object key here, a
/// provider operation id in [`crate::provider`]. Carrying a history across two
/// logical operations leaks the first one's dispatch uncertainty into the
/// second, which can only over-report ambiguity (`AmbiguousConflict` where a
/// definitive `Conflict`/`PreconditionFailed` held) and never under-report it.
/// Debug builds assert the single-identity binding.
#[derive(Default)]
pub struct AttemptHistory {
    may_have_been_sent: bool,
    #[cfg(debug_assertions)]
    identity: Option<String>,
}

impl AttemptHistory {
    /// Records that a dispatch is about to be attempted, returning what was known before it.
    ///
    /// Callers mark before awaiting, so a cancelled await still leaves the evidence set.
    pub(crate) fn mark_possible_send(&mut self) -> bool {
        let prior = self.may_have_been_sent;
        self.may_have_been_sent = true;
        prior
    }

    /// Replaces the evidence with the caller's verdict for the attempt that just finished.
    ///
    /// What retires uncertainty differs by boundary, so the verdict is the caller's to compute:
    /// an object store has a final object state that a definite result reconciles, while a model
    /// invocation has none, and there no later attempt's result can retire an earlier attempt's
    /// possible billable work.
    pub(crate) fn resolve(&mut self, still_uncertain: bool) {
        self.may_have_been_sent = still_uncertain;
    }

    pub(crate) fn bind(&mut self, identity: &str) {
        #[cfg(debug_assertions)]
        match &self.identity {
            Some(bound) => debug_assert_eq!(
                bound, identity,
                "an AttemptHistory covers one operation identity; reusing it across \
                 operations leaks dispatch uncertainty"
            ),
            None => self.identity = Some(identity.to_owned()),
        }
        let _ = identity;
    }
}

impl AttemptHistory {
    /// An earlier attempt for this operation identity may have reached the remote service
    /// without a result that resolves the question.
    ///
    /// A definite verdict clears this where the boundary can reconcile one, so `false` means
    /// no unresolved uncertainty rather than no dispatch. What reached the service is read
    /// from the outcome, not from here.
    pub fn may_have_been_sent(&self) -> bool {
        self.may_have_been_sent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "one operation identity")]
    fn one_history_cannot_span_two_operation_identities() {
        let mut history = AttemptHistory::default();
        history.bind("campaigns/c/head.json");
        history.bind("campaigns/other/head.json");
    }
}
