//! In-memory store of approved agent login requests.
//!
//! When a signed-in user approves an agent login request for one of their devices, the approval is
//! recorded here under the request ID (the SHA-256 hex digest of the agent's secret). The agent
//! then claims the device by presenting that secret. Unapproved requests allocate no state on the
//! server, and server restarts clear any unclaimed approvals.

use crate::error::Code;
use chrono::{DateTime, TimeDelta, Utc};
use std::{collections::HashMap, sync::Mutex};

/// Maximum age of an agent login request timestamp when a user approves it.
pub const REQUEST_LIFETIME: TimeDelta = TimeDelta::minutes(15);
/// How long an approved request remains claimable by the agent.
const APPROVAL_LIFETIME: TimeDelta = TimeDelta::minutes(10);
/// Grace period after the first claim during which the agent can retry if the response was lost.
const RETRY_LIFETIME: TimeDelta = TimeDelta::minutes(2);
/// Maximum number of concurrent pending approvals allowed per account.
const PENDING_PER_ACCOUNT: usize = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    pub device_id: String,
    /// Account that approved the request.
    pub account_id: String,
    expires_at: DateTime<Utc>,
}

/// Thread-safe map of pending agent claim approvals keyed by request ID.
#[derive(Default)]
pub struct AgentApprovals {
    approvals: Mutex<HashMap<String, Approval>>,
}

impl AgentApprovals {
    /// Records that `account_id` approved request `id` for `device_id`. Returns
    /// [`Code::ClaimTaken`] if another account already approved `id`, or
    /// [`Code::ClaimLimitReached`] if `account_id` already has [`PENDING_PER_ACCOUNT`] active
    /// approvals.
    pub fn approve(
        &self,
        id: String,
        device_id: String,
        account_id: String,
        now: DateTime<Utc>,
    ) -> Result<(), Code> {
        let mut approvals = self.approvals.lock().expect("approvals lock");
        approvals.retain(|_, a| a.expires_at > now);
        if approvals
            .get(&id)
            .is_some_and(|a| a.account_id != account_id)
        {
            return Err(Code::ClaimTaken);
        }
        let pending = approvals
            .iter()
            .filter(|(other, a)| a.account_id == account_id && **other != id)
            .count();
        if pending >= PENDING_PER_ACCOUNT {
            return Err(Code::ClaimLimitReached);
        }
        let expires_at = now + APPROVAL_LIFETIME;
        approvals.insert(
            id,
            Approval {
                device_id,
                account_id,
                expires_at,
            },
        );
        Ok(())
    }

    /// Returns the active approval for request `id` and shortens its remaining lifetime to
    /// [`RETRY_LIFETIME`].
    pub fn claim(&self, id: &str, now: DateTime<Utc>) -> Option<Approval> {
        let mut approvals = self.approvals.lock().expect("approvals lock");
        let approval = approvals.get_mut(id).filter(|a| a.expires_at > now)?;
        approval.expires_at = approval.expires_at.min(now + RETRY_LIFETIME);
        Some(approval.clone())
    }

    /// Removes all pending approvals for `device_id` when the device is revoked, blocked, or
    /// deleted.
    pub fn forget_device(&self, device_id: &str) {
        let mut approvals = self.approvals.lock().expect("approvals lock");
        approvals.retain(|_, a| a.device_id != device_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    /// Approves `count` requests `r0`, `r1`, … of the account `account_id` at `now()`.
    fn approve_requests(approvals: &AgentApprovals, account_id: &str, count: usize) {
        for n in 0..count {
            let id = format!("r{n}");
            let approval = approvals.approve(id, "d".into(), account_id.into(), now());
            approval.unwrap();
        }
    }

    #[test]
    fn accounts_hold_a_limited_number_of_pending_approvals() {
        let approvals = AgentApprovals::default();
        approve_requests(&approvals, "a", PENDING_PER_ACCOUNT);
        let extra = approvals.approve("extra".into(), "d".into(), "a".into(), now());
        assert_eq!(extra, Err(Code::ClaimLimitReached));
    }

    #[test]
    fn approving_a_request_again_takes_no_slot() {
        let approvals = AgentApprovals::default();
        approve_requests(&approvals, "a", PENDING_PER_ACCOUNT);
        let again = approvals.approve("r0".into(), "d".into(), "a".into(), now());
        assert_eq!(again, Ok(()));
    }

    #[test]
    fn pending_limits_are_per_account() {
        let approvals = AgentApprovals::default();
        approve_requests(&approvals, "a", PENDING_PER_ACCOUNT);
        let other = approvals.approve("other".into(), "d".into(), "b".into(), now());
        assert_eq!(other, Ok(()));
    }

    #[test]
    fn expired_approvals_free_their_slot() {
        let approvals = AgentApprovals::default();
        approve_requests(&approvals, "a", PENDING_PER_ACCOUNT);
        let later = now() + APPROVAL_LIFETIME;
        let fresh = approvals.approve("fresh".into(), "d".into(), "a".into(), later);
        assert_eq!(fresh, Ok(()));
    }

    #[test]
    fn claim_retries_never_extend_the_original_retry_deadline() {
        let approvals = AgentApprovals::default();
        approvals
            .approve("r".into(), "d".into(), "a".into(), now())
            .unwrap();
        assert_eq!(approvals.claim("r", now()).unwrap().device_id, "d");
        assert!(
            approvals
                .claim("r", now() + RETRY_LIFETIME - TimeDelta::seconds(1))
                .is_some()
        );
        assert!(approvals.claim("r", now() + RETRY_LIFETIME).is_none());
    }

    #[test]
    fn unknown_and_expired_approvals_cannot_be_claimed() {
        let approvals = AgentApprovals::default();
        assert!(approvals.claim("unknown", now()).is_none());
        approvals
            .approve("r".into(), "d".into(), "a".into(), now())
            .unwrap();
        assert!(approvals.claim("r", now() + APPROVAL_LIFETIME).is_none());
    }

    #[test]
    fn approved_requests_stay_with_their_account() {
        let approvals = AgentApprovals::default();
        approvals
            .approve("r".into(), "d".into(), "a".into(), now())
            .unwrap();
        let taken = approvals.approve("r".into(), "e".into(), "b".into(), now());
        assert_eq!(taken, Err(Code::ClaimTaken));
        assert_eq!(approvals.claim("r", now()).unwrap().device_id, "d");
    }

    #[test]
    fn forgotten_devices_lose_their_approvals() {
        let approvals = AgentApprovals::default();
        approvals
            .approve("r".into(), "d".into(), "a".into(), now())
            .unwrap();
        approvals.forget_device("d");
        assert!(approvals.claim("r", now()).is_none());
    }

    #[test]
    fn forgotten_requests_are_free_for_other_accounts() {
        let approvals = AgentApprovals::default();
        approvals
            .approve("r".into(), "d".into(), "a".into(), now())
            .unwrap();
        approvals.forget_device("d");
        let freed = approvals.approve("r".into(), "e".into(), "b".into(), now());
        assert_eq!(freed, Ok(()));
    }
}
