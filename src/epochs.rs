// SPDX-License-Identifier: MIT
//! Which key epochs new content may use after a revocation.
//!
//! A revoked member keeps every key it ever held, so anything encrypted
//! under one of them stays readable to it. Each revocation rotates the
//! key, so in a node's own view of the share the **required epoch** is
//! `1 + removals` (`AuthState::required_epoch`), raised by the epoch floor
//! when two different keys were seen for one epoch (a fork, see
//! `crypto::InstallOutcome::Conflict`). Then:
//!
//! - a node encrypts new content only under a key at or above it
//!   ([`may_encrypt`]); otherwise local changes wait for the rotated key;
//! - a node announces only a version encrypted at or above it
//!   ([`announceable`]);
//! - a received version is applied only if its manifest is at or above it
//!   and every file blob has the manifest's epoch
//!   (`transfer::check_version_epochs`);
//! - when a node's keyring advances it re-encrypts its current version
//!   under the new key with the same clock ([`needs_republish`]), so peers
//!   that were behind can still fetch it;
//! - an Owner mints a new epoch only if it will satisfy the required epoch
//!   after the revocation or rotation ([`check_mint`]); minting from behind
//!   would fork the epoch.
//!
//! See INTEGRATION_NOTES.md, "Old keys after revocation".

use anyhow::{anyhow, Result};

/// The required epoch: removals in effect (`AuthState::required_epoch`)
/// and the floor a key fork left (`crypto::load_epoch_floor`).
pub fn required(auth_required: u64, floor: u64) -> u64 {
    auth_required.max(floor).max(1)
}

/// Whether a node whose keyring is at `current_epoch` may encrypt new
/// content (or re-encrypt its current version).
pub fn may_encrypt(current_epoch: u64, required: u64) -> bool {
    current_epoch >= required
}

/// Whether a version encrypted under `version_epoch` may be announced.
/// Epoch 0 means not published at all.
pub fn announceable(version_epoch: u64, required: u64) -> bool {
    version_epoch > 0 && version_epoch >= required
}

/// Whether the current version (encrypted under `version_epoch`, 0 if not
/// published) should be re-encrypted now that the keyring is at
/// `current_epoch`.
pub fn needs_republish(version_epoch: u64, current_epoch: u64, required: u64) -> bool {
    version_epoch < current_epoch && may_encrypt(current_epoch, required)
}

/// May an Owner whose keyring is at `current_epoch` mint epoch
/// `current_epoch + 1`, given the required epoch *after* the action
/// (one more removal for a revocation)? The new key has to satisfy it:
/// minting while a revocation's key hasn't arrived yet produces a second,
/// different key for an epoch another Owner already minted.
pub fn check_mint(current_epoch: u64, required_after: u64) -> Result<()> {
    if current_epoch + 1 >= required_after {
        return Ok(());
    }
    Err(anyhow!(
        "this node's newest key is epoch {current_epoch}, but the share needs epoch {} \
         or later after an earlier revocation; minting epoch {} now would fork the key. \
         Wait until the rotated key arrives (the daemon logs \"installed rotated key\")",
        required_after - 1,
        current_epoch + 1
    ))
}

/// May a node invite while its keyring is at `current_epoch`? The ticket
/// carries our keys; a joiner without the required epoch could neither
/// read new content nor publish, and would get no envelope from the
/// rotation it missed.
pub fn check_invite(current_epoch: u64, required: u64) -> Result<()> {
    if may_encrypt(current_epoch, required) {
        return Ok(());
    }
    Err(anyhow!(
        "this node hasn't received the key for epoch {required} from an earlier revocation \
         yet (it has epoch {current_epoch}); invite once it has"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_is_the_larger_of_removals_and_floor() {
        assert_eq!(required(1, 0), 1);
        assert_eq!(required(3, 0), 3);
        assert_eq!(required(2, 4), 4);
        assert_eq!(required(5, 4), 5);
        assert_eq!(required(0, 0), 1);
    }

    #[test]
    fn the_publish_gate() {
        assert!(may_encrypt(1, 1));
        assert!(may_encrypt(3, 2), "a manual rotation puts us ahead");
        assert!(!may_encrypt(1, 2), "revoked, rotated key not here yet");
    }

    #[test]
    fn announce_gate() {
        assert!(announceable(2, 2));
        assert!(announceable(3, 2));
        assert!(!announceable(1, 2));
        assert!(!announceable(0, 1), "nothing published");
    }

    #[test]
    fn republish_after_the_keyring_advances() {
        assert!(needs_republish(1, 2, 2), "rotated key installed");
        assert!(needs_republish(2, 3, 2), "manual rotation");
        assert!(needs_republish(0, 2, 2), "held back while gated");
        assert!(!needs_republish(2, 2, 2), "already current");
        assert!(!needs_republish(1, 1, 2), "still waiting for the key");
    }

    #[test]
    fn minting_from_behind_is_refused() {
        // Revoke at epoch 1 with no earlier removal: mint 2, need 2.
        check_mint(1, 2).unwrap();
        // Ahead after a manual rotation: fine.
        check_mint(3, 2).unwrap();
        // One earlier removal whose key (epoch 2) hasn't arrived: revoking
        // needs 3 afterwards, minting 2 would collide with the other 2.
        let err = check_mint(1, 3).unwrap_err().to_string();
        assert!(err.contains("fork"), "{err}");
        // Recovering from a fork (floor 3) at epoch 2: mint 3.
        check_mint(2, 3).unwrap();
    }

    #[test]
    fn invites_wait_for_the_required_key() {
        check_invite(2, 2).unwrap();
        assert!(check_invite(1, 2).is_err());
    }
}
