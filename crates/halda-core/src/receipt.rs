//! Signed receipts: proof, not logs.
//!
//! Each receipt is signed with an Ed25519 key no agent holds, and carries the
//! hash of the one before it. Editing, deleting or reordering a receipt breaks
//! verification. Verification needs only the public key.
//!
//! A hash chain cannot detect removal of its newest entries on its own. To catch
//! that, pass the last known head to [`verify_chain`]; see docs/THREAT_MODEL.md.

use crate::canon;
use crate::model::{Actor, Consequence, Verdict};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Hash used as `prev_hash` by the first receipt in a chain.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Who answered an approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    /// The approver.
    pub by: String,
    /// True for yes.
    pub approved: bool,
    /// When, in Unix milliseconds.
    pub at_ms: u64,
    /// Where it was answered: `slack`, `console`, `cli`.
    pub via: String,
}

/// The signed content of a receipt. Secrets are redacted before this is built.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReceiptBody {
    /// Position in the chain, from 1.
    pub seq: u64,
    /// When, in Unix milliseconds.
    pub at_ms: u64,
    /// Hash of the previous receipt.
    pub prev_hash: String,
    /// Decision id this receipt records.
    pub decision_id: String,
    /// Which agent, for whom.
    pub actor: Actor,
    /// Tool name.
    pub tool: String,
    /// Redacted normal form of the action.
    pub action: String,
    /// Fingerprint of the exact action.
    pub action_fingerprint: String,
    /// The simulated effect.
    pub consequence: Option<Consequence>,
    /// What the policy decided.
    pub verdict: Verdict,
    /// What applied. Differs from `verdict` in watch mode.
    pub enforced: Verdict,
    /// Why.
    pub reason: String,
    /// Rule responsible.
    pub rule: Option<String>,
    /// Who approved or refused, if anyone did.
    pub approval: Option<ApprovalRecord>,
    /// Hash of the policy in force.
    pub policy_hash: String,
}

/// A receipt: the body plus its hash and signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    /// The signed content.
    pub body: ReceiptBody,
    /// SHA-256 of the canonical body.
    pub hash: String,
    /// Identifies the signing key: first 16 hex digits of its public key's hash.
    pub key_id: String,
    /// Hex Ed25519 signature over `hash`.
    pub signature: String,
}

/// Why verification failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// Body does not match its hash.
    #[error("receipt {seq}: content was changed after signing")]
    HashMismatch {
        /// Position.
        seq: u64,
    },
    /// Signature is wrong.
    #[error("receipt {seq}: signature is invalid")]
    BadSignature {
        /// Position.
        seq: u64,
    },
    /// Links to the wrong predecessor.
    #[error("receipt {seq}: does not link to the receipt before it")]
    BrokenChain {
        /// Position.
        seq: u64,
    },
    /// Numbering has a gap.
    #[error("receipt {seq}: expected sequence number {expected}")]
    BadSequence {
        /// Position found.
        seq: u64,
        /// Position expected.
        expected: u64,
    },
    /// Chain ends before the head the caller knew about.
    #[error("the chain does not end at the expected head: newest receipts may have been removed")]
    HeadMismatch,
    /// Key material could not be read.
    #[error("invalid key: {0}")]
    BadKey(String),
}

/// Identifies a public key.
pub fn key_id(key: &VerifyingKey) -> String {
    canon::sha256_hex(key.as_bytes())[..16].to_string()
}

/// Signs `body`.
pub fn sign(body: ReceiptBody, key: &SigningKey) -> Receipt {
    let hash = canon::hash_canonical(&body).unwrap_or_default();
    let signature = key.sign(hash.as_bytes());
    Receipt {
        body,
        hash,
        key_id: key_id(&key.verifying_key()),
        signature: hex::encode(signature.to_bytes()),
    }
}

/// Checks one receipt's hash and signature.
pub fn verify_one(receipt: &Receipt, key: &VerifyingKey) -> Result<(), VerifyError> {
    let seq = receipt.body.seq;
    if canon::hash_canonical(&receipt.body).unwrap_or_default() != receipt.hash {
        return Err(VerifyError::HashMismatch { seq });
    }
    let bytes: [u8; 64] = hex::decode(&receipt.signature)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(VerifyError::BadSignature { seq })?;
    key.verify(receipt.hash.as_bytes(), &Signature::from_bytes(&bytes))
        .map_err(|_| VerifyError::BadSignature { seq })
}

/// Checks a whole chain, oldest first. Pass `expected_head` to also detect
/// removal of the newest receipts.
pub fn verify_chain(
    receipts: &[Receipt],
    key: &VerifyingKey,
    expected_head: Option<&str>,
) -> Result<(), VerifyError> {
    let mut prev = GENESIS.to_string();
    for (index, receipt) in receipts.iter().enumerate() {
        let expected = index as u64 + 1;
        if receipt.body.seq != expected {
            return Err(VerifyError::BadSequence {
                seq: receipt.body.seq,
                expected,
            });
        }
        if receipt.body.prev_hash != prev {
            return Err(VerifyError::BrokenChain {
                seq: receipt.body.seq,
            });
        }
        verify_one(receipt, key)?;
        prev.clone_from(&receipt.hash);
    }
    if let Some(head) = expected_head {
        if head != prev {
            return Err(VerifyError::HeadMismatch);
        }
    }
    Ok(())
}

/// Parses a hex public key.
pub fn parse_public_key(text: &str) -> Result<VerifyingKey, VerifyError> {
    let bytes: [u8; 32] = hex::decode(text.trim())
        .map_err(|e| VerifyError::BadKey(e.to_string()))?
        .try_into()
        .map_err(|_| VerifyError::BadKey("expected 32 bytes".into()))?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| VerifyError::BadKey(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::generate(&mut rand::rngs::OsRng)
    }

    fn body(seq: u64, prev: &str) -> ReceiptBody {
        ReceiptBody {
            seq,
            at_ms: 1_700_000_000_000 + seq,
            prev_hash: prev.into(),
            decision_id: format!("d{seq}"),
            actor: Actor {
                agent: "claude-code".into(),
                principal: "jordan".into(),
                ..Actor::default()
            },
            tool: "Bash".into(),
            action: "terraform destroy".into(),
            action_fingerprint: "f".into(),
            consequence: None,
            verdict: Verdict::Block,
            enforced: Verdict::Block,
            reason: "r".into(),
            rule: None,
            approval: Some(ApprovalRecord {
                by: "priya".into(),
                approved: false,
                at_ms: 1,
                via: "slack".into(),
            }),
            policy_hash: "p".into(),
        }
    }

    fn chain(k: &SigningKey, n: u64) -> Vec<Receipt> {
        let mut out: Vec<Receipt> = Vec::new();
        let mut prev = GENESIS.to_string();
        for seq in 1..=n {
            let r = sign(body(seq, &prev), k);
            prev.clone_from(&r.hash);
            out.push(r);
        }
        out
    }

    #[test]
    fn a_good_chain_verifies() {
        let k = key();
        let c = chain(&k, 5);
        assert_eq!(
            verify_chain(&c, &k.verifying_key(), Some(&c[4].hash)),
            Ok(())
        );
    }

    #[test]
    fn editing_any_field_is_detected() {
        let k = key();
        let mut c = chain(&k, 3);
        c[1].body.approval = Some(ApprovalRecord {
            by: "attacker".into(),
            approved: true,
            at_ms: 1,
            via: "slack".into(),
        });
        assert_eq!(
            verify_chain(&c, &k.verifying_key(), None),
            Err(VerifyError::HashMismatch { seq: 2 })
        );
    }

    #[test]
    fn rehashing_after_an_edit_is_detected_by_the_signature() {
        let k = key();
        let mut c = chain(&k, 1);
        c[0].body.reason = "edited".into();
        c[0].hash = canon::hash_canonical(&c[0].body).expect("hash");
        assert_eq!(
            verify_chain(&c, &k.verifying_key(), None),
            Err(VerifyError::BadSignature { seq: 1 })
        );
    }

    #[test]
    fn deleting_from_the_middle_is_detected() {
        let k = key();
        let mut c = chain(&k, 3);
        c.remove(1);
        assert!(verify_chain(&c, &k.verifying_key(), None).is_err());
    }

    #[test]
    fn signing_with_another_key_is_detected() {
        let k = key();
        let c = chain(&k, 2);
        assert_eq!(
            verify_chain(&c, &key().verifying_key(), None),
            Err(VerifyError::BadSignature { seq: 1 })
        );
    }

    #[test]
    fn removing_the_newest_is_only_caught_with_a_known_head() {
        let k = key();
        let mut c = chain(&k, 3);
        let head = c[2].hash.clone();
        c.pop();
        assert_eq!(verify_chain(&c, &k.verifying_key(), None), Ok(()));
        assert_eq!(
            verify_chain(&c, &k.verifying_key(), Some(&head)),
            Err(VerifyError::HeadMismatch)
        );
    }

    #[test]
    fn public_keys_round_trip() {
        let k = key();
        let text = hex::encode(k.verifying_key().as_bytes());
        assert_eq!(parse_public_key(&text).expect("parse"), k.verifying_key());
        assert!(parse_public_key("nothex").is_err());
    }
}
