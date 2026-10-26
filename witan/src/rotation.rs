//! Key rotation under a stable node id.
//!
//! A node's id is `hex(SHA-256(kem_pk || sig_pk))` over the keys it was created
//! with, its *inception* keys. Without this module, new keys mean a new id, so
//! a validator that rotates drops out of every validator set keyed by its id.
//!
//! A [`KeyLineage`] keeps the id and moves the keys: it is the inception keys
//! plus an ordered chain of [`KeyRotation`] records. Anyone holding the lineage
//! can check, offline, that the id was derived from the inception keys and that
//! each rotation was authorized, and so learn which keys currently speak for
//! the id.
//!
//! ## Rules for a rotation record
//!
//! A record at sequence `n` replaces the state at sequence `n - 1`:
//!
//! 1. `node_id` equals the lineage's id, and `sequence` is exactly `n`.
//! 2. `prev_state_digest` equals the digest of the state being replaced, so a
//!    record cannot be replayed onto a different chain or position.
//! 3. `possession` is a valid ML-DSA-65 signature by the **new** signing key
//!    (context [`SIG_CTX_KEY_POSSESSION`]). A node cannot rotate onto a key it
//!    does not hold.
//! 4. Authorization depends on the state being replaced:
//!    - It carries **no** `next_key_commitment`: `authorization` must be a
//!      valid signature by the **previous** signing key (context
//!      [`SIG_CTX_KEY_ROTATION`]).
//!    - It **does** carry one: `SHA-256(new_sig_public_key)` must equal that
//!      commitment, and `authorization` must be empty. The pre-committed key
//!      authorizes itself, so a node whose current key is lost or compromised
//!      can still rotate, and whoever stole the current key cannot.
//!
//! Without a commitment, whoever holds the current signing key controls the
//! next rotation. Validators that need to survive key compromise should set
//! `next_key_commitment` on every rotation and keep the next signing seed
//! offline. A lineage that has never rotated has no commitment, since the id
//! does not commit to one.
//!
//! ## Wire compatibility
//!
//! Nothing here changes an existing message. A rotated node sends its stable
//! id in `sender_node_id` and its current key in `sender_public_key`, which
//! witan 0.2.1 peers already accept (they never check the id against the key).
//! Peers that hold the lineage can check it with
//! [`KeyLineage::check_envelope_sender`].
//!
//! Lineages travel as bincode ([`KeyLineage::encode`]); the host distributes
//! them however it distributes validator-set membership.

use pqc_sig::fips204::MlDsa65Keypair;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::GossipError;
use crate::identity::NodeIdentity;
use crate::types::GossipEnvelope;

/// ML-DSA-65 context for the previous key's authorization of a rotation.
pub const SIG_CTX_KEY_ROTATION: &[u8] = b"WITAN_KEY_ROTATION_V1";

/// ML-DSA-65 context for the new key's proof of possession in a rotation.
pub const SIG_CTX_KEY_POSSESSION: &[u8] = b"WITAN_KEY_POSSESSION_V1";

/// Domain tag for [`KeyLineage`] state digests.
const STATE_DIGEST_TAG: &[u8] = b"WITAN_KEY_STATE_V1";

/// Domain tag for the bytes both rotation signatures cover.
const ROTATION_SIGNING_TAG: &[u8] = b"WITAN_KEY_ROTATION_RECORD_V1";

/// Domain tag for pre-rotation key commitments.
const COMMITMENT_TAG: &[u8] = b"WITAN_NEXT_KEY_COMMITMENT_V1";

/// ML-DSA-65 public key length in bytes.
const SIG_PK_LEN: usize = 1952;

/// Hybrid KEM public key length in bytes (X25519 32 + ML-KEM-768 1184).
const KEM_PK_LEN: usize = 32 + 1184;

/// Current lineage/rotation encoding version.
const LINEAGE_VERSION: u8 = 1;

/// Upper bound on a decoded lineage, so a hostile blob cannot make a verifier
/// allocate without limit. One record is about 9 KB.
const MAX_LINEAGE_BYTES: usize = 4 * 1024 * 1024;

// ── Commitments ───────────────────────────────────────────────────────────────

/// Pre-rotation commitment to a signing public key:
/// `SHA-256("WITAN_NEXT_KEY_COMMITMENT_V1" || sig_pk)`.
pub fn key_commitment(sig_public_key: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(COMMITMENT_TAG);
    h.update(sig_public_key);
    h.finalize().into()
}

/// Commitment to the signing key that `sig_seed` (32 bytes) generates.
///
/// Lets a host commit to its next key while keeping only the seed offline.
pub fn key_commitment_for_seed(sig_seed: &[u8]) -> Result<[u8; 32], GossipError> {
    let kp = MlDsa65Keypair::from_secret_key_bytes(sig_seed)
        .map_err(|e| GossipError::IdentityError(format!("SIG restore failed: {e}")))?;
    Ok(key_commitment(&kp.public_key().bytes))
}

// ── KeyRotation ───────────────────────────────────────────────────────────────

/// One signed step in a [`KeyLineage`]. See the module docs for the rules.
///
/// Wire format: bincode, as an element of an encoded [`KeyLineage`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotation {
    /// Record format version. Always 1.
    pub version: u8,

    /// The stable node id this record rotates (64-char hex).
    pub node_id: String,

    /// Position in the chain. The inception state is 0; the first rotation is 1.
    pub sequence: u64,

    /// Digest of the state this record replaces.
    pub prev_state_digest: [u8; 32],

    /// New hybrid KEM public key, canonical bytes (X25519 || ML-KEM-768).
    pub new_kem_public_key: Vec<u8>,

    /// New ML-DSA-65 public key. 1952 bytes.
    pub new_sig_public_key: Vec<u8>,

    /// Key epoch label for the new keys.
    pub new_key_epoch: String,

    /// Commitment ([`key_commitment`]) to the signing key the next rotation
    /// must reveal. `None` leaves the next rotation to the new key's holder.
    pub next_key_commitment: Option<[u8; 32]>,

    /// Unix timestamp (ms) when the record was made. Informational.
    pub timestamp_unix_ms: u64,

    /// Previous key's signature, or empty when the previous state committed to
    /// this record's key.
    pub authorization: Vec<u8>,

    /// New key's signature (proof of possession).
    pub possession: Vec<u8>,
}

impl KeyRotation {
    /// The bytes both signatures cover: every field except the signatures,
    /// length-prefixed and domain-separated.
    pub fn signing_input(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            ROTATION_SIGNING_TAG.len()
                + 128
                + self.new_kem_public_key.len()
                + self.new_sig_public_key.len(),
        );
        out.extend_from_slice(ROTATION_SIGNING_TAG);
        out.push(self.version);
        put_bytes(&mut out, self.node_id.as_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.prev_state_digest);
        put_bytes(&mut out, &self.new_kem_public_key);
        put_bytes(&mut out, &self.new_sig_public_key);
        put_bytes(&mut out, self.new_key_epoch.as_bytes());
        put_commitment(&mut out, &self.next_key_commitment);
        out.extend_from_slice(&self.timestamp_unix_ms.to_be_bytes());
        out
    }
}

// ── KeyState ──────────────────────────────────────────────────────────────────

/// The keys that speak for a node id at one point in its lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyState {
    sequence: u64,
    kem_public_key: Vec<u8>,
    sig_public_key: Vec<u8>,
    key_epoch: String,
    next_key_commitment: Option<[u8; 32]>,
}

impl KeyState {
    fn digest(&self, node_id: &str) -> [u8; 32] {
        let mut buf = Vec::with_capacity(
            STATE_DIGEST_TAG.len() + 128 + self.kem_public_key.len() + self.sig_public_key.len(),
        );
        buf.extend_from_slice(STATE_DIGEST_TAG);
        put_bytes(&mut buf, node_id.as_bytes());
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        put_bytes(&mut buf, &self.kem_public_key);
        put_bytes(&mut buf, &self.sig_public_key);
        put_bytes(&mut buf, self.key_epoch.as_bytes());
        put_commitment(&mut buf, &self.next_key_commitment);
        Sha256::digest(&buf).into()
    }
}

// ── KeyLineage ────────────────────────────────────────────────────────────────

/// Serialized form of a [`KeyLineage`]. Only the inputs travel; the current
/// state is always recomputed by verifying the chain on decode.
#[derive(Serialize, Deserialize)]
struct LineageWire {
    version: u8,
    inception_kem_public_key: Vec<u8>,
    inception_sig_public_key: Vec<u8>,
    inception_key_epoch: String,
    rotations: Vec<KeyRotation>,
}

/// A stable node id and the verified chain of keys that have spoken for it.
///
/// Every way of obtaining one ([`Self::inception`], [`Self::decode`],
/// [`Self::apply`]) verifies, so holding a `KeyLineage` means holding a valid
/// chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLineage {
    node_id: String,
    inception: KeyState,
    rotations: Vec<KeyRotation>,
    current: KeyState,
}

impl KeyLineage {
    /// Start a lineage from inception public keys. The id is derived exactly
    /// as [`NodeIdentity::derive_node_id`] derives it.
    pub fn inception(
        kem_public_key: &[u8],
        sig_public_key: &[u8],
        key_epoch: &str,
    ) -> Result<Self, GossipError> {
        check_key_lengths(kem_public_key, sig_public_key)?;
        let state = KeyState {
            sequence: 0,
            kem_public_key: kem_public_key.to_vec(),
            sig_public_key: sig_public_key.to_vec(),
            key_epoch: key_epoch.to_string(),
            next_key_commitment: None,
        };
        Ok(Self {
            node_id: NodeIdentity::derive_node_id(kem_public_key, sig_public_key),
            inception: state.clone(),
            rotations: Vec::new(),
            current: state,
        })
    }

    /// Start a lineage from a never-rotated identity.
    ///
    /// Fails if the identity's `node_id` is not derived from its own keys,
    /// which is the case for an identity that has already rotated: rebuild
    /// that one's lineage with [`Self::decode`] instead.
    pub fn from_identity(identity: &NodeIdentity) -> Result<Self, GossipError> {
        let lineage = Self::inception(
            &identity.kem_public_key_canonical_bytes()?,
            &identity.sig_public_key_bytes(),
            &identity.key_epoch,
        )?;
        if lineage.node_id != identity.node_id {
            return Err(GossipError::IdentityError(
                "identity node_id is not derived from its keys; supply its lineage".to_string(),
            ));
        }
        Ok(lineage)
    }

    /// The stable node id.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Sequence of the current state (0 = never rotated).
    pub fn sequence(&self) -> u64 {
        self.current.sequence
    }

    /// Current ML-DSA-65 public key.
    pub fn current_sig_public_key(&self) -> &[u8] {
        &self.current.sig_public_key
    }

    /// Current hybrid KEM public key, canonical bytes (X25519 || ML-KEM-768).
    pub fn current_kem_public_key(&self) -> &[u8] {
        &self.current.kem_public_key
    }

    /// Current key epoch label.
    pub fn current_key_epoch(&self) -> &str {
        &self.current.key_epoch
    }

    /// The commitment the next rotation must satisfy, if any.
    pub fn next_key_commitment(&self) -> Option<[u8; 32]> {
        self.current.next_key_commitment
    }

    /// The signing key the current one replaced, if the lineage has rotated.
    ///
    /// For hosts that want a short grace period for envelopes signed just
    /// before a rotation. Accepting it re-opens whatever the rotation closed,
    /// so keep any such window no longer than the replay window.
    pub fn previous_sig_public_key(&self) -> Option<&[u8]> {
        match self.rotations.len() {
            0 => None,
            1 => Some(&self.inception.sig_public_key),
            n => Some(&self.rotations[n - 2].new_sig_public_key),
        }
    }

    /// The verified rotation records, oldest first.
    pub fn rotations(&self) -> &[KeyRotation] {
        &self.rotations
    }

    /// Verify `rotation` against the current state and, if valid, advance.
    ///
    /// Re-applying a record already in the chain is a no-op. A different valid
    /// record at a sequence the chain already has is reported as a fork:
    /// two keys each signed a successor, so at least one of them is in the
    /// wrong hands.
    pub fn apply(&mut self, rotation: KeyRotation) -> Result<(), GossipError> {
        if rotation.sequence >= 1 && rotation.sequence <= self.current.sequence {
            let existing = &self.rotations[(rotation.sequence - 1) as usize];
            if *existing == rotation {
                return Ok(());
            }
            return Err(GossipError::IdentityError(format!(
                "lineage fork: conflicting rotation at sequence {} for node {}",
                rotation.sequence, self.node_id
            )));
        }
        let next = self.verify_next(&rotation)?;
        self.rotations.push(rotation);
        self.current = next;
        Ok(())
    }

    /// Check that an envelope's sender is this lineage's node, speaking with
    /// its current signing key. This is an identity check only; the envelope's
    /// own signature, replay window and TTL are checked by
    /// [`crate::envelope::verify_envelope`].
    pub fn check_envelope_sender(&self, envelope: &GossipEnvelope) -> Result<(), GossipError> {
        if envelope.sender_node_id != self.node_id {
            return Err(GossipError::IdentityError(format!(
                "sender {} is not lineage node {}",
                envelope.sender_node_id, self.node_id
            )));
        }
        if envelope.sender_public_key != self.current.sig_public_key {
            return Err(GossipError::IdentityError(format!(
                "sender key is not the current key for node {} (sequence {})",
                self.node_id, self.current.sequence
            )));
        }
        Ok(())
    }

    /// Encode to bincode for storage or distribution.
    pub fn encode(&self) -> Result<Vec<u8>, GossipError> {
        let wire = LineageWire {
            version: LINEAGE_VERSION,
            inception_kem_public_key: self.inception.kem_public_key.clone(),
            inception_sig_public_key: self.inception.sig_public_key.clone(),
            inception_key_epoch: self.inception.key_epoch.clone(),
            rotations: self.rotations.clone(),
        };
        bincode::serialize(&wire)
            .map_err(|e| GossipError::SerializationError(format!("bincode encode failed: {e}")))
    }

    /// Decode and verify a lineage. Fails unless every record verifies.
    pub fn decode(bytes: &[u8]) -> Result<Self, GossipError> {
        use bincode::Options;
        if bytes.len() > MAX_LINEAGE_BYTES {
            return Err(GossipError::InvalidInput(format!(
                "lineage too large: {} > {MAX_LINEAGE_BYTES} bytes",
                bytes.len()
            )));
        }
        // Same encoding as bincode::serialize (fixint, little-endian), plus a
        // size limit so a forged length prefix cannot trigger a huge allocation.
        let wire: LineageWire = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_LINEAGE_BYTES as u64)
            .deserialize(bytes)
            .map_err(|e| GossipError::SerializationError(format!("bincode decode failed: {e}")))?;
        if wire.version != LINEAGE_VERSION {
            return Err(GossipError::IdentityError(format!(
                "unsupported lineage version: {}",
                wire.version
            )));
        }
        let mut lineage = Self::inception(
            &wire.inception_kem_public_key,
            &wire.inception_sig_public_key,
            &wire.inception_key_epoch,
        )?;
        for rotation in wire.rotations {
            if rotation.sequence != lineage.current.sequence + 1 {
                return Err(GossipError::IdentityError(format!(
                    "lineage out of order: expected sequence {}, got {}",
                    lineage.current.sequence + 1,
                    rotation.sequence
                )));
            }
            lineage.apply(rotation)?;
        }
        Ok(lineage)
    }

    /// Build and sign the rotation from `current` (which must hold this
    /// lineage's current keys) to `next`, apply it, and return the record.
    ///
    /// When the current state carries a commitment, `next` must hold the
    /// committed key.
    pub fn rotate(
        &mut self,
        current: &NodeIdentity,
        next: &NodeIdentity,
        next_key_commitment: Option<[u8; 32]>,
        now_ms: u64,
    ) -> Result<KeyRotation, GossipError> {
        if current.sig_public_key_bytes() != self.current.sig_public_key {
            return Err(GossipError::IdentityError(
                "rotating identity does not hold this lineage's current key".to_string(),
            ));
        }
        self.build_and_apply(Some(current), next, next_key_commitment, now_ms)
    }

    /// Rotate to the pre-committed key without the current key: the path for a
    /// node whose current key is lost or compromised. Requires the current
    /// state to carry a commitment, which `next` must satisfy.
    pub fn recover(
        &mut self,
        next: &NodeIdentity,
        next_key_commitment: Option<[u8; 32]>,
        now_ms: u64,
    ) -> Result<KeyRotation, GossipError> {
        if self.current.next_key_commitment.is_none() {
            return Err(GossipError::IdentityError(
                "recovery needs a pre-rotation commitment; this lineage has none".to_string(),
            ));
        }
        self.build_and_apply(None, next, next_key_commitment, now_ms)
    }

    fn build_and_apply(
        &mut self,
        current: Option<&NodeIdentity>,
        next: &NodeIdentity,
        next_key_commitment: Option<[u8; 32]>,
        now_ms: u64,
    ) -> Result<KeyRotation, GossipError> {
        let mut rotation = KeyRotation {
            version: 1,
            node_id: self.node_id.clone(),
            sequence: self.current.sequence + 1,
            prev_state_digest: self.current.digest(&self.node_id),
            new_kem_public_key: next.kem_public_key_canonical_bytes()?,
            new_sig_public_key: next.sig_public_key_bytes(),
            new_key_epoch: next.key_epoch.clone(),
            next_key_commitment,
            timestamp_unix_ms: now_ms,
            authorization: Vec::new(),
            possession: Vec::new(),
        };
        let input = rotation.signing_input();
        if self.current.next_key_commitment.is_none() {
            let current = current.ok_or_else(|| {
                GossipError::IdentityError("rotation needs the current key".to_string())
            })?;
            rotation.authorization = current.sign(&input, SIG_CTX_KEY_ROTATION)?;
        }
        rotation.possession = next.sign(&input, SIG_CTX_KEY_POSSESSION)?;
        self.apply(rotation.clone())?;
        Ok(rotation)
    }

    /// Check `rotation` as the successor of the current state; return the new state.
    fn verify_next(&self, r: &KeyRotation) -> Result<KeyState, GossipError> {
        let fail = |msg: &str| Err(GossipError::IdentityError(format!("rotation rejected: {msg}")));

        if r.version != 1 {
            return fail(&format!("unsupported version {}", r.version));
        }
        if r.node_id != self.node_id {
            return fail("node_id does not match lineage");
        }
        if r.sequence != self.current.sequence + 1 {
            return fail(&format!(
                "expected sequence {}, got {}",
                self.current.sequence + 1,
                r.sequence
            ));
        }
        if r.prev_state_digest != self.current.digest(&self.node_id) {
            return fail("prev_state_digest does not match current state");
        }
        check_key_lengths(&r.new_kem_public_key, &r.new_sig_public_key)?;

        let input = r.signing_input();
        if !NodeIdentity::verify_external(
            &r.new_sig_public_key,
            &input,
            &r.possession,
            SIG_CTX_KEY_POSSESSION,
        )? {
            return fail("new key's proof of possession is invalid");
        }

        match self.current.next_key_commitment {
            Some(commitment) => {
                if key_commitment(&r.new_sig_public_key) != commitment {
                    return fail("new key does not match the pre-rotation commitment");
                }
                if !r.authorization.is_empty() {
                    return fail("authorization must be empty when a commitment is in force");
                }
            }
            None => {
                if !NodeIdentity::verify_external(
                    &self.current.sig_public_key,
                    &input,
                    &r.authorization,
                    SIG_CTX_KEY_ROTATION,
                )? {
                    return fail("previous key's authorization is invalid");
                }
            }
        }

        Ok(KeyState {
            sequence: r.sequence,
            kem_public_key: r.new_kem_public_key.clone(),
            sig_public_key: r.new_sig_public_key.clone(),
            key_epoch: r.new_key_epoch.clone(),
            next_key_commitment: r.next_key_commitment,
        })
    }
}

// ── Encoding helpers ──────────────────────────────────────────────────────────

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn put_commitment(out: &mut Vec<u8>, c: &Option<[u8; 32]>) {
    match c {
        Some(c) => {
            out.push(1);
            out.extend_from_slice(c);
        }
        None => out.push(0),
    }
}

fn check_key_lengths(kem_pk: &[u8], sig_pk: &[u8]) -> Result<(), GossipError> {
    if kem_pk.len() != KEM_PK_LEN {
        return Err(GossipError::IdentityError(format!(
            "invalid kem pk size: expected {KEM_PK_LEN}, got {}",
            kem_pk.len()
        )));
    }
    if sig_pk.len() != SIG_PK_LEN {
        return Err(GossipError::IdentityError(format!(
            "invalid sig pk size: expected {SIG_PK_LEN}, got {}",
            sig_pk.len()
        )));
    }
    Ok(())
}
