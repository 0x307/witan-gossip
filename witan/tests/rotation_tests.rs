//! Key rotation under a stable node id: `KeyLineage` rules and the global API.
//!
//! Its own test binary, so the global engine here is independent of the one in
//! integration_tests.rs.

use sha2::{Digest, Sha256};

use witan::envelope::{build_envelope, decode_envelope, encode_envelope, verify_envelope};
use witan::identity::NodeIdentity;
use witan::rotation::{key_commitment, key_commitment_for_seed, KeyLineage, KeyRotation};
use witan::types::PayloadType;
use witan::GossipConfig;

// ── Fixtures ──────────────────────────────────────────────────────────────────

/// Seeds for test identity `n`: (kem_seed 96 bytes, sig_seed 32 bytes).
fn seeds(n: u8) -> (Vec<u8>, Vec<u8>) {
    let mut kem = vec![n; 32];
    kem.extend(vec![n.wrapping_add(100); 64]);
    (kem, vec![n.wrapping_add(200); 32])
}

fn ident(n: u8) -> NodeIdentity {
    let (kem, sig) = seeds(n);
    NodeIdentity::from_seeds(&kem[..32], &kem[32..], &sig, &format!("epoch-{n}")).unwrap()
}

fn lineage_of(id: &NodeIdentity) -> KeyLineage {
    KeyLineage::from_identity(id).unwrap()
}

const T: u64 = 1_790_000_000_000;

fn config() -> witan::config::ResolvedConfig {
    GossipConfig::from_json("{}").unwrap().resolve().unwrap()
}

/// A valid one-step rotation record from identity 1 to identity 2.
fn one_rotation() -> (KeyLineage, KeyRotation) {
    let mut l = lineage_of(&ident(1));
    let r = l.rotate(&ident(1), &ident(2), None, T).unwrap();
    (lineage_of(&ident(1)), r)
}

// ── Inception ─────────────────────────────────────────────────────────────────

#[test]
fn inception_id_is_the_identity_id() {
    let id = ident(1);
    let l = lineage_of(&id);
    assert_eq!(l.node_id(), id.node_id);
    assert_eq!(l.sequence(), 0);
    assert_eq!(l.current_sig_public_key(), &id.sig_public_key_bytes()[..]);
    assert_eq!(l.current_kem_public_key().len(), 32 + 1184);
    assert!(l.previous_sig_public_key().is_none());
}

#[test]
fn from_identity_rejects_an_id_not_derived_from_its_keys() {
    let mut id = ident(2);
    id.node_id = ident(1).node_id.clone();
    assert!(KeyLineage::from_identity(&id).is_err());
}

// ── Rotation keeps the id ─────────────────────────────────────────────────────

#[test]
fn rotation_keeps_id_and_moves_keys() {
    let mut l = lineage_of(&ident(1));
    let id0 = l.node_id().to_string();

    l.rotate(&ident(1), &ident(2), None, T).unwrap();
    l.rotate(&ident(2), &ident(3), None, T + 1).unwrap();

    assert_eq!(l.node_id(), id0);
    assert_eq!(l.sequence(), 2);
    assert_eq!(l.current_sig_public_key(), &ident(3).sig_public_key_bytes()[..]);
    assert_eq!(l.previous_sig_public_key().unwrap(), &ident(2).sig_public_key_bytes()[..]);
    assert_eq!(l.current_key_epoch(), "epoch-3");

    let decoded = KeyLineage::decode(&l.encode().unwrap()).unwrap();
    assert_eq!(decoded, l);
}

#[test]
fn rotate_requires_the_current_key() {
    let mut l = lineage_of(&ident(1));
    let before = l.clone();
    assert!(l.rotate(&ident(9), &ident(2), None, T).is_err());
    assert_eq!(l, before, "a refused rotation must not change the lineage");
}

// ── Every field of a record is bound ──────────────────────────────────────────

#[test]
fn tampered_records_are_rejected() {
    let (base, good) = one_rotation();
    // Positive control: the untampered record applies.
    base.clone().apply(good.clone()).unwrap();

    type Tamper = Box<dyn Fn(&mut KeyRotation)>;
    let tampers: Vec<(&str, Tamper)> = vec![
        ("node_id", Box::new(|r| r.node_id = ident(9).node_id.clone())),
        ("sequence", Box::new(|r| r.sequence = 2)),
        ("prev_state_digest", Box::new(|r| r.prev_state_digest[0] ^= 1)),
        ("new_kem_public_key", Box::new(|r| r.new_kem_public_key[0] ^= 1)),
        ("new_sig_public_key", Box::new(|r| r.new_sig_public_key[0] ^= 1)),
        ("new_key_epoch", Box::new(|r| r.new_key_epoch.push('x'))),
        ("next_key_commitment", Box::new(|r| r.next_key_commitment = Some([7; 32]))),
        ("timestamp", Box::new(|r| r.timestamp_unix_ms += 1)),
        ("authorization", Box::new(|r| r.authorization[0] ^= 1)),
        ("possession", Box::new(|r| r.possession[0] ^= 1)),
        ("version", Box::new(|r| r.version = 2)),
    ];
    for (field, tamper) in tampers {
        let mut r = good.clone();
        tamper(&mut r);
        assert!(base.clone().apply(r).is_err(), "tampered {field} was accepted");
    }
}

#[test]
fn a_rotation_authorized_by_another_key_is_rejected() {
    let (base, mut r) = one_rotation();
    // Re-sign the authorization with a key that is not the lineage's current key.
    r.authorization = ident(9).sign(&r.signing_input(), witan::SIG_CTX_KEY_ROTATION).unwrap();
    assert!(base.clone().apply(r).is_err());
}

#[test]
fn a_rotation_onto_a_key_the_rotator_does_not_hold_is_rejected() {
    let (base, mut r) = one_rotation();
    // Possession signed by the old key instead of the new one.
    r.possession = ident(1).sign(&r.signing_input(), witan::SIG_CTX_KEY_POSSESSION).unwrap();
    assert!(base.clone().apply(r).is_err());
}

#[test]
fn signature_contexts_are_not_interchangeable() {
    let (base, mut r) = one_rotation();
    std::mem::swap(&mut r.authorization, &mut r.possession);
    assert!(base.clone().apply(r).is_err());
}

// ── Ordering and forks ────────────────────────────────────────────────────────

#[test]
fn reapplying_a_known_record_is_a_no_op_and_a_conflicting_one_is_a_fork() {
    let (mut l, r) = one_rotation();
    l.apply(r.clone()).unwrap();
    l.apply(r).unwrap();
    assert_eq!(l.sequence(), 1);

    // A second, independently valid successor of the same state.
    let mut other = lineage_of(&ident(1));
    let fork = other.rotate(&ident(1), &ident(5), None, T).unwrap();
    let err = l.apply(fork).unwrap_err();
    assert!(format!("{err:?}").contains("fork"), "{err:?}");
}

#[test]
fn a_record_must_follow_the_current_state() {
    let mut l = lineage_of(&ident(1));
    l.rotate(&ident(1), &ident(2), None, T).unwrap();
    l.rotate(&ident(2), &ident(3), None, T).unwrap();
    let bytes = l.encode().unwrap();
    KeyLineage::decode(&bytes).unwrap();

    // Drop the first record: the second no longer follows inception.
    let mut short = lineage_of(&ident(1));
    let r2 = l.rotations()[1].clone();
    assert!(short.apply(r2).is_err());
}

#[test]
fn decode_refuses_oversized_length_prefixes() {
    let l = lineage_of(&ident(1));
    let mut bytes = l.encode().unwrap();
    // bincode layout: version (1 byte), then the u64 length of the first Vec.
    bytes[1..9].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(KeyLineage::decode(&bytes).is_err());
}

// ── Pre-rotation ──────────────────────────────────────────────────────────────

#[test]
fn a_commitment_locks_out_the_current_key_holder() {
    let mut l = lineage_of(&ident(1));
    let (_, sig3) = seeds(3);
    let c3 = key_commitment_for_seed(&sig3).unwrap();
    assert_eq!(c3, key_commitment(&ident(3).sig_public_key_bytes()));

    l.rotate(&ident(1), &ident(2), Some(c3), T).unwrap();
    assert_eq!(l.next_key_commitment(), Some(c3));

    // Whoever holds key 2 cannot rotate to a key of their choosing.
    assert!(l.clone().rotate(&ident(2), &ident(9), None, T).is_err());

    // The committed key can take over without key 2 at all.
    let r = l.recover(&ident(3), None, T + 1).unwrap();
    assert!(r.authorization.is_empty());
    assert_eq!(l.current_sig_public_key(), &ident(3).sig_public_key_bytes()[..]);

    // And the chain verifies from bytes.
    assert_eq!(KeyLineage::decode(&l.encode().unwrap()).unwrap(), l);
}

#[test]
fn recovery_needs_a_commitment() {
    let mut l = lineage_of(&ident(1));
    assert!(l.recover(&ident(2), None, T).is_err());
}

#[test]
fn a_committed_rotation_carrying_an_authorization_is_rejected() {
    let (_, sig3) = seeds(3);
    let mut l = lineage_of(&ident(1));
    l.rotate(&ident(1), &ident(2), Some(key_commitment_for_seed(&sig3).unwrap()), T).unwrap();
    let mut probe = l.clone();
    let mut r = probe.recover(&ident(3), None, T).unwrap();
    r.authorization = ident(2).sign(&r.signing_input(), witan::SIG_CTX_KEY_ROTATION).unwrap();
    assert!(l.apply(r).is_err());
}

// ── Envelopes ─────────────────────────────────────────────────────────────────

/// What a rotated engine signs with: the next keys under the stable id.
fn rotated_sender(l: &KeyLineage, n: u8) -> NodeIdentity {
    let mut id = ident(n);
    id.node_id = l.node_id().to_string();
    id
}

#[test]
fn envelope_sender_is_checked_against_the_current_key() {
    let mut l = lineage_of(&ident(1));
    l.rotate(&ident(1), &ident(2), None, T).unwrap();

    let current = build_envelope(PayloadType::FinalityVote, b"v", &rotated_sender(&l, 2), 8, T).unwrap();
    l.check_envelope_sender(&current).unwrap();

    // The retired key, under the right id.
    let retired = build_envelope(PayloadType::FinalityVote, b"v", &ident(1), 8, T).unwrap();
    assert_eq!(retired.sender_node_id, l.node_id());
    assert!(l.check_envelope_sender(&retired).is_err());

    // The right key claimed under another id.
    let mut other_id = rotated_sender(&l, 2);
    other_id.node_id = ident(9).node_id.clone();
    let wrong_id = build_envelope(PayloadType::FinalityVote, b"v", &other_id, 8, T).unwrap();
    assert!(l.check_envelope_sender(&wrong_id).is_err());
}

#[test]
fn rotated_envelopes_still_pass_the_existing_verifier() {
    // A 0.2.1 peer runs verify_envelope and nothing else; a rotated sender
    // must not break it.
    let mut l = lineage_of(&ident(1));
    l.rotate(&ident(1), &ident(2), None, T).unwrap();
    let env = build_envelope(PayloadType::BlockProposal, b"block", &rotated_sender(&l, 2), 8, T).unwrap();
    let bytes = encode_envelope(&env).unwrap();
    assert!(verify_envelope(&decode_envelope(&bytes).unwrap(), &config(), T).unwrap());
}

// ── Golden vectors ────────────────────────────────────────────────────────────
//
// These pin bytes other nodes depend on. A change to either digest is a wire
// format change: per STABILITY.md it is breaking, needs a new minor version
// and a changelog migration note, and must never ship in a patch release.

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

#[test]
fn golden_envelope_encoding_is_unchanged() {
    // Identical bytes are produced by the published witan 0.2.1.
    let env = build_envelope(PayloadType::FinalityVote, b"golden", &ident(1), 8, T).unwrap();
    assert_eq!(
        sha256_hex(&encode_envelope(&env).unwrap()),
        "e8598e08f60dea93d02ed98951f76aa2b23adedcb8231135ac013989f61924a8"
    );
}

#[test]
fn golden_lineage_encoding_is_unchanged() {
    let (_, sig3) = seeds(3);
    let mut l = lineage_of(&ident(1));
    l.rotate(&ident(1), &ident(2), Some(key_commitment_for_seed(&sig3).unwrap()), T).unwrap();
    l.recover(&ident(3), None, T + 1).unwrap();
    assert_eq!(sha256_hex(&l.encode().unwrap()), "73ccde1cd58aea39b90aa472bbd37a58368ad2ec63d9667a345339301dd88fe8");
}

// ── Global API ────────────────────────────────────────────────────────────────

#[test]
fn api_rotation_under_a_stable_id() {
    use witan::*;

    let (kem1, sig1) = seeds(1);
    gossip_init(&format!(
        r#"{{"kem_seed_hex":"{}","sig_seed_hex":"{}","key_epoch":"epoch-1"}}"#,
        hex::encode(&kem1),
        hex::encode(&sig1)
    ))
    .unwrap();
    let id: serde_json::Value = serde_json::from_str(&gossip_get_node_identity().unwrap()).unwrap();
    let stable_id = id["node_id"].as_str().unwrap().to_string();
    assert_eq!(stable_id, ident(1).node_id);

    // Rotate to 2, committing to 3.
    let (kem2, sig2) = seeds(2);
    let (kem3, sig3) = seeds(3);
    let c3 = gossip_key_commitment(&sig3).unwrap();
    let lineage = gossip_rotate_keys_under_id(&kem2, &sig2, "epoch-2", Some(&c3)).unwrap();
    assert_eq!(lineage, gossip_get_key_lineage().unwrap());

    let summary: serde_json::Value =
        serde_json::from_str(&gossip_verify_key_lineage(&lineage).unwrap()).unwrap();
    assert_eq!(summary["node_id"], stable_id.as_str());
    assert_eq!(summary["sequence"], 1);
    assert_eq!(summary["sig_public_key_hex"], ident(2).sig_public_key_hex());
    assert_eq!(summary["next_key_commitment_hex"], hex::encode(&c3));

    // Same id, new key.
    let id: serde_json::Value = serde_json::from_str(&gossip_get_node_identity().unwrap()).unwrap();
    assert_eq!(id["node_id"], stable_id.as_str());
    assert_eq!(id["sig_public_key_hex"], ident(2).sig_public_key_hex());
    assert_eq!(id["key_epoch"], "epoch-2");

    // Envelopes from the node verify against its lineage; the retired key's do not.
    let env = gossip_encode_envelope(PayloadType::FinalityVote.as_u8(), b"vote").unwrap();
    assert!(gossip_verify_envelope_from_lineage(&env, &lineage).unwrap());
    let retired = encode_envelope(
        &build_envelope(PayloadType::FinalityVote, b"vote", &ident(1), 8, current_time_unix_ms()).unwrap(),
    )
    .unwrap();
    assert!(gossip_verify_envelope(&retired).unwrap(), "positive control: signature itself is fine");
    assert!(gossip_verify_envelope_from_lineage(&retired, &lineage).is_err());

    // The commitment holds: a rotation to an uncommitted key fails and changes nothing.
    let (kem9, sig9) = seeds(9);
    assert!(gossip_rotate_keys_under_id(&kem9, &sig9, "epoch-9", None).is_err());
    assert_eq!(gossip_get_key_lineage().unwrap(), lineage);
    let id: serde_json::Value = serde_json::from_str(&gossip_get_node_identity().unwrap()).unwrap();
    assert_eq!(id["sig_public_key_hex"], ident(2).sig_public_key_hex());

    // Recovery to the committed key works offline, from the lineage alone.
    let recovered = gossip_recover_lineage(&lineage, &kem3, &sig3, "epoch-3", None).unwrap();
    let summary: serde_json::Value =
        serde_json::from_str(&gossip_verify_key_lineage(&recovered).unwrap()).unwrap();
    assert_eq!(summary["node_id"], stable_id.as_str());
    assert_eq!(summary["sequence"], 2);

    // A second init in this process is still refused, lineage or not.
    assert!(matches!(
        gossip_init_with_lineage("{}", &recovered),
        Err(GossipError::AlreadyInitialized)
    ));

    // The old API still mints a new id, and resets the lineage to match.
    let new_id = gossip_rotate_keys().unwrap();
    assert_ne!(new_id, stable_id);
    let summary: serde_json::Value =
        serde_json::from_str(&gossip_verify_key_lineage(&gossip_get_key_lineage().unwrap()).unwrap())
            .unwrap();
    assert_eq!(summary["node_id"], new_id.as_str());
    assert_eq!(summary["sequence"], 0);
}
