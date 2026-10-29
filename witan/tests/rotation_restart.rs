//! Restarting a rotated node: `gossip_init_with_lineage`.
//!
//! Its own test binary because it needs a fresh, uninitialized global engine.

use witan::identity::NodeIdentity;
use witan::rotation::KeyLineage;
use witan::*;

fn seeds(n: u8) -> (Vec<u8>, Vec<u8>) {
    let mut kem = vec![n; 32];
    kem.extend(vec![n.wrapping_add(100); 64]);
    (kem, vec![n.wrapping_add(200); 32])
}

fn ident(n: u8) -> NodeIdentity {
    let (kem, sig) = seeds(n);
    NodeIdentity::from_seeds(&kem[..32], &kem[32..], &sig, &format!("epoch-{n}")).unwrap()
}

fn config_for(n: u8) -> String {
    let (kem, sig) = seeds(n);
    format!(
        r#"{{"kem_seed_hex":"{}","sig_seed_hex":"{}","key_epoch":"epoch-{n}"}}"#,
        hex::encode(kem),
        hex::encode(sig)
    )
}

#[test]
fn a_rotated_node_restarts_under_its_stable_id() {
    let mut l = KeyLineage::from_identity(&ident(1)).unwrap();
    l.rotate(&ident(1), &ident(2), None, 1_790_000_000_000).unwrap();
    let lineage = l.encode().unwrap();

    // Refusals leave the engine uninitialized.
    // Seeds for the retired keys, not the current ones.
    assert!(gossip_init_with_lineage(&config_for(1), &lineage).is_err());
    // No seeds at all.
    assert!(gossip_init_with_lineage("{}", &lineage).is_err());
    // A tampered lineage.
    let mut bad = lineage.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(gossip_init_with_lineage(&config_for(2), &bad).is_err());
    assert!(matches!(gossip_get_node_identity(), Err(GossipError::NotInitialized)));

    // The current seeds with the lineage.
    gossip_init_with_lineage(&config_for(2), &lineage).unwrap();
    let id: serde_json::Value = serde_json::from_str(&gossip_get_node_identity().unwrap()).unwrap();
    assert_eq!(id["node_id"], ident(1).node_id.as_str());
    assert_eq!(id["sig_public_key_hex"], ident(2).sig_public_key_hex());
    assert_eq!(gossip_get_key_lineage().unwrap(), lineage);

    let env = gossip_encode_envelope(PayloadType::BlockProposal.as_u8(), b"block").unwrap();
    assert!(gossip_verify_envelope_from_lineage(&env, &lineage).unwrap());

    // And it can keep rotating from there.
    let (kem3, sig3) = seeds(3);
    let next = gossip_rotate_keys_under_id(&kem3, &sig3, "epoch-3", None).unwrap();
    assert_eq!(KeyLineage::decode(&next).unwrap().sequence(), 2);
}
