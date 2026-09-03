//! Node identity management using pqc-kem and pqc-sig.
//!
//! `NodeIdentity` holds the live keypairs in memory. It is never serialized.
//! Use `NodeIdentityPublic` for wire/API representation.

use pqc_kem::fips203::HybridKemKeypair;
use pqc_sig::fips204::MlDsa65Keypair;
use pqc_sig::types::SigPublicKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::error::GossipError;
use crate::types::{NodeIdentityPublic, SIG_CTX_HANDSHAKE, SIG_CTX_MESSAGE, SIG_CTX_NODE_ID};

/// Context constants for ML-DSA-65 domain separation.
pub const CTX_HANDSHAKE: &[u8] = SIG_CTX_HANDSHAKE;
pub const CTX_MESSAGE: &[u8] = SIG_CTX_MESSAGE;
pub const CTX_NODE_ID: &[u8] = SIG_CTX_NODE_ID;

/// Node identity: holds live keypairs in memory.
///
/// Never serialized. Use `public_view()` to get the serializable public parts.
pub struct NodeIdentity {
    /// Deterministic node identifier.
    /// Derived as: hex(SHA-256(kem_public_key_bytes || sig_public_key_bytes))
    pub node_id: String,

    /// Hybrid KEM keypair (X25519 + ML-KEM-768).
    /// Used for: KEM encapsulation/decapsulation during handshake.
    pub kem_keypair: HybridKemKeypair,

    /// ML-DSA-65 signing keypair (FIPS 204).
    /// Used for: signing GossipEnvelopes and handshake transcripts.
    pub sig_keypair: MlDsa65Keypair,

    /// Key epoch label. Default: "ephemeral-runtime".
    pub key_epoch: String,
}

impl NodeIdentity {
    /// Generate a new random identity using OsRng.
    ///
    /// In WASM, OsRng routes through getrandom/js → window.crypto.getRandomValues().
    pub fn generate(key_epoch: &str) -> Result<Self, GossipError> {
        let mut rng = OsRng;

        let kem_keypair = HybridKemKeypair::generate(&mut rng)
            .map_err(|e| GossipError::IdentityError(format!("KEM keygen failed: {e}")))?;

        let sig_keypair = MlDsa65Keypair::generate(&mut rng)
            .map_err(|e| GossipError::IdentityError(format!("SIG keygen failed: {e}")))?;

        let kem_pk = kem_keypair.public_key();
        let kem_pk_bytes = Self::kem_public_key_bytes(&kem_pk)?;
        let sig_pk_bytes = sig_keypair.public_key().bytes.clone();

        let node_id = Self::derive_node_id(&kem_pk_bytes, &sig_pk_bytes);

        Ok(Self {
            node_id,
            kem_keypair,
            sig_keypair,
            key_epoch: key_epoch.to_string(),
        })
    }

    /// Generate from seeds (deterministic, for configured nodes).
    ///
    /// - `x25519_seed`: 32 bytes (X25519 static secret)
    /// - `mlkem_seed`: 64 bytes (ML-KEM-768 seed)
    /// - `sig_seed`: 32 bytes (ML-DSA-65 seed)
    pub fn from_seeds(
        x25519_seed: &[u8],
        mlkem_seed: &[u8],
        sig_seed: &[u8],
        key_epoch: &str,
    ) -> Result<Self, GossipError> {
        let kem_keypair = HybridKemKeypair::from_secret_key_bytes(x25519_seed, mlkem_seed)
            .map_err(|e| GossipError::IdentityError(format!("KEM restore failed: {e}")))?;

        let sig_keypair = MlDsa65Keypair::from_secret_key_bytes(sig_seed)
            .map_err(|e| GossipError::IdentityError(format!("SIG restore failed: {e}")))?;

        let kem_pk = kem_keypair.public_key();
        let kem_pk_bytes = Self::kem_public_key_bytes(&kem_pk)?;
        let sig_pk_bytes = sig_keypair.public_key().bytes.clone();

        let node_id = Self::derive_node_id(&kem_pk_bytes, &sig_pk_bytes);

        Ok(Self {
            node_id,
            kem_keypair,
            sig_keypair,
            key_epoch: key_epoch.to_string(),
        })
    }

    /// Derive node_id = hex(SHA-256(kem_pk_bytes || sig_pk_bytes)).
    pub fn derive_node_id(kem_pk_bytes: &[u8], sig_pk_bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(kem_pk_bytes);
        hasher.update(sig_pk_bytes);
        hex::encode(hasher.finalize())
    }

    /// Get the public identity (safe to share).
    pub fn public_view(&self) -> Result<NodeIdentityPublic, GossipError> {
        let kem_pk = self.kem_keypair.public_key();
        let kem_public_key_json = kem_pk
            .to_json()
            .map_err(|e| GossipError::IdentityError(format!("KEM pk to_json failed: {e}")))?;

        let sig_pk_bytes = self.sig_keypair.public_key().bytes.clone();
        let sig_public_key_hex = hex::encode(&sig_pk_bytes);

        Ok(NodeIdentityPublic {
            node_id: self.node_id.clone(),
            kem_public_key_json,
            sig_public_key_hex,
            key_epoch: self.key_epoch.clone(),
        })
    }

    /// Sign bytes with ML-DSA-65 using a context string.
    ///
    /// `pqc-sig`'s public API signs raw bytes only (no built-in FIPS 204 context
    /// parameter), so the context is bound in exactly the same way
    /// [`Self::verify_external`] reconstructs it: the tagged message is
    /// `0x00 || context_len_byte || context || message`. Signing is deterministic
    /// (no RNG), matching the non-repudiation property relied on elsewhere in this
    /// crate (see `docs/architecture/08-nats-gossip-security-architecture.md`).
    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<Vec<u8>, GossipError> {
        if context.len() > 255 {
            return Err(GossipError::CryptoError(
                "context must be ≤ 255 bytes".to_string(),
            ));
        }
        let mut tagged: Vec<u8> = Vec::with_capacity(2 + context.len() + message.len());
        tagged.push(0x00u8);
        tagged.push(context.len() as u8);
        tagged.extend_from_slice(context);
        tagged.extend_from_slice(message);

        let sig = self
            .sig_keypair
            .sign_deterministic(&tagged)
            .map_err(|e| GossipError::CryptoError(format!("ML-DSA-65 sign failed: {e}")))?;
        Ok(sig.bytes)
    }

    /// Verify a signature against this node's own public key.
    pub fn verify(&self, message: &[u8], signature: &[u8], context: &[u8]) -> Result<bool, GossipError> {
        let pk = self.sig_keypair.public_key();
        Self::verify_external(&pk.bytes, message, signature, context)
    }

    /// Verify a signature against an external public key (raw bytes).
    pub fn verify_external(
        sig_public_key_bytes: &[u8],
        message: &[u8],
        signature: &[u8],
        context: &[u8],
    ) -> Result<bool, GossipError> {
        use pqc_sig::types::{SigAlgorithm, Signature};

        let pk = SigPublicKey::new(SigAlgorithm::MlDsa65, sig_public_key_bytes.to_vec());
        let sig = Signature::new(SigAlgorithm::MlDsa65, signature.to_vec());

        // Reconstruct the tagged message: 0x00 || context_len_byte || context || message
        if context.len() > 255 {
            return Err(GossipError::CryptoError(
                "context must be ≤ 255 bytes".to_string(),
            ));
        }
        let mut tagged: Vec<u8> = Vec::with_capacity(2 + context.len() + message.len());
        tagged.push(0x00u8);
        tagged.push(context.len() as u8);
        tagged.extend_from_slice(context);
        tagged.extend_from_slice(message);

        match MlDsa65Keypair::verify(&pk, &tagged, &sig) {
            Ok(()) => Ok(true),
            Err(pqc_sig::error::SigError::VerificationFailed) => Ok(false),
            Err(e) => Err(GossipError::CryptoError(format!("ML-DSA-65 verify error: {e}"))),
        }
    }

    /// Get KEM public key as JSON string.
    pub fn kem_public_key_json(&self) -> Result<String, GossipError> {
        self.kem_keypair
            .public_key()
            .to_json()
            .map_err(|e| GossipError::IdentityError(format!("KEM pk to_json failed: {e}")))
    }

    /// Get SIG public key as hex string.
    pub fn sig_public_key_hex(&self) -> String {
        hex::encode(&self.sig_keypair.public_key().bytes)
    }

    /// Get SIG public key as raw bytes.
    pub fn sig_public_key_bytes(&self) -> Vec<u8> {
        self.sig_keypair.public_key().bytes.clone()
    }

    /// Get KEM public key as canonical bytes (x25519 || mlkem).
    fn kem_public_key_bytes(pk: &pqc_kem::types::HybridPublicKey) -> Result<Vec<u8>, GossipError> {
        let x25519 = pk
            .x25519_bytes()
            .map_err(|e| GossipError::IdentityError(format!("KEM x25519_bytes failed: {e}")))?;
        let mlkem = pk
            .mlkem_bytes()
            .map_err(|e| GossipError::IdentityError(format!("KEM mlkem_bytes failed: {e}")))?;
        let mut out = Vec::with_capacity(x25519.len() + mlkem.len());
        out.extend_from_slice(&x25519);
        out.extend_from_slice(&mlkem);
        Ok(out)
    }
}
