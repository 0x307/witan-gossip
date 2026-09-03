//! GossipConfig deserialization and validation.

use serde::{Deserialize, Serialize};

use crate::error::GossipError;

/// Configuration for the gossip component.
///
/// All fields are optional; missing fields are filled with defaults via `with_defaults()`.
/// Passed as JSON to `gossip_init`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipConfig {
    /// Optional node ID override. If None, derived from keypairs.
    pub node_id: Option<String>,

    /// Optional KEM seed as hex string.
    /// Must be 96 bytes (192 hex chars): 32 x25519 + 64 mlkem secret.
    /// If None, generates fresh ephemeral keypair.
    pub kem_seed_hex: Option<String>,

    /// Optional SIG seed as hex string.
    /// Must be 32 bytes (64 hex chars): ML-DSA-65 seed.
    /// If None, generates fresh ephemeral keypair.
    pub sig_seed_hex: Option<String>,

    /// Key epoch label. Default: "ephemeral-runtime".
    pub key_epoch: Option<String>,

    /// Target mesh degree. Default: 8.
    pub mesh_n: Option<u8>,

    /// Minimum mesh degree before adding peers. Default: 4.
    pub mesh_n_low: Option<u8>,

    /// Maximum mesh degree before pruning peers. Default: 12.
    pub mesh_n_high: Option<u8>,

    /// Heartbeat interval in milliseconds. Default: 700.
    pub heartbeat_ms: Option<u64>,

    /// Maximum message size in bytes. Default: 1_048_576 (1MB).
    pub max_message_bytes: Option<usize>,

    /// Deduplication cache TTL in seconds. Default: 60.
    pub dedup_cache_secs: Option<u64>,

    /// BFT quorum fraction (0.0–1.0). Default: 0.67 (≥2/3).
    pub quorum_fraction: Option<f64>,

    /// Replay protection window in milliseconds. Default: 30_000 (±30s).
    pub replay_window_ms: Option<u64>,

    /// Default TTL hop count for new envelopes. Default: 8.
    pub default_ttl: Option<u8>,
}

/// Resolved configuration with all defaults applied.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub node_id_override: Option<String>,
    pub kem_seed: Option<Vec<u8>>,   // decoded from hex, 96 bytes
    pub sig_seed: Option<Vec<u8>>,   // decoded from hex, 32 bytes
    pub key_epoch: String,
    pub mesh_n: u8,
    pub mesh_n_low: u8,
    pub mesh_n_high: u8,
    pub heartbeat_ms: u64,
    pub max_message_bytes: usize,
    pub dedup_cache_secs: u64,
    pub quorum_fraction: f64,
    pub replay_window_ms: u64,
    pub default_ttl: u8,
}

impl GossipConfig {
    /// Parse a GossipConfig from a JSON string.
    pub fn from_json(s: &str) -> Result<Self, GossipError> {
        serde_json::from_str(s)
            .map_err(|e| GossipError::ConfigError(format!("JSON parse error: {e}")))
    }

    /// Fill None fields with defaults and decode hex seeds.
    pub fn resolve(self) -> Result<ResolvedConfig, GossipError> {
        // Decode KEM seed if provided
        let kem_seed = if let Some(hex_str) = self.kem_seed_hex {
            let bytes = hex::decode(&hex_str)
                .map_err(|e| GossipError::ConfigError(format!("kem_seed_hex decode error: {e}")))?;
            if bytes.len() != 96 {
                return Err(GossipError::ConfigError(format!(
                    "kem_seed_hex must be 96 bytes (192 hex chars), got {} bytes",
                    bytes.len()
                )));
            }
            Some(bytes)
        } else {
            None
        };

        // Decode SIG seed if provided
        let sig_seed = if let Some(hex_str) = self.sig_seed_hex {
            let bytes = hex::decode(&hex_str)
                .map_err(|e| GossipError::ConfigError(format!("sig_seed_hex decode error: {e}")))?;
            if bytes.len() != 32 {
                return Err(GossipError::ConfigError(format!(
                    "sig_seed_hex must be 32 bytes (64 hex chars), got {} bytes",
                    bytes.len()
                )));
            }
            Some(bytes)
        } else {
            None
        };

        let mesh_n = self.mesh_n.unwrap_or(8);
        let mesh_n_low = self.mesh_n_low.unwrap_or(4);
        let mesh_n_high = self.mesh_n_high.unwrap_or(12);
        let quorum_fraction = self.quorum_fraction.unwrap_or(0.67);

        // Validate mesh parameters
        if mesh_n_low > mesh_n {
            return Err(GossipError::ConfigError(
                "mesh_n_low must be <= mesh_n".to_string(),
            ));
        }
        if mesh_n > mesh_n_high {
            return Err(GossipError::ConfigError(
                "mesh_n must be <= mesh_n_high".to_string(),
            ));
        }
        if !(0.0..=1.0).contains(&quorum_fraction) {
            return Err(GossipError::ConfigError(
                "quorum_fraction must be between 0.0 and 1.0".to_string(),
            ));
        }

        Ok(ResolvedConfig {
            node_id_override: self.node_id,
            kem_seed,
            sig_seed,
            key_epoch: self.key_epoch.unwrap_or_else(|| "ephemeral-runtime".to_string()),
            mesh_n,
            mesh_n_low,
            mesh_n_high,
            heartbeat_ms: self.heartbeat_ms.unwrap_or(700),
            max_message_bytes: self.max_message_bytes.unwrap_or(1_048_576),
            dedup_cache_secs: self.dedup_cache_secs.unwrap_or(60),
            quorum_fraction,
            replay_window_ms: self.replay_window_ms.unwrap_or(30_000),
            default_ttl: self.default_ttl.unwrap_or(8),
        })
    }
}
