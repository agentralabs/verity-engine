//! RFC 3161 Timestamp Authority integration.
//! Provides temporal proof independent of ZexRail's clock.

use sha2::{Sha256, Digest};

/// Configuration for the Timestamp Authority.
#[allow(dead_code)]
pub struct TsaConfig {
    /// URL of the TSA endpoint (RFC 3161 HTTP).
    /// Dev: https://freetsa.org/tsr
    /// Prod: https://timestamp.digicert.com
    pub url: String,
}

/// A verified RFC 3161 timestamp token.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TsaToken {
    pub tsa_serial:     String,
    pub tsa_issuer:     String,
    pub tsa_timestamp:  String,  // ISO 8601 UTC
    pub tsa_token_hash: String,  // "sha256:" + hex
    /// DER-encoded token bytes — store in Evidence Ledger
    pub raw_der: Vec<u8>,
}

/// Request a timestamp token from the TSA for the given hash.
/// The hash should be the SHA-256 of the VerityReceipt's canonical JSON
/// (excluding the timestamp_authority block itself).
pub async fn request_tsa_token(
    _config: &TsaConfig,
    _receipt_hash: &[u8],
) -> Result<TsaToken, Box<dyn std::error::Error + Send + Sync>> {
    todo!("implement RFC 3161 request — use rcgen or rasn crate")
}

/// Verify a stored TSA token against the original receipt hash.
/// Returns true if the token is valid and covers receipt_hash.
pub fn verify_tsa_token(
    _raw_der: &[u8],
    _receipt_hash: &[u8],
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    todo!("implement RFC 3161 response verification")
}

/// Compute SHA-256 of DER bytes, returned as "sha256:{hex}"
pub fn tsa_token_hash(raw_der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_der);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tsa_token_hash_deterministic() {
        let data = b"test-der-token-bytes";
        let h1 = tsa_token_hash(data);
        let h2 = tsa_token_hash(data);
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
        assert_eq!(h1.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn test_tsa_token_hash_different_input() {
        let h1 = tsa_token_hash(b"data1");
        let h2 = tsa_token_hash(b"data2");
        assert_ne!(h1, h2);
    }
}
