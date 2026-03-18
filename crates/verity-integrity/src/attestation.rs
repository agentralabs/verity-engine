//! External verifier attestation for probabilistic conditions.
//! Requires external verifiers to cryptographically sign their results,
//! preventing result fabrication.

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey, SigningKey};
use sha2::{Sha256, Digest};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// The data an external verifier signs over.
/// Canonical JSON of: condition_id + result (bool) + confidence_bps + signed_at
pub struct AttestationPayload {
    pub condition_id:   String,
    pub result:         bool,
    pub confidence_bps: u16,
    pub signed_at:      String,  // ISO 8601 UTC
}

/// Compute SHA-256 of the canonical attestation payload.
pub fn attestation_payload_hash(payload: &AttestationPayload) -> String {
    let canonical = format!(
        "{{\"condition_id\":\"{}\",\"confidence_bps\":{},\"result\":{},\"signed_at\":\"{}\"}}",
        payload.condition_id,
        payload.confidence_bps,
        payload.result,
        payload.signed_at
    );
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Verify an external verifier's attestation signature.
/// Returns Ok(true) if valid, Ok(false) if invalid, Err on malformed input.
pub fn verify_attestation(
    payload_hash: &str,
    signature_b64: &str,
    public_key_b64: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let hash_hex = payload_hash.strip_prefix("sha256:")
        .ok_or("invalid payload_hash format")?;
    let hash_bytes = hex::decode(hash_hex)?;

    let sig_bytes = URL_SAFE_NO_PAD.decode(signature_b64)?;
    let pub_bytes = URL_SAFE_NO_PAD.decode(public_key_b64)?;

    let verifying_key = VerifyingKey::from_bytes(
        pub_bytes.as_slice().try_into()
            .map_err(|_| "public key must be 32 bytes")?
    )?;
    let signature = Signature::from_bytes(
        sig_bytes.as_slice().try_into()
            .map_err(|_| "signature must be 64 bytes")?
    );

    Ok(verifying_key.verify(&hash_bytes, &signature).is_ok())
}

/// Sign an attestation payload as an external verifier.
/// Used by verifier agents to produce their attestation.
pub fn sign_attestation(
    payload: &AttestationPayload,
    signing_key: &SigningKey,
) -> (String, String) {
    let hash = attestation_payload_hash(payload);
    let hash_hex = hash.strip_prefix("sha256:").unwrap();
    let hash_bytes = hex::decode(hash_hex).unwrap();
    let sig = signing_key.sign(&hash_bytes);
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    (hash, sig_b64)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn make_signing_key() -> SigningKey {
        let secret: [u8; 32] = rand::random();
        SigningKey::from_bytes(&secret)
    }

    fn make_payload() -> AttestationPayload {
        AttestationPayload {
            condition_id:   "cond_0001".to_string(),
            result:         true,
            confidence_bps: 9200,
            signed_at:      "2026-03-18T10:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_payload_hash_deterministic() {
        let p = make_payload();
        let h1 = attestation_payload_hash(&p);
        let h2 = attestation_payload_hash(&make_payload());
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sign_and_verify_valid() {
        let key = make_signing_key();
        let vk = key.verifying_key();
        let vk_b64 = URL_SAFE_NO_PAD.encode(vk.as_bytes());
        let payload = make_payload();
        let (hash, sig) = sign_attestation(&payload, &key);
        assert!(verify_attestation(&hash, &sig, &vk_b64).unwrap());
    }

    #[test]
    fn test_verify_wrong_key_returns_false() {
        let key1 = make_signing_key();
        let key2 = make_signing_key();
        let vk2_b64 = URL_SAFE_NO_PAD.encode(key2.verifying_key().as_bytes());
        let payload = make_payload();
        let (hash, sig) = sign_attestation(&payload, &key1);
        assert!(!verify_attestation(&hash, &sig, &vk2_b64).unwrap());
    }

    #[test]
    fn test_verify_tampered_hash_returns_false() {
        let key = make_signing_key();
        let vk_b64 = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
        let payload = make_payload();
        let (_, sig) = sign_attestation(&payload, &key);
        let bad_hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(!verify_attestation(bad_hash, &sig, &vk_b64).unwrap());
    }
}
