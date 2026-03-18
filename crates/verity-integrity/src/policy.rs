//! Policy version content addressing.
//! Enables independent verification that the correct rules governed
//! a settlement decision.

use sha2::{Sha256, Digest};
use serde_json::Value;

/// Compute SHA-256 of the canonical JSON of a policy document.
/// canonical = sort_keys=true, no whitespace, UTF-8.
/// Returns "sha256:{hex}"
pub fn policy_content_hash(rules_json: &Value) -> String {
    let canonical = canonical_json(rules_json);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Verify that a retrieved policy document matches the hash
/// recorded in a VerityReceipt's rules_applied block.
pub fn verify_policy_hash(
    rules_json: &Value,
    expected_hash: &str,
) -> bool {
    policy_content_hash(rules_json) == expected_hash
}

/// Canonical JSON: keys sorted recursively, no whitespace.
/// This MUST produce identical output across all implementations.
pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut sorted: Vec<(&String, &Value)> = map.iter().collect();
            sorted.sort_by_key(|(k, _)| k.as_str());
            let pairs: Vec<String> = sorted
                .iter()
                .map(|(k, v)| format!("\"{}\":{}", k, canonical_json(v)))
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonical_json_sorts_keys() {
        let input = json!({"z": 1, "a": 2, "m": 3});
        assert_eq!(canonical_json(&input), r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn test_canonical_json_nested_sorts() {
        let input = json!({"b": {"d": 1, "c": 2}, "a": 3});
        assert_eq!(canonical_json(&input), r#"{"a":3,"b":{"c":2,"d":1}}"#);
    }

    #[test]
    fn test_policy_hash_deterministic() {
        let rules = json!({"version": "xap-v0.2", "max_counter_rounds": 20});
        let h1 = policy_content_hash(&rules);
        let h2 = policy_content_hash(&rules);
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[test]
    fn test_verify_policy_hash_valid() {
        let rules = json!({"max_counter_rounds": 20});
        let hash = policy_content_hash(&rules);
        assert!(verify_policy_hash(&rules, &hash));
    }

    #[test]
    fn test_verify_policy_hash_tampered() {
        let rules = json!({"max_counter_rounds": 20});
        let tampered = json!({"max_counter_rounds": 99});
        let hash = policy_content_hash(&rules);
        assert!(!verify_policy_hash(&tampered, &hash));
    }
}
