//! Canonical JSON: object keys sorted recursively, no insignificant whitespace.
//! Hashes and signatures are always computed over this form, so a receipt
//! verifies regardless of how a tool reordered its keys.

use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Returns `value` with every object's keys sorted.
pub fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut sorted = Map::with_capacity(map.len());
            for key in keys {
                sorted.insert(key.clone(), canonicalize(&map[key]));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

/// Serializes `value` to canonical JSON bytes.
pub fn to_canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&canonicalize(&serde_json::to_value(value)?))
}

/// Lower-case hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Lower-case hex SHA-256 of the canonical JSON form of `value`.
pub fn hash_canonical<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    Ok(sha256_hex(&to_canonical_bytes(value)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_does_not_change_the_hash() {
        let a = json!({"b": 1, "a": {"y": [1, {"d": 1, "c": 2}], "x": null}});
        let b = json!({"a": {"x": null, "y": [1, {"c": 2, "d": 1}]}, "b": 1});
        assert_eq!(
            hash_canonical(&a).expect("hash"),
            hash_canonical(&b).expect("hash")
        );
    }

    #[test]
    fn array_order_does_change_the_hash() {
        assert_ne!(
            hash_canonical(&json!([1, 2])).expect("hash"),
            hash_canonical(&json!([2, 1])).expect("hash")
        );
    }
}
