extern crate alloc;
use alloc::collections::BTreeMap;

use models::TestUnit;

pub fn cbor_serialize(data: &[u8]) -> Vec<u8> {
    let suite: BTreeMap<String, TestUnit> = serde_json::from_slice(data).map_err(|e| e).unwrap();
    serde_cbor::to_vec(&suite).unwrap()
}
