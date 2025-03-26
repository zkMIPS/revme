use std::env;
use std::fs::File;
use std::io::Read;

extern crate alloc;
use alloc::collections::BTreeMap;

use guest_lib::verify_revm_tx;
use models::TestUnit;

pub fn main() {
    let manifest_path = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let json_path =
        env::var("JSON_PATH").unwrap_or(format!("{}/test-vectors/test.json", manifest_path));
    let mut f = File::open(json_path).unwrap();
    let mut data = vec![];
    f.read_to_end(&mut data).unwrap();

    let suite: BTreeMap<String, TestUnit> = serde_json::from_slice(&data).map_err(|e| e).unwrap();
    let encoded = serde_cbor::to_vec(&suite).unwrap();

    assert!(verify_revm_tx(&encoded));

    println!("finish");
}
