use std::env;
use std::fs::File;
use std::io::Read;

use guest::verify_revm_tx;
use guest_std::cbor_serialize;

pub fn main() {
    let manifest_path = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let json_path =
        env::var("JSON_PATH").unwrap_or(format!("{}/test-vectors/test.json", manifest_path));
    let mut f = File::open(json_path).unwrap();
    let mut data = vec![];
    f.read_to_end(&mut data).unwrap();

    let encoded = cbor_serialize(&data).unwrap();
    assert!(verify_revm_tx(&encoded));

    println!("finish");
}
