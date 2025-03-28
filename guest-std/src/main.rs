use std::env;
use std::fs::File;
use std::io::Read;

use guest::verify_revm_tx;
use guest_std::{cbor_serialize, TEST_DATA};

pub fn main() {
    let data = if let Ok(json_path) = env::var("JSON_PATH") {
        let mut f = File::open(json_path).unwrap();
        let mut data = vec![];
        f.read_to_end(&mut data).unwrap();
        data
    } else {
        TEST_DATA.to_vec()
    };

    let encoded = cbor_serialize(&data).unwrap();
    assert!(verify_revm_tx(&encoded).unwrap());

    println!("finish");
}
