extern crate alloc;
use alloc::collections::BTreeMap;

use models::TestUnit;

pub const TEST_DATA: &[u8] = include_bytes!("../test-vectors/test.json");

#[derive(Debug)]
pub enum HostDataErr {
    SerdeJsonErr(serde_json::Error),
    SerdeCborErr(serde_cbor::Error),
}

pub fn cbor_serialize(data: &[u8]) -> Result<Vec<u8>, HostDataErr> {
    let suite: BTreeMap<String, TestUnit> =
        serde_json::from_slice(data).map_err(HostDataErr::SerdeJsonErr)?;
    serde_cbor::to_vec(&suite).map_err(HostDataErr::SerdeCborErr)
}
