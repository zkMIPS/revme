use std::fs::File;
use std::io::Read;

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use models::TestUnit;

#[derive(Debug)]
pub enum HostDataErr {
    IoErr(std::io::Error),
    SerdeJsonErr(serde_json::Error),
    SerdeCborErr(serde_cbor::Error),
}

pub fn read_data(json_path: &str) -> Result<Vec<u8>, HostDataErr> {
    let mut f = File::open(json_path).map_err(HostDataErr::IoErr)?;
    let mut data = vec![];
    f.read_to_end(&mut data).map_err(HostDataErr::IoErr)?;

    let suite: BTreeMap<String, TestUnit> = serde_json::from_slice(&data).map_err(HostDataErr::SerdeJsonErr)?;
    serde_cbor::to_vec(&suite).map_err(HostDataErr::SerdeCborErr)
}
