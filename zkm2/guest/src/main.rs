#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;

use guest_lib::verify_revm_tx;

zkm2_zkvm::entrypoint!(main);

pub fn main() {
    let tx_list: Vec<u8> = zkm2_zkvm::io::read();
    verify_revm_tx(&tx_list);
}
