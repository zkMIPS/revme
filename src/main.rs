#![no_std]
#![feature(alloc_error_handler)]
#![feature(lang_items, start)]

use revm::{
    db::CacheState,
    interpreter::CreateScheme,
    primitives::{calc_excess_blob_gas, keccak256, Bytecode, Env, SpecId, TransactTo, U256},
    Evm,
};

use models::*;

extern crate alloc;
extern crate libc;

use alloc::alloc::*;
use alloc::collections::BTreeMap;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::panic::PanicInfo;
use core::slice;
use core::str;

use libc::{c_int, free, malloc, printf};
use sha2::{Digest, Sha256};

#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
    loop {}
}

/// The global allocator type.
#[derive(Default)]
pub struct Allocator;

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        malloc(layout.size()) as *mut u8
    }
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        free(ptr as *mut c_void);
    }
}

/// If there is an out of memory error, just panic.
#[alloc_error_handler]
fn my_allocator_error(_layout: Layout) -> ! {
    panic!("out of memory");
}

/// The static global allocator.
#[global_allocator]
static GLOBAL_ALLOCATOR: Allocator = Allocator;

fn to_hex_string(bytes: &[u8]) -> [u8; 65] {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut hex_str = [0u8; 65];
    for (i, &byte) in bytes.iter().enumerate() {
        hex_str[i * 2] = HEX_CHARS[(byte >> 4) as usize];
        hex_str[i * 2 + 1] = HEX_CHARS[(byte & 0x0f) as usize];
    }
    hex_str[64] = 0; // null terminator
    hex_str
}

fn parse_hex_string(hex_str: &[u8]) -> Result<[u8; 32], &'static str> {
    // if hex_str.len() != 64 {
    //     return Err("Input string length is not 64 characters");
    // }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(
            core::str::from_utf8(&hex_str[i * 2..i * 2 + 2])
                .map_err(|_| "Invalid UTF-8 sequence")?,
            16,
        )
        .map_err(|_| "Invalid hex digit")?;
    }
    Ok(bytes)
}

fn parse_hex_to_u32(hex_str: &[u8]) -> Result<u32, &'static str> {
    // if hex_str.len() != 8 {
    //     return Err("Input string length is not 8 characters");
    // }
    u32::from_str_radix(
        str::from_utf8(hex_str).map_err(|_| "Invalid UTF-8 sequence")?,
        16,
    )
    .map_err(|_| "Invalid hex digit")
}

#[start]
fn main(_argc: isize, argv: *const *const u8) -> isize {
    // unsafe {
    //     printf(b"Starting the program...\n\0".as_ptr() as *const i8);
    // }

    // if argc < 3 {
    //     unsafe {
    //         printf(b"Usage: <program> <4_byte_string> <64_byte_string>\n\0".as_ptr() as *const i8);
    //     }
    //     return 1;
    // }

    let iters = {
        let arg1 = unsafe { slice::from_raw_parts(*argv.offset(1), 8) };
        match parse_hex_to_u32(&arg1) {
            Ok(num) => num,
            Err(_err) => {
                // unsafe {
                //     printf(
                //         b"Error parsing number from second argument: %s\n\0".as_ptr() as *const i8,
                //         err.as_ptr() as *const i8,
                //     );
                // }
                return 1;
            }
        }
    };

    let inputs_and_outputs = unsafe { slice::from_raw_parts(*argv.offset(2), 128) };

    let inputs: [u8; 32] = match parse_hex_string(&inputs_and_outputs[..64]) {
        Ok(arr) => arr,
        Err(_err) => {
            // unsafe {
            // printf(
            //     b"Error parsing second argument: %s\n\0".as_ptr() as *const i8,
            //     err.as_ptr() as *const i8,
            // );
            // }
            return 1;
        }
    };

    let outputs: [u8; 32] = match parse_hex_string(&inputs_and_outputs[64..]) {
        Ok(arr) => arr,
        Err(_err) => {
            // unsafe {
            // printf(
            //     b"Error parsing second argument: %s\n\0".as_ptr() as *const i8,
            //     err.as_ptr() as *const i8,
            // );
            // }
            return 1;
        }
    };

    sha2_chain(inputs, iters, outputs);
    0
}

fn sha2_chain(inputs: [u8; 32], iters: u32, outputs: [u8; 32]) {
    // unsafe {
    //     printf(b"inputs:\n".as_ptr() as *const i8);
    //     for &byte in &inputs {
    //         printf(b"input %02x \n".as_ptr() as *const i8, byte as c_int);
    //     }
    //     printf(b"\n".as_ptr() as *const i8);
    //
    //     printf(b"outputs: \n".as_ptr() as *const i8);
    //     for &byte_o in &outputs {
    //         printf(b"output %02x\n ".as_ptr() as *const i8, byte_o as c_int);
    //     }
    //     printf(b"\n".as_ptr() as *const i8);
    //
    //     // printf(b"iters: %u\n\0".as_ptr() as *const i8, iters);
    // }

    let mut hash = inputs;
    for _ in 0..iters {
        let mut hasher = Sha256::new();
        hasher.update(hash);
        let res = &hasher.finalize();
        hash = Into::<[u8; 32]>::into(*res);
    }

    if hash == outputs {
        unsafe {
            printf(b"hash equal\n\0".as_ptr() as *const i8);
        }
    } else {
        unsafe {
            printf(b"hash not equal\n\0".as_ptr() as *const i8);
        }
    }
}
