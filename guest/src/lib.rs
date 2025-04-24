// #![no_std]

extern crate alloc;
extern crate libc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use models::{SpecName, Test, TestSuite};
use revm::db::EmptyDB;
use revm::primitives::{EVMResultGeneric, ExecutionResult};
use revm::{
    db::CacheState,
    primitives::{calc_excess_blob_gas, keccak256, Bytecode, Env, SpecId, TransactTo},
    Evm, State,
};
use std::convert::Infallible;
mod merkle_trie;
mod utils;

use merkle_trie::{log_rlp_hash, state_merkle_trie_root};
use utils::recover_address;

pub fn verify_revm_tx(tx_list: &Vec<u8>) -> Result<[u8; 32], String> {
    let suite = read_suite(&tx_list)?;
    execute_test_suite(suite)
}

pub fn read_suite(s: &Vec<u8>) -> Result<TestSuite, String> {
    match serde_cbor::from_slice(s) {
        Ok(btm) => Ok(TestSuite(btm)),
        Err(e) => Err(e.to_string()),
    }
}

pub fn execute_test_suite(suite: TestSuite) -> Result<[u8; 32], String> {
    let mut state_root = None;
    for (txid, unit) in suite.0 {
        // Create database and insert cache
        let mut cache_state = CacheState::new(false);
        for (address, info) in unit.pre {
            let acc_info = revm::primitives::AccountInfo {
                balance: info.balance,
                code_hash: keccak256(&info.code),
                code: Some(Bytecode::new_raw(info.code)),
                nonce: info.nonce,
            };
            cache_state.insert_account_with_storage(address, acc_info, info.storage);
        }

        let mut env = Env::default();
        // for mainnet
        env.cfg.chain_id = unit.chain_id.unwrap_or(1);
        // env.cfg.spec_id is set down the road
        env.cfg.disable_base_fee = true;
        env.cfg.disable_balance_check = true;

        // block env
        env.block.number = unit.env.current_number;
        env.block.coinbase = unit.env.current_coinbase;
        env.block.timestamp = unit.env.current_timestamp;
        env.block.gas_limit = unit.env.current_gas_limit;
        env.block.basefee = unit.env.current_base_fee.unwrap_or_default();
        env.block.difficulty = unit.env.current_difficulty;
        // after the Merge prevrandao replaces mix_hash field in block and replaced difficulty opcode in EVM.
        env.block.prevrandao = unit.env.current_random;
        // EIP-4844
        if let (Some(parent_blob_gas_used), Some(parent_excess_blob_gas)) = (
            unit.env.parent_blob_gas_used,
            unit.env.parent_excess_blob_gas,
        ) {
            env.block
                .set_blob_excess_gas_and_price(calc_excess_blob_gas(
                    parent_blob_gas_used.to(),
                    parent_excess_blob_gas.to(),
                ));
        }

        // tx env
        env.tx.caller = match unit.transaction.sender {
            Some(address) => address,
            _ => recover_address(unit.transaction.secret_key.as_slice())
                .ok_or_else(|| String::new())?,
        };
        env.tx.gas_price = unit
            .transaction
            .gas_price
            .or(unit.transaction.max_fee_per_gas)
            .unwrap_or_default();
        env.tx.gas_priority_fee = unit.transaction.max_priority_fee_per_gas;
        // EIP-4844
        env.tx.blob_hashes = unit.transaction.blob_versioned_hashes;
        env.tx.max_fee_per_blob_gas = unit.transaction.max_fee_per_blob_gas;

        // post and execution
        for (spec_name, tests) in unit.post {
            if matches!(
                spec_name,
                SpecName::ByzantiumToConstantinopleAt5
                    | SpecName::Constantinople
                    | SpecName::Unknown
            ) {
                continue;
            }

            let spec_id = spec_name.to_spec_id();

            for (_index, test) in tests.into_iter().enumerate() {
                env.tx.gas_limit = unit.transaction.gas_limit[test.indexes.gas].saturating_to();
                env.tx.data = unit
                    .transaction
                    .data
                    .get(test.indexes.data)
                    .unwrap()
                    .clone();
                env.tx.value = unit.transaction.value[test.indexes.value];

                env.tx.access_list = unit
                    .transaction
                    .access_lists
                    .get(test.indexes.data)
                    .and_then(Option::as_deref)
                    .unwrap_or_default()
                    .iter()
                    .map(|item| revm::primitives::AccessListItem {
                        address: item.address,
                        storage_keys: item.storage_keys.iter().copied().collect(),
                    })
                    .collect();

                let to = match unit.transaction.to {
                    Some(add) => TransactTo::Call(add),
                    None => TransactTo::Create,
                };
                env.tx.transact_to = to;

                let mut cache = cache_state.clone();
                cache.set_state_clear_flag(SpecId::enabled(
                    spec_id,
                    revm::primitives::SpecId::SPURIOUS_DRAGON,
                ));
                let mut state = revm::db::State::builder()
                    .with_cached_prestate(cache)
                    .with_bundle_update()
                    .build();
                let mut evm = Evm::builder()
                    .with_db(&mut state)
                    .modify_env(|e| *e = Box::new(env.clone()))
                    .with_spec_id(spec_id)
                    .build();

                // do the deed
                let mut check = || {
                    let exec_result = evm.transact_commit();
                    check_evm_execution(&test, &txid, &exec_result, &evm)
                };

                state_root = Some(test.hash.0);
                let Err(e) = check() else { continue };

                return Err(e);
            }
        }
    }
    Ok(state_root.unwrap())
}

pub fn check_evm_execution<EXT>(
    test: &Test,
    test_name: &str,
    exec_result: &EVMResultGeneric<ExecutionResult, Infallible>,
    evm: &Evm<'_, EXT, &mut State<EmptyDB>>,
) -> Result<(), String> {
    let logs_root = log_rlp_hash(exec_result.as_ref().map(|r| r.logs()).unwrap_or_default());
    let state_root = state_merkle_trie_root(evm.context.evm.db.cache.trie_account());

    // If we expect exception revm should return error from execution.
    // So we do not check logs and state root.
    //
    // Note that some tests that have exception and run tests from before state clear
    // would touch the caller account and make it appear in state root calculation.
    // This is not something that we would expect as invalid tx should not touch state.
    // but as this is a cleanup of invalid tx it is not properly defined and in the end
    // it does not matter.
    // Test where this happens: `tests/GeneralStateTests/stTransactionTest/NoSrcAccountCreate.json`
    // and you can check that we have only two "hash" values for before and after state clear.
    match (&test.expect_exception, &exec_result) {
        // do nothing
        (None, Ok(_)) => (),
        // return okay, exception is expected.
        (Some(_), Err(_e)) => (),
        _ => {
            let s = exec_result.clone().err().map(|e| e.to_string()).unwrap();
            return Err(s);
        }
    }

    if logs_root != test.logs {
        return Err(format!(
            "{} logs root mismatch, {},expected {}",
            test_name, logs_root, test.logs
        ));
    }

    if state_root != test.hash {
        return Err(format!(
            "{} state root mismatch, {},expected {}",
            test_name, state_root, test.hash
        ));
    }

    Ok(())
}
