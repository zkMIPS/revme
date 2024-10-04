//! Ported from https://github.com/bluealloy/revm/blob/main/examples/generate_block_traces.rs
//! Ported from https://github.com/0xEigenLabs/eigen-prover/blob/main/executor/src/lib.rs

use ethers_core::types::{
    BlockId, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions, GethTrace,
    GethTraceFrame, PreStateFrame,
};
use ethers_providers::Middleware;
use ethers_providers::{Http, Provider};
use revm::{
    db::{CacheDB, EthersDB, PlainAccount, StateBuilder},
    inspector_handle_register,
    inspectors::TracerEip3155,
    primitives::{Address, Bytes, FixedBytes, HashMap, ResultAndState, TxKind, B256, U256},
    Database, DatabaseCommit, Evm,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

// type ExecResult = Result<Vec<(Vec<u8>, Bytes, Uint<256, 4>, ResultAndState)>>;
mod merkle_trie;
use merkle_trie::state_merkle_trie_root;

macro_rules! local_fill {
    ($left:expr, $right:expr, $fun:expr) => {
        if let Some(right) = $right {
            $left = $fun(right.0)
        }
    };
    ($left:expr, $right:expr) => {
        if let Some(right) = $right {
            $left = Address::from(right.as_fixed_bytes())
        }
    };
}

fn new_storage(storage: &revm::primitives::state::EvmStorage) -> HashMap<U256, U256> {
    storage
        .iter()
        .map(|(k, v)| (*k, v.present_value))
        .collect()
}

fn core256_to_revm256(core256: ethers_core::types::U256) -> revm::primitives::U256 {
    revm::primitives::U256::from_str_radix(core256.to_string().as_str(), 10).unwrap()
}

fn fill_test_tx(
    transaction_parts: &mut models::TransactionParts,
    tx: &ethers_core::types::Transaction,
) {
    let gas_limit_uint = core256_to_revm256(tx.gas);
    transaction_parts.gas_limit.push(gas_limit_uint);

    let tx_data = tx.input.0.clone();
    transaction_parts.data.push(tx_data.into());

    let mut tx_gas_price = revm::primitives::U256::from(0);
    local_fill!(tx_gas_price, tx.gas_price, U256::from_limbs);
    transaction_parts.gas_price = Some(tx_gas_price);
    transaction_parts.nonce = core256_to_revm256(tx.nonce);
    transaction_parts.secret_key = B256::default();
    transaction_parts.sender = Some(Address::from(tx.from.as_fixed_bytes()));

    transaction_parts.to = tx.to.map_or_else(
        || Some(Address::default()),
        |to_address| Some(Address::from(to_address.as_fixed_bytes())),
    );

    let mut tx_value = revm::primitives::U256::from(0);
    local_fill!(tx_value, Some(tx.value), U256::from_limbs);
    transaction_parts.value.push(tx_value);
    transaction_parts.max_fee_per_gas = if tx.max_fee_per_gas.is_some() {
        Some(core256_to_revm256(tx.max_fee_per_gas.unwrap()))
    } else {
        None
    };
    transaction_parts.max_priority_fee_per_gas = if tx.max_priority_fee_per_gas.is_some() {
        Some(core256_to_revm256(tx.max_priority_fee_per_gas.unwrap()))
    } else {
        None
    };

    let access_list_vec = tx.access_list.as_ref().map(|access_list| {
        access_list
            .0
            .iter()
            .map(|item| models::AccessListItem {
                address: Address::from(item.address.as_fixed_bytes()),
                storage_keys: item
                    .storage_keys
                    .iter()
                    .map(|h256| B256::from(h256.to_fixed_bytes()))
                    .collect(),
            })
            .collect()
    });

    transaction_parts.access_lists.push(access_list_vec);
}

fn fill_test_env(
    block: &ethers_core::types::Block<ethers_core::types::Transaction>,
) -> models::Env {
    let mut test_env = models::Env {
        current_coinbase: Address(block.author.map(|h160| FixedBytes(h160.0)).unwrap()),
        current_difficulty: U256::default(),
        current_gas_limit: U256::default(),
        current_number: U256::default(),
        current_timestamp: U256::default(),
        current_base_fee: Some(U256::default()),
        // current_excess_blob_gas: Some(U256::default()),
        previous_hash: B256::default(),

        current_random: Some(B256::default()),
        current_beacon_root: Some(B256::default()),
        current_withdrawals_root: Some(B256::default()),

        parent_blob_gas_used: Some(U256::default()),
        parent_excess_blob_gas: Some(U256::default()),
    };
    test_env.current_coinbase = Address(block.author.map(|h160| FixedBytes(h160.0)).unwrap());
    local_fill!(
        test_env.current_difficulty,
        Some(block.difficulty),
        U256::from_limbs
    );
    local_fill!(
        test_env.current_gas_limit,
        Some(block.gas_limit),
        U256::from_limbs
    );
    if let Some(number) = block.number {
        let nn = number.0[0];
        test_env.current_number = U256::from(nn);
    }
    local_fill!(
        test_env.current_timestamp,
        Some(block.timestamp),
        U256::from_limbs
    );
    let mut base_fee = revm::primitives::U256::from(0);
    local_fill!(base_fee, block.base_fee_per_gas, U256::from_limbs);
    test_env.current_base_fee = Some(base_fee);
    test_env.previous_hash = FixedBytes(block.parent_hash.0);
    // local_fill!(test_env.current_random, block.random);
    // local_fill!(test_env.current_beacon_root, block.beacon_root);
    test_env.current_withdrawals_root = if block.withdrawals_root.is_some() {
        Some(FixedBytes(block.withdrawals_root.unwrap().0))
    } else {
        None
    };

    let mut gas_used = revm::primitives::U256::from(0);
    local_fill!(gas_used, Some(block.gas_used), U256::from_limbs);
    test_env.parent_blob_gas_used = Some(gas_used);
    test_env.parent_excess_blob_gas = Some(gas_used);

    test_env
}

fn fill_test_post(
    all_result: &[(Vec<u8>, Bytes, revm::primitives::U256, ResultAndState)],
) -> BTreeMap<models::SpecName, Vec<models::Test>> {
    let mut test_post: BTreeMap<models::SpecName, Vec<models::Test>> = BTreeMap::new();
    for (idx, res) in all_result.iter().enumerate() {
        let (txbytes, data, value, ResultAndState { result, state }) = res;
        {
            // 1. expect_exception: Option<String>,
            log::info!("expect_exception: {:?}", result.is_success());
            // indexes: TxPartIndices,
            log::info!(
                "indexes: data{:?}, value: {}, gas: {}",
                data,
                value,
                result.gas_used()
            );
            log::info!("output: {:?}", result.output());

            // post_state: HashMap<Address, AccountInfo>,
            log::info!("post_state: {:?}", state);
            // logs: B256,
            log::info!("logs: {:?}", result.logs());
            // txbytes: Option<Bytes>,
            log::info!("txbytes: {:?}", txbytes);

            let mut new_state: HashMap<Address, models::AccountInfo> = HashMap::new();

            let mut plain_accounts = vec![];
            for (address, account) in state.iter() {
                let account_info = models::AccountInfo {
                    balance: account.info.balance,
                    code: account
                        .info
                        .code
                        .clone()
                        .map(|code| code.bytecode().clone())
                        .unwrap_or_default(),
                    nonce: account.info.nonce,
                    storage: new_storage(&account.storage),
                };

                new_state.insert(*address, account_info);
                plain_accounts.push((
                    *address,
                    PlainAccount {
                        info: account.info.clone(),
                        storage: new_storage(&account.storage),
                    },
                ));
            }

            let post_value = test_post
                .entry(models::SpecName::Shanghai)
                .or_default();
            let mut new_post_value = std::mem::take(post_value);

            let state_root = state_merkle_trie_root(plain_accounts);
            new_post_value.push(models::Test {
                expect_exception: None,
                indexes: models::TxPartIndices {
                    data: idx,
                    gas: idx,
                    value: idx,
                },
                post_state: new_state,
                // TODO: fill logs
                logs: FixedBytes::default(),
                txbytes: Some(Bytes::from_iter(txbytes)),
                hash: state_root,
            });

            test_post.insert(
                // TODO: get specID
                models::SpecName::Shanghai,
                new_post_value,
            );
        }
    }
    test_post
}

async fn fill_test_pre(
    block: &ethers_core::types::Block<ethers_core::types::Transaction>,
    state: &mut revm::db::State<CacheDB<EthersDB<Provider<Http>>>>,
    client: &Arc<Provider<Http>>,
) -> HashMap<Address, models::AccountInfo> {
    let mut test_pre: HashMap<Address, models::AccountInfo> = HashMap::new();

    for tx in &block.transactions {
        let from_acc = Address::from(tx.from.as_fixed_bytes());
        // query basic properties of an account incl bytecode
        let acc_info: revm::primitives::AccountInfo = state.basic(from_acc).unwrap().unwrap();
        log::info!("acc_info: {} => {:?}", from_acc, acc_info);

        let trace_options = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::PreStateTracer,
            )),
            ..Default::default()
        };

        let geth_trace_res = client
            .debug_trace_transaction(tx.hash, trace_options)
            .await;

        match geth_trace_res {
            Ok(geth_trace) => {
                log::info!("geth_trace: {:#?}", geth_trace);

                match geth_trace.clone() {
                    GethTrace::Known(frame) => {
                        if let GethTraceFrame::PreStateTracer(PreStateFrame::Default(pre_state_mode)) =
                            frame
                        {
                            for (address, account_state) in pre_state_mode.0.iter() {
                                let mut account_info = models::AccountInfo {
                                    balance: U256::from(0),
                                    code: Bytes::from(account_state.code.clone().unwrap_or_default()),
                                    nonce: account_state.nonce.unwrap_or_default().as_u64(),
                                    storage: HashMap::new(),
                                };


                                let balance: ethers_core::types::U256 =
                                    account_state.balance.unwrap_or_default();
                                // The radix of account_state.balance is 10, while that of account_info.balance is 16.
                                account_info.balance =  revm::primitives::U256::from_str_radix(balance.to_string().as_str(), 10).unwrap();
                            

                                if let Some(storage) = account_state.storage.clone() {
                                    for (key, value) in storage.iter() {
                                        let new_key: U256 = U256::from_be_bytes(key.0);
                                        let new_value: U256 = U256::from_be_bytes(value.0);
                                        account_info.storage.insert(new_key, new_value);
                                    }
                                }
                                test_pre.insert(Address::from(address.as_fixed_bytes()), account_info);
                            }
                        }
                    }
                    GethTrace::Unknown(_) => {}
                }
            }
            Err(e) => {
                log::info!("debug_trace_transaction faild {}", e)
            }        
        }
    }
    test_pre
}


pub async fn process(
    client: Arc<Provider<Http>>,
    block_no: u64,
    chain_id: u64,
) -> anyhow::Result<String> {
    // Fetch the transaction-rich block
    let block = match client.get_block_with_txs(block_no).await {
        Ok(Some(block)) => block,
        Ok(None) => anyhow::bail!("Block not found"),
        Err(error) => anyhow::bail!("Error: {:?}", error),
    };
    log::info!("Fetched block number: {}", block.number.unwrap().0[0]);

    let previous_block_number = block_no - 1;
    // Use the previous block state as the db with caching
    let prev_id: BlockId = previous_block_number.into();
    // SAFETY: This cannot fail since this is in the top-level tokio runtime
    let state_db = EthersDB::new(Arc::clone(&client), Some(prev_id)).expect("panic");
    let cache_db: CacheDB<EthersDB<Provider<Http>>> = CacheDB::new(state_db);
    let mut state = StateBuilder::new_with_database(cache_db).build();

    let test_pre = fill_test_pre(&block, &mut state, &client).await;

    let mut evm = Evm::builder()
        .with_db(&mut state)
        .with_external_context(TracerEip3155::new(Box::new(std::io::stdout())))
        .modify_block_env(|b| {
            if let Some(number) = block.number {
                let nn = number.0[0];
                b.number = U256::from(nn);
            }
            local_fill!(b.coinbase, block.author);
            local_fill!(b.timestamp, Some(block.timestamp), U256::from_limbs);
            local_fill!(b.difficulty, Some(block.difficulty), U256::from_limbs);
            local_fill!(b.gas_limit, Some(block.gas_limit), U256::from_limbs);
            if let Some(base_fee) = block.base_fee_per_gas {
                local_fill!(b.basefee, Some(base_fee), U256::from_limbs);
            }
        })
        .modify_cfg_env(|c| {
            c.chain_id = chain_id;
        })
        .append_handler_register(inspector_handle_register)
        .build();

    let txs = block.transactions.len();
    log::info!("Found {txs} transactions.");

    let start = Instant::now();
    let mut transaction_parts = models::TransactionParts {
        sender: Some(Address::default()),
        to: Some(Address::default()),
        ..Default::default()
    };

    // Fill in CfgEnv
    let mut all_result: Vec<(Vec<u8>, Bytes, revm::primitives::U256, ResultAndState)> = vec![];
    for tx in block.transactions.clone() {
        evm = evm
            .modify()
            .modify_tx_env(|etx| {
                etx.caller = Address::from(tx.from.as_fixed_bytes());
                etx.gas_limit = tx.gas.as_u64();
                local_fill!(etx.gas_price, tx.gas_price, U256::from_limbs);
                local_fill!(etx.value, Some(tx.value), U256::from_limbs);
                etx.data = tx.input.0.clone().into();
                let mut gas_priority_fee = U256::ZERO;
                local_fill!(
                    gas_priority_fee,
                    tx.max_priority_fee_per_gas,
                    U256::from_limbs
                );
                etx.gas_priority_fee = Some(gas_priority_fee);
                etx.chain_id = Some(chain_id);
                etx.nonce = Some(tx.nonce.as_u64());

                if let Some(access_list) = tx.access_list.clone() {
                    etx.access_list = access_list
                        .0
                        .into_iter()
                        .map(|item| {
                            let storage_keys: Vec<B256> = item
                                .storage_keys
                                .into_iter()
                                .map(|h256| B256::new(h256.0))
                                .collect();
                            revm::primitives::AccessListItem {
                                address: Address::new(item.address.0),
                                storage_keys,
                            }
                        })
                        .collect();
                } else {
                    etx.access_list = Default::default();
                }

                etx.transact_to = match tx.to {
                    Some(to_address) => TxKind::Call(Address::from(to_address.as_fixed_bytes())),
                    None => TxKind::Create,
                };
            })
            .build();

        fill_test_tx(&mut transaction_parts, &tx);

        let result = evm.transact().unwrap();
        log::info!("evm transact result: {:?}", result.result);
        evm.context.evm.db.commit(result.state.clone());
        let env = evm.context.evm.env.clone();
        let txbytes = serde_json::to_vec(&env.tx).unwrap();
        all_result.push((txbytes, env.tx.data, env.tx.value, result));
        // TODO over Archive rate limit
        // tokio::time::sleep(time::Duration::from_secs(1)).await;
    }

    let test_env = fill_test_env(&block);
    let test_post = fill_test_post(&all_result);

    let test_unit = models::TestUnit {
        info: None,
        chain_id: Some(chain_id),
        env: test_env,
        pre: test_pre,
        post: test_post,
        transaction: transaction_parts,
        out: None,
    };

    let json_string = serde_json::to_string(&test_unit).expect("Failed to serialize");
    log::debug!("test_unit: {}", json_string);

    let elapsed = start.elapsed();
    log::info!(
        "Finished execution. Total CPU time: {:.6}s",
        elapsed.as_secs_f64()
    );

    Ok(json_string)
}
