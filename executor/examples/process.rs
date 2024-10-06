use ethers_providers::{Http, Provider};
use std::env;
use std::sync::Arc;
use std::fs::File;
use std::io::Write;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::try_init().unwrap_or_default();
    let block_no = env::var("BLOCK_NO").unwrap_or(String::from("1"));
    let block_no: u64 = block_no.parse().unwrap();
    let rpc_url = env::var("RPC_URL").unwrap_or(String::from("http://localhost:8545"));
    let chain_id = env::var("CHAIN_ID").unwrap_or(String::from("1"));
    let suite_json_path = env::var("SUITE_JSON_PATH").unwrap_or(String::from("/tmp/suite.json"));
    let client = Provider::<Http>::try_from(rpc_url).unwrap();
    let client = Arc::new(client);
    let json_string = executor::process(
        client,
        block_no,
        chain_id.parse::<u64>().unwrap(),
    )
    .await.unwrap();
    let mut file = File::create(suite_json_path).expect("Failed to create file");
    if let Err(e) = file.write_all(json_string.as_bytes()) {
        log::info!("Failed to write json string to file: {}", e);
    }
    Ok(())
}