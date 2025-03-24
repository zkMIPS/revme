# revme

Lib to generate suite_json for [zkMIPS/revm](https://github.com/zkMIPS/zkm/tree/main/prover/examples/revme)

## Testing

```
RPC_URL=http://localhost:8545 CHAIN_ID=1337 SPEC_NAME=Shanghai BLOCK_NO=3 RUST_LOG=debug SUITE_JSON_PATH=./test-vectors/3.json cargo run --example fetch_block
```

For GOAT Testnet3:

```
RPC_URL=https://rpc.testnet3.goat.network CHAIN_ID=48816 SPEC_NAME=Cancun BLOCK_NO=3168249 RUST_LOG=debug SUITE_JSON_PATH=/tmp/3168249.json cargo run --example fetch_block 
```
