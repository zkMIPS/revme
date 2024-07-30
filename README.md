# revme

Lib to generate suite_json for [zkMIPS/revm](https://github.com/zkMIPS/zkm/tree/main/prover/examples/revme)

## Testing

```
RPC_URL=http://localhost:8545 CHAIN_ID=1337 BLOCK_NO=3 RUST_LOG=debug SUITE_JSON_PATH=./test-vectors/3.json cargo run --example process
```