extern crate alloc;

use std::env;
use std::fs::File;
use std::io::Read;

use alloc::collections::BTreeMap;
use models::TestUnit;
use ark_bn254::Bn254;
use ark_groth16::{r1cs_to_qap::LibsnarkReduction, Groth16};
use zkm2_prover::build::groth16_bn254_artifacts_dev_dir;
use zkm2_sdk::{include_elf, utils, HashableKey, ProverClient, ZKMProofWithPublicValues, ZKMStdin};
use zkm2_verifier::convert_ark;

const ELF: &[u8] = include_elf!("revme-guest");

fn main() {
    utils::setup_logger();
    prove_revm();
}

fn prove_revm() { 
    let manifest_path = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let json_path =
        env::var("JSON_PATH").unwrap_or(format!("{}/../test-vectors/test.json", manifest_path));
    let mut f = File::open(json_path).unwrap();
    let mut data = vec![];
    f.read_to_end(&mut data).unwrap();

    let suite: BTreeMap<String, TestUnit> = serde_json::from_slice(&data).map_err(|e| e).unwrap();
    let encoded = serde_cbor::to_vec(&suite).unwrap();

    let mut stdin = ZKMStdin::new();
    stdin.write(&encoded);

    // Create a `ProverClient` method.
    let client = ProverClient::new();

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(ELF, stdin.clone()).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());

    // Generate the proof for the given program and input.
    let (pk, vk) = client.setup(ELF);
    let proof = client.prove(&pk, stdin).groth16().run().unwrap();

    // Verify proof and public values
    client.verify(&proof, &vk).expect("verification failed");

    // Test a round trip of proof serialization and deserialization.
    proof.save("proof-with-pis.bin").expect("saving proof failed");
    let deserialized_proof =
        ZKMProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    // Verify the deserialized proof.
    client.verify(&deserialized_proof, &vk).expect("verification failed");

    // Load the groth16 vk.
    let mut groth16_vk_bytes = Vec::new();
    let groth16_vk_path =
        format!("{}/groth16_vk.bin", groth16_bn254_artifacts_dev_dir().to_str().unwrap());
    File::open(groth16_vk_path).unwrap().read_to_end(&mut groth16_vk_bytes).unwrap();

    // Convert the deserialized proof to an arkworks proof.
    let ark_proof = convert_ark(&deserialized_proof, &vk.bytes32(), &groth16_vk_bytes).unwrap();

    // Verify the arkworks proof.
    let ok = Groth16::<Bn254, LibsnarkReduction>::verify_proof(
        &ark_proof.groth16_vk,
        &ark_proof.proof,
        &ark_proof.public_inputs,
    ).unwrap();
    assert!(ok);

    println!("successfully generated and verified proof for the program!");
}
