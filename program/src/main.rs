//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);


use fibonacci_program::m_secp256k1::{m_keccak_hash_chain, m_verify_signature, verify_signature, verify_signature_with_hash};
use serde::{Deserialize, Serialize};

use alloy_sol_types::{sol, SolType};

use k256::{
    ecdsa::{RecoveryId, Signature, VerifyingKey},
    EncodedPoint, PublicKey,
};
use tiny_keccak::{Hasher, Keccak};

/// The public values encoded as a tuple that can be easily deserialized inside Solidity.
type PublicValuesTuple = sol! {
    tuple(uint32, uint32, uint32)
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigVerify {
    pub message: Vec<u8>,
    pub pubkey: PublicKey,
    pub signature: Signature,
    pub recovery_id: u8
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigVerifyWithHash {
    pub pubkey: PublicKey,
    pub signature: Signature,
    pub recovery_id: u8,
    pub prehash: [u8; 32],
}

pub fn sig_verify_with_hash() {
    let stdin = sp1_zkvm::io::read::<Vec<SigVerifyWithHash>>();
    let mut result_set: Vec<u32> = Vec::new();
    stdin.iter().for_each(|stdin| {   
        let pubkey = stdin.pubkey;
        let signature = stdin.signature;
        let recovery_id = RecoveryId::from_byte(stdin.recovery_id).unwrap();
        let prehash = stdin.prehash;
        let result = verify_signature_with_hash(signature, recovery_id, &prehash, pubkey);
        assert!(result == true, "Signature verification failed");
        result_set.push(result as u32)
    });
    
    sp1_zkvm::io::commit(&result_set);
}

pub fn sig_verify() {
    let mut stdin = sp1_zkvm::io::read::<SigVerify>();
    let pubkey = stdin.pubkey;
    let message = stdin.message;
    let signature = stdin.signature;
    let recovery_id = RecoveryId::from_byte(stdin.recovery_id).unwrap();

    let result = verify_signature(signature, recovery_id, &message, pubkey);
    sp1_zkvm::io::commit(&result);
}

pub fn keccak_hash() {
    let (data, hash_chain_num) = sp1_zkvm::io::read::<(Vec<u8>, usize)>();
    let hash = m_keccak_hash_chain(&data, hash_chain_num);
    sp1_zkvm::io::commit(&hash);
}

pub fn main() {
    // keccak_hash()
    sig_verify_with_hash()
    // sig_verify()
}
