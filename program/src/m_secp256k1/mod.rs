extern crate k256;
extern crate rand;

use k256::{ecdsa::{signature::{SignatureEncoding, Signer, Verifier}, DerSignature, RecoveryId, Signature, SigningKey, VerifyingKey}, elliptic_curve::PublicKey, Secp256k1};
use sha3::{Digest, Keccak256};
use tiny_keccak::{Hasher, Keccak};
use sp1_zkvm::precompiles::secp256k1 as precompiled_secp256k1;

fn sign_message(signing_key: &SigningKey, message: &[u8]) -> Signature {
    let signature = signing_key.sign(message);
    signature
}

pub fn m_verify_signature(verifying_key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
    verifying_key.verify(message, signature).is_ok()
}

pub fn recover_signer_public_key(sig: Signature, recovery_id: RecoveryId ,prehash: &[u8; 32]) -> PublicKey<Secp256k1> {
    let recid = recovery_id;

    // let pubkey = sp1_precompiles::secp256k1::ecrecover(sig, prehash).unwrap();
    // let recovered_key = VerifyingKey::recover_from_prehash(&prehash[..], &sig, recid).unwrap();
    let sig_bytes:[u8; 64]= sig.to_bytes().as_slice()[0..64].try_into().unwrap();
    // concat the recovery id to the signature
    let mut realworldsig = [0u8; 65];
    realworldsig[0..64].copy_from_slice(&sig_bytes);
    realworldsig[64] = recid.to_byte();
    let recovered_key = precompiled_secp256k1::ecrecover(&realworldsig, &prehash).unwrap();
    let recovered_key = VerifyingKey::from_sec1_bytes(&recovered_key).unwrap();

    let pubkey = PublicKey::from(&recovered_key);
    pubkey
}


pub fn verify_signature(sig: Signature, recovery_id: RecoveryId, message: &[u8],pubkey: PublicKey<Secp256k1>) -> bool {
    let prehash: [u8; 32] = Keccak256::new_with_prefix(message).finalize().into();
    let rec_pub_key = recover_signer_public_key(sig, recovery_id, &prehash);
    return pubkey == rec_pub_key
}

pub fn verify_signature_with_hash(sig: Signature, recovery_id: RecoveryId,  prehash: &[u8; 32], pubkey: PublicKey<Secp256k1>,) -> bool {
    let rec_pub_key = recover_signer_public_key(sig, recovery_id, prehash);
    return pubkey == rec_pub_key
}

pub fn m_keccak_hash_chain(data: &[u8], chain_num: usize) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut data = data;
    for _ in 0..chain_num {
        let mut hasher = Keccak::v256();
        hasher.update(data);
        hasher.finalize(&mut output);
        data = &output;
    }
    output
}

pub fn keccak_hash(data: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}


#[cfg(test)]
mod tests {
    use std::io::Read;

    use k256::{
        ecdsa::{signature::DigestVerifier, RecoveryId, Signature, SigningKey, VerifyingKey},
    };

    use sha3::{Digest, Keccak256};
    use hex_literal::hex;
    // use crate::m_secp256k1::keccak_hash;
    #[test]
    fn ethereum_end_to_end_example() {
        let signing_key = SigningKey::from_bytes(
            &hex!("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318").into(),
        )
        .unwrap();

        let msg = hex!(
            "e9808504e3b29200831e848094f0109fc8df283027b6285cc889f5aa624eac1f55843b9aca0080018080"
        );
        let digest = Keccak256::new_with_prefix(msg);

        let (sig, recid) = signing_key.sign_digest_recoverable(digest.clone()).unwrap();
        assert_eq!(
            sig.to_bytes().as_slice(),
            &hex!("c9cf86333bcb065d140032ecaab5d9281bde80f21b9687b3e94161de42d51895727a108a0b8d101465414033c3f705a9c7b826e596766046ee1183dbc8aeaa68")
        );
        assert_eq!(recid, RecoveryId::from_byte(0).unwrap());

        let verifying_key =
            VerifyingKey::recover_from_digest(digest.clone(), &sig, recid).unwrap();

        assert_eq!(signing_key.verifying_key(), &verifying_key);
        assert!(verifying_key.verify_digest(digest, &sig).is_ok());
    }
}