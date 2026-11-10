//! Pinned NIST ACVP-Server FIPS-203 ML-KEM-768 primitive vectors.
//!
//! These vectors are independent of the SSH transcript fixture in
//! `mlkem_vector.rs`. They exercise the `RustCrypto` `ml-kem` 0.3 implementation
//! used by `neotales-ssh`.
//!
//! # Provenance
//!
//! **From the specification**: selected records from the NIST ACVP-Server
//! FIPS-203 corpus at commit `65370b861b96efd30dfe0daae607bde26a78a5c8`, as
//! recorded in `data/README.md`. Every value in this file and every `.bin` file
//! it loads was checked back against those records, not merely against the crate:
//!
//! | what | record |
//! |---|---|
//! | `KEYGEN_SEED`, `KEYGEN_EK`, `KEYGEN_DK` | keyGen, `tgId=2`, `tcId=26` (`d` and `z` concatenated) |
//! | `ENCAPSULATION_RANDOMNESS`, `ENCAPSULATION_EK`, `ENCAPSULATION_CT`, shared secret | encapDecap, `tgId=2`, `tcId=26` |
//! | `DECAPSULATION_DK`, `DECAPSULATION_VALID_CT`, shared secret | encapDecap, `tgId=5`, `tcId=88` (the decapsulation key is the group-level `dk` field) |
//! | `DECAPSULATION_REJECTED_CT`, shared secret | encapDecap, `tgId=5`, `tcId=86` (implicit rejection) |
//!
//! The three source JSON files' SHA-256 values in `data/README.md` were confirmed
//! against the pinned commit, so the citation is checkable rather than a memory.
//!
//! The two seeds are inputs. The three 32-byte shared secrets and the seven
//! `.bin` blobs are the specification's expected values.

#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::{
    self, B32, Decapsulate, ExpandedDecapsulationKey, FromSeed, Key, KeyExport, MlKem768,
};

// PROVENANCE: **from the specification** -- NIST ACVP-Server FIPS-203,
// tgId=2 tcId=26, the record's `d` and `z` fields concatenated into the 64-byte
// keygen seed FIPS 203 asks for. Inputs to the vector, not expected values; see
// the module comment for the full citation.
const KEYGEN_SEED: &str = "e34a701c4c87582f42264ee422d3c684d97611f2523efe0c998af05056d693dca85768f3486bd32a01bf9a8f21ea938e648eae4e5448c34c3eb88820b159eedd";
// PROVENANCE: **from the specification** -- the same corpus, encapDecap
// tgId=2 tcId=26, field `m`. An input.
const ENCAPSULATION_RANDOMNESS: &str =
    "2ce74ad291133518fe60c7df5d251b9d82add48462ff505c6e547e949e6b6bf7";

// PROVENANCE: **from the specification** -- NIST ACVP-Server FIPS-203 records,
// as tabulated in the module comment. All seven blobs were compared field by field
// against the corpus at the pinned commit.
const KEYGEN_EK: &[u8] = include_bytes!("data/nist-mlkem768-keygen-ek.bin");
const KEYGEN_DK: &[u8] = include_bytes!("data/nist-mlkem768-keygen-dk.bin");
const ENCAPSULATION_EK: &[u8] = include_bytes!("data/nist-mlkem768-encapsulation-ek.bin");
const ENCAPSULATION_CT: &[u8] = include_bytes!("data/nist-mlkem768-encapsulation-ct.bin");
const DECAPSULATION_DK: &[u8] = include_bytes!("data/nist-mlkem768-decapsulation-dk.bin");
const DECAPSULATION_VALID_CT: &[u8] =
    include_bytes!("data/nist-mlkem768-decapsulation-valid-ct.bin");
const DECAPSULATION_REJECTED_CT: &[u8] =
    include_bytes!("data/nist-mlkem768-decapsulation-rejected-ct.bin");

fn from_hex<const N: usize>(input: &str) -> [u8; N] {
    assert_eq!(input.len(), N * 2);
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16).unwrap();
    }
    output
}

#[test]
#[allow(deprecated)]
fn nist_acvp_fips203_mlkem768_keygen_encapsulation_and_decapsulation_vectors() {
    let seed = ml_kem::Seed::from(from_hex::<64>(KEYGEN_SEED));
    let (decapsulation_key, encapsulation_key) = MlKem768::from_seed(&seed);
    assert_eq!(&encapsulation_key.to_bytes()[..], KEYGEN_EK);
    assert_eq!(&decapsulation_key.to_expanded_bytes()[..], KEYGEN_DK);

    let encapsulation_key = ml_kem::EncapsulationKey::<MlKem768>::new(
        &Key::<ml_kem::EncapsulationKey<MlKem768>>::try_from(ENCAPSULATION_EK)
            .expect("valid NIST encapsulation key"),
    )
    .expect("valid NIST encapsulation key");
    let randomness = B32::from(from_hex::<32>(ENCAPSULATION_RANDOMNESS));
    let (ciphertext, shared_key) = encapsulation_key.encapsulate_deterministic(&randomness);
    assert_eq!(&ciphertext[..], ENCAPSULATION_CT);
    assert_eq!(
        shared_key.as_ref(),
        // PROVENANCE: **from the specification** -- NIST ACVP-Server FIPS-203,
        // encapDecap tgId=2 tcId=26, the record's `k`. Not computed here.
        from_hex::<32>("2696d28e9c61c2a01ce9b1608dcb9d292785a0cd58efb7fe13b1de95f0db55b3")
    );

    let expanded = ExpandedDecapsulationKey::<MlKem768>::try_from(DECAPSULATION_DK)
        .expect("valid NIST expanded decapsulation key");
    let decapsulation_key = ml_kem::DecapsulationKey::<MlKem768>::from_expanded(&expanded)
        .expect("valid NIST expanded decapsulation key");
    let valid_ciphertext = ml_kem::Ciphertext::<MlKem768>::try_from(DECAPSULATION_VALID_CT)
        .expect("valid NIST ciphertext");
    assert_eq!(
        decapsulation_key.decapsulate(&valid_ciphertext).as_ref(),
        // PROVENANCE: **from the specification** -- encapDecap tgId=5 tcId=88,
        // the record's `k`. The decapsulation key is that group's `dk` field.
        from_hex::<32>("dc5b8888bc1eba5c1969c21164ea43e22e7ac0cd012a2f26cb8c487e69ef7ce4")
    );

    let rejected_ciphertext = ml_kem::Ciphertext::<MlKem768>::try_from(DECAPSULATION_REJECTED_CT)
        .expect("structurally valid NIST ciphertext");
    assert_eq!(
        decapsulation_key.decapsulate(&rejected_ciphertext).as_ref(),
        // PROVENANCE: **from the specification** -- encapDecap tgId=5 tcId=86,
        // the record's `k`. FIPS 203 implicit rejection yields a shared secret
        // rather than an error, which is the point of the case.
        from_hex::<32>("3d23b10df232a180786f61261e85278251746580bebca6acbad60aef6952be69")
    );
}
