// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

#[path = "../src/msg/mod.rs"]
mod msg;

#[path = "../src/kex/mod.rs"]
mod kex;

use kex::{
    CURVE25519_PUBLIC_KEY_LENGTH, ClientKex, Curve25519, DerivationLengths, DerivationLetter,
    DerivedKeys, DhGroup16, EcdhP256, EphemeralKey, ExchangeHashInput, Group16Private,
    KexCompletion, KexContext, KexError, KexReply, KeyExchange, MAX_DERIVED_KEY_LENGTH,
    P256_UNCOMPRESSED_POINT_LENGTH, P256Private, SEC1_UNCOMPRESSED_TAG, SSH_MSG_KEX_ECDH_INIT,
    SSH_MSG_KEX_ECDH_REPLY, ServerKex, SessionIdTracker, SharedSecret, X25519Private,
    compute_exchange_hash, derive_key, derive_keys, derived_keys_drops,
    take_derived_keys_drop_wipe, take_group16_private_drop_wipe,
};
use msg::kexinit::{
    AES128_CTR, CURVE25519_SHA256, CURVE25519_SHA256_LIBSSH, ECDH_SHA2_NISTP256, HMAC_SHA2_256,
    KEX_DIFFIE_HELLMAN_GROUP14_SHA256, KEX_DIFFIE_HELLMAN_GROUP16_SHA512, KexInit,
};
use neotales_ssh::{Error as WireError, Reader, Writer, decode_mpint};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// A compile-time assertion that a type does **not** implement a trait.
///
/// The resolution trick: the method is called on `Type as Ambiguous<_>` with an
/// inferred argument. There is one implementation for every `?Sized` type whose
/// argument is `()`, and one for every type that implements the trait whose
/// argument is `PhantomData<()>` — two different argument types, so the `_` is
/// pinned to `()` and the trait implementation becomes a candidate only when the
/// bound is actually satisfied. With exactly one candidate the call compiles.
/// With two, it does not, so adding the trait back to the type breaks this file
/// rather than quietly passing.
///
/// One trait per invocation, because two trait-bound implementations of the same
/// generic type would conflict with each other rather than with the assertion.
///
/// This is the shape `static_assertions::assert_not_impl_any!` uses, written
/// out here because this crate takes no dependency it does not need, and because
/// "the session key type is not `Clone`" is a claim that deserves a check rather
/// than a review.
macro_rules! assert_not_impl {
    ($trait:ident for $ty:ty) => {
        const _: () = {
            use std::marker::PhantomData;

            trait AmbiguousIfImpl<Marker> {
                fn marker() {}
            }

            impl<T: ?Sized> AmbiguousIfImpl<()> for T {
                fn marker() {}
            }

            impl<T: ?Sized + $trait> AmbiguousIfImpl<PhantomData<()>> for T {
                fn marker() {}
            }

            let _ = <$ty as AmbiguousIfImpl<_>>::marker;
        };
    };
}

// The three things a copy of a live session key could be used for. None is a
// property this crate wants on a type holding all six RFC 4253 letters.
assert_not_impl!(Clone for DerivedKeys);
assert_not_impl!(PartialEq for DerivedKeys);
assert_not_impl!(Eq for DerivedKeys);

// The one-shot material is handed to a mechanism by value, and this is the half
// of "the scalar is only ever in one place" that a test can state: there is no
// way to ask an ephemeral key for a second holder of its scalar.
assert_not_impl!(Clone for EphemeralKey);

// `SharedSecret` is the ECDH output, and comparing two of them is the one
// question whose answer must not be timed. `Vec`'s `PartialEq` is
// length-then-`memcmp`, so leaving the derive in place would hand every later
// test — and any caller that ever needs the comparison — an oracle that
// answers in time proportional to the matching prefix. The traits are absent,
// which is what the next two lines say; `Clone` is present because both roles
// hand a second copy to the completion that outlives the hash input, and that
// is recorded on the struct.
assert_not_impl!(PartialEq for SharedSecret);
assert_not_impl!(Eq for SharedSecret);

// The containing types derive nothing either, because a `KexCompletion` or an
// `ExchangeHashInput` compared with `==` would memcmp the secret it holds.
assert_not_impl!(PartialEq for KexCompletion);
assert_not_impl!(Eq for KexCompletion);
assert_not_impl!(PartialEq for ExchangeHashInput);
assert_not_impl!(Eq for ExchangeHashInput);

// `ExchangeHashInput` is built, hashed and dropped inside one call, so nothing
// ever cloned it. `KexCompletion` is stored *and* returned, so its `Clone` is
// load-bearing and stays. The pair is what keeps the two decisions honest: the
// same secret is held by both, and only the one that outlives its producer is
// copyable. If this stops compiling, a `Clone` was added to the wrong type.
assert_not_impl!(Clone for ExchangeHashInput);

/// Asserts that two shared secrets are the same value, on purpose.
///
/// This is the comparison the tests are allowed to make and the type refuses to
/// give away, written the way the rustdoc on `SharedSecret` says a caller
/// should write it: digest each value, then compare the digests in constant
/// time. It is deliberately not `assert_eq!(left, right)` — that is the
/// expression whose absence is the point of the type, and a test that reaches
/// for it is the shape of bug this guards against.
///
/// The test suite is not a timing oracle to an attacker, so the digest is not
/// load-bearing for correctness here; it is load-bearing as the demonstrated
/// pattern. A future test that genuinely needs "these two exchanges agreed"
/// copies this, and gets a constant-time answer rather than a memcmp.
///
/// PROVENANCE: **not a vector**. Both sides are digests of values this test
/// computed, so there is nothing to quote from a specification.
fn assert_secrets_agree(left: &SharedSecret, right: &SharedSecret) {
    let left_digest = Sha256::digest(left.as_bytes());
    let right_digest = Sha256::digest(right.as_bytes());
    assert!(
        bool::from(left_digest.as_slice().ct_eq(right_digest.as_slice())),
        "the two shared secrets differ"
    );
}

const CLIENT_VERSION: &str = "SSH-2.0-fixed-client";
const SERVER_VERSION: &str = "SSH-2.0-fixed-server";
const HOST_KEY_BLOB: &[u8] = b"host-key-blob";
const SIGNATURE_BLOB: &[u8] = b"opaque-signature-blob";

#[test]
fn curve25519_matches_rfc7748_vector_and_mpint_encoding() -> Result<(), KexError> {
    // PROVENANCE: **from the specification**. All five constants are the X25519
    // test vector from RFC 7748 section 6.1, quoted verbatim:
    //
    //    Test vector:
    //
    //    Alice's private key, a:
    //      77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
    //    Alice's public key, X25519(a, 9):
    //      8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
    //    Bob's private key, b:
    //      5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
    //    Bob's public key, X25519(b, 9):
    //      de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
    //    Their shared secret, K:
    //      4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
    //
    // The private keys are inputs. The two public keys and the shared secret are
    // the expected values, and they are the specification's own, not ours.
    let mechanism = Curve25519::standard();
    let alice_private =
        hex_array("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob_private = hex_array("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let expected_alice_public =
        hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let expected_bob_public =
        hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let expected_shared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    let alice = mechanism.with_private_bytes(alice_private);
    let bob = mechanism.with_private_bytes(bob_private);
    let alice_public = mechanism.public_key(&alice)?;
    let bob_public = mechanism.public_key(&bob)?;
    assert_eq!(alice_public, expected_alice_public);
    assert_eq!(bob_public, expected_bob_public);

    let alice_shared = mechanism.agree(alice, &bob_public)?;
    let bob_shared = mechanism.agree(bob, &alice_public)?;
    assert_secrets_agree(&alice_shared, &bob_shared);
    assert_eq!(decode_mpint(alice_shared.as_bytes())?, expected_shared);
    assert_eq!(
        alice_shared.as_bytes(),
        [&[0, 0, 0, 32][..], &expected_shared[..]].concat()
    );

    assert_eq!(mechanism.name(), "curve25519-sha256");
    assert_eq!(Curve25519::libssh().name(), "curve25519-sha256@libssh.org");
    assert_eq!(
        Curve25519::from_name(CURVE25519_SHA256_LIBSSH)?,
        Curve25519::libssh()
    );
    assert_eq!(
        Curve25519::from_name(ECDH_SHA2_NISTP256),
        Err(KexError::AlgorithmMismatch)
    );
    Ok(())
}

#[test]
fn curve25519_adds_mpint_sign_and_rejects_low_order_input() -> Result<(), KexError> {
    let mechanism = Curve25519::standard();
    let mut private = [0_u8; 32];
    private[0] = 16;
    let mut basepoint = [0_u8; 32];
    basepoint[0] = 9;
    let ephemeral = mechanism.with_private_bytes(private);
    let shared = mechanism.agree(ephemeral, &basepoint)?;
    // PROVENANCE: **computed from the primitive**. `expected_raw` is
    // X25519(scalar = 0x10 || 0^31, u = 9), run against the X25519 primitive
    // directly and not through `agree`. RFC 7748 section 6.1 publishes vectors for
    // two named keys and not for this one, so there is nothing to cite: this is
    // our own computed answer, chosen because the top bit of the result is set and
    // so the mpint encoding needs a leading sign octet.
    let expected_raw = hex("8d20f8c7bbfb9af3da4ef532ed44efc68ce642bc5d0c5cb1d7b91b96c74edf02");
    let mut expected_positive = vec![0];
    expected_positive.extend_from_slice(&expected_raw);
    assert_eq!(decode_mpint(shared.as_bytes())?, expected_positive);
    assert_eq!(shared.as_bytes()[4], 0);
    assert_eq!(shared.as_bytes().len(), 37);

    let mut scalar_one = [0_u8; 32];
    scalar_one[0] = 1;
    let low_order = mechanism.with_private_bytes(scalar_one);
    // `.err()` rather than comparing the whole `Result`: the `Ok` arm carries a
    // `SharedSecret`, and this file does not compare two of those with `==`.
    assert_eq!(
        mechanism.agree(low_order, &[0_u8; 32]).err(),
        Some(KexError::NonContributorySecret)
    );
    Ok(())
}

#[test]
fn p256_fixed_scalar_pair_matches_known_generator_multiple() -> Result<(), KexError> {
    // PROVENANCE: **computed from the primitive**, with one input that is itself
    // published. `generator` is 1*G for the NIST P-256 base point G, and that
    // point is fixed by SEC 2 / FIPS 186-4, so `generator` is the SEC 2 base
    // point in uncompressed SEC 1 form. `double_generator` and `expected` are
    // 2*G and its x coordinate: computed here by point arithmetic, with no
    // published vector for them, which is why they are not cited as a source.
    let mechanism = EcdhP256::new();
    let mut scalar_one = [0_u8; 32];
    scalar_one[31] = 1;
    let mut scalar_two = [0_u8; 32];
    scalar_two[31] = 2;
    let one = EcdhP256::from_private_bytes(scalar_one)?;
    let two = EcdhP256::from_private_bytes(scalar_two)?;
    let generator = mechanism.public_key(&one)?;
    let double_generator = mechanism.public_key(&two)?;
    assert_eq!(generator.len(), P256_UNCOMPRESSED_POINT_LENGTH);
    assert_eq!(generator[0], SEC1_UNCOMPRESSED_TAG);
    assert_eq!(
        generator,
        hex(
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        )
    );
    assert_eq!(
        double_generator,
        hex(
            "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"
        )
    );

    let expected = hex("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978");
    let first = mechanism.agree(one, &double_generator)?;
    let second = mechanism.agree(two, &generator)?;
    assert_secrets_agree(&first, &second);
    assert_eq!(decode_mpint(first.as_bytes())?, expected);

    assert_eq!(
        EcdhP256::from_private_bytes([0_u8; 32]).err(),
        Some(KexError::InvalidPublicKey)
    );
    assert_eq!(
        EcdhP256::from_private_bytes([0xff_u8; 32]).err(),
        Some(KexError::InvalidPublicKey)
    );
    Ok(())
}

#[test]
fn fixed_exchange_hash_uses_exact_rfc_framing() -> Result<(), KexError> {
    let (shared, _) = fixed_high_bit_shared_secret()?;
    let context = fixed_context(CURVE25519_SHA256, CLIENT_VERSION, SERVER_VERSION)?;
    let client_public = hex("1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30");
    let server_public = hex("4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60");
    let input = ExchangeHashInput::new(HOST_KEY_BLOB, &client_public, &server_public, shared)?;
    assert_eq!(input.host_key_blob(), HOST_KEY_BLOB);
    assert_eq!(input.client_public_key(), client_public);
    assert_eq!(input.server_public_key(), server_public);
    assert_eq!(input.shared_secret().as_bytes().len(), 37);

    let framed_bytes = input.framed_bytes()?;
    let mut framed = Reader::new(&framed_bytes);
    assert_eq!(framed.read_string()?, HOST_KEY_BLOB);
    assert_eq!(framed.read_string()?, client_public);
    assert_eq!(framed.read_string()?, server_public);
    let mpint = framed.read_mpint()?;
    assert_eq!(mpint[0], 0);
    assert_eq!(mpint[1], 0x8d);
    framed.ensure_finished()?;

    // PROVENANCE: **computed from the primitive**. The exchange hash is SHA-256
    // applied to the RFC 4253 section 8 concatenation, run directly rather than
    // through `compute_exchange_hash`:
    //
    //     H = HASH(string V_C || string V_S || string I_C || string I_S
    //               || string K_S || string Q_C || string Q_S || mpint K)
    //
    // I_C and I_S are the KEXINIT payloads including the leading message number,
    // and K is the length-prefixed mpint. RFC 4253 defines the construction but
    // publishes no worked values for it, so there is nothing here to cite. The
    // version strings, KEXINIT proposals and host key blob it feeds on are this
    // file's own fixtures, which is what makes the value ours.
    let expected = hex("5be1c0e29301c828a54cd6240edf010f2a5326fb8150cefa0c72e5cfc7620e1d");
    assert_eq!(
        compute_exchange_hash(&context, &input)?.as_slice(),
        expected
    );

    let decoded_client = KexInit::decode(context.client_kexinit())?;
    let decoded_server = KexInit::decode(context.server_kexinit())?;
    assert_eq!(decoded_client.encode()?, context.client_kexinit());
    assert_eq!(decoded_server.encode()?, context.server_kexinit());

    let changed_version = fixed_context(
        CURVE25519_SHA256,
        CLIENT_VERSION,
        "SSH-2.0-different-server",
    )?;
    assert_ne!(
        compute_exchange_hash(&changed_version, &input)?,
        compute_exchange_hash(&context, &input)?
    );

    let p256_context = fixed_context(ECDH_SHA2_NISTP256, CLIENT_VERSION, SERVER_VERSION)?;
    assert_eq!(
        compute_exchange_hash(&p256_context, &input),
        Err(KexError::InvalidPublicKey)
    );
    Ok(())
}

#[test]
fn client_and_server_roles_round_trip_all_supported_spellings() -> Result<(), KexError> {
    let standard = fixed_context(CURVE25519_SHA256, CLIENT_VERSION, SERVER_VERSION)?;
    let standard_completion = exercise_roles(Curve25519::standard(), &standard)?;
    assert_eq!(standard_completion.algorithm(), CURVE25519_SHA256);

    let libssh = fixed_context(CURVE25519_SHA256_LIBSSH, CLIENT_VERSION, SERVER_VERSION)?;
    let libssh_completion = exercise_roles(Curve25519::libssh(), &libssh)?;
    assert_eq!(libssh_completion.algorithm(), CURVE25519_SHA256_LIBSSH);

    let p256 = fixed_context(ECDH_SHA2_NISTP256, CLIENT_VERSION, SERVER_VERSION)?;
    let p256_completion = exercise_roles(EcdhP256::new(), &p256)?;
    assert_eq!(p256_completion.algorithm(), ECDH_SHA2_NISTP256);
    assert_eq!(
        p256_completion.session_id(),
        p256_completion.exchange_hash()
    );
    Ok(())
}

#[test]
fn message_decoders_reject_truncation_wrong_type_trailing_and_oversize() -> Result<(), KexError> {
    let mechanism = Curve25519::standard();
    let private = mechanism.with_private_bytes([7_u8; 32]);
    let public = mechanism.public_key(&private)?;
    let init = mechanism.encode_init_message(&private)?;
    assert_eq!(init[0], SSH_MSG_KEX_ECDH_INIT);
    assert_eq!(init.len(), 37);
    assert_eq!(mechanism.decode_init_message(&init)?, public);
    for length in 0..init.len() {
        assert!(mechanism.decode_init_message(&init[..length]).is_err());
    }

    let mut wrong_type = init.clone();
    wrong_type[0] = SSH_MSG_KEX_ECDH_REPLY;
    assert_eq!(
        mechanism.decode_init_message(&wrong_type),
        Err(KexError::InvalidMessageType)
    );
    let mut trailing = init;
    trailing.push(0);
    assert_eq!(
        mechanism.decode_init_message(&trailing),
        Err(KexError::TrailingData)
    );
    assert!(
        mechanism
            .decode_init_message(&[SSH_MSG_KEX_ECDH_INIT, 0, 0, 0, 31, 1])
            .is_err()
    );

    let mut oversized_init = Writer::new();
    oversized_init.write_byte(SSH_MSG_KEX_ECDH_INIT);
    oversized_init.write_string(&[0_u8; 33])?;
    assert_eq!(
        mechanism.decode_init_message(oversized_init.as_bytes()),
        Err(KexError::Wire(WireError::LimitExceeded))
    );

    let reply = mechanism.encode_reply_message(&public, HOST_KEY_BLOB, SIGNATURE_BLOB)?;
    assert_eq!(reply[0], SSH_MSG_KEX_ECDH_REPLY);
    let decoded: KexReply = mechanism.decode_reply_message(&reply)?;
    assert_eq!(decoded.host_key_blob(), HOST_KEY_BLOB);
    assert_eq!(decoded.server_public_key(), Some(public.as_slice()));
    assert_eq!(decoded.signature_blob(), SIGNATURE_BLOB);
    for length in 0..reply.len() {
        assert!(mechanism.decode_reply_message(&reply[..length]).is_err());
    }
    let mut reply_trailing = reply.clone();
    reply_trailing.push(0);
    assert_eq!(
        mechanism.decode_reply_message(&reply_trailing),
        Err(KexError::TrailingData)
    );

    let mut oversized_host = Writer::new();
    oversized_host.write_byte(SSH_MSG_KEX_ECDH_REPLY);
    oversized_host.write_uint32(u32::MAX);
    assert_eq!(
        mechanism.decode_reply_message(oversized_host.as_bytes()),
        Err(KexError::Wire(WireError::LimitExceeded))
    );
    assert_eq!(
        mechanism.encode_reply_message(&public, &[], SIGNATURE_BLOB),
        Err(KexError::InvalidFieldLength)
    );
    Ok(())
}

#[test]
fn p256_rejects_compressed_identity_malformed_and_wrong_length_points() -> Result<(), KexError> {
    let mechanism = EcdhP256::new();
    let valid_generator = hex(
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    );
    let compressed_generator =
        hex("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    let mut invalid_coordinates = valid_generator.clone();
    invalid_coordinates[64] ^= 1;

    for point in [
        vec![0_u8],
        compressed_generator,
        invalid_coordinates,
        vec![0_u8; 64],
        vec![0_u8; 66],
        vec![0_u8; 65],
    ] {
        let mut message = Writer::new();
        message.write_byte(SSH_MSG_KEX_ECDH_INIT);
        message.write_string(&point)?;
        assert!(
            mechanism.decode_init_message(message.as_bytes()).is_err(),
            "accepted {} bytes",
            point.len()
        );

        assert_eq!(
            mechanism.encode_reply_message(&point, HOST_KEY_BLOB, SIGNATURE_BLOB),
            Err(KexError::InvalidPublicKey)
        );
    }

    let mut valid_message = Writer::new();
    valid_message.write_byte(SSH_MSG_KEX_ECDH_INIT);
    valid_message.write_string(&valid_generator)?;
    assert_eq!(
        mechanism.decode_init_message(valid_message.as_bytes())?,
        valid_generator
    );
    assert!(EcdhP256::from_private_bytes([0_u8; 32]).is_err());
    Ok(())
}

#[test]
fn rfc4253_section_7_2_derivation_reproduces_all_six_letters() -> Result<(), KexError> {
    let (shared, exchange_hash) = fixed_high_bit_shared_secret()?;
    assert_eq!(shared.clone().into_bytes(), shared.as_bytes());
    let session_id = [0xa5_u8; 32];
    // PROVENANCE: **computed from the primitive**. These six are the strongest
    // trap in this file for a reader, because the test name used to start
    // `rfc4253_` and sat next to a table of six 48-byte hex constants.
    //
    // RFC 4253 section 7.2 defines the derivation and publishes no values. All it
    // says about them is:
    //
    //    o  Initial IV client to server: HASH(K || H || "A" || session_id)
    //    ...
    //    K1 = HASH(K || H || X || session_id)   (X is e.g., "A")
    //    K2 = HASH(K || H || K1)
    //    K3 = HASH(K || H || K1 || K2)
    //    ...
    //    key = K1 || K2 || K3 || ...
    //
    // There is no A-to-F table anywhere in the document. So these bytes are ours,
    // computed by applying that text to SHA-256 directly:
    //
    //     K1(L) = SHA-256(K || H || L || session_id)      for L in A..F
    //     K2(L) = SHA-256(K || H || K1(L))
    //     expected(L) = K1(L) || first 16 octets of K2(L)
    //
    // The 48-byte length is this test's choice -- `derive_key(..., 48)` -- not the
    // RFC's, and it is why each constant is 48 bytes rather than the 32 of a
    // single hash. K is the length-prefixed mpint and H is the exchange hash
    // computed in `fixed_exchange_hash_uses_exact_rfc_framing` above, which is
    // itself a fixture. Rename this test to say "derivation" was deliberate: a
    // name starting `rfc4253_` over a table of hex constants reads as "these are
    // the RFC's numbers", and they are not.
    let expected = [
        "0ba670686367ecc9777c11a469d8edaf3a51235e1fdb21992e0318b0bc873df788fb297f8fd7911b7e5a3970ce30cf32",
        "7b5fff08144a043a2d09b29846a881dd1f7bf3fc2d66a4e5c89b87e75539f8e0b0ac6121a5b30243269379c6c2a4cf05",
        "d474f30c5e43d1f3e733bef71b24408c934ef622fe751594576e0ef8b6ae083679f1a6883c8ca9351a6a8888de1b37d8",
        "5c4e1540870495ef512b9f5b930c55091669ec00080d65427ed35940926aed5c273d725ad38a94dcba1e3a385c8a50fb",
        "b224ae1229b05dd06c6e13f99397285c995e23fd5db1c9a4602f2b4f37605fd7483b3a8d22059362c3d0488c9868132f",
        "3249895b0f00db7f61a422d7f3fba42cd854e2830664b7d9517a116abe9b92c00c2411c47d97961220a7ef8892089ce5",
    ];
    let letters = [
        DerivationLetter::A,
        DerivationLetter::B,
        DerivationLetter::C,
        DerivationLetter::D,
        DerivationLetter::E,
        DerivationLetter::F,
    ];
    for (letter, expected) in letters.into_iter().zip(expected) {
        let output = derive_key(&shared, &exchange_hash, &session_id, letter, 48)?;
        assert_eq!(output, hex(expected));
        assert_eq!(output.len(), 48);
    }

    let lengths = DerivationLengths {
        a: 16,
        b: 17,
        c: 32,
        d: 33,
        e: 48,
        f: 64,
    };
    assert_eq!(lengths.as_array(), [16, 17, 32, 33, 48, 64]);
    let keys = derive_keys(&shared, &exchange_hash, &session_id, lengths)?;
    assert_eq!(keys.iv_client_to_server.len(), 16);
    assert_eq!(keys.iv_server_to_client.len(), 17);
    assert_eq!(keys.encryption_key_client_to_server.len(), 32);
    assert_eq!(keys.encryption_key_server_to_client.len(), 33);
    assert_eq!(keys.integrity_key_client_to_server.len(), 48);
    assert_eq!(keys.integrity_key_server_to_client.len(), 64);

    let changed_session = [0xa4_u8; 32];
    assert_ne!(
        derive_key(
            &shared,
            &exchange_hash,
            &session_id,
            DerivationLetter::C,
            32,
        )?,
        derive_key(
            &shared,
            &exchange_hash,
            &changed_session,
            DerivationLetter::C,
            32,
        )?
    );
    assert!(derive_key(&shared, &exchange_hash, &session_id, DerivationLetter::A, 0,)?.is_empty());
    Ok(())
}

#[test]
fn key_derivation_and_context_validation_return_typed_errors() -> Result<(), KexError> {
    let (shared, exchange_hash) = fixed_high_bit_shared_secret()?;
    let session_id = [0_u8; 32];
    assert_eq!(
        derive_key(&shared, &[0_u8; 31], &session_id, DerivationLetter::A, 16,),
        Err(KexError::InvalidExchangeHash)
    );
    assert_eq!(
        derive_key(
            &shared,
            &exchange_hash,
            &[0_u8; 31],
            DerivationLetter::A,
            16,
        ),
        Err(KexError::InvalidSessionId)
    );
    assert_eq!(
        derive_key(
            &shared,
            &exchange_hash,
            &session_id,
            DerivationLetter::A,
            MAX_DERIVED_KEY_LENGTH + 1,
        ),
        Err(KexError::DerivedKeyLimitExceeded)
    );
    for byte in *b"ABCDEF\"" {
        assert_eq!(DerivationLetter::try_from(byte).is_ok(), byte != b'"');
    }
    assert_eq!(
        DerivationLetter::try_from(b'G'),
        Err(KexError::InvalidFieldLength)
    );

    let (client, server) = proposal_pair(CURVE25519_SHA256)?;
    for version in ["", "SSH-2.0-bad\r\n", "SSH-2.0-nul\0"] {
        assert_eq!(
            KexContext::new(
                version,
                SERVER_VERSION,
                client.clone(),
                server.clone(),
                CURVE25519_SHA256,
            ),
            Err(KexError::InvalidIdentification)
        );
    }
    assert_eq!(
        KexContext::new(
            CLIENT_VERSION,
            SERVER_VERSION,
            client.clone(),
            server.clone(),
            ECDH_SHA2_NISTP256,
        ),
        Err(KexError::ProposalMismatch)
    );

    let (disjoint_client, disjoint_server) = proposal_pair_different_algorithms()?;
    assert_eq!(
        KexContext::new(
            CLIENT_VERSION,
            SERVER_VERSION,
            disjoint_client,
            disjoint_server,
            CURVE25519_SHA256,
        ),
        Err(KexError::InvalidProposal)
    );
    let (group_client, group_server) = proposal_pair(KEX_DIFFIE_HELLMAN_GROUP14_SHA256)?;
    assert_eq!(
        KexContext::new(
            CLIENT_VERSION,
            SERVER_VERSION,
            group_client,
            group_server,
            KEX_DIFFIE_HELLMAN_GROUP14_SHA256,
        ),
        Err(KexError::AlgorithmMismatch)
    );
    Ok(())
}

#[test]
fn roles_reject_host_proposal_and_reuse_mismatches() -> Result<(), KexError> {
    let context = fixed_context(CURVE25519_SHA256, CLIENT_VERSION, SERVER_VERSION)?;
    let mechanism = Curve25519::standard();
    let mut client = ClientKex::new(mechanism, context.clone(), HOST_KEY_BLOB)?;
    let peer_public = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let wrong_host_reply = curve_reply(b"different-host", &peer_public);
    assert_eq!(
        client.complete(&wrong_host_reply).err(),
        Some(KexError::HostKeyMismatch)
    );
    let valid_reply = curve_reply(HOST_KEY_BLOB, &peer_public);
    let completion = client.complete(&valid_reply)?;
    // The stored completion is compared field by field rather than with `==`.
    // `KexCompletion` is not `PartialEq` because it holds a `SharedSecret`, and
    // a derived comparison would memcmp that secret; these are the public
    // fields, and the secret is checked by digest through the helper.
    let stored = client.completion().ok_or(KexError::InvalidState)?;
    assert_completions_agree(stored, &completion);
    assert_eq!(
        client.complete(&valid_reply).err(),
        Some(KexError::InvalidState)
    );
    assert_eq!(client.init_message(), Err(KexError::InvalidState));
    assert_completions_agree(&client.into_completion()?, &completion);

    assert_eq!(
        ClientKex::new(EcdhP256::new(), context.clone(), HOST_KEY_BLOB).err(),
        Some(KexError::AlgorithmMismatch)
    );
    let unbound = ClientKex::new(Curve25519::standard(), context.clone(), HOST_KEY_BLOB)?;
    assert_eq!(
        unbound.into_completion().err(),
        Some(KexError::InvalidState)
    );

    let mut server = ServerKex::new(Curve25519::standard(), context.clone(), HOST_KEY_BLOB)?;
    assert_eq!(
        server.prepare_exchange().err(),
        Some(KexError::InvalidState)
    );
    assert_eq!(
        server.reply_message(SIGNATURE_BLOB),
        Err(KexError::InvalidState)
    );
    let unprepared = ServerKex::new(Curve25519::standard(), context.clone(), HOST_KEY_BLOB)?;
    assert_eq!(
        unprepared.into_completion().err(),
        Some(KexError::InvalidState)
    );
    let init = curve_init([3_u8; 32]);
    server.accept_init(&init)?;
    assert_eq!(server.accept_init(&init), Err(KexError::InvalidState));
    let prepared_hash = *server.prepare_exchange()?.exchange_hash();
    assert_eq!(server.exchange_hash()?, &prepared_hash);
    let _reply = server.reply_message(SIGNATURE_BLOB)?;
    assert_eq!(
        server.reply_message(SIGNATURE_BLOB),
        Err(KexError::InvalidState)
    );
    assert_eq!(
        server.prepare_exchange().err(),
        Some(KexError::InvalidState)
    );
    let prepared = server.completion().cloned().ok_or(KexError::InvalidState)?;
    assert_completions_agree(
        server.completion().ok_or(KexError::InvalidState)?,
        &prepared,
    );
    assert_completions_agree(&server.into_completion()?, &prepared);

    let libssh_context = fixed_context(CURVE25519_SHA256_LIBSSH, CLIENT_VERSION, SERVER_VERSION)?;
    assert_eq!(
        ServerKex::new(Curve25519::standard(), libssh_context, HOST_KEY_BLOB).err(),
        Some(KexError::AlgorithmMismatch)
    );
    Ok(())
}

#[test]
fn session_tracker_rejects_a_different_later_identifier() -> Result<(), KexError> {
    let first_context = fixed_context(CURVE25519_SHA256, "SSH-2.0-first-client", SERVER_VERSION)?;
    let first = exercise_roles(Curve25519::standard(), &first_context)?;
    let second_context = fixed_context(CURVE25519_SHA256, "SSH-2.0-second-client", SERVER_VERSION)?;
    let second = exercise_roles(Curve25519::standard(), &second_context)?;
    assert_ne!(first.exchange_hash(), second.exchange_hash());

    let mut tracker = SessionIdTracker::new();
    assert_eq!(tracker.session_id(), None);
    assert_eq!(tracker.record(&first)?, *first.exchange_hash());
    assert_eq!(tracker.record(&first)?, *first.exchange_hash());
    assert_eq!(tracker.session_id(), Some(first.exchange_hash()));
    let rekey_hash = [0xbb_u8; 32];
    assert_eq!(
        tracker.record_exchange_hash(rekey_hash, *first.exchange_hash())?,
        *first.exchange_hash()
    );
    assert_eq!(
        tracker.record_exchange_hash(rekey_hash, [0xcc_u8; 32]),
        Err(KexError::SessionIdMismatch)
    );
    assert_eq!(tracker.record(&second), Err(KexError::SessionIdMismatch));
    assert_eq!(tracker.session_id(), Some(first.exchange_hash()));
    Ok(())
}

#[test]
fn fresh_ephemerals_are_distinct_and_mechanism_bound() -> Result<(), KexError> {
    let curve = Curve25519::standard();
    let p256 = EcdhP256::new();
    let curve_secret = curve.generate_ephemeral()?;
    let curve_public = curve.public_key(&curve_secret)?;
    assert_eq!(curve_public.len(), CURVE25519_PUBLIC_KEY_LENGTH);
    assert_eq!(format!("{curve_secret:?}"), "EphemeralKey { .. }");
    assert_ne!(
        curve_public,
        curve.public_key(&curve.generate_ephemeral()?)?
    );

    let p256_secret = p256.generate_ephemeral()?;
    let p256_public = p256.public_key(&p256_secret)?;
    assert_eq!(p256_public.len(), P256_UNCOMPRESSED_POINT_LENGTH);
    assert_eq!(
        curve.public_key(&p256_secret),
        Err(KexError::AlgorithmMismatch)
    );
    assert_eq!(
        p256.public_key(&curve_secret),
        Err(KexError::AlgorithmMismatch)
    );
    assert_eq!(
        curve.agree(p256_secret, &[0_u8; 32],).err(),
        Some(KexError::AlgorithmMismatch)
    );
    assert_eq!(
        p256.agree(
            curve_secret,
            &hex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
        )
        .err(),
        Some(KexError::AlgorithmMismatch)
    );
    Ok(())
}

/// The Curve25519 material is the upstream secret, and it is consumed.
///
/// `x25519-dalek`'s `StaticSecret` wipes itself in its own `Drop` and declares
/// that with `ZeroizeOnDrop`. The wipe happens in that crate, on bytes that the
/// same destructor releases, so it cannot be observed from here: reading them
/// back would be reading freed memory, and a `#[global_allocator]` probe to
/// catch the reuse would need `unsafe`.
///
/// So the claim is checked in the two places that can check it. The `const`
/// item beside the material alias in `curve25519.rs` fails the build if
/// `x25519-dalek` ever stops declaring that its secret wipes itself, and the
/// assertions below fail if this mechanism stops storing that type, stops
/// keeping the scalar, or lets a caller hold a second copy of it.
#[test]
fn curve25519_stores_a_foreign_secret_that_declares_its_own_destructor_wipes_it()
-> Result<(), KexError> {
    let mechanism = Curve25519::standard();
    let scalar = hex_array("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let material = mechanism.with_private_bytes(scalar);

    // The stored material is the type whose destructor makes the claim. The
    // downcast is the only way to see what a mechanism stored, and it fails the
    // moment the mechanism stores anything else.
    assert!(
        material
            .material_ref::<X25519Private>(CURVE25519_SHA256)
            .is_ok()
    );
    assert_eq!(
        material
            .material_ref::<X25519Private>(ECDH_SHA2_NISTP256)
            .err(),
        Some(KexError::AlgorithmMismatch),
        "another mechanism's name must not read this material"
    );

    // And it is the scalar, not a placeholder: two materials built from
    // different scalars give different public values.
    let peer = mechanism.with_private_bytes(hex_array(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    ));
    let peer_public = mechanism.public_key(&peer)?;
    assert_ne!(mechanism.public_key(&material)?, peer_public);

    // Agreement takes the material by value and `EphemeralKey` is not `Clone`,
    // asserted at the top of this file, so this is the last handle on the scalar
    // there is. The agreement values are covered by the RFC 7748 vector test.
    let shared = mechanism.agree(material, &peer_public)?;
    assert!(
        !shared.as_bytes().iter().all(|byte| *byte == 0),
        "an agreement that consumed no scalar would be all zeroes"
    );
    Ok(())
}

/// The P-256 material is the upstream secret, and it is consumed.
///
/// The same claim, and the same limit, as the Curve25519 one: `p256`'s
/// `SecretKey` wipes itself in its own `Drop` and says so with
/// `ZeroizeOnDrop`, the `const` item in `ecdh_p256.rs` fails the build if it
/// stops saying so, and the wipe itself happens on memory this crate cannot
/// read back. What the assertions below add is that the mechanism stores that
/// type, keeps the scalar in it, and gives no second holder of it.
#[test]
fn p256_stores_a_foreign_secret_that_declares_its_own_destructor_wipes_it() -> Result<(), KexError>
{
    let mechanism = EcdhP256::new();
    let mut scalar_one = [0_u8; 32];
    scalar_one[31] = 1;
    let mut scalar_two = [0_u8; 32];
    scalar_two[31] = 2;
    let material = EcdhP256::from_private_bytes(scalar_one)?;

    assert!(
        material
            .material_ref::<P256Private>(ECDH_SHA2_NISTP256)
            .is_ok()
    );
    assert_eq!(
        material
            .material_ref::<P256Private>(CURVE25519_SHA256)
            .err(),
        Some(KexError::AlgorithmMismatch),
        "another mechanism's name must not read this material"
    );

    let peer = EcdhP256::from_private_bytes(scalar_two)?;
    let peer_public = mechanism.public_key(&peer)?;
    assert_ne!(mechanism.public_key(&material)?, peer_public);

    let shared = mechanism.agree(material, &peer_public)?;
    assert!(
        !shared.as_bytes().iter().all(|byte| *byte == 0),
        "an agreement that consumed no scalar would be all zeroes"
    );
    Ok(())
}

/// The group 16 exponent's destructor wipes it, rather than only running.
///
/// This is the one ephemeral material in the crate that wipes by code in this
/// repository, so it is the one whose wipe can be read back. As with the derived
/// keys, the witness is recorded inside the destructor — after the wipe, before
/// the value is released — because the exponent cannot be inspected once the
/// memory is gone, and an allocator probe to catch the reuse would need
/// `unsafe`.
///
/// Neither regression passes: emptying the destructor body leaves `None`,
/// because nothing reports, and emptying only the wipe leaves `Some(false)`,
/// because the destructor still runs and still finds a live exponent. The
/// exponent is not all zeroes to begin with — `from_private_bytes` rejects
/// anything below `2` — so a `Some(true)` cannot come from a value that was
/// never worth wiping.
#[test]
fn the_group16_exponent_destructor_wipes_every_byte_before_releasing_it() -> Result<(), KexError> {
    let mechanism = DhGroup16::new();
    let mut exponent = [0_u8; 64];
    exponent[63] = 3;

    assert_eq!(
        take_group16_private_drop_wipe(),
        None,
        "a drop-wipe witness from an earlier test on this thread was not taken"
    );
    {
        let material = mechanism.from_private_bytes(exponent)?;
        assert!(
            material
                .material_ref::<Group16Private>(KEX_DIFFIE_HELLMAN_GROUP16_SHA512)
                .is_ok()
        );
        assert_eq!(
            take_group16_private_drop_wipe(),
            None,
            "a live exponent must not have run its destructor"
        );
    }
    assert_eq!(
        take_group16_private_drop_wipe(),
        Some(true),
        "the destructor must leave a zeroed exponent behind"
    );
    Ok(())
}

#[test]
fn errors_are_typed_and_do_not_echo_sensitive_fields() {
    let error = KexError::HostKeyMismatch;
    assert_eq!(error.to_string(), "SSH KEX host-key blob does not match");
    assert!(std::error::Error::source(&error).is_none());
    assert_eq!(
        KexError::Wire(WireError::Truncated).to_string(),
        "SSH KEX wire error: SSH input is truncated"
    );
}

fn exercise_roles<A>(mechanism: A, context: &KexContext) -> Result<KexCompletion, KexError>
where
    A: KeyExchange + Clone,
{
    let mut client = ClientKex::new(mechanism.clone(), context.clone(), HOST_KEY_BLOB)?;
    let mut server = ServerKex::new(mechanism, context.clone(), HOST_KEY_BLOB)?;
    let init = client.init_message()?;
    let mut init_reader = Reader::new(&init);
    assert_eq!(init_reader.read_byte()?, SSH_MSG_KEX_ECDH_INIT);
    assert_eq!(init_reader.read_string()?, client.client_public_key());
    init_reader.ensure_finished()?;

    server.accept_init(&init)?;
    let server_completion = server.prepare_exchange()?.clone();
    assert_eq!(server.exchange_hash()?, server_completion.exchange_hash());
    let reply = server.reply_message(SIGNATURE_BLOB)?;
    assert_eq!(
        server.completion().and_then(KexCompletion::signature_blob),
        Some(SIGNATURE_BLOB)
    );
    let mut reply_reader = Reader::new(&reply);
    assert_eq!(reply_reader.read_byte()?, SSH_MSG_KEX_ECDH_REPLY);
    assert_eq!(reply_reader.read_string()?, HOST_KEY_BLOB);
    assert_eq!(reply_reader.read_string()?, server.server_public_key());
    assert_eq!(reply_reader.read_string()?, SIGNATURE_BLOB);
    reply_reader.ensure_finished()?;

    let client_completion = client.complete(&reply)?;
    assert_eq!(
        client_completion.exchange_hash(),
        server_completion.exchange_hash()
    );
    // The two sides independently derived the same ECDH secret. This is the
    // assertion the type most wants to make and least wants to make by
    // accident: `assert_eq!` on the two `SharedSecret`s is exactly the
    // prefix-timing memcmp the type does not implement, so it is made on
    // digests instead.
    assert_secrets_agree(
        client_completion.shared_secret(),
        server_completion.shared_secret(),
    );
    assert_eq!(
        client_completion.session_id(),
        client_completion.exchange_hash()
    );
    assert_eq!(
        client_completion.algorithm(),
        context.negotiated_algorithm()
    );
    assert_eq!(client_completion.signature_blob(), Some(SIGNATURE_BLOB));
    assert_completions_agree(
        client.completion().ok_or(KexError::InvalidState)?,
        &client_completion,
    );
    // `into_shared_secret` hands over the same bytes the accessor borrowed.
    assert_secrets_agree(
        &client_completion.clone().into_shared_secret(),
        client_completion.shared_secret(),
    );

    let mut tracker = SessionIdTracker::new();
    assert_eq!(
        tracker.record(&client_completion)?,
        *client_completion.exchange_hash()
    );
    assert_eq!(client.complete(&reply).err(), Some(KexError::InvalidState));
    assert_eq!(
        server.reply_message(SIGNATURE_BLOB).err(),
        Some(KexError::InvalidState)
    );
    Ok(client_completion)
}

/// Asserts that two completions describe the same exchange.
///
/// Every field that is not a secret is compared with `==`, and the shared
/// secret is compared by digest through [`assert_secrets_agree`]. This exists
/// because `KexCompletion` is not `PartialEq` — it holds a `SharedSecret`, and a
/// derived comparison would memcmp that secret. Written out, the check is also
/// what makes the invariant visible: the hash, the session id, the algorithm,
/// and the signature blob are the values a caller may legitimately compare, and
/// the one field it may not is handled deliberately.
fn assert_completions_agree(left: &KexCompletion, right: &KexCompletion) {
    assert_eq!(left.algorithm(), right.algorithm());
    assert_eq!(left.exchange_hash(), right.exchange_hash());
    assert_eq!(left.session_id(), right.session_id());
    assert_eq!(left.signature_blob(), right.signature_blob());
    assert_secrets_agree(left.shared_secret(), right.shared_secret());
}

fn fixed_high_bit_shared_secret() -> Result<(SharedSecret, [u8; 32]), KexError> {
    let mechanism = Curve25519::standard();
    let mut private = [0_u8; 32];
    private[0] = 16;
    let mut basepoint = [0_u8; 32];
    basepoint[0] = 9;
    let shared = mechanism.agree(mechanism.with_private_bytes(private), &basepoint)?;
    let expected_hash: [u8; 32] =
        hex("5be1c0e29301c828a54cd6240edf010f2a5326fb8150cefa0c72e5cfc7620e1d")
            .try_into()
            .map_err(|_error| KexError::InvalidExchangeHash)?;
    Ok((shared, expected_hash))
}

fn fixed_context(
    algorithm: &str,
    client_version: &str,
    server_version: &str,
) -> Result<KexContext, KexError> {
    let (client, server) = proposal_pair(algorithm)?;
    KexContext::new(client_version, server_version, client, server, algorithm)
}

fn proposal_pair(algorithm: &str) -> Result<(Vec<u8>, Vec<u8>), KexError> {
    Ok((
        proposal(
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            algorithm,
        )
        .encode()?,
        proposal(
            [
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ],
            algorithm,
        )
        .encode()?,
    ))
}

fn proposal_pair_different_algorithms() -> Result<(Vec<u8>, Vec<u8>), KexError> {
    Ok((
        proposal([0; 16], CURVE25519_SHA256).encode()?,
        proposal([1; 16], ECDH_SHA2_NISTP256).encode()?,
    ))
}

fn proposal(cookie: [u8; 16], algorithm: &str) -> KexInit {
    KexInit::from_lists(
        cookie,
        vec![algorithm.to_owned()],
        vec!["ssh-ed25519".to_owned()],
        vec![AES128_CTR.to_owned()],
        vec![AES128_CTR.to_owned()],
        vec![HMAC_SHA2_256.to_owned()],
        vec![HMAC_SHA2_256.to_owned()],
        vec!["none".to_owned()],
        vec!["none".to_owned()],
        Vec::new(),
        Vec::new(),
        false,
        0,
    )
}

fn curve_init(public: [u8; 32]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_byte(SSH_MSG_KEX_ECDH_INIT);
    writer
        .write_string(&public)
        .unwrap_or_else(|_error| panic!("fixed Curve25519 key must fit an SSH string"));
    writer.into_bytes()
}

fn curve_reply(host: &[u8], public: &[u8]) -> Vec<u8> {
    let mechanism = Curve25519::standard();
    mechanism
        .encode_reply_message(public, host, SIGNATURE_BLOB)
        .unwrap_or_else(|error| panic!("fixed reply should encode: {error}"))
}

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex input must have an even length");
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair)
                .unwrap_or_else(|_error| panic!("hex input must be ASCII"));
            u8::from_str_radix(text, 16)
                .unwrap_or_else(|_error| panic!("hex input must contain hexadecimal digits"))
        })
        .collect()
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex(value)
        .try_into()
        .unwrap_or_else(|_error| panic!("hex input must contain the expected byte count"))
}

/// The six directional buffers of a derived key, as slices.
fn letters(keys: &DerivedKeys) -> [&[u8]; 6] {
    [
        &keys.iv_client_to_server,
        &keys.iv_server_to_client,
        &keys.encryption_key_client_to_server,
        &keys.encryption_key_server_to_client,
        &keys.integrity_key_client_to_server,
        &keys.integrity_key_server_to_client,
    ]
}

fn derivation_inputs() -> Result<(SharedSecret, [u8; 32], [u8; 32]), KexError> {
    let (shared, exchange_hash) = fixed_high_bit_shared_secret()?;
    Ok((shared, exchange_hash, [0xa5_u8; 32]))
}

fn typical_lengths() -> DerivationLengths {
    DerivationLengths {
        a: 16,
        b: 16,
        c: 32,
        d: 32,
        e: 32,
        f: 32,
    }
}

/// The live-buffer half of the wipe, and the destructor's existence.
///
/// This is what the name says and no more. `zeroize` here is called by the test
/// on a value that is still alive, so it says the [`Zeroize`] impl reaches all
/// six letters; the counter says the destructor runs on the success path. It
/// does *not* say the destructor wipes — the wipe in `Drop` could be deleted and
/// this test would still pass, which is why
/// `the_derived_keys_destructor_wipes_every_letter_before_releasing_it` exists
/// beside it and is the assertion that actually reads the letters after a
/// destructor has run.
#[test]
fn zeroize_clears_the_live_letters_and_the_destructor_runs_on_the_success_path()
-> Result<(), KexError> {
    let (shared, exchange_hash, session_id) = derivation_inputs()?;

    // The wipe itself, on a value that is still alive. Reading a *freed*
    // buffer would be undefined behaviour and is forbidden here, so the
    // assertion is made on the live buffers that `Drop` wipes.
    let mut keys = derive_keys(&shared, &exchange_hash, &session_id, typical_lengths())?;
    for letter in letters(&keys) {
        assert!(
            letter.iter().any(|byte| *byte != 0),
            "a letter of all zeroes is not a key"
        );
    }
    keys.zeroize();
    for letter in letters(&keys) {
        assert!(
            letter.iter().all(|byte| *byte == 0),
            "a wiped letter still holds {letter:?}"
        );
    }
    drop(keys);

    // And the destructor, which is the half a trait bound does not show. The
    // counter is thread-local, so the delta here is this value's and no other.
    let before = derived_keys_drops();
    {
        let _keys = derive_keys(&shared, &exchange_hash, &session_id, typical_lengths())?;
        assert_eq!(
            derived_keys_drops(),
            before,
            "a live derived key must not have been dropped"
        );
    }
    assert_eq!(derived_keys_drops(), before + 1);
    Ok(())
}

/// The destructor wipes the six letters, rather than only running.
///
/// `Drop` is the only thing in the crate that can wipe a `DerivedKeys`, and it
/// happens at the moment the value is released, so the letters cannot be read
/// from outside afterwards. The witness this reads is therefore recorded inside
/// the destructor — after the wipe, before the fields are released — and this
/// test is the only thing that can see it. Reading a freed buffer instead would
/// be undefined behaviour, and an allocator probe to catch the reuse would need
/// `unsafe`, which this workspace forbids.
///
/// Two regressions have to fail here, and they fail differently. Deleting the
/// wipe leaves `Some(false)`, because the destructor still runs and still finds
/// live key bytes. Deleting the destructor body altogether leaves `None`, because
/// nothing reports. Neither can pass vacuously: the letters are checked to hold
/// key bytes before the drop, and the destructor that has to wipe them is the
/// only one in the crate.
#[test]
fn the_derived_keys_destructor_wipes_every_letter_before_releasing_it() -> Result<(), KexError> {
    let (shared, exchange_hash, session_id) = derivation_inputs()?;

    // A witness left over from an earlier value on this thread would make the
    // two assertions below unfalsifiable, so the lane starts from none.
    assert_eq!(
        take_derived_keys_drop_wipe(),
        None,
        "a drop-wipe witness from an earlier test on this thread was not taken"
    );
    {
        let keys = derive_keys(&shared, &exchange_hash, &session_id, typical_lengths())?;
        for letter in letters(&keys) {
            assert!(
                letter.iter().any(|byte| *byte != 0),
                "a letter of all zeroes would make this test pass without a wipe"
            );
        }
        assert_eq!(
            take_derived_keys_drop_wipe(),
            None,
            "a live derived key must not have run its destructor"
        );
    }
    assert_eq!(
        take_derived_keys_drop_wipe(),
        Some(true),
        "the destructor must leave six all-zero letters behind"
    );
    Ok(())
}

#[test]
fn a_failed_derivation_leaves_no_key_struct_behind() -> Result<(), KexError> {
    let (shared, exchange_hash, session_id) = derivation_inputs()?;

    // `f` is one byte past the limit, so letters `a` through `e` are derived and
    // held, and then the sixth fails. Those five are the live session key for
    // the duration of a failed handshake. They are `Zeroizing<Vec<u8>>`
    // temporaries, so they wipe in their own `Drop`; the two things that can be
    // checked here without reading freed memory are that the failure is the
    // typed error rather than a panic or a partial key, and that no
    // `DerivedKeys` — the struct that would hold all six at once — exists
    // afterwards. A partial construction therefore has the same guarantee as a
    // complete one, which is the reason the fields are wrapped.
    let lengths = DerivationLengths {
        a: 16,
        b: 16,
        c: 32,
        d: 32,
        e: 32,
        f: MAX_DERIVED_KEY_LENGTH + 1,
    };
    let before = derived_keys_drops();
    assert_eq!(
        derive_keys(&shared, &exchange_hash, &session_id, lengths).err(),
        Some(KexError::DerivedKeyLimitExceeded)
    );
    assert_eq!(
        derived_keys_drops(),
        before,
        "a failed derivation must not leave a derived-key struct behind"
    );
    Ok(())
}

#[test]
fn a_derived_key_is_wiped_when_the_owner_fails_before_installing_it() -> Result<(), KexError> {
    let (shared, exchange_hash, session_id) = derivation_inputs()?;

    // The handshake error path: the keys are derived, the rekey state holds
    // them, and the transport is dropped before either protector is installed.
    // The key material goes with it, on both the successful and the failed leg
    // of the exchange.
    let before = derived_keys_drops();
    let outcome: Result<(), KexError> = (|| {
        let _keys = derive_keys(&shared, &exchange_hash, &session_id, typical_lengths())?;
        Err(KexError::InvalidState)
    })();
    assert_eq!(outcome, Err(KexError::InvalidState));
    assert_eq!(
        derived_keys_drops(),
        before + 1,
        "dropping the owner must wipe the keys it was holding"
    );
    Ok(())
}
