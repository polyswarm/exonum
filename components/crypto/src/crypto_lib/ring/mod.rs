// Copyright 2019 The Exonum Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This module implements cryptographic backend based
//! on [Sodium library](https://github.com/jedisct1/libsodium)
//! through [sodiumoxide rust bindings](https://github.com/dnaq/sodiumoxide).
//! The constants in this module are imported from Sodium.
//!
//! The SHA-256 function applied in this backend splits the input data into blocks
//! and runs each block through a cycle of 64 iterations. The result of the
//! function is a cryptographic hash 256 bits or 32 bytes in length. This
//! hash can later be used to verify the integrity of data without accessing the
//! data itself.
//!
//! This backend also makes use of Ed25519 keys. Ed25519 is a signature system that ensures
//! fast signing and key generation, as well as security and collision
//! resilience.

// spell-checker:ignore DIGESTBYTES, PUBLICKEYBYTES, SECRETKEYBYTES, SEEDBYTES, SIGNATUREBYTES

use ring;

use untrusted::Input;

pub use self::digest::Digest;

pub use self::signature::Signature as RingSignature;

pub use self::signature::EcdsaKeyPair;

#[macro_use]
pub mod macros;

/// Seed type for not used in ring-base implementation.
new_wrapper!(Seed; SEED_LENGTH);

/// Public key type for ring-based implementation.
new_wrapper!(PublicKey; PUBLIC_KEY_LENGTH);

/// Secret key type for ring-based implementation.
new_wrapper!(SecretKey; SECRET_KEY_LENGTH);

/// Signature type for ring-based implementation.
new_wrapper!(Signature; SIGNATURE_LENGTH);

/// Hash Digest type for ring-based implementation.
new_wrapper!(Hash; SIGNATURE_LENGTH);

/// Contains the state for multi-part (streaming) hash computations
/// for sodiumoxide-based implementation.
pub use self::digest::Context as HashState;

use self::ring::{digest, signature, rand};

/// Number of bytes in a `Hash`.
pub const HASH_SIZE: usize = digest::SHA256_OUTPUT_LEN;

/// Number of bytes in a public key.
pub const PUBLIC_KEY_LENGTH: usize = 65;

/// Number of bytes in a secret key.
pub const SECRET_KEY_LENGTH: usize = 65;

/// Number of bytes in a seed.
pub const SEED_LENGTH: usize = 32;

/// Number of bytes in a signature.
pub const SIGNATURE_LENGTH: usize = digest::SHA256_OUTPUT_LEN;

/// Hash of an empty slice.
pub const EMPTY_SLICE_HASH: Hash = Hash([
    227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228,
    100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
]);

/// Empty spot for initing ring.
pub fn init() -> bool {
    true
}

/// Signs a slice of bytes using the signer's secret key and returns the
/// resulting `Signature`.
pub fn sign(data: &[u8], secret_key: &SecretKey) -> Signature {
    let rng = rand::SystemRandom::new();
    let keypair = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, Input::from(secret_key.as_ref())).unwrap()
    Signature::from_slice(keypair.sign(&rng, Input::from(data)).as_ref()).unwrap()
}

/// Computes a secret key and a corresponding public key from a `Seed`.
/// Ecdsa doesn't take a seed. So this is useless. Just generates a key.
pub fn gen_keypair_from_seed(seed: &Seed) -> (PublicKey, SecretKey) {
    gen_keypair()
}

/// Generates a secret key and a corresponding public key using a cryptographically secure
/// pseudo-random number generator.
pub fn gen_keypair() -> (PublicKey, SecretKey) {
    let rng = rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let keypair = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, Input::from(pkcs8.as_ref())).unwrap();
    (PublicKey::from_slice(signature::KeyPair::public_key(&keypair).as_ref()).unwrap(), SecretKey::from_slice(keypair.as_ref()).unwrap())
}

/// Verifies that `data` is signed with a secret key corresponding to the
/// given public key.
pub fn verify(sig: &Signature, data: &[u8], pub_key: &PublicKey) -> bool {
    match signature::verify(&signature::ECDSA_P256_SHA256_FIXED, Input::from(pub_key.as_ref()), Input::from(data), Input::from(sig.as_ref())) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Calculates hash of a bytes slice.
pub fn hash(data: &[u8]) -> Hash {
    Hash::from_slice(digest::digest(&digest::SHA256, data).as_ref()).unwrap()
}

