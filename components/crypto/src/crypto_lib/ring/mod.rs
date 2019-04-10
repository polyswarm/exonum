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

/// Public key type for ring-based implementation.
pub use self::digest::Digest as Hash;

/// Public key type for ring-based implementation.
pub use self::signature::Signature;

/// Public key type for ring-based implementation.
pub use self::signature::EcdsaKeyPair as SecretKey;

/// Public key type for ring-based implementation.
pub use self::ec::suite_b::ecdsa::signing::PublicKey;

/// Seed type for sodiumoxide-based implementation.
pub use self::ed25519::Seed;

/// State for multi-part (streaming) computation of signature for sodiumoxide-based
/// implementation.
pub use self::ed25519::State as SignState;

/// Contains the state for multi-part (streaming) hash computations
/// for sodiumoxide-based implementation.
pub use self::sha256::State as HashState;

use self::ring::{digest, signature, ec, error};

use failure::Error;

/// Number of bytes in a `Hash`.
pub const HASH_SIZE: usize = digest::SHA256_OUTPUT_LEN;

/// Number of bytes in a public key.
pub const PUBLIC_KEY_LENGTH: usize = 65;

/// Number of bytes in a secret key.
pub const SECRET_KEY_LENGTH: usize = 65;

/// Number of bytes in a seed.
pub const SEED_LENGTH: usize = ed25519::SEEDBYTES;

/// Number of bytes in a signature.
pub const SIGNATURE_LENGTH: usize = digest::SHA256_OUTPUT_LEN;

/// Hash of an empty slice.
pub const EMPTY_SLICE_HASH: Hash = Hash::from([
    227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228,
    100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
]);

/// Empty spot for initing ring.
pub fn init() -> bool {

}

/// Signs a slice of bytes using the signer's secret key and returns the
/// resulting `Signature`.
pub fn sign(data: &[u8], secret_key: &SecretKey) -> Signature {
    let rng = rand::SystemRandom::new();
    let mut signature = vec![0; secret_key.public_modulus_len()];
    secret_key.sign(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng, data, &mut signature).unwrap()
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
    let pkcs8 = SecretKey::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED, &rng).unwrap();
    let keypair = SecretKey::from_pcks8(&signature::ECDSA_P256_SHA256_FIXED, pkcs8);
    (keypair.public_key().clone(), keypair)
}

/// Verifies that `data` is signed with a secret key corresponding to the
/// given public key.
pub fn verify(sig: &Signature, data: &[u8], pub_key: &PublicKey) -> bool {
    signature::verify(&signature::ECDSA_P256_SHA256_FIXED, pub_key, data, sig)
}

/// Calculates hash of a bytes slice.
pub fn hash(data: &[u8]) -> Hash {
    digest::digest(&digest::SHA_256, data)
}
