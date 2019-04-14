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

use rand::OsRng;

/// Digest type for sodiumoxide-based implementation.
pub use keccak_hash::H256 as Hash;

/// Seed type for sodiumoxide-based implementation.

use self::secp256k1::{Secp256k1, Signature, Message, SecretKey, PublicKey};

pub struct Seed([u8; 64])

/// Number of bytes in a `Hash`.
pub const HASH_SIZE: usize = 32;

/// Number of bytes in a public key.
pub const PUBLIC_KEY_LENGTH: usize = 65;

/// Number of bytes in a secret key.
pub const SECRET_KEY_LENGTH: usize = 32;

/// Number of bytes in a signature.
pub const SIGNATURE_LENGTH: usize = 64;

/// Hash of an empty slice.
pub const EMPTY_SLICE_HASH: Hash = Hash([
    227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228,
    100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
]);

/// Initializes the sodium library and automatically selects faster versions
/// of the primitives, if possible.
pub fn init() -> bool {
    sodiumoxide::init()
}

/// Signs a slice of bytes using the signer's secret key and returns the
/// resulting `Signature`.
pub fn sign(data: &[u8], secret_key: &SecretKey) -> Signature {
    let context = Secp256k1::signing_only();
    let message = Message::from_slice(data).unwrap();
    context.sign(message, secret_key)
}

/// Computes a secret key and a corresponding public key from a `Seed`.
pub fn gen_keypair_from_seed(seed: &Seed) -> (PublicKey, SecretKey) {
    gen_keypair()
}

/// Generates a secret key and a corresponding public key using a cryptographically secure
/// pseudo-random number generator.
pub fn gen_keypair() -> (PublicKey, SecretKey) {
    let context = Secp256k1::new();
    let mut rng = OsRng::new().unwrap();
    let (secret_key, public_key) = context.generate_keypair(&mut rng);
    (public_key, secret_key)
}

/// Verifies that `data` is signed with a secret key corresponding to the
/// given public key.
pub fn verify(sig: &Signature, data: &[u8], pub_key: &PublicKey) -> bool {
    let context = Secp256k1::new();
    let message = Message.from_slice(data).unwrap();
    context.verify(&message, sig, pub_key).is_ok()
}

/// Calculates hash of a bytes slice.
pub fn hash(data: &[u8]) -> Hash {
    let mut output = &[];
    keccak_hash::keccak_256(data, &mut output);
    H256::from_slice(output)
}
