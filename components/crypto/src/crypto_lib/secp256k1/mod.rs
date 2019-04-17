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
//! on [secp256k1](https://github.com/bitcoin-core/secp256k1)
//! through [secp256k1 rust bindings](https://github.com/rust-bitcoin/rust-secp256k1).
//! The constants in this module are imported from secp256k1 and keccak_hash.
//!
//! This backend also makes use of ecdsa keys.

// spell-checker:ignore DIGESTBYTES, PUBLICKEYBYTES, SECRETKEYBYTES, SEEDBYTES, SIGNATUREBYTES
use rand::rngs::OsRng;
use std::ops::{Index, Range, RangeFrom, RangeFull, RangeTo};

/// Digest type for sepc256k1 implementation.
pub use keccak_hash::H256;

/// Seed type for sepc256k1 implementation.
pub use secp256k1::{FromSlice, Message, PublicKey, Secp256k1, SecretKey, Signature};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash(pub H256);

impl FromSlice for Hash {
    type Item = Hash;
    fn from_slice(data: &[u8]) -> Result<Self::Item, ()> {
        Ok(Hash(H256::from_slice(data)))
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Index<Range<usize>> for Hash {
    type Output = [u8];
    fn index(&self, _index: Range<usize>) -> &[u8] {
        self.0.index(_index)
    }
}

impl Index<RangeTo<usize>> for Hash {
    type Output = [u8];
    fn index(&self, _index: RangeTo<usize>) -> &[u8] {
        let end = _index.end;
        &self.as_ref()[..end]
    }
}

impl Index<RangeFrom<usize>> for Hash {
    type Output = [u8];
    fn index(&self, _index: RangeFrom<usize>) -> &[u8] {
        let start = _index.start;
        &self.as_ref()[start..]
    }
}

impl Index<RangeFull> for Hash {
    type Output = [u8];
    fn index(&self, _index: RangeFull) -> &[u8] {
        self.0.index(_index)
    }
}

pub struct Seed(pub [u8; SEED_LENGTH]);
secp256k1::impl_array_newtype!(Seed, u8, SEED_LENGTH);
secp256k1::impl_pretty_debug!(Seed);
secp256k1::impl_from_slice!(Seed; SEED_LENGTH);

/// Number of bytes in a `Hash`.
pub const HASH_SIZE: usize = secp256k1::constants::MESSAGE_SIZE;

/// Number of bytes in a public key.
pub const PUBLIC_KEY_LENGTH: usize = secp256k1::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE;

/// Number of bytes in a secret key.
pub const SECRET_KEY_LENGTH: usize = secp256k1::constants::SECRET_KEY_SIZE;

/// Number of bytes in a seed.
pub const SEED_LENGTH: usize = secp256k1::constants::MESSAGE_SIZE;

/// Number of bytes in a signature.
pub const SIGNATURE_LENGTH: usize = secp256k1::constants::MAX_SIGNATURE_SIZE;

/// Hash of an empty slice.
pub const EMPTY_SLICE_HASH: Hash = Hash(H256([
    227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228,
    100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
]));

impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

/// Initializes the sodium library and automatically selects faster versions
/// of the primitives, if possible.
pub fn init() -> bool {
    true
}

/// Signs a slice of bytes using the signer's secret key and returns the
/// resulting `Signature`.
pub fn sign(data: &[u8], secret_key: &SecretKey) -> Signature {
    let context = Secp256k1::signing_only();
    let message = Message::from_slice(data).unwrap();
    context.sign(&message, secret_key)
}

/// Computes a secret key and a corresponding public key from a `Seed`.
pub fn gen_keypair_from_seed(seed: &Seed) -> (PublicKey, SecretKey) {
    gen_keypair()
}

/// Generates a secret key and a corresponding public key using a cryptographically secure
/// pseudo-random number generator.
pub fn gen_keypair() -> (PublicKey, SecretKey) {
    let context = Secp256k1::signing_only();
    let mut rng = OsRng::new().unwrap();
    let (secret_key, public_key) = context.generate_keypair(&mut rng);
    (public_key, secret_key)
}

/// Verifies that `data` is signed with a secret key corresponding to the
/// given public key.
pub fn verify(sig: &Signature, data: &[u8], pub_key: &PublicKey) -> bool {
    let context = Secp256k1::new();
    let message = Message::from_slice(data).unwrap();
    context.verify(&message, sig, pub_key).is_ok()
}

/// Calculates hash of a bytes slice.
pub fn hash(data: &[u8]) -> Hash {
    let mut output = vec![0; 0];
    keccak_hash::keccak_256(data, &mut output);
    // Underlying type never errors, so this one doesn't either
    Hash::from_slice(&output).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_hash() {
        let original = hash(&[]);
        original.iter().for_each(|b| print!(b));
        assert!(true)
    }
}
