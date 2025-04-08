use ed25519_dalek::Verifier;
use ed25519_dalek::ed25519::signature::Signer;
use sha2::{Digest, digest::Output};

use crate::crypto::{self, Address, KeyPair};

pub struct SecretKey(ed25519_dalek::SigningKey);
pub struct PublicKey(ed25519_dalek::VerifyingKey);

pub struct PublicKeyHash(pub Output<sha2::Sha256>);

pub struct Ed25519;

impl KeyPair for Ed25519 {
    type SecretKey = SecretKey;
    type PublicKey = PublicKey;

    fn to_public_key(secret_key: &Self::SecretKey) -> Self::PublicKey {
        PublicKey(secret_key.0.verifying_key())
    }
}

impl Address for Ed25519 {
    type PublicKeyHash = PublicKeyHash;

    fn address(public_key: &Self::PublicKey) -> Self::PublicKeyHash {
        let mut hasher = sha2::Sha256::new();
        hasher.update(public_key.0.to_bytes());
        let hash = hasher.finalize();
        PublicKeyHash(hash)
    }

    fn to_public_key_hash(secret_key: &Self::SecretKey) -> Self::PublicKeyHash {
        let public_key = Self::to_public_key(secret_key);
        Self::address(&public_key)
    }
}

pub struct Signature(ed25519_dalek::Signature);

impl crypto::Signer for Ed25519 {
    type Signature = Signature;
    type Error = std::convert::Infallible;

    fn sign(secret_key: &Self::SecretKey, message: &[u8]) -> Result<Self::Signature, Self::Error> {
        Ok(Signature(secret_key.0.sign(message)))
    }

    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, Self::Error> {
        Ok(public_key.0.verify(message, &signature.0).is_ok())
    }
}
