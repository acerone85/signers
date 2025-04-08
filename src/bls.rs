use std::fmt::{self, Formatter};

use blst::{BLST_ERROR, min_pk};
use sha2::{Digest, Sha256, digest::Output};

use crate::crypto::{Address, AggregateSigner, KeyPair, Signer};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid secret key: {0:?}")]
    InvalidSecretKey(BLST_ERROR),
    #[error("Invalid public key: {0:?}")]
    InvalidPublicKey(BLST_ERROR),
    #[error("Signature aggregation failed: {0:?}")]
    SignatureAggregationFailed(BLST_ERROR),
    #[error("Invalid signature: {0:?}")]
    InvalidSignature(BLST_ERROR),
}

pub struct SecretKey(min_pk::SecretKey);
pub struct PublicKey(min_pk::PublicKey);
pub struct PublicKeyHash(Output<Sha256>);

impl SecretKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let sk = min_pk::SecretKey::from_bytes(bytes).map_err(Error::InvalidSecretKey)?;
        Ok(SecretKey(sk))
    }

    pub fn key_gen(ikm: &[u8; 32]) -> Result<Self, Error> {
        let sk = min_pk::SecretKey::key_gen(ikm, &[]).map_err(Error::InvalidSecretKey)?;
        Ok(SecretKey(sk))
    }
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8; 48]) -> Result<Self, Error> {
        let pk = min_pk::PublicKey::key_validate(bytes).map_err(Error::InvalidSecretKey)?;
        Ok(PublicKey(pk))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0.to_bytes()))
    }
}

impl fmt::Display for PublicKeyHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

pub const DST: &[u8] = &[
    66, 76, 83, 95, 83, 73, 71, 95, 66, 76, 83, 49, 50, 51, 56, 49, 71, 50, 95, 88, 77, 68, 58, 83,
    72, 65, 45, 50, 53, 54, 95, 83, 83, 87, 85, 95, 82, 79, 95, 80, 79, 80, 95,
];

pub struct Bls;

impl Bls {
    fn prepend_pkh(message: &[u8], pkh: &PublicKeyHash) -> Vec<u8> {
        let mut message_with_pkh = Vec::with_capacity(message.len() + pkh.0.len());
        message_with_pkh.extend_from_slice(message);
        message_with_pkh.extend_from_slice(&pkh.0);
        message_with_pkh
    }
}

impl KeyPair for Bls {
    type SecretKey = SecretKey;
    type PublicKey = PublicKey;

    fn to_public_key(secret_key: &Self::SecretKey) -> Self::PublicKey {
        PublicKey(secret_key.0.sk_to_pk())
    }
}

impl Address for Bls {
    type PublicKeyHash = PublicKeyHash;

    fn address(public_key: &Self::PublicKey) -> Self::PublicKeyHash {
        let mut hasher = Sha256::new();
        hasher.update(public_key.0.to_bytes());
        let hash = hasher.finalize();
        PublicKeyHash(hash)
    }
}

pub struct Signature(min_pk::Signature);

impl Signature {
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, Error> {
        let signature =
            min_pk::Signature::sig_validate(bytes, true).map_err(Error::InvalidPublicKey)?;
        Ok(Signature(signature))
    }
}

impl Signer for Bls {
    type Signature = Signature;

    fn sign(secret_key: &Self::SecretKey, message: &[u8]) -> Self::Signature {
        let pk_hash = Bls::to_public_key_hash(secret_key);
        let message = Bls::prepend_pkh(message, &pk_hash);

        Signature(secret_key.0.sign(&message, DST, &[]))
    }

    fn verify(public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> bool {
        let pk_hash = Bls::address(public_key);
        let message = Bls::prepend_pkh(message, &pk_hash);

        signature
            .0
            .verify(false, &message, DST, &[], &public_key.0, true)
            == BLST_ERROR::BLST_SUCCESS
    }
}

pub struct AggregateSignature(min_pk::AggregateSignature);

impl AggregateSignature {
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, Error> {
        let signature =
            min_pk::Signature::from_bytes(bytes).map_err(|e| Error::InvalidSignature(e))?;
        let aggregate_signature = min_pk::AggregateSignature::from_signature(&signature);
        Ok(AggregateSignature(aggregate_signature))
    }
}

impl AggregateSigner for Bls {
    type AggregateSignature = AggregateSignature;
    type Error = Error;

    fn aggregate_signatures(
        signatures: &[Self::Signature],
    ) -> Result<Self::AggregateSignature, Self::Error> {
        let signatures = signatures.iter().map(|s| &s.0).collect::<Vec<_>>();
        let aggregate_signature = min_pk::AggregateSignature::aggregate(&signatures, false)
            .map_err(Error::SignatureAggregationFailed)?;
        Ok(AggregateSignature(aggregate_signature))
    }

    fn verify_aggregate_signature(
        messages_with_pks: &[(impl AsRef<[u8]>, &Self::PublicKey)],
        aggregate_signature: &Self::AggregateSignature,
    ) -> bool {
        let (messages, public_keys): (Vec<_>, Vec<&min_pk::PublicKey>) = messages_with_pks
            .iter()
            .map(|(m, pk)| {
                let pk_hash = Bls::address(pk);
                let message = Bls::prepend_pkh(m.as_ref(), &pk_hash);
                (message, &pk.0)
            })
            .unzip();

        let messages = messages.iter().map(|m| m.as_slice()).collect::<Vec<_>>();

        aggregate_signature.0.to_signature().aggregate_verify(
            true,
            &messages,
            DST,
            public_keys.as_slice(),
            true,
        ) == BLST_ERROR::BLST_SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use ssz_derive::{Decode, Encode};

    use super::*;
    use crate::{
        crypto::{Signable, SignableExt, Signer},
        encode::Ssz,
    };

    #[test]
    fn test_sign_verify() {
        let ikm = [1u8; 32];
        let secret_key = SecretKey::key_gen(&ikm).unwrap();
        let public_key = Bls::to_public_key(&secret_key);
        let message = b"Hello, world!";
        let signature = Bls::sign(&secret_key, message);
        assert!(Bls::verify(&public_key, message, &signature));
    }

    #[test]
    fn test_sign_verify_wrong_message_fails() {
        let ikm = [1u8; 32];
        let secret_key = SecretKey::key_gen(&ikm).unwrap();
        let public_key = Bls::to_public_key(&secret_key);
        let message = b"Hello, world!";
        let wrong_message = b"Goodbye, world!";
        let signature = Bls::sign(&secret_key, wrong_message);
        assert!(!Bls::verify(&public_key, message, &signature));
    }

    #[test]
    fn test_sign_verify_wrong_signature_fails() {
        let ikm = [1u8; 32];
        let secret_key = SecretKey::key_gen(&ikm).unwrap();
        let public_key = Bls::to_public_key(&secret_key);
        let wrong_secret_key = SecretKey::key_gen(&[2u8; 32]).unwrap();

        let message = b"Hello, world!";
        let wrong_signature = Bls::sign(&wrong_secret_key, message);
        assert!(!Bls::verify(&public_key, message, &wrong_signature));
    }

    #[test]
    fn test_aggregate_signatures() {
        let ikm1 = [1u8; 32];
        let ikm2 = [2u8; 32];
        let secret_key1 = SecretKey::key_gen(&ikm1).unwrap();
        let secret_key2 = SecretKey::key_gen(&ikm2).unwrap();
        let public_key1 = Bls::to_public_key(&secret_key1);
        let public_key2 = Bls::to_public_key(&secret_key2);
        let message = b"Hello, world!";
        let signature1 = Bls::sign(&secret_key1, message);
        let signature2 = Bls::sign(&secret_key2, message);

        let aggregate_signature = Bls::aggregate_signatures(&[signature1, signature2]).unwrap();
        assert!(Bls::verify_aggregate_signature(
            &[(message, &public_key1), (message, &public_key2)],
            &aggregate_signature
        ));
    }

    #[test]
    fn test_aggregate_signatures_swap_pks_fails() {
        let ikm1 = [1u8; 32];
        let ikm2 = [2u8; 32];
        let secret_key1 = SecretKey::key_gen(&ikm1).unwrap();
        let secret_key2 = SecretKey::key_gen(&ikm2).unwrap();
        let public_key1 = Bls::to_public_key(&secret_key1);
        let public_key2 = Bls::to_public_key(&secret_key2);
        let message1 = b"Hello, world!";
        let message2 = b"Goodbye, world!";
        let signature1 = Bls::sign(&secret_key1, message1);
        let signature2 = Bls::sign(&secret_key2, message2);

        let aggregate_signature = Bls::aggregate_signatures(&[signature1, signature2]).unwrap();
        assert!(!Bls::verify_aggregate_signature(
            &[
                (message1.as_slice(), &public_key2),
                (message2.as_slice(), &public_key1)
            ],
            &aggregate_signature
        ));
    }

    #[derive(Encode, Decode)]
    struct TestSignable {
        message: Vec<u8>,
        sender: u64,
    }

    impl From<&[u8]> for TestSignable {
        fn from(message: &[u8]) -> Self {
            TestSignable {
                message: message.to_vec(),
                sender: 0,
            }
        }
    }

    impl Signable for TestSignable {}

    #[test]
    fn verify_signable() {
        let ikm = [1u8; 32];
        let secret_key = SecretKey::key_gen(&ikm).unwrap();
        let public_key = Bls::to_public_key(&secret_key);
        let message = b"Hello, world!";
        let signable = TestSignable::from(message.as_slice());
        let signature = signable.sign::<Bls, Ssz>(&secret_key);
        assert!(signable.verify::<Bls, Ssz>(&public_key, &signature));
    }
}
