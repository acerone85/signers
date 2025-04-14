use std::{
    borrow::Cow,
    fmt::{self, Formatter},
};

use blst::{BLST_ERROR, min_pk};
use sha2::{Digest, Sha256, digest::Output};
use ssz_derive::{Decode, Encode};

use crate::crypto::{Address, AggregateSigner, KeyPair, Signer, SignerBuf};

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
    #[error("Message does not fit in buffer: expected {expected}, actual {actual}")]
    MessageTooLong { expected: usize, actual: usize },
}

#[derive(Clone)]
pub struct SecretKey(min_pk::SecretKey);

#[derive(Clone, Copy)]
pub struct PublicKey(min_pk::PublicKey);

#[derive(Clone, Copy)]
pub struct PublicKeyHash(Output<Sha256>);

impl SecretKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let sk = min_pk::SecretKey::from_bytes(bytes).map_err(Error::InvalidSecretKey)?;
        Ok(SecretKey(sk))
    }

    pub fn key_gen(ikm: &[u8; 32], key_info: &[u8]) -> Result<Self, Error> {
        let sk = min_pk::SecretKey::key_gen(ikm, key_info).map_err(Error::InvalidSecretKey)?;
        Ok(SecretKey(sk))
    }

    pub fn to_public_key(&self) -> PublicKey {
        PublicKey(self.0.sk_to_pk())
    }
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8; 48]) -> Result<Self, Error> {
        let pk = min_pk::PublicKey::key_validate(bytes).map_err(Error::InvalidSecretKey)?;
        Ok(PublicKey(pk))
    }

    fn address(&self) -> PublicKeyHash {
        let mut hasher = Sha256::new();
        hasher.update(self.0.to_bytes());
        let hash = hasher.finalize();
        PublicKeyHash(hash)
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

#[derive(Clone)]

pub struct SecretWallet {
    secret_key: SecretKey,
    public_key: PublicKey,
    public_key_hash: PublicKeyHash,
}

impl From<SecretKey> for SecretWallet {
    fn from(secret_key: SecretKey) -> Self {
        let public_key = secret_key.to_public_key();
        let public_key_hash = public_key.address();

        SecretWallet {
            secret_key,
            public_key,
            public_key_hash,
        }
    }
}

#[derive(Clone)]
pub struct PublicWallet {
    public_key: PublicKey,
    public_key_hash: PublicKeyHash,
}

impl From<PublicKey> for PublicWallet {
    fn from(public_key: PublicKey) -> Self {
        let public_key_hash = public_key.address();

        PublicWallet {
            public_key,
            public_key_hash,
        }
    }
}

pub const DST: &[u8] = &[
    66, 76, 83, 95, 83, 73, 71, 95, 66, 76, 83, 49, 50, 51, 56, 49, 71, 50, 95, 88, 77, 68, 58, 83,
    72, 65, 45, 50, 53, 54, 95, 83, 83, 87, 85, 95, 82, 79, 95, 80, 79, 80, 95,
];

pub struct Bls;

impl Bls {
    fn prepend_pkh_no_alloc(
        message: &[u8],
        pkh: &PublicKeyHash,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        let pkh_len = pkh.0.len();
        let message_len = message.len();
        if buf.len() < pkh_len + message_len {
            return Err(Error::MessageTooLong {
                expected: pkh_len + message_len,
                actual: buf.len(),
            });
        }
        buf[0..pkh_len].copy_from_slice(&pkh.0);
        buf[pkh_len..pkh_len + message_len].copy_from_slice(message);
        Ok(pkh_len + message_len)
    }

    fn prepend_pkh_owned(message: &[u8], pkh: &PublicKeyHash) -> Vec<u8> {
        let mut buf = vec![0u8; pkh.0.len() + message.len()];
        buf[0..pkh.0.len()].copy_from_slice(&pkh.0);
        buf[pkh.0.len()..].copy_from_slice(message);
        buf
    }
}

impl KeyPair for Bls {
    type SecretKey = SecretWallet;
    type PublicKey = PublicWallet;

    fn to_public_key(secret_wallet: &SecretWallet) -> PublicWallet {
        PublicWallet {
            public_key: secret_wallet.public_key.clone(),
            public_key_hash: secret_wallet.public_key_hash.clone(),
        }
    }
}

impl Address for Bls {
    type PublicKeyHash = PublicKeyHash;

    fn address(public_wallet: &PublicWallet) -> PublicKeyHash {
        public_wallet.public_key_hash
    }
}

pub const SIGNATURE_BYTES: usize = 96;

pub struct Signature(min_pk::Signature);

impl Signature {
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, Error> {
        let signature = min_pk::Signature::from_bytes(bytes).map_err(Error::InvalidPublicKey)?;
        Ok(Signature(signature))
    }
}

impl ssz::Encode for Signature {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        SIGNATURE_BYTES
    }

    fn ssz_bytes_len(&self) -> usize {
        SIGNATURE_BYTES
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let mut encoder = ssz::SszEncoder::container(buf, SIGNATURE_BYTES);
        encoder.append(&self.0.to_bytes());
        encoder.finalize();
    }
}

impl ssz::Decode for Signature {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        SIGNATURE_BYTES
    }

    fn from_ssz_bytes(bytes: &[u8]) -> std::result::Result<Self, ssz::DecodeError> {
        if bytes.len() != SIGNATURE_BYTES {
            return Err(ssz::DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: SIGNATURE_BYTES,
            });
        }
        let signature = min_pk::Signature::from_bytes(bytes)
            .map_err(|e| ssz::DecodeError::BytesInvalid(format! {"{e:?}"}))?;
        Ok(Self(signature))
    }
}

impl Signer for Bls {
    type Signature = Signature;
    type Error = Error;

    fn sign(wallet: &Self::SecretKey, message: &[u8]) -> Result<Self::Signature, Error> {
        let pk_hash = wallet.public_key_hash;
        let message = Bls::prepend_pkh_owned(message, &pk_hash);
        Ok(Signature(wallet.secret_key.0.sign(&message, DST, &[])))
    }

    fn verify(
        wallet: &PublicWallet,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, Error> {
        let pk_hash = wallet.public_key_hash;
        let message = Bls::prepend_pkh_owned(message, &pk_hash);

        Ok(signature
            .0
            .verify(true, &message, DST, &[], &wallet.public_key.0, false)
            == BLST_ERROR::BLST_SUCCESS)
    }
}

impl SignerBuf for Bls {
    fn sign_no_alloc(
        wallet: &SecretWallet,
        message: &[u8],
        buf: &mut [u8],
    ) -> Result<Self::Signature, Error> {
        let pk_hash = wallet.public_key_hash;
        let len = Bls::prepend_pkh_no_alloc(message, &pk_hash, buf)?;
        Ok(Signature(wallet.secret_key.0.sign(&buf[0..len], DST, &[])))
    }

    fn verify_no_alloc(
        wallet: &PublicWallet,
        message: &[u8],
        signature: &Self::Signature,
        buf: &mut [u8],
    ) -> Result<bool, Error> {
        let pk_hash = wallet.public_key_hash;
        let len = Bls::prepend_pkh_no_alloc(message, &pk_hash, buf)?;

        Ok(signature.0.verify(
            true,
            &buf[0..len],
            DST,
            &[],
            &wallet.public_key.0,
            // The only way to create a public key is either by converting a
            // secret key or by using the `PublicKey::from_bytes` method, which
            // also validates the public key.
            false,
        ) == BLST_ERROR::BLST_SUCCESS)
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

impl ssz::Encode for AggregateSignature {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        SIGNATURE_BYTES
    }

    fn ssz_bytes_len(&self) -> usize {
        SIGNATURE_BYTES
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let mut encoder = ssz::SszEncoder::container(buf, SIGNATURE_BYTES);
        encoder.append(&self.0.to_signature().to_bytes());
        encoder.finalize();
    }
}

impl ssz::Decode for AggregateSignature {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        SIGNATURE_BYTES
    }

    fn from_ssz_bytes(bytes: &[u8]) -> std::result::Result<Self, ssz::DecodeError> {
        if bytes.len() != SIGNATURE_BYTES {
            return Err(ssz::DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: SIGNATURE_BYTES,
            });
        }
        let signature = min_pk::Signature::from_bytes(bytes)
            .map_err(|e| ssz::DecodeError::BytesInvalid(format! {"{e:?}"}))?;
        Ok(Self(min_pk::AggregateSignature::from_signature(&signature)))
    }
}

impl AggregateSigner for Bls {
    type AggregateSignature = AggregateSignature;

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
                let pk_hash = pk.public_key_hash;
                let message = Bls::prepend_pkh_owned(m.as_ref(), &pk_hash);
                (message, &pk.public_key.0)
            })
            .unzip();

        // We need to allocate a new vector to hold the references, as this is required by the signature of
        // `blst::aggregate_verify`.
        let messages = messages.iter().map(|m| m.as_ref()).collect::<Vec<_>>();

        aggregate_signature.0.to_signature().aggregate_verify(
            true,
            &messages,
            DST,
            public_keys.as_slice(),
            // The only way to create a public key is either by converting a
            // secret key or by using the `PublicKey::from_bytes` method, which
            // also validates the public key.
            false,
        ) == BLST_ERROR::BLST_SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use ssz_derive::{Decode, Encode};

    use super::*;
    use crate::{crypto::Signable, encode::Ssz};

    #[test]
    fn test_sign_verify() {
        // 45 bytes are enough for the public key hash and the message
        let mut buf = [0u8; 45];
        let ikm = [1u8; 32];
        let secret_key = SecretKey::key_gen(&ikm, &[]).unwrap().into();
        let public_key = Bls::to_public_key(&secret_key);
        let message = b"Hello, world!";

        let signature = Bls::sign_no_alloc(&secret_key, message, &mut buf).unwrap();
        assert!(Bls::verify_no_alloc(&public_key, message, &signature, &mut buf).unwrap());
    }

    #[test]
    fn test_sign_fails_message_too_long() {
        // 30 bytes are not enough for the public key hash and the message
        let mut buf = [0u8; 30];
        let ikm = [1u8; 32];
        let secret_key = SecretKey::key_gen(&ikm, &[]).unwrap().into();
        let message = b"Hello, world!";

        let signature = Bls::sign_no_alloc(&secret_key, message, &mut buf);
        assert!(matches!(signature, Err(Error::MessageTooLong { .. })));
    }

    #[test]
    fn test_sign_verify_wrong_message_fails() {
        let mut buf = [0u8; 47];

        let ikm = [1u8; 32];
        let secret_key = SecretKey::key_gen(&ikm, &[]).unwrap().into();
        let public_key = Bls::to_public_key(&secret_key);
        let message = b"Hello, world!";
        let wrong_message = b"Goodbye, world!";
        let signature = Bls::sign_no_alloc(&secret_key, wrong_message, &mut buf).unwrap();
        assert!(!Bls::verify_no_alloc(&public_key, message, &signature, &mut buf).unwrap());
    }

    #[test]
    fn test_sign_verify_wrong_signature_fails() {
        let mut buf = [0u8; 45];
        let ikm = [1u8; 32];
        let secret_key = SecretKey::key_gen(&ikm, &[]).unwrap().into();
        let public_key = Bls::to_public_key(&secret_key);
        let wrong_secret_key = SecretKey::key_gen(&[2u8; 32], &[]).unwrap().into();

        let message = b"Hello, world!";
        let wrong_signature = Bls::sign_no_alloc(&wrong_secret_key, message, &mut buf).unwrap();
        assert!(!Bls::verify_no_alloc(&public_key, message, &wrong_signature, &mut buf).unwrap());
    }

    #[test]
    fn test_aggregate_signatures() {
        let mut buf = [0u8; 45];
        let ikm1 = [1u8; 32];
        let ikm2 = [2u8; 32];
        let secret_key1 = SecretKey::key_gen(&ikm1, &[]).unwrap().into();
        let secret_key2 = SecretKey::key_gen(&ikm2, &[]).unwrap().into();
        let public_key1 = Bls::to_public_key(&secret_key1);
        let public_key2 = Bls::to_public_key(&secret_key2);
        let message = b"Hello, world!";
        let signature1 = Bls::sign_no_alloc(&secret_key1, message, &mut buf).unwrap();
        let signature2 = Bls::sign_no_alloc(&secret_key2, message, &mut buf).unwrap();

        let aggregate_signature = Bls::aggregate_signatures(&[signature1, signature2]).unwrap();
        assert!(Bls::verify_aggregate_signature(
            &[(message, &public_key1), (message, &public_key2)],
            &aggregate_signature
        ));
    }

    #[test]
    fn test_aggregate_signatures_swap_pks_fails() {
        let mut buf = [0u8; 100];
        let ikm1 = [1u8; 32];
        let ikm2 = [2u8; 32];
        let secret_key1 = SecretKey::key_gen(&ikm1, &[]).unwrap().into();
        let secret_key2 = SecretKey::key_gen(&ikm2, &[]).unwrap().into();
        let public_key1 = Bls::to_public_key(&secret_key1);
        let public_key2 = Bls::to_public_key(&secret_key2);
        let message1 = b"Hello, world!";
        let message2 = b"Goodbye, world!";
        let signature1 = Bls::sign_no_alloc(&secret_key1, message1, &mut buf).unwrap();
        let signature2 = Bls::sign_no_alloc(&secret_key2, message2, &mut buf).unwrap();

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
        let secret_key = SecretKey::key_gen(&ikm, &[]).unwrap().into();
        let public_key = Bls::to_public_key(&secret_key);
        let message = b"Hello, world!";
        let signable = TestSignable::from(message.as_slice());
        let signature = signable.sign::<Bls, Ssz>(&secret_key).unwrap();
        assert!(
            signable
                .verify::<Bls, Ssz>(&public_key, &signature)
                .unwrap()
        );
    }
}
