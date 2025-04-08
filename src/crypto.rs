use crate::encode::{Encodable, Encoder};

pub trait KeyPair {
    type SecretKey;
    type PublicKey;

    fn to_public_key(secret_key: &Self::SecretKey) -> Self::PublicKey;
}

pub trait Address: KeyPair {
    type PublicKeyHash;

    fn address(public_key: &Self::PublicKey) -> Self::PublicKeyHash;

    fn to_public_key_hash(secret_key: &Self::SecretKey) -> Self::PublicKeyHash {
        let public_key = Self::to_public_key(secret_key);
        Self::address(&public_key)
    }
}

pub trait Signer: KeyPair {
    type Signature;
    type Error;

    fn sign(secret_key: &Self::SecretKey, message: &[u8]) -> Result<Self::Signature, Self::Error>;

    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, Self::Error>;
}

pub trait SignerBuf: Signer {
    fn sign_no_alloc(
        secret_key: &Self::SecretKey,
        message: &[u8],
        buf: &mut [u8],
    ) -> Result<Self::Signature, Self::Error>;
    fn verify_no_alloc(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
        buf: &mut [u8],
    ) -> Result<bool, Self::Error>;
}

pub trait AggregateSigner: Signer {
    type AggregateSignature;

    fn aggregate_signatures(
        signatures: &[Self::Signature],
    ) -> Result<Self::AggregateSignature, Self::Error>;
    fn verify_aggregate_signature(
        messages_with_pk: &[(impl AsRef<[u8]>, &Self::PublicKey)],
        aggregate_signature: &Self::AggregateSignature,
    ) -> bool;
}

pub trait Signable {}

pub trait SignableExt: Signable {
    fn sign_no_alloc<C: SignerBuf, E: Encoder>(
        &self,
        secret_key: &C::SecretKey,
        buf: &mut [u8],
    ) -> Result<C::Signature, C::Error>
    where
        Self: Encodable<E>;
    fn verify_no_alloc<C: SignerBuf, E: Encoder>(
        &self,
        messages_with_pks: &C::PublicKey,
        signature: &C::Signature,
        buf: &mut [u8],
    ) -> Result<bool, C::Error>
    where
        Self: Encodable<E>;

    fn sign<C: Signer, E: Encoder>(
        &self,
        secret_key: &C::SecretKey,
    ) -> Result<C::Signature, C::Error>
    where
        Self: Encodable<E>;

    fn verify<C: Signer, E: Encoder>(
        &self,
        public_key: &C::PublicKey,
        signature: &C::Signature,
    ) -> Result<bool, C::Error>
    where
        Self: Encodable<E>;
}

impl<P> SignableExt for P
where
    P: Signable,
{
    fn sign_no_alloc<C: SignerBuf, E: Encoder>(
        &self,
        secret_key: &C::SecretKey,
        buf: &mut [u8],
    ) -> Result<C::Signature, C::Error>
    where
        P: Encodable<E>,
    {
        C::sign_no_alloc(secret_key, self.encode().as_ref(), buf)
    }

    fn verify_no_alloc<C: SignerBuf, E: Encoder>(
        &self,
        public_key: &C::PublicKey,
        signature: &C::Signature,
        buf: &mut [u8],
    ) -> Result<bool, C::Error>
    where
        P: Encodable<E>,
    {
        C::verify_no_alloc(public_key, self.encode().as_ref(), signature, buf)
    }

    fn sign<C: Signer, E: Encoder>(
        &self,
        secret_key: &C::SecretKey,
    ) -> Result<C::Signature, C::Error>
    where
        P: Encodable<E>,
    {
        C::sign(secret_key, self.encode().as_ref())
    }

    fn verify<C: Signer, E: Encoder>(
        &self,
        public_key: &C::PublicKey,
        signature: &C::Signature,
    ) -> Result<bool, C::Error>
    where
        P: Encodable<E>,
    {
        C::verify(public_key, self.encode().as_ref(), signature)
    }
}
