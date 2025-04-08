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

    fn sign(secret_key: &Self::SecretKey, message: &[u8]) -> Self::Signature;
    fn verify(public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> bool;
}

pub trait AggregateSigner: Signer {
    type AggregateSignature;
    type Error;

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
    fn sign<C: Signer, E: Encoder>(&self, secret_key: &C::SecretKey) -> C::Signature
    where
        Self: Encodable<E>;
    fn verify<C: Signer, E: Encoder>(
        &self,
        messages_with_pks: &C::PublicKey,
        signature: &C::Signature,
    ) -> bool
    where
        Self: Encodable<E>;
}

impl<P> SignableExt for P
where
    P: Signable,
{
    fn sign<C: Signer, E: Encoder>(&self, secret_key: &C::SecretKey) -> C::Signature
    where
        P: Encodable<E>,
    {
        C::sign(secret_key, self.encode().as_ref())
    }

    fn verify<C: Signer, E: Encoder>(
        &self,
        public_key: &C::PublicKey,
        signature: &C::Signature,
    ) -> bool
    where
        P: Encodable<E>,
    {
        C::verify(public_key, self.encode().as_ref(), signature)
    }
}
