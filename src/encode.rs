pub trait Encoder {}

pub trait Encodable<E: Encoder> {
    fn encode(&self) -> impl AsRef<[u8]>;
}

pub struct Ssz;

impl Encoder for Ssz {}

impl<E> Encodable<Ssz> for E
where
    E: ssz::Encode,
{
    fn encode(&self) -> impl AsRef<[u8]> {
        self.as_ssz_bytes()
    }
}
