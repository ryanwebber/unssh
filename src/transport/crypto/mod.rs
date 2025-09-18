pub mod aes;
pub mod hmac;
pub mod null;

pub trait DecryptionCipher: Send {
    fn decrypt(&mut self, buf: &mut [u8]);
}

pub trait EncryptionCipher: Send {
    fn block_size(&self) -> usize;
    fn encrypt(&mut self, buf: &mut [u8]);
}

pub trait MacVerification: Send {
    fn len(&self) -> usize;
    fn verify(&mut self, seq_num: u32, packet: &[u8], mac: &[u8]) -> bool;
}

pub trait MacSigner: Send {
    fn compute(&mut self, seq_num: u32, packet: &[u8]) -> anyhow::Result<Vec<u8>>;
}
