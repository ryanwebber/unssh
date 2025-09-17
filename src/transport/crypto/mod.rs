mod null;

pub mod aes;
pub mod hmac;

pub trait Cipher: Send {
    fn block_size(&self) -> usize;
    fn name(&self) -> &'static str;
    fn encrypt(&mut self, buf: &mut [u8]);
    fn decrypt(&mut self, buf: &mut [u8]);
}

pub trait Mac: Send {
    fn len(&self) -> usize;
    fn name(&self) -> &'static str;
    fn compute(&mut self, seq_num: u32, packet: &[u8]) -> anyhow::Result<Vec<u8>>;
    fn verify(&mut self, seq_num: u32, packet: &[u8], mac: &[u8]) -> bool;
}

pub fn null() -> (Box<dyn Cipher>, Box<dyn Mac>) {
    (
        Box::new(null::NullCipher::new()),
        Box::new(null::NullMac::new()),
    )
}
