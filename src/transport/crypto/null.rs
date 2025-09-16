use crate::transport::crypto::{Cipher, Mac};

pub struct NullCipher;

impl NullCipher {
    pub fn new() -> Self {
        Self
    }
}

impl Cipher for NullCipher {
    fn block_size(&self) -> usize {
        8
    }

    fn encrypt(&mut self, _: &mut [u8]) {
        // No-op
    }

    fn decrypt(&mut self, _: &mut [u8]) {
        // No-op
    }
}

pub struct NullMac;

impl NullMac {
    pub fn new() -> Self {
        Self
    }
}

impl Mac for NullMac {
    fn len(&self) -> usize {
        0
    }

    fn compute(&mut self, _seq_num: u32, _packet: &[u8]) -> Vec<u8> {
        Vec::new()
    }

    fn verify(&mut self, _seq_num: u32, _packet: &[u8], _mac: &[u8]) -> bool {
        true
    }
}
