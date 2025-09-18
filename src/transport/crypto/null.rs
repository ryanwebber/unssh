use crate::transport::crypto::{DecryptionCipher, EncryptionCipher, MacSigner, MacVerification};

pub struct Null;

impl Null {
    pub fn new() -> Box<Self> {
        Box::new(Self)
    }
}

impl EncryptionCipher for Null {
    fn block_size(&self) -> usize {
        8
    }

    fn encrypt(&mut self, _: &mut [u8]) {
        // No-op
    }
}

impl DecryptionCipher for Null {
    fn decrypt(&mut self, _: &mut [u8]) {
        // No-op
    }
}

impl MacSigner for Null {
    fn compute(&mut self, _seq_num: u32, _packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

impl MacVerification for Null {
    fn len(&self) -> usize {
        0
    }

    fn verify(&mut self, _seq_num: u32, _packet: &[u8], _mac: &[u8]) -> bool {
        true
    }
}
