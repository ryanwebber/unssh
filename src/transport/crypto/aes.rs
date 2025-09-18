use aes::Aes128;
use aes::cipher::KeyIvInit;
use anyhow::{Result, anyhow};
use ctr::cipher::StreamCipher;

use crate::transport::crypto::{DecryptionCipher, EncryptionCipher};

// SSH-CTR uses a big-endian counter (RFC 4344). Use BE, not LE.
type Ctr128<T> = ctr::Ctr128BE<T>;

pub struct Key<'a> {
    pub key: &'a [u8],
    pub iv: &'a [u8],
}

pub struct Aes128Ctr {
    inner: Ctr128<Aes128>,
}

impl Aes128Ctr {
    pub fn new(key: Key<'_>) -> Result<Self> {
        let Key { key, iv } = key;
        if key.len() != 16 {
            return Err(anyhow!(
                "invalid AES-128 key length: expected 16 bytes, got {} bytes",
                key.len()
            ));
        }

        if iv.len() != 16 {
            return Err(anyhow!(
                "invalid AES-128 IV length: expected 16 bytes, got {} bytes",
                iv.len()
            ));
        }

        let inner = Ctr128::<Aes128>::new_from_slices(key, iv)
            .map_err(|e| anyhow!("failed to create CTR cipher: {:?}", e))?;

        Ok(Self { inner })
    }
}

impl DecryptionCipher for Aes128Ctr {
    fn decrypt(&mut self, buf: &mut [u8]) {
        self.inner.apply_keystream(buf);
    }
}

impl EncryptionCipher for Aes128Ctr {
    fn block_size(&self) -> usize {
        16
    }

    fn encrypt(&mut self, buf: &mut [u8]) {
        self.inner.apply_keystream(buf);
    }
}
