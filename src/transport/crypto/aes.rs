use aes::Aes128;
use aes::cipher::KeyIvInit;
use anyhow::{Result, anyhow};
use ctr::cipher::StreamCipher;

use crate::transport::crypto::Cipher;

// SSH-CTR uses a big-endian counter (RFC 4344). Use BE, not LE.
type Ctr128<T> = ctr::Ctr128BE<T>;

pub struct KeyPair<'a> {
    pub server_to_client: Key<'a>,
    pub client_to_server: Key<'a>,
}

pub struct Key<'a> {
    pub key: &'a [u8],
    pub iv: &'a [u8],
}

impl<'a> Key<'a> {
    fn to_cipher(&self) -> Result<Ctr128<Aes128>> {
        let Key { key, iv } = self;
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

        Ctr128::<Aes128>::new_from_slices(key, iv)
            .map_err(|e| anyhow!("failed to create CTR cipher: {:?}", e))
    }
}

pub struct Aes128Ctr {
    encryption: Ctr128<Aes128>,
    decryption: Ctr128<Aes128>,
}

impl Aes128Ctr {
    /// Create a new AES-128-CTR cipher instance from a 16-byte key and 16-byte IV.
    pub fn new(keys: KeyPair<'_>) -> Result<Self> {
        Ok(Self {
            encryption: keys.server_to_client.to_cipher()?,
            decryption: keys.client_to_server.to_cipher()?,
        })
    }
}

impl Cipher for Aes128Ctr {
    /// AES block size = 16 bytes.
    fn block_size(&self) -> usize {
        16
    }

    fn name(&self) -> &'static str {
        "aes128-ctr"
    }

    /// Encrypt in-place (CTR: same as decrypt).
    fn encrypt(&mut self, buf: &mut [u8]) {
        self.encryption.apply_keystream(buf);
    }

    /// Decrypt in-place (CTR: same as encrypt).
    fn decrypt(&mut self, buf: &mut [u8]) {
        self.decryption.apply_keystream(buf);
    }
}
