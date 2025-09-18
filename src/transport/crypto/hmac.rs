use crate::transport::crypto::{MacSigner, MacVerification};

pub struct HmacSha256 {
    key: Vec<u8>,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }
}

impl HmacSha256 {
    fn compute_impl(&mut self, seq_num: u32, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        use hmac::{Hmac, Mac as HmacTrait};
        use sha2::Sha256;

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).map_err(|e| {
            tracing::error!("Failed to create HMAC: {}", e);
            e
        })?;
        mac.update(&seq_num.to_be_bytes());
        mac.update(packet);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

impl MacVerification for HmacSha256 {
    fn len(&self) -> usize {
        32
    }

    fn verify(&mut self, seq_num: u32, packet: &[u8], mac: &[u8]) -> bool {
        match self.compute_impl(seq_num, packet) {
            Ok(computed_mac) => computed_mac.as_slice() == mac,
            Err(_) => false,
        }
    }
}

impl MacSigner for HmacSha256 {
    fn len(&self) -> usize {
        32
    }

    fn compute(&mut self, seq_num: u32, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.compute_impl(seq_num, packet)
    }
}
