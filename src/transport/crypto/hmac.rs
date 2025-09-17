use crate::transport::crypto::Mac;

pub struct HmacSha256 {
    key: Vec<u8>,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }
}

impl HmacSha256 {
    fn compute(&mut self, seq_num: u32, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
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

pub struct DirectionalHmacSha256 {
    pub client_to_server: HmacSha256,
    pub server_to_client: HmacSha256,
}

impl Mac for DirectionalHmacSha256 {
    fn len(&self) -> usize {
        32
    }

    fn name(&self) -> &'static str {
        "hmac-sha256"
    }

    fn compute(&mut self, seq_num: u32, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.server_to_client.compute(seq_num, packet)
    }

    fn verify(&mut self, seq_num: u32, packet: &[u8], mac: &[u8]) -> bool {
        match self.client_to_server.compute(seq_num, packet) {
            Ok(computed_mac) => computed_mac.as_slice() == mac,
            Err(_) => false,
        }
    }
}
