use crate::transport::{
    buffer::{Packet, PacketDecodable, PacketDecoder, PacketEncodable, PacketEncoder},
    common::{ByteString, MultiPrecisionInteger, NameList, OwnedNameList},
};

#[derive(Debug, PartialEq, Eq)]
pub struct KexInit {
    pub kex_algorithms: Vec<String>,
    pub server_host_key_algorithms: Vec<String>,
    pub encryption_algorithms_client_to_server: Vec<String>,
    pub encryption_algorithms_server_to_client: Vec<String>,
    pub mac_algorithms_client_to_server: Vec<String>,
    pub mac_algorithms_server_to_client: Vec<String>,
    pub compression_algorithms_client_to_server: Vec<String>,
    pub compression_algorithms_server_to_client: Vec<String>,
    pub languages_client_to_server: Vec<String>,
    pub languages_server_to_client: Vec<String>,
    pub first_kex_packet_follows: bool,
    pub reserved: u32,
}

impl KexInit {
    const COOKIE_LENGTH: usize = 16;
}

impl Packet for KexInit {
    const MESSAGE_NUMBER: u8 = 20;
    const MESSAGE_NAME: &'static str = "SSH_MSG_KEXINIT";
}

impl PacketEncodable for KexInit {
    fn write_into(&self, encoder: &mut PacketEncoder) -> anyhow::Result<()> {
        // 16-byte random cookie
        encoder.write_random_bytes(Self::COOKIE_LENGTH);

        // KEX algorithms
        encoder.write(&NameList::new(&self.kex_algorithms))?;

        // Server host key algorithms
        encoder.write(&NameList::new(&self.server_host_key_algorithms))?;

        // Encryption algorithms
        encoder.write(&NameList::new(&self.encryption_algorithms_client_to_server))?;
        encoder.write(&NameList::new(&self.encryption_algorithms_server_to_client))?;

        // MAC algorithms
        encoder.write(&NameList::new(&self.mac_algorithms_client_to_server))?;
        encoder.write(&NameList::new(&self.mac_algorithms_server_to_client))?;

        // Compression algorithms
        encoder.write(&NameList::new(
            &self.compression_algorithms_client_to_server,
        ))?;
        encoder.write(&NameList::new(
            &self.compression_algorithms_server_to_client,
        ))?;

        // Languages
        encoder.write(&NameList::new(&self.languages_client_to_server))?;
        encoder.write(&NameList::new(&self.languages_server_to_client))?;

        // First KEX packet follows
        encoder.write_u8(if self.first_kex_packet_follows { 1 } else { 0 });

        // Reserved
        encoder.write_u32(self.reserved);

        Ok(())
    }
}

impl PacketDecodable for KexInit {
    fn read_from<'a>(decoder: &mut PacketDecoder<'a>) -> anyhow::Result<Self> {
        // Skip cookie
        decoder.skip_bytes(Self::COOKIE_LENGTH)?;

        Ok(Self {
            kex_algorithms: decoder.read::<OwnedNameList>()?.into_inner(),
            server_host_key_algorithms: decoder.read::<OwnedNameList>()?.into_inner(),
            encryption_algorithms_client_to_server: decoder.read::<OwnedNameList>()?.into_inner(),
            encryption_algorithms_server_to_client: decoder.read::<OwnedNameList>()?.into_inner(),
            mac_algorithms_client_to_server: decoder.read::<OwnedNameList>()?.into_inner(),
            mac_algorithms_server_to_client: decoder.read::<OwnedNameList>()?.into_inner(),
            compression_algorithms_client_to_server: decoder.read::<OwnedNameList>()?.into_inner(),
            compression_algorithms_server_to_client: decoder.read::<OwnedNameList>()?.into_inner(),
            languages_client_to_server: decoder.read::<OwnedNameList>()?.into_inner(),
            languages_server_to_client: decoder.read::<OwnedNameList>()?.into_inner(),
            first_kex_packet_follows: decoder.read_u8()? != 0,
            reserved: decoder.read_u32()?,
        })
    }
}

#[derive(Debug)]
pub struct KexDhInit {
    /// Client public value
    pub e: Vec<u8>,
}

impl Packet for KexDhInit {
    const MESSAGE_NUMBER: u8 = 30;
    const MESSAGE_NAME: &'static str = "SSH_MSG_KEXDH_INIT";
}

impl PacketDecodable for KexDhInit {
    fn read_from<'a>(decoder: &mut PacketDecoder<'a>) -> anyhow::Result<Self> {
        Ok(Self {
            e: decoder.read_remaining().to_vec(),
        })
    }
}

#[derive(Debug)]
pub struct KexDhReply {
    /// Encoded server host key
    pub host_key: Vec<u8>,
    /// Server public value
    pub f: Vec<u8>,
    /// Signature over exchange hash H
    pub signature: Vec<u8>,
}

impl Packet for KexDhReply {
    const MESSAGE_NUMBER: u8 = 31;
    const MESSAGE_NAME: &'static str = "SSH_MSG_KEXDH_REPLY";
}

impl PacketEncodable for KexDhReply {
    fn write_into(&self, encoder: &mut PacketEncoder) -> anyhow::Result<()> {
        encoder.write(&ByteString::new(&self.host_key))?;
        encoder.write(&MultiPrecisionInteger::new(self.f.clone()))?;
        encoder.write(&ByteString::new(&self.signature))?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct NewKeys;

impl Packet for NewKeys {
    const MESSAGE_NUMBER: u8 = 21;
    const MESSAGE_NAME: &'static str = "SSH_MSG_NEWKEYS";
}

impl PacketEncodable for NewKeys {
    fn write_into(&self, _: &mut PacketEncoder) -> anyhow::Result<()> {
        Ok(())
    }
}

impl PacketDecodable for NewKeys {
    fn read_from<'a>(_: &mut PacketDecoder<'a>) -> anyhow::Result<Self> {
        Ok(NewKeys)
    }
}

#[cfg(test)]
mod tests {
    use crate::transport::buffer::{PacketDecodableExt, PacketEncodableExt};

    use super::*;

    #[test]
    fn test_kex_init_roundtrip() -> anyhow::Result<()> {
        let original = KexInit {
            kex_algorithms: vec![
                "diffie-hellman-group14-sha256".into(),
                "curve25519-sha256".into(),
                "ecdh-sha2-nistp256".into(),
            ],
            server_host_key_algorithms: vec!["ssh-ed25519".into()],
            encryption_algorithms_client_to_server: vec!["aes128-ctr".into()],
            encryption_algorithms_server_to_client: vec!["aes128-ctr".into()],
            mac_algorithms_client_to_server: vec!["hmac-sha1".into()],
            mac_algorithms_server_to_client: vec!["hmac-sha1".into()],
            compression_algorithms_client_to_server: vec!["none".into()],
            compression_algorithms_server_to_client: vec!["none".into()],
            languages_client_to_server: vec![],
            languages_server_to_client: vec![],
            first_kex_packet_follows: false,
            reserved: 0,
        };

        let encoded = original.try_as_bytes()?;
        let decoded = KexInit::try_from_bytes(&encoded)?;

        assert_eq!(original, decoded);

        Ok(())
    }
}
