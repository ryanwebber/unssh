use num_enum::TryFromPrimitive;

use crate::transport::{
    buffer::{Packet, PacketDecodable, PacketDecoder, PacketEncodable, PacketEncoder},
    common::{ByteString, MultiPrecisionInteger, NameList, OwnedByteString, OwnedNameList},
};

#[derive(Debug, PartialEq, Eq)]
pub struct Disconnect {
    pub reason_code: u32,
    pub description: String,
    pub language_tag: String,
}

impl Packet for Disconnect {
    const MESSAGE_NUMBER: u8 = 1;
    const MESSAGE_NAME: &'static str = "SSH_MSG_DISCONNECT";
}

impl PacketEncodable for Disconnect {
    fn write_into(&self, encoder: &mut PacketEncoder) -> anyhow::Result<()> {
        // Reason code 11 = SSH_DISCONNECT_BY_APPLICATION
        encoder.write_u32(self.reason_code);
        encoder.write_string(&self.description)?;
        encoder.write_string(&self.language_tag)?;
        Ok(())
    }
}

impl PacketDecodable for Disconnect {
    fn read_from<'a>(decoder: &mut PacketDecoder<'a>) -> anyhow::Result<Self> {
        Ok(Self {
            reason_code: decoder.read_u32()?,
            description: decoder.read_string()?,
            language_tag: decoder.read_string()?,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ignore {
    pub data: Vec<u8>,
}

impl Packet for Ignore {
    const MESSAGE_NUMBER: u8 = 2;
    const MESSAGE_NAME: &'static str = "SSH_MSG_IGNORE";
}

impl PacketDecodable for Ignore {
    fn read_from<'a>(decoder: &mut PacketDecoder<'a>) -> anyhow::Result<Self> {
        let data = decoder.read::<OwnedByteString>()?.into_inner();
        Ok(Self { data })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Debug {
    pub always_display: bool,
    pub message: String,
    pub language_tag: String,
}

impl Packet for Debug {
    const MESSAGE_NUMBER: u8 = 4;
    const MESSAGE_NAME: &'static str = "SSH_MSG_DEBUG";
}

impl PacketDecodable for Debug {
    fn read_from<'a>(decoder: &mut PacketDecoder<'a>) -> anyhow::Result<Self> {
        Ok(Self {
            always_display: decoder.read_u8()? != 0,
            message: decoder.read_string()?,
            language_tag: decoder.read_string()?,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ServiceRequest {
    pub service_name: String,
}

impl Packet for ServiceRequest {
    const MESSAGE_NUMBER: u8 = 5;
    const MESSAGE_NAME: &'static str = "SSH_MSG_SERVICE_REQUEST";
}

impl PacketDecodable for ServiceRequest {
    fn read_from<'a>(decoder: &mut PacketDecoder<'a>) -> anyhow::Result<Self> {
        Ok(Self {
            service_name: decoder.read_string()?,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ServiceAccept {
    pub service_name: String,
}

impl Packet for ServiceAccept {
    const MESSAGE_NUMBER: u8 = 6;
    const MESSAGE_NAME: &'static str = "SSH_MSG_SERVICE_ACCEPT";
}

impl PacketEncodable for ServiceAccept {
    fn write_into(&self, encoder: &mut PacketEncoder) -> anyhow::Result<()> {
        encoder.write_string(&self.service_name)?;
        Ok(())
    }
}

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

#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq)]
pub struct UserAuthRequest {
    pub user_name: String,
    pub service_name: String,
    pub method_name: String,
}

impl Packet for UserAuthRequest {
    const MESSAGE_NUMBER: u8 = 50;
    const MESSAGE_NAME: &'static str = "SSH_MSG_USERAUTH_REQUEST";
}

impl PacketDecodable for UserAuthRequest {
    fn read_from<'a>(decoder: &mut PacketDecoder<'a>) -> anyhow::Result<Self> {
        Ok(Self {
            user_name: decoder.read_string()?,
            service_name: decoder.read_string()?,
            method_name: decoder.read_string()?,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct UserAuthBanner {
    pub message: String,
    pub language_tag: String,
}

impl Packet for UserAuthBanner {
    const MESSAGE_NUMBER: u8 = 53;
    const MESSAGE_NAME: &'static str = "SSH_MSG_USERAUTH_BANNER";
}

impl PacketEncodable for UserAuthBanner {
    fn write_into(&self, encoder: &mut PacketEncoder) -> anyhow::Result<()> {
        encoder.write_string(&self.message)?;
        encoder.write_string(&self.language_tag)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct UserAuthSuccess;

impl Packet for UserAuthSuccess {
    const MESSAGE_NUMBER: u8 = 52;
    const MESSAGE_NAME: &'static str = "SSH_MSG_USERAUTH_SUCCESS";
}

impl PacketEncodable for UserAuthSuccess {
    fn write_into(&self, _: &mut PacketEncoder) -> anyhow::Result<()> {
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ChannelOpen {
    pub channel_type: String,
    pub sender_channel: u32,
    pub initial_window_size: u32,
    pub maximum_packet_size: u32,
}

impl Packet for ChannelOpen {
    const MESSAGE_NUMBER: u8 = 90;
    const MESSAGE_NAME: &'static str = "SSH_MSG_CHANNEL_OPEN";
}

impl PacketDecodable for ChannelOpen {
    fn read_from<'a>(decoder: &mut PacketDecoder<'a>) -> anyhow::Result<Self> {
        Ok(Self {
            channel_type: decoder.read_string()?,
            sender_channel: decoder.read_u32()?,
            initial_window_size: decoder.read_u32()?,
            maximum_packet_size: decoder.read_u32()?,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ChannelOpenConfirmation {
    pub recipient_channel: u32,
    pub sender_channel: u32,
    pub initial_window_size: u32,
    pub maximum_packet_size: u32,
}

impl Packet for ChannelOpenConfirmation {
    const MESSAGE_NUMBER: u8 = 91;
    const MESSAGE_NAME: &'static str = "SSH_MSG_CHANNEL_OPEN_CONFIRMATION";
}

impl PacketEncodable for ChannelOpenConfirmation {
    fn write_into(&self, encoder: &mut PacketEncoder) -> anyhow::Result<()> {
        encoder.write_u32(self.recipient_channel);
        encoder.write_u32(self.sender_channel);
        encoder.write_u32(self.initial_window_size);
        encoder.write_u32(self.maximum_packet_size);
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ChannelOpenFailure {
    pub recipient_channel: u32,
    pub reason_code: u32,
    pub description: String,
    pub language_tag: String,
}

impl Packet for ChannelOpenFailure {
    const MESSAGE_NUMBER: u8 = 92;
    const MESSAGE_NAME: &'static str = "SSH_MSG_CHANNEL_OPEN_FAILURE";
}

impl PacketEncodable for ChannelOpenFailure {
    fn write_into(&self, encoder: &mut PacketEncoder) -> anyhow::Result<()> {
        encoder.write_u32(self.recipient_channel);
        encoder.write_u32(self.reason_code);
        encoder.write_string(&self.description)?;
        encoder.write_string(&self.language_tag)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ChannelSuccess {
    pub recipient_channel: u32,
}

impl Packet for ChannelSuccess {
    const MESSAGE_NUMBER: u8 = 99;
    const MESSAGE_NAME: &'static str = "SSH_MSG_CHANNEL_SUCCESS";
}

impl PacketEncodable for ChannelSuccess {
    fn write_into(&self, encoder: &mut PacketEncoder) -> anyhow::Result<()> {
        encoder.write_u32(self.recipient_channel);
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ChannelRequest {
    pub recipient_channel: u32,
    pub request_type: ChannelRequestType,
    pub want_reply: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChannelRequestType {
    Env {
        name: String,
        value: String,
    },
    PtyReq {
        term: String,
        columns: u32,
        rows: u32,
        width_px: u32,
        height_px: u32,
        modes: Vec<EncodedTerminalMode>,
    },
    Unknown {
        name: String,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct EncodedTerminalMode {
    opcode: EncodedTerminalOpcode,
    value: u32,
}

#[repr(u8)]
#[derive(TryFromPrimitive, Debug, PartialEq, Eq)]
pub enum EncodedTerminalOpcode {
    TtyOpEnd = 0,
    VIntr = 1,
    VQuit = 2,
    VErase = 3,
    VKill = 4,
    VEof = 5,
    VEol = 6,
    VEol2 = 7,
    VStart = 8,
    VStop = 9,
    VSusp = 10,
    VDsusp = 11,
    VReprint = 12,
    VWerase = 13,
    VLnext = 14,
    VFlush = 15,
    VSwtch = 16,
    VStatus = 17,
    VDiscard = 18,
    Ignpar = 30,
    Parmrk = 31,
    Inpck = 32,
    Istrip = 33,
    Inlcr = 34,
    Igncr = 35,
    Icrnl = 36,
    Iuclc = 37,
    Ixon = 38,
    Ixany = 39,
    Ixoff = 40,
    Imaxbel = 41,
    Isig = 50,
    Icanon = 51,
    Xcase = 52,
    Echo = 53,
    Echoe = 54,
    Echok = 55,
    Echonl = 56,
    Noflsh = 57,
    Tostop = 58,
    Iexten = 59,
    Echocl = 60,
    Echoke = 61,
    Pendin = 62,
    Opost = 70,
    Olcuc = 71,
    Onlcr = 72,
    Ocrnl = 73,
    Onocr = 74,
    Onlret = 75,
    Cs7 = 90,
    Cs8 = 91,
    Parenb = 92,
    Parodd = 93,
    TtyOpIspeed = 128,
    TtyOpOspeed = 129,
    Unknown = 255,
}

impl Packet for ChannelRequest {
    const MESSAGE_NUMBER: u8 = 98;
    const MESSAGE_NAME: &'static str = "SSH_MSG_CHANNEL_REQUEST";
}

impl PacketDecodable for ChannelRequest {
    fn read_from<'a>(decoder: &mut PacketDecoder<'a>) -> anyhow::Result<Self> {
        let recipient_channel = decoder.read_u32()?;
        let request_type_str = decoder.read_string()?;
        let want_reply = decoder.read_u8()? != 0;

        let request_type = match request_type_str.as_str() {
            "env" => {
                let name = decoder.read_string()?;
                let value = decoder.read_string()?;
                ChannelRequestType::Env { name, value }
            }
            "pty-req" => {
                let term = decoder.read_string()?;
                let columns = decoder.read_u32()?;
                let rows = decoder.read_u32()?;
                let width_px = decoder.read_u32()?;
                let height_px = decoder.read_u32()?;
                let modes = {
                    let bytestream = decoder.read::<OwnedByteString>()?.into_inner();
                    let mut modes = Vec::new();
                    for bytes in bytestream.chunks(5) {
                        let opcode = EncodedTerminalOpcode::try_from(bytes[0])
                            .unwrap_or(EncodedTerminalOpcode::Unknown);

                        if opcode == EncodedTerminalOpcode::TtyOpEnd {
                            break;
                        }

                        let value = PacketDecoder::new(&bytes[1..5]).read_u32()?;
                        modes.push(EncodedTerminalMode { opcode, value });
                    }

                    modes
                };
                ChannelRequestType::PtyReq {
                    term,
                    columns,
                    rows,
                    width_px,
                    height_px,
                    modes,
                }
            }
            _ => ChannelRequestType::Unknown {
                name: request_type_str,
            },
        };

        Ok(Self {
            recipient_channel,
            request_type,
            want_reply,
        })
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
