use std::{fmt::Debug, io::Write};

use smol::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};

use crate::transport::{
    buffer::{Packet, PacketDecodable, PacketDecoder, PacketEncodable, PacketEncoder},
    crypto::{self, DecryptionCipher, EncryptionCipher, MacSigner, MacVerification},
};

pub struct EncryptedPacketReader<R> {
    inner: BufReader<R>,
    seqence_number: u32,
    cipher: Box<dyn DecryptionCipher>,
    mac: Box<dyn MacVerification>,
}

impl<R> EncryptedPacketReader<R>
where
    R: smol::io::AsyncRead + Clone + Unpin,
{
    pub fn new(reader: R) -> Self {
        EncryptedPacketReader {
            inner: BufReader::new(reader),
            seqence_number: 0,
            cipher: crypto::null::Null::new(),
            mac: crypto::null::Null::new(),
        }
    }

    pub fn set_cipher(&mut self, cipher: Box<dyn DecryptionCipher>, mac: Box<dyn MacVerification>) {
        self.cipher = cipher;
        self.mac = mac;
    }

    pub async fn read_packet(&mut self) -> anyhow::Result<PacketPayload> {
        // CTR mode: read exactly 4-byte header and decrypt it to get packet_length
        let mut header = [0u8; 4];
        self.inner.read_exact(&mut header).await?;
        let header_cipher = header;
        self.cipher.decrypt(&mut header);
        let header_plain = header;
        let packet_length = u32::from_be_bytes(header_plain) as usize;

        // Heuristic: if decrypted length is implausible but raw header looks plausible,
        // negotiation may have selected an ETM variant unexpectedly.
        let raw_len = u32::from_be_bytes(header_cipher) as usize;
        if (packet_length < 1 || packet_length > 35000) && (1..=35000).contains(&raw_len) {
            tracing::warn!(
                "Decrypted packet_length={} looks invalid but raw header={} looks plausible; \n\
                 check MAC negotiation (ETM vs non-ETM).",
                packet_length,
                raw_len
            );
        }

        if packet_length < 1 || packet_length > 35000 {
            anyhow::bail!("Invalid packet_length: {packet_length}");
        }

        tracing::trace!("Got new packet header, length: {}", packet_length);
        // Read body and decrypt streaming
        let mut body = vec![0u8; packet_length];
        self.inner.read_exact(&mut body).await?;
        self.cipher.decrypt(&mut body);

        let mut full_plain = header.to_vec();
        full_plain.extend_from_slice(&body);

        // Read and verify MAC if needed
        let mac_len = self.mac.len();
        if mac_len > 0 {
            let mut mac_buf = vec![0u8; mac_len];
            self.inner.read_exact(&mut mac_buf).await?;
            if !self.mac.verify(self.seqence_number, &full_plain, &mac_buf) {
                anyhow::bail!("MAC verification failed");
            }
        }

        // Extract and parse payload
        let padding_length = full_plain[4] as usize;
        let payload_end = 5 + packet_length - padding_length - 1;
        if payload_end > full_plain.len() {
            anyhow::bail!("Packet payload length mismatch");
        }

        let payload_data = full_plain[5..payload_end].to_vec();
        let payload = PacketPayload {
            payload_bytes: payload_data,
        };

        tracing::trace!(
            "Read packet with message number: {}",
            payload.message_number()?
        );

        self.seqence_number = self.seqence_number.wrapping_add(1);

        Ok(payload)
    }

    pub async fn read_packet_as<T: Packet + PacketDecodable + Debug>(
        &mut self,
    ) -> anyhow::Result<T> {
        let payload = self.read_packet().await?;
        let packet = payload.try_unpack::<T>()?;
        tracing::trace!("Read and decoded packet: {:#?}", packet);
        Ok(packet)
    }
}

#[derive(Clone)]
pub struct PacketPayload {
    payload_bytes: Vec<u8>,
}

impl PacketPayload {
    pub fn try_unpack<T: PacketDecodable + Packet>(&self) -> anyhow::Result<T> {
        let mut decoder = PacketDecoder::new(&self.payload_bytes);
        let message_number = decoder.read_u8()?;
        if message_number != T::MESSAGE_NUMBER {
            anyhow::bail!(
                "Invalid message number for {}: {}",
                T::MESSAGE_NAME,
                message_number
            );
        }

        T::read_from(&mut decoder)
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.payload_bytes
    }

    pub fn message_number(&self) -> anyhow::Result<u8> {
        let mut decoder = PacketDecoder::new(&self.payload_bytes);
        decoder.read_u8()
    }
}

pub struct EncryptedPacketWriter<W> {
    inner: BufWriter<W>,
    sequence_number: u32,
    cipher: Box<dyn EncryptionCipher>,
    mac: Box<dyn MacSigner>,
}

impl<W> EncryptedPacketWriter<W>
where
    W: smol::io::AsyncWrite + Clone + Unpin,
{
    pub fn new(inner: W) -> Self {
        EncryptedPacketWriter {
            inner: BufWriter::new(inner),
            sequence_number: 0,
            cipher: crypto::null::Null::new(),
            mac: crypto::null::Null::new(),
        }
    }

    pub fn set_cipher(&mut self, cipher: Box<dyn EncryptionCipher>, mac: Box<dyn MacSigner>) {
        self.cipher = cipher;
        self.mac = mac;
    }

    pub async fn write_packet<T: Packet + PacketEncodable + Debug>(
        &mut self,
        packet: &T,
    ) -> anyhow::Result<Vec<u8>> {
        tracing::trace!("Writing packet: {:#?}", packet);

        // 1. Encode plaintext packet

        let payload_data = {
            let mut encoder = PacketEncoder::new();
            encoder.write_u8(T::MESSAGE_NUMBER);
            packet.write_into(&mut encoder)?;
            encoder.into_bytes()
        };

        let mut packet_data = {
            let mut data: Vec<u8> = vec![];
            let mut packet_writer: PacketWriter<&mut Vec<u8>> = PacketWriter::new(&mut data);

            packet_writer.write(&payload_data, self.cipher.block_size())?;
            data
        };

        // 2. Compute MAC over plaintext (RFC 4253 §6)
        let mac = self.mac.compute(self.sequence_number, &packet_data)?;

        // 3. Encrypt in place (CTR)
        self.cipher.encrypt(&mut packet_data);

        // 4. Write cipher text + mac
        self.inner.write_all(&packet_data).await?;
        if !mac.is_empty() {
            self.inner.write_all(&mac).await?;
        }

        // 5. Increment outbound sequence number
        self.sequence_number = self.sequence_number.wrapping_add(1);

        // 6. Flush
        self.inner.flush().await?;

        Ok(payload_data)
    }
}

struct PacketWriter<W: Write> {
    inner: W,
}

impl<W: Write> PacketWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    fn write(&mut self, payload: &[u8], block_size: usize) -> anyhow::Result<()> {
        /*
           6.  Binary Packet Protocol

           Each packet is in the following format:

               uint32    packet_length
               byte      padding_length
               byte[n1]  payload; n1 = packet_length - padding_length - 1
               byte[n2]  random padding; n2 = padding_length
               byte[m]   mac (Message Authentication Code - MAC); m = mac_length

               packet_length
                   The length of the packet in bytes, not including 'mac' or the
                   'packet_length' field itself.

               padding_length
                   Length of 'random padding' (bytes).

               payload
                   The useful contents of the packet.  If compression has been
                   negotiated, this field is compressed.  Initially, compression
                   MUST be "none".

               random padding
                   Arbitrary-length padding, such that the total length of
                   (packet_length || padding_length || payload || random padding)
                   is a multiple of the cipher block size or 8, whichever is
                   larger.  There MUST be at least four bytes of padding.  The
                   padding SHOULD consist of random bytes.  The maximum amount of
                   padding is 255 bytes.

               mac
                   Message Authentication Code.  If message authentication has
                   been negotiated, this field contains the MAC bytes.  Initially,
                   the MAC algorithm MUST be "none".
        */

        let padding_length = {
            let payload_len = payload.len();

            // packet_length must be payload_len + 1 (for padding_len field) + padding_len
            // We need (packet_length + 4) % block_size == 0
            let padding_length = (block_size - ((payload_len + 1 + 4) % block_size)) % block_size;

            // Ensure at least 4 bytes padding
            if padding_length < 4 {
                padding_length + block_size
            } else {
                padding_length
            }
        };

        // TODO: Randomize padding
        let random_padding = vec![0u8; padding_length];

        debug_assert!(random_padding.len() == padding_length && padding_length >= 4);

        let packet_length =
            u32::try_from(1 + payload.len() + random_padding.len()).map_err(|_| {
                anyhow::anyhow!(
                    "Packet too large to encode ({} bytes, max is {})",
                    1 + payload.len() + random_padding.len(),
                    u32::MAX
                )
            })?;

        self.inner.write_all(&packet_length.to_be_bytes())?;
        self.inner.write_all(&[u8::try_from(padding_length)?])?;

        self.inner.write_all(&payload)?;
        self.inner.write_all(&random_padding)?;

        Ok(())
    }
}
