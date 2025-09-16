use std::{fmt::Debug, io::Write};

use smol::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};

use crate::transport::{
    buffer::{Packet, PacketDecodable, PacketDecoder, PacketEncodable, PacketEncoder},
    crypto::{Cipher, Mac},
};

pub struct CryptoState {
    cipher: Box<dyn Cipher>,
    mac: Box<dyn Mac>,
    seq_num: u32,
}

impl CryptoState {
    pub fn null() -> Self {
        let (cipher, mac) = crate::transport::crypto::null();
        Self {
            cipher,
            mac,
            seq_num: 0,
        }
    }

    pub fn set_cipher(&mut self, cipher: Box<dyn Cipher>) {
        self.cipher = cipher;
    }

    pub fn set_mac(&mut self, mac: Box<dyn Mac>) {
        self.mac = mac;
    }
}

pub struct EncryptedPacketReader<R> {
    inner: BufReader<R>,
}

impl<R> EncryptedPacketReader<R>
where
    R: smol::io::AsyncRead + Clone + Unpin,
{
    pub fn new(reader: R) -> Self {
        EncryptedPacketReader {
            inner: BufReader::new(reader),
        }
    }

    pub async fn read_packet_and_data<T: Packet + PacketDecodable + Debug>(
        &mut self,
        crypto: &mut CryptoState,
    ) -> anyhow::Result<(T, Vec<u8>)> {
        let block_size = crypto.cipher.block_size();

        // Read and decrypt the first cipher block
        let mut first_block = vec![0u8; block_size];
        self.inner.read_exact(&mut first_block).await?;
        crypto.cipher.decrypt(&mut first_block);

        // First 4 bytes are packet_length
        let packet_length = u32::from_be_bytes(first_block[..4].try_into()?) as usize;

        if packet_length < 1 {
            anyhow::bail!("Invalid packet_length: {packet_length}");
        }

        // We already decrypted part of the packet (block_size bytes)
        let mut full_plain = first_block;

        // Read the rest of the packet (encrypted)
        let remaining = packet_length + 4 - block_size; // total - what we already have
        if remaining > 0 {
            let mut rest = vec![0u8; remaining];
            self.inner.read_exact(&mut rest).await?;
            crypto.cipher.decrypt(&mut rest);
            full_plain.extend_from_slice(&rest);
        }

        // Read and verify MAC if needed
        let mac_len = crypto.mac.len();
        if mac_len > 0 {
            let mut mac_buf = vec![0u8; mac_len];
            self.inner.read_exact(&mut mac_buf).await?;
            if !crypto.mac.verify(crypto.seq_num, &full_plain, &mac_buf) {
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
        let payload = {
            let mut decoder = PacketDecoder::new(&payload_data);
            let message_number = decoder.read_u8()?;
            match message_number {
                n if n == T::MESSAGE_NUMBER => {}
                1 => {
                    anyhow::bail!("Received SSH_MSG_DISCONNECT");
                }
                _ => {
                    anyhow::bail!(
                        "Invalid message number for {}: {}",
                        T::MESSAGE_NAME,
                        message_number
                    );
                }
            }

            T::read_from(&mut decoder)?
        };

        crypto.seq_num = crypto.seq_num.wrapping_add(1);

        tracing::trace!("Read packet: {:#?}", payload);

        Ok((payload, payload_data))
    }

    pub async fn read_packet<T: Packet + PacketDecodable + Debug>(
        &mut self,
        crypto: &mut CryptoState,
    ) -> anyhow::Result<T> {
        let (packet, _) = self.read_packet_and_data(crypto).await?;
        Ok(packet)
    }
}

pub struct EncryptedPacketWriter<W> {
    inner: BufWriter<W>,
}

impl<W> EncryptedPacketWriter<W>
where
    W: smol::io::AsyncWrite + Clone + Unpin,
{
    pub fn new(inner: W) -> Self {
        EncryptedPacketWriter {
            inner: BufWriter::new(inner),
        }
    }

    pub async fn write_packet<T: Packet + PacketEncodable + Debug>(
        &mut self,
        packet: &T,
        crypto: &mut CryptoState,
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

            packet_writer.write(&payload_data, crypto.cipher.block_size())?;
            data
        };

        // 2. Encrypt in place
        crypto.cipher.encrypt(&mut packet_data);

        // 3. Compute MAC
        let mac = crypto.mac.compute(crypto.seq_num, &packet_data);

        // 4. Write cipher text + mac
        self.inner.write_all(&packet_data).await?;
        if !mac.is_empty() {
            self.inner.write_all(&mac).await?;
        }

        // 5. Increment seq_num
        crypto.seq_num = crypto.seq_num.wrapping_add(1);

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
