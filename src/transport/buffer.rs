use std::vec;

pub trait Packet {
    const MESSAGE_NUMBER: u8;
    const MESSAGE_NAME: &'static str;
}

pub trait PacketEncodable {
    fn write_into(&self, encoder: &mut PacketEncoder) -> anyhow::Result<()>;
}

pub trait PacketEncodableExt {
    fn try_as_bytes(&self) -> anyhow::Result<Vec<u8>>;
}

impl<T: PacketEncodable> PacketEncodableExt for T {
    fn try_as_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut encoder = PacketEncoder::new();
        self.write_into(&mut encoder)?;
        Ok(encoder.into_bytes())
    }
}

pub trait PacketDecodable: Sized {
    fn read_from<'a>(decoder: &mut PacketDecoder<'a>) -> anyhow::Result<Self>;
}

pub trait PacketDecodableExt: Sized {
    fn try_from_bytes(data: &[u8]) -> anyhow::Result<Self>;
}

impl<T: PacketDecodable> PacketDecodableExt for T {
    fn try_from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        let mut decoder = PacketDecoder::new(data);
        let value = T::read_from(&mut decoder)?;
        if !decoder.read_remaining().is_empty() {
            anyhow::bail!("Extra data after decoding packet");
        }

        Ok(value)
    }
}

pub struct PacketEncoder {
    buffer: Vec<u8>,
}

impl PacketEncoder {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn write(&mut self, encodable: &impl PacketEncodable) -> anyhow::Result<()> {
        encodable.write_into(self)
    }

    pub fn write_u8(&mut self, value: u8) {
        self.buffer.push(value);
    }

    pub fn write_u32(&mut self, value: u32) {
        self.buffer.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    pub fn write_random_bytes(&mut self, len: usize) {
        // TODO: Random bytes
        let buf = vec![0u8; len];
        self.buffer.extend_from_slice(&buf);
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }
}

pub struct PacketDecoder<'a> {
    buffer: &'a [u8],
}

impl<'a> PacketDecoder<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer }
    }

    pub fn read<T: PacketDecodable>(&mut self) -> anyhow::Result<T> {
        T::read_from(self)
    }

    pub fn read_u8(&mut self) -> anyhow::Result<u8> {
        if self.buffer.len() < 1 {
            anyhow::bail!("Buffer underflow");
        }

        let value = self.buffer[0];
        self.buffer = &self.buffer[1..];
        Ok(value)
    }

    pub fn read_u32(&mut self) -> anyhow::Result<u32> {
        if self.buffer.len() < 4 {
            anyhow::bail!("Buffer underflow");
        }

        let value = u32::from_be_bytes(self.buffer[0..4].try_into()?);
        self.buffer = &self.buffer[4..];
        Ok(value)
    }

    pub fn read_exact(&mut self, buf: &mut [u8]) -> anyhow::Result<()> {
        if self.buffer.len() < buf.len() {
            anyhow::bail!("Buffer underflow");
        }

        buf.copy_from_slice(&self.buffer[0..buf.len()]);
        self.buffer = &self.buffer[buf.len()..];
        Ok(())
    }

    pub fn read_remaining(&mut self) -> &'a [u8] {
        let remaining = self.buffer;
        self.buffer = &[];
        remaining
    }

    pub fn skip_bytes(&mut self, len: usize) -> anyhow::Result<()> {
        if self.buffer.len() < len {
            anyhow::bail!("Buffer underflow");
        }

        self.buffer = &self.buffer[len..];
        Ok(())
    }
}
