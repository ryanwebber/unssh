use crate::transport::buffer::{PacketDecodable, PacketDecoder, PacketEncodable, PacketEncoder};

pub struct NameList<'a, T: AsRef<str>> {
    pub names: &'a [T],
}

impl<'a, T: AsRef<str>> NameList<'a, T> {
    pub fn new(names: &'a [T]) -> Self {
        Self { names }
    }
}

impl<'a, T: AsRef<str>> PacketEncodable for NameList<'a, T> {
    fn write_into(&self, encoder: &mut PacketEncoder) -> anyhow::Result<()> {
        let size = {
            let raw_size: usize = self.names.iter().map(|n| n.as_ref().len()).sum();
            let comma_count: usize = self.names.len().saturating_sub(1);
            raw_size + comma_count
        };

        let size_u32 = u32::try_from(size).map_err(|_| {
            anyhow::anyhow!(
                "NameList too large to encode ({} bytes, max is {})",
                size,
                u32::MAX
            )
        })?;

        encoder.write_u32(size_u32);
        for (i, name) in self.names.iter().enumerate() {
            if i > 0 {
                encoder.write_bytes(b",");
            }
            encoder.write_bytes(name.as_ref().as_bytes());
        }

        Ok(())
    }
}

pub struct OwnedNameList {
    names: Vec<String>,
}

impl OwnedNameList {
    pub fn into_inner(self) -> Vec<String> {
        self.names
    }
}

impl PacketDecodable for OwnedNameList {
    fn read_from<'a>(decoder: &mut PacketDecoder<'a>) -> anyhow::Result<Self> {
        let size = decoder.read_u32()? as usize;
        if size > 35000 {
            anyhow::bail!(
                "NameList too large to decode ({} bytes, max is 35000)",
                size
            );
        }

        let mut buf = vec![0u8; size];
        decoder.read_exact(&mut buf)?;

        let names = if buf.is_empty() {
            Vec::new()
        } else {
            let s = std::str::from_utf8(&buf)?;
            s.split(',').map(|s| s.to_string()).collect()
        };

        Ok(OwnedNameList { names })
    }
}

pub struct ByteString<'a> {
    pub bytes: &'a [u8],
}

impl<'a> ByteString<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl<'a> PacketEncodable for ByteString<'a> {
    fn write_into(&self, encoder: &mut PacketEncoder) -> anyhow::Result<()> {
        let size_u32 = u32::try_from(self.bytes.len()).map_err(|_| {
            anyhow::anyhow!(
                "ByteString too large to encode ({} bytes, max is {})",
                self.bytes.len(),
                u32::MAX
            )
        })?;
        encoder.write_u32(size_u32);
        encoder.write_bytes(self.bytes);
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct OwnedByteString {
    pub bytes: Vec<u8>,
}

impl OwnedByteString {
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }

    pub fn borrowed(&self) -> ByteString<'_> {
        ByteString { bytes: &self.bytes }
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl std::fmt::Debug for OwnedByteString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bytes(...<{} bytes>)", self.bytes.len())
    }
}

impl PacketDecodable for OwnedByteString {
    fn read_from<'a>(decoder: &mut PacketDecoder<'a>) -> anyhow::Result<Self> {
        let size = decoder.read_u32()? as usize;
        if size > 1_000_000 {
            anyhow::bail!(
                "ByteString too large to decode ({} bytes, max is 1,000,000)",
                size
            );
        }

        let mut bytes = vec![0u8; size];
        decoder.read_exact(&mut bytes)?;

        Ok(OwnedByteString { bytes })
    }
}

pub struct MultiPrecisionInteger {
    pub bytes: Vec<u8>,
}

impl MultiPrecisionInteger {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn bytes_without_length_prefix(&self) -> Vec<u8> {
        // Remove leading zeros for positive integers
        let mut mp = self.bytes.clone();
        while mp.len() > 0 && mp[0] == 0 {
            mp.remove(0);
        }

        // Add leading 0 if high bit is set
        if mp.len() > 0 && mp[0] & 0x80 != 0 {
            mp.insert(0, 0);
        }

        mp
    }
}

impl From<&num_bigint::BigUint> for MultiPrecisionInteger {
    fn from(value: &num_bigint::BigUint) -> Self {
        Self {
            bytes: value.to_bytes_be(),
        }
    }
}

impl PacketEncodable for MultiPrecisionInteger {
    fn write_into(&self, encoder: &mut PacketEncoder) -> anyhow::Result<()> {
        let bytes = self.bytes_without_length_prefix();
        let bytestring = ByteString::new(&bytes);
        bytestring.write_into(encoder)?;

        Ok(())
    }
}

impl PacketDecodable for MultiPrecisionInteger {
    fn read_from<'a>(decoder: &mut PacketDecoder<'a>) -> anyhow::Result<Self> {
        // Read 4-byte length prefix
        let len = decoder.read_u32()? as usize;
        let data = decoder.read_remaining();
        if data.len() < len {
            anyhow::bail!("invalid mpint: insufficient bytes");
        }

        // mpint is two’s complement, but for DH values they should always be non-negative
        // Leading 0x00 is just to keep it positive, so strip it if present
        let int_bytes = if !data.is_empty() && data[0] == 0 {
            &data[1..]
        } else {
            data
        };

        Ok(MultiPrecisionInteger {
            bytes: int_bytes.to_vec(),
        })
    }
}
