use ed25519_dalek::{SigningKey, VerifyingKey, ed25519::signature::SignerMut};
use num_bigint::BigUint;
use num_traits::Num;
use sha2::Digest;

use crate::transport::{
    buffer::{PacketDecodableExt, PacketEncodableExt},
    common::{ByteString, MultiPrecisionInteger},
    kex::KexContext,
    packet::{self},
    stream::{CryptoState, EncryptedPacketReader, EncryptedPacketWriter},
};

/// RFC3526 group14 prime as a single hex string (no spaces/newlines)
const P: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D",
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9",
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
);

const G: u32 = 2;

/// Build K_S (host key blob) for ssh-ed25519:
/// K_S = string("ssh-ed25519") || string(pubkey_bytes)
fn build_ed25519_host_key_blob(pubkey_bytes: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    let mut inner = Vec::new();

    inner.extend_from_slice(ByteString::new(b"ssh-ed25519").try_as_bytes()?.as_slice());
    inner.extend_from_slice(ByteString::new(pubkey_bytes).try_as_bytes()?.as_slice());

    // The host key field itself is an SSH string containing this blob:
    // but callers often expect the "host_key" variable to already be the blob (i.e. inner).
    Ok(inner)
}

/// Build the signature blob for ssh-ed25519:
/// signature_blob = string("ssh-ed25519") || string(signature_bytes)
fn build_ed25519_signature_blob(sig: &ed25519_dalek::Signature) -> anyhow::Result<Vec<u8>> {
    let sig_bytes = sig.to_bytes();
    let mut inner = Vec::new();
    inner.extend_from_slice(ByteString::new(b"ssh-ed25519").try_as_bytes()?.as_slice());
    inner.extend_from_slice(ByteString::new(&sig_bytes).try_as_bytes()?.as_slice());
    Ok(inner)
}

pub async fn perform_key_exchange(
    rng: &mut (impl rand::CryptoRng + rand::RngCore),
    crypto: &mut CryptoState,
    kex_context: &KexContext,
    reader: &mut EncryptedPacketReader<impl smol::io::AsyncRead + Clone + Unpin>,
    writer: &mut EncryptedPacketWriter<impl smol::io::AsyncWrite + Clone + Unpin>,
) -> anyhow::Result<()> {
    // 1. Create a signing key for the server host (Ed25519)
    let mut server_host_key = generate_signing_key(rng)?;
    let server_verifying_key: VerifyingKey = server_host_key.verifying_key();

    // 2. Read KEXDH_INIT
    let init: packet::KexDhInit = reader.read_packet(crypto).await?;
    let client_pub = BigUint::from_bytes_be(&MultiPrecisionInteger::try_from_bytes(&init.e)?.bytes);

    // 3. Generate server DH keypair
    let p = BigUint::from_str_radix(P, 16)?;
    let g = BigUint::from(G);
    let x = {
        // generate private exponent in [1, p-2]
        let nbytes = (p.bits() + 7) / 8;
        let mut b = vec![0u8; nbytes as usize];
        rng.try_fill_bytes(&mut b)?;

        let mut x = BigUint::from_bytes_be(&b);
        let two = BigUint::from(2u8);
        if &x >= &(p.clone() - &two) {
            x %= &(p.clone() - &two);
        }

        x += BigUint::from(1u8);
        x
    };

    let f = g.modpow(&x, &p);

    // 4. Compute shared secret K
    let k = client_pub.modpow(&x, &p);

    // 5. Build exchange hash H (simplified, real version includes version strings + KEXINITs)
    let pubkey_bytes: [u8; 32] = server_verifying_key.to_bytes();
    let host_key_blob = build_ed25519_host_key_blob(&pubkey_bytes)?;

    let mut hasher = sha2::Sha256::new();
    hasher.update(ByteString::new(kex_context.client_version.as_bytes()).try_as_bytes()?);
    hasher.update(ByteString::new(kex_context.server_version.as_bytes()).try_as_bytes()?);
    hasher.update(ByteString::new(&kex_context.client_kexinit).try_as_bytes()?);
    hasher.update(ByteString::new(&kex_context.server_kexinit).try_as_bytes()?);
    hasher.update(ByteString::new(&host_key_blob).try_as_bytes()?);
    hasher.update(MultiPrecisionInteger::from(&client_pub).try_as_bytes()?);
    hasher.update(MultiPrecisionInteger::from(&f).try_as_bytes()?);
    hasher.update(MultiPrecisionInteger::from(&k).try_as_bytes()?);

    let h = hasher.finalize();
    assert_eq!(h.len(), 32);

    // 6. Sign H with server’s host key (Ed25519)
    let signature = server_host_key.try_sign(&h)?;
    let signature_blob = build_ed25519_signature_blob(&signature)?;

    // 7. Send KEXDH_REPLY
    let reply = packet::KexDhReply {
        host_key: host_key_blob,
        f: f.to_bytes_be(),
        signature: signature_blob,
    };

    writer.write_packet(&reply, crypto).await?;

    // 8. Send and receive NEWKEYS
    writer.write_packet(&packet::NewKeys, crypto).await?;
    let _: packet::NewKeys = reader.read_packet(crypto).await?;

    todo!("Send NEWKEYS and set up encryption/MAC in the crypto state");

    Ok(())
}

fn generate_signing_key<R: rand::CryptoRng + rand::RngCore>(
    rng: &mut R,
) -> anyhow::Result<ed25519_dalek::SigningKey> {
    let mut secret_key = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
    rng.try_fill_bytes(&mut secret_key)
        .map_err(|e| anyhow::anyhow!("RNG error: {:?}", e))?;

    Ok(SigningKey::from_bytes(&secret_key))
}
