use crate::{
    config::Config,
    transport::{
        packet::KexInit,
        stream::{EncryptedPacketReader, EncryptedPacketWriter},
    },
};

mod diffie_hellman_group14_sha256;

pub struct KexContext {
    pub client_version: String,
    pub server_version: String,
    pub client_kexinit: Vec<u8>,
    pub server_kexinit: Vec<u8>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Algorithms {
    pub kex_algorithm: String,
    pub server_host_key_algorithm: String,
    pub encryption_algorithm_client_to_server: String,
    pub encryption_algorithm_server_to_client: String,
    pub mac_algorithm_client_to_server: String,
    pub mac_algorithm_server_to_client: String,
    pub compression_algorithm_client_to_server: String,
    pub compression_algorithm_server_to_client: String,
}

pub fn default_kex_init() -> KexInit {
    KexInit {
        kex_algorithms: vec![String::from("diffie-hellman-group14-sha256")],
        server_host_key_algorithms: vec![String::from("ssh-ed25519")],
        encryption_algorithms_client_to_server: vec![String::from("aes128-ctr")],
        encryption_algorithms_server_to_client: vec![String::from("aes128-ctr")],
        mac_algorithms_client_to_server: vec![String::from("hmac-sha2-256")],
        mac_algorithms_server_to_client: vec![String::from("hmac-sha2-256")],
        compression_algorithms_client_to_server: vec![String::from("none")],
        compression_algorithms_server_to_client: vec![String::from("none")],
        languages_client_to_server: vec![],
        languages_server_to_client: vec![],
        first_kex_packet_follows: false,
        reserved: 0,
    }
}

pub async fn perform_key_exchange(
    rng: &mut (impl rand::CryptoRng + rand::RngCore),
    crypto: &mut crate::transport::stream::CryptoState,
    config: &Config,
    kex_context: &KexContext,
    server_kex: &KexInit,
    client_kex: &KexInit,
    reader: &mut EncryptedPacketReader<impl smol::io::AsyncRead + Clone + Unpin>,
    writer: &mut EncryptedPacketWriter<impl smol::io::AsyncWrite + Clone + Unpin>,
) -> anyhow::Result<()> {
    let negotiated_algorithms = negotiate(&server_kex, &client_kex)?;
    tracing::info!("Negotiated algorithms: {:#?}", negotiated_algorithms);

    match negotiated_algorithms.kex_algorithm.as_str() {
        "diffie-hellman-group14-sha256" => {
            if negotiated_algorithms.server_host_key_algorithm != "ssh-ed25519" {
                anyhow::bail!(
                    "Unsupported host key algorithm: {}",
                    negotiated_algorithms.server_host_key_algorithm
                );
            }

            let host_key = {
                let contents = std::fs::read_to_string(&config.host_key_path).map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to read host key at path {}: {}",
                        config.host_key_path.display(),
                        e
                    )
                })?;

                let public_key = ssh_key::PublicKey::from_openssh(&contents)?;
                let Some(key_data) = public_key.key_data().ed25519() else {
                    anyhow::bail!(
                        "Expected an ed25519 host key, got {}",
                        public_key.algorithm()
                    );
                };

                key_data.as_ref().to_vec()
            };

            diffie_hellman_group14_sha256::perform_key_exchange(
                rng,
                crypto,
                kex_context,
                &host_key,
                reader,
                writer,
            )
            .await
        }
        _ => {
            anyhow::bail!(
                "Unsupported key exchange algorithm: {}",
                negotiated_algorithms.kex_algorithm
            )
        }
    }
}

fn negotiate(client_kex: &KexInit, server_kex: &KexInit) -> anyhow::Result<Algorithms> {
    fn select(a: &[String], b: &[String], kind: &str) -> anyhow::Result<String> {
        a.iter()
            .find(|item| b.contains(item))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No compatible {} found", kind))
    }

    Ok(Algorithms {
        kex_algorithm: select(
            &client_kex.kex_algorithms,
            &server_kex.kex_algorithms,
            "kex algorithm",
        )?,
        server_host_key_algorithm: select(
            &client_kex.server_host_key_algorithms,
            &server_kex.server_host_key_algorithms,
            "host key algorithm",
        )?,
        encryption_algorithm_client_to_server: select(
            &client_kex.encryption_algorithms_client_to_server,
            &server_kex.encryption_algorithms_client_to_server,
            "cipher",
        )?,
        encryption_algorithm_server_to_client: select(
            &client_kex.encryption_algorithms_server_to_client,
            &server_kex.encryption_algorithms_server_to_client,
            "ciper",
        )?,
        mac_algorithm_client_to_server: select(
            &client_kex.mac_algorithms_client_to_server,
            &server_kex.mac_algorithms_client_to_server,
            "MAC algorithm",
        )?,
        mac_algorithm_server_to_client: select(
            &client_kex.mac_algorithms_server_to_client,
            &server_kex.mac_algorithms_server_to_client,
            "MAC algorithm",
        )?,
        compression_algorithm_client_to_server: select(
            &client_kex.compression_algorithms_client_to_server,
            &server_kex.compression_algorithms_client_to_server,
            "compresion algorithm",
        )?,
        compression_algorithm_server_to_client: select(
            &client_kex.compression_algorithms_server_to_client,
            &server_kex.compression_algorithms_server_to_client,
            "compresion algorithm",
        )?,
    })
}
