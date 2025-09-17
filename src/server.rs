use smol::io::{AsyncBufReadExt, AsyncWriteExt};
use tracing::Instrument;

use crate::{
    id::ShortCodeGenerator,
    transport::{
        kex,
        packet::{self},
        stream::{CryptoState, EncryptedPacketReader, EncryptedPacketWriter},
    },
};

pub struct Server {
    listener: std::net::TcpListener,
    id_generator: ShortCodeGenerator,
}

impl Server {
    pub fn new(listener: std::net::TcpListener) -> Self {
        Server {
            listener,
            id_generator: ShortCodeGenerator::new(8),
        }
    }

    pub fn run(self) -> anyhow::Result<()> {
        smol::block_on(async { self.run_async().await })
    }

    async fn run_async(mut self) -> anyhow::Result<()> {
        tracing::info!("Server running on {:?}", self.listener.local_addr()?);
        let async_listener = {
            let asyncified = smol::Async::new(self.listener)?;
            smol::net::TcpListener::from(asyncified)
        };

        loop {
            let (stream, addr) = async_listener.accept().await?;
            let id = self.id_generator.next();
            let span = tracing::info_span!("client", id = %id, addr = %addr);

            tracing::info!("Accepted connection from {} with id: {}", addr, id);

            let future = async {
                let connection = Connection::new();
                if let Err(e) = connection.handle(stream).await {
                    tracing::error!("Error handling connection: {e}");
                }
            };

            smol::spawn(future.instrument(span)).detach();
        }
    }
}

struct Connection;

impl Connection {
    fn new() -> Self {
        Connection
    }

    async fn handle(&self, mut stream: smol::net::TcpStream) -> anyhow::Result<()> {
        tracing::info!("Handling connection");

        let client_banner = {
            let mut reader = smol::io::BufReader::new(stream.clone());
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            line
        };

        tracing::info!("Client banner received: {:?}", client_banner.trim_end());

        let server_banner = format!(
            "SSH-2.0-{}_{}\r\n",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );

        stream.write_all(server_banner.as_bytes()).await?;

        stream.flush().await?;

        // TODO: This cannot be right, surely this is not secure?
        let mut rng = rand::rngs::OsRng::new()?;
        let mut crypto_state = CryptoState::null();

        let mut reader = EncryptedPacketReader::new(stream.clone());
        let mut writer = EncryptedPacketWriter::new(stream.clone());

        // Algorithm negotiation
        {
            let server_kexinit = kex::default_kex_init();
            let server_kexinit_bytes = writer
                .write_packet(&server_kexinit, &mut crypto_state)
                .await?;

            let client_response = reader.read_some_packet(&mut crypto_state).await?;
            let client_kexinit: packet::KexInit = client_response.try_unpack()?;
            let client_kexinit_bytes = client_response.into_bytes();

            let kex_context = kex::KexContext {
                client_version: client_banner.trim_end().to_string(),
                server_version: server_banner.trim_end().to_string(),
                client_kexinit: client_kexinit_bytes,
                server_kexinit: server_kexinit_bytes,
            };

            kex::perform_key_exchange(
                &mut rng,
                &mut crypto_state,
                &kex_context,
                &server_kexinit,
                &client_kexinit,
                &mut reader,
                &mut writer,
            )
            .await?;
        }

        // Main packet processing loop
        loop {
            tracing::info!("Waiting for packet...");

            let packet = reader.read_some_packet(&mut crypto_state).await?;
            match packet.message_number()? {
                1 => {
                    let disconnect: packet::Disconnect = packet.try_unpack()?;
                    tracing::info!("Received client disconnect packet: {:#?}", disconnect);
                    return Ok(());
                }
                2 => {
                    let ignore: packet::Ignore = packet.try_unpack()?;
                    tracing::info!("Received ignore packet: {:#?}", ignore);
                }
                5 => {
                    let service_request: packet::ServiceRequest = packet.try_unpack()?;
                    tracing::info!("Received service request: {:#?}", service_request);
                    anyhow::bail!("Service requests not supported yet");
                }
                _ => {
                    tracing::info!(
                        "Received unhandled packet type: {}",
                        packet.message_number()?
                    );

                    // Write a disconnect and close the connection
                    let disconnect = packet::Disconnect {
                        reason_code: 2,
                        description: "Protocol error: unhandled packet type".to_string(),
                        language_tag: "".to_string(),
                    };

                    writer.write_packet(&disconnect, &mut crypto_state).await?;

                    anyhow::bail!("Unhandled packet type: {}", packet.message_number()?);
                }
            }
        }
    }
}
