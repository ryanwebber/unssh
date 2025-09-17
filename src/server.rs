use std::sync::Arc;

use smol::io::{AsyncBufReadExt, AsyncWriteExt};
use tracing::Instrument;

use crate::{
    config::Config,
    id::ShortCodeGenerator,
    transport::{
        buffer::Packet,
        kex,
        packet::{self},
        stream::{CryptoState, EncryptedPacketReader, EncryptedPacketWriter},
    },
};

pub struct Server {
    config: Arc<Config>,
    listener: std::net::TcpListener,
    id_generator: ShortCodeGenerator,
}

impl Server {
    pub fn new(listener: std::net::TcpListener, config: Arc<Config>) -> Self {
        Server {
            config,
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

            let config = self.config.clone();
            let future = async {
                let connection = Connection::new(config);
                if let Err(e) = connection.handle(stream).await {
                    tracing::error!("Error handling connection: {e}");
                }
            };

            smol::spawn(future.instrument(span)).detach();
        }
    }
}

struct Connection {
    config: Arc<Config>,
}

impl Connection {
    fn new(config: Arc<Config>) -> Self {
        Connection { config }
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
                self.config.as_ref(),
                &kex_context,
                &server_kexinit,
                &client_kexinit,
                &mut reader,
                &mut writer,
            )
            .await?;
        }

        tracing::info!("Beginning main packet processing loop");

        // Main packet processing loop
        loop {
            let packet = reader.read_some_packet(&mut crypto_state).await?;
            match packet.message_number()? {
                packet::Disconnect::MESSAGE_NUMBER => {
                    let msg: packet::Disconnect = packet.try_unpack()?;
                    tracing::info!("Received client disconnect packet: {:#?}", msg);
                    return Ok(());
                }
                packet::Ignore::MESSAGE_NUMBER => {
                    let msg: packet::Ignore = packet.try_unpack()?;
                    tracing::info!("Received ignore packet: {:#?}", msg);
                }
                packet::Debug::MESSAGE_NUMBER => {
                    let msg: packet::Debug = packet.try_unpack()?;
                    tracing::info!("Received debug packet: {:#?}", msg);
                }
                packet::ServiceRequest::MESSAGE_NUMBER => {
                    let msg: packet::ServiceRequest = packet.try_unpack()?;
                    tracing::info!("Received service request: {:#?}", msg);

                    match msg.service_name.as_str() {
                        "ssh-userauth" => {
                            let service_accept = packet::ServiceAccept {
                                service_name: msg.service_name.clone(),
                            };
                            writer
                                .write_packet(&service_accept, &mut crypto_state)
                                .await?;
                        }
                        _ => {
                            tracing::warn!("Unsupported service request: {}", msg.service_name);

                            let disconnect = packet::Disconnect {
                                reason_code: 3,
                                description: format!("Unsupported service: {}", msg.service_name),
                                language_tag: "".to_string(),
                            };

                            writer.write_packet(&disconnect, &mut crypto_state).await?;
                            return Ok(());
                        }
                    }
                }
                packet::UserAuthRequest::MESSAGE_NUMBER => {
                    let msg: packet::UserAuthRequest = packet.try_unpack()?;
                    tracing::info!("Received user auth request: {:#?}", msg);

                    writer
                        .write_packet(
                            &packet::UserAuthBanner {
                                message: "Welcome to the unssh server!\n".to_string(),
                                language_tag: "".to_string(),
                            },
                            &mut crypto_state,
                        )
                        .await?;

                    // For now, we accept zero authentication and just auth everyone
                    writer
                        .write_packet(&packet::UserAuthSuccess, &mut crypto_state)
                        .await?;
                }
                packet::ChannelOpen::MESSAGE_NUMBER => {
                    let msg: packet::ChannelOpen = packet.try_unpack()?;
                    tracing::info!("Received channel open request: {:#?}", msg);

                    if msg.channel_type != "session" {
                        tracing::warn!("Unsupported channel type: {}", msg.channel_type);

                        let failure = packet::ChannelOpenFailure {
                            recipient_channel: msg.sender_channel,
                            reason_code: 3,
                            description: format!("Unsupported channel type: {}", msg.channel_type),
                            language_tag: "".to_string(),
                        };

                        writer.write_packet(&failure, &mut crypto_state).await?;
                        continue;
                    }

                    // For now, we only support one channel
                    let server_channel = 0;

                    let open_confirmation = packet::ChannelOpenConfirmation {
                        recipient_channel: msg.sender_channel,
                        sender_channel: server_channel,
                        initial_window_size: msg.initial_window_size, // Echo back the client's window size
                        maximum_packet_size: msg.maximum_packet_size, // Echo back the client's max packet size
                    };

                    writer
                        .write_packet(&open_confirmation, &mut crypto_state)
                        .await?;
                }
                packet::ChannelRequest::MESSAGE_NUMBER => {
                    let msg: packet::ChannelRequest = packet.try_unpack()?;
                    tracing::info!("Received channel request: {:#?}", msg);

                    match &msg.request_type {
                        packet::ChannelRequestType::Env { .. } => {
                            // TODO: Handle this
                        }
                        packet::ChannelRequestType::PtyReq { .. } => {
                            // TODO: Handle this
                        }
                        packet::ChannelRequestType::Unknown { name } => {
                            tracing::warn!("Received unknown channel request type: {}", name);
                        }
                    }

                    if msg.want_reply {
                        writer
                            .write_packet(
                                &packet::ChannelSuccess {
                                    recipient_channel: msg.recipient_channel,
                                },
                                &mut crypto_state,
                            )
                            .await?;
                    }
                }
                _ => {
                    tracing::info!(
                        "Received unhandled packet type: {}",
                        packet.message_number()?
                    );

                    // Write a disconnect and close the connection
                    let disconnect = packet::Disconnect {
                        reason_code: 2,
                        description: format!("Unhandled packet type: {}", packet.message_number()?),
                        language_tag: String::new(),
                    };

                    writer.write_packet(&disconnect, &mut crypto_state).await?;

                    anyhow::bail!("Unhandled packet type: {}", packet.message_number()?);
                }
            }
        }
    }
}
