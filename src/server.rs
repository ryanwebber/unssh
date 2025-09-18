use std::sync::Arc;

use smol::io::{AsyncBufReadExt, AsyncWriteExt};
use tracing::Instrument;

use crate::{
    config::Config,
    id::ShortCodeGenerator,
    session::{Session, channel, pty::PtySize},
    transport::{
        buffer::{Packet, PacketEncodable},
        common::OwnedByteString,
        kex,
        packet::{self},
        stream::{EncryptedPacketReader, EncryptedPacketWriter, PacketPayload},
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

        let mut reader = EncryptedPacketReader::new(stream.clone());
        let mut writer = EncryptedPacketWriter::new(stream.clone());

        // Algorithm negotiation
        {
            let server_kexinit = kex::default_kex_init();
            let server_kexinit_bytes = writer.write_packet(&server_kexinit).await?;

            let client_response = reader.read_packet().await?;
            let client_kexinit: packet::KexInit = client_response.try_unpack()?;
            let client_kexinit_bytes = client_response.into_bytes();

            let kex_context = kex::KexContext {
                client_version: client_banner.trim_end().to_string(),
                server_version: server_banner.trim_end().to_string(),
                client_kexinit: client_kexinit_bytes,
                server_kexinit: server_kexinit_bytes,
            };

            let kex_result = kex::perform_key_exchange(
                &mut rng,
                self.config.as_ref(),
                &kex_context,
                &server_kexinit,
                &client_kexinit,
                &mut reader,
                &mut writer,
            )
            .await?;

            reader.set_cipher(kex_result.decryption_cipher, kex_result.mac_verifier);
            writer.set_cipher(kex_result.encryption_cipher, kex_result.mac_signer);
        }

        tracing::info!("Beginning main packet processing loop");

        // Channel for events from the reader task to the main event loop
        let (tx, rx) = smol::channel::unbounded::<Event>();

        // Spawn a task to run the main event loop
        let task_tx = tx.clone();
        let client_task: smol::Task<anyhow::Result<()>> = smol::spawn(async move {
            loop {
                let packet = reader.read_packet().await?;
                task_tx
                    .send(Event::PacketReceived { payload: packet })
                    .await?;
            }
        });

        // Main event processing loop
        let event_loop = ConnectionEventLoop { rx, tx, writer };

        event_loop.run().await?;
        client_task.await?;

        Ok(())
    }
}

struct ConnectionEventLoop {
    rx: smol::channel::Receiver<Event>,
    tx: smol::channel::Sender<Event>,
    writer: EncryptedPacketWriter<smol::net::TcpStream>,
}

impl ConnectionEventLoop {
    async fn send(
        &mut self,
        packet: &(impl Packet + PacketEncodable + std::fmt::Debug),
    ) -> anyhow::Result<()> {
        self.writer.write_packet(packet).await?;
        Ok(())
    }

    async fn run(mut self) -> anyhow::Result<()> {
        let mut session = Session::new();
        while let Ok(event) = self.rx.recv().await {
            match event {
                Event::PacketReceived { payload } => {
                    match payload.message_number()? {
                        packet::Disconnect::MESSAGE_NUMBER => {
                            let msg: packet::Disconnect = payload.try_unpack()?;
                            tracing::info!("Received client disconnect packet: {:#?}", msg);
                            return Ok(());
                        }
                        packet::Ignore::MESSAGE_NUMBER => {
                            let msg: packet::Ignore = payload.try_unpack()?;
                            tracing::info!("Received ignore packet: {:#?}", msg);
                        }
                        packet::Debug::MESSAGE_NUMBER => {
                            let msg: packet::Debug = payload.try_unpack()?;
                            tracing::info!("Received debug packet: {:#?}", msg);
                        }
                        packet::ServiceRequest::MESSAGE_NUMBER => {
                            let msg: packet::ServiceRequest = payload.try_unpack()?;
                            tracing::info!("Received service request: {:#?}", msg);

                            match msg.service_name.as_str() {
                                "ssh-userauth" => {
                                    self.send(&packet::ServiceAccept {
                                        service_name: msg.service_name.clone(),
                                    })
                                    .await?;
                                }
                                _ => {
                                    tracing::warn!(
                                        "Unsupported service request: {}",
                                        msg.service_name
                                    );

                                    self.send(&packet::Disconnect {
                                        reason_code: 3,
                                        description: format!(
                                            "Unsupported service: {}",
                                            msg.service_name
                                        ),
                                        language_tag: "".to_string(),
                                    })
                                    .await?;

                                    return Ok(());
                                }
                            }
                        }
                        packet::UserAuthRequest::MESSAGE_NUMBER => {
                            let msg: packet::UserAuthRequest = payload.try_unpack()?;
                            tracing::info!("Received user auth request: {:#?}", msg);

                            // User auth banner
                            self.send(&packet::UserAuthBanner {
                                message: "Welcome to the unssh server!\n".to_string(),
                                language_tag: "".to_string(),
                            })
                            .await?;

                            // For now, we accept zero authentication and just auth everyone
                            self.send(&packet::UserAuthSuccess).await?;
                        }
                        packet::ChannelOpen::MESSAGE_NUMBER => {
                            let msg: packet::ChannelOpen = payload.try_unpack()?;
                            tracing::info!("Received channel open request: {:#?}", msg);

                            if msg.channel_type != "session" {
                                tracing::warn!("Unsupported channel type: {}", msg.channel_type);

                                self.send(&packet::ChannelOpenFailure {
                                    recipient_channel: msg.sender_channel,
                                    reason_code: 3,
                                    description: format!(
                                        "Unsupported channel type: {}",
                                        msg.channel_type
                                    ),
                                    language_tag: "".to_string(),
                                })
                                .await?;

                                continue;
                            }

                            // Create a new channel in the session
                            let (channel, local_id) =
                                session.open_channel(channel::RemoteID(msg.sender_channel));

                            self.send(&packet::ChannelOpenConfirmation {
                                recipient_channel: channel.remote_id().as_u32(),
                                sender_channel: local_id.as_u32(),
                                initial_window_size: msg.initial_window_size, // Echo back the client's window size
                                maximum_packet_size: msg.maximum_packet_size, // Echo back the client's max packet size
                            })
                            .await?;
                        }
                        packet::ChannelRequest::MESSAGE_NUMBER => {
                            let msg: packet::ChannelRequest = payload.try_unpack()?;
                            tracing::info!("Received channel request: {:#?}", msg);

                            let channel = match session
                                .channel_mut(channel::LocalID(msg.recipient_channel))
                            {
                                Some(chan) => chan,
                                None => {
                                    // Disconnect the client for requesting on an unknown channel
                                    self.send(&packet::Disconnect {
                                        reason_code: 2,
                                        description: format!(
                                            "Channel request on unknown channel: {}",
                                            msg.recipient_channel
                                        ),
                                        language_tag: String::new(),
                                    })
                                    .await?;

                                    anyhow::bail!(
                                        "Channel request on unknown channel: {}",
                                        msg.recipient_channel
                                    );
                                }
                            };

                            let response: anyhow::Result<()> = match &msg.request_type {
                                packet::ChannelRequestType::Env { name, value } => {
                                    channel.set_env(name.clone(), value.clone());
                                    Ok(())
                                }
                                packet::ChannelRequestType::Exec { .. } => {
                                    // TODO: Support exec requests
                                    Err(anyhow::anyhow!("Exec requests are not supported yet"))
                                }
                                packet::ChannelRequestType::PtyReq {
                                    columns,
                                    rows,
                                    width_px,
                                    height_px,
                                    ..
                                } => channel.open_pty(PtySize {
                                    rows: *rows as u16,
                                    cols: *columns as u16,
                                    pixel_width: *width_px as u16,
                                    pixel_height: *height_px as u16,
                                }),
                                packet::ChannelRequestType::Shell => {
                                    channel.spawn_shell(self.tx.clone())
                                }
                                packet::ChannelRequestType::Subsystem { .. } => {
                                    // TODO: Support subsystems like SFTP
                                    Err(anyhow::anyhow!("Subsystems are not implemented yet"))
                                }
                                packet::ChannelRequestType::Unknown { name } => {
                                    Err(anyhow::anyhow!("Unknown channel request type: {}", name))
                                }
                                &packet::ChannelRequestType::X11Req { .. } => {
                                    Err(anyhow::anyhow!("X11 forwarding is not supported"))
                                }
                            };

                            if let Err(ref e) = response {
                                tracing::warn!("Channel request failed: {}", e);
                            }

                            if msg.want_reply {
                                match response {
                                    Ok(..) => {
                                        self.send(&packet::ChannelSuccess {
                                            recipient_channel: channel.remote_id().as_u32(),
                                        })
                                        .await?;
                                    }
                                    Err(..) => {
                                        self.send(&packet::ChannelFailure {
                                            recipient_channel: channel.remote_id().as_u32(),
                                        })
                                        .await?;
                                    }
                                }
                            }
                        }
                        packet::ChannelData::MESSAGE_NUMBER => {
                            let msg: packet::ChannelData = payload.try_unpack()?;
                            tracing::info!("Received channel data: {:#?}", msg);

                            let channel = match session
                                .channel_mut(channel::LocalID(msg.recipient_channel))
                            {
                                Some(chan) => chan,
                                None => {
                                    // Disconnect the client for sending data on an unknown channel
                                    self.send(&packet::Disconnect {
                                        reason_code: 2,
                                        description: format!(
                                            "Channel data on unknown channel: {}",
                                            msg.recipient_channel
                                        ),
                                        language_tag: String::new(),
                                    })
                                    .await?;

                                    anyhow::bail!(
                                        "Channel data on unknown channel: {}",
                                        msg.recipient_channel
                                    );
                                }
                            };

                            // Try to write the data to the channel's PTY
                            if let Some(pty_writer) = channel.pty_writer_mut() {
                                smol::pin!(pty_writer);
                                pty_writer.write_all(&msg.data.bytes).await?;
                            } else {
                                tracing::warn!(
                                    "Received data for channel {} which has no PTY",
                                    msg.recipient_channel
                                );

                                Err(anyhow::anyhow!(
                                    "Channel {} has no PTY to write data to",
                                    msg.recipient_channel
                                ))?;
                            }
                        }
                        packet::ChannelClose::MESSAGE_NUMBER => {
                            let msg: packet::ChannelClose = payload.try_unpack()?;
                            tracing::info!("Received channel close: {:#?}", msg);

                            let local_id = channel::LocalID(msg.recipient_channel);
                            if session.close_channel(local_id) {
                                // Acknowledge the close
                                self.send(&packet::ChannelClose {
                                    recipient_channel: msg.recipient_channel,
                                })
                                .await?;
                            }
                        }
                        _ => {
                            tracing::info!(
                                "Received unhandled packet type: {}",
                                payload.message_number()?
                            );

                            // Write a disconnect and close the connection
                            self.send(&packet::Disconnect {
                                reason_code: 2,
                                description: format!(
                                    "Unhandled packet type: {}",
                                    payload.message_number()?
                                ),
                                language_tag: String::new(),
                            })
                            .await?;

                            anyhow::bail!("Unhandled packet type: {}", payload.message_number()?);
                        }
                    }
                }
                Event::PtyClosed { channel } => {
                    tracing::info!("PTY closed for channel {:?}", channel);

                    // Send EOF
                    self.send(&packet::ChannelEof {
                        recipient_channel: channel.as_u32(),
                    })
                    .await?;

                    // Send close
                    self.send(&packet::ChannelClose {
                        recipient_channel: channel.as_u32(),
                    })
                    .await?;

                    if let Some(local_id) = session.find_local_id(channel) {
                        session.close_channel(local_id);
                    }
                }
                Event::PtyOutput {
                    data,
                    channel,
                    stream,
                } => {
                    // TODO: Handle stderr vs stdout
                    _ = stream;

                    self.send(&packet::ChannelData {
                        recipient_channel: channel.as_u32(),
                        data: OwnedByteString { bytes: data },
                    })
                    .await?;
                }
            }
        }

        tracing::info!("Event loop exiting");

        Ok(())
    }
}

#[derive(Clone)]
pub enum Event {
    PacketReceived {
        payload: PacketPayload,
    },
    PtyClosed {
        channel: channel::RemoteID,
    },
    PtyOutput {
        data: Vec<u8>,
        channel: channel::RemoteID,
        stream: OutputStream,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputStream {
    Stdout,
}
