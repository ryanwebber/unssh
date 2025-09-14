use std::net::{TcpListener, TcpStream};

use tiny_id::ShortCodeGenerator;
use tracing::Instrument;

pub struct Server {
    listener: TcpListener,
    id_generator: ShortCodeGenerator<char>,
}

impl Server {
    pub fn new(listener: TcpListener) -> Self {
        Server {
            listener,
            id_generator: ShortCodeGenerator::new_alphanumeric(8),
        }
    }

    pub fn run(mut self) -> anyhow::Result<()> {
        smol::block_on(async { self.run_async().await })
    }

    async fn run_async(&mut self) -> anyhow::Result<()> {
        tracing::info!("Server running on {:?}", self.listener.local_addr()?);
        loop {
            let (stream, addr) = self.listener.accept()?;
            let id = self.id_generator.next_string();
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

    async fn handle(&self, _stream: TcpStream) -> anyhow::Result<()> {
        tracing::info!("Handling connection");

        // TODO: Implement SSH protocol handling here

        Ok(())
    }
}
