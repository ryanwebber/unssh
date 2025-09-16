use clap::{Args, Parser, Subcommand, command};

mod id;
mod logging;
mod server;
mod transport;

/// A dodgy SSH server that you shouldn't use
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the ssh server
    Run {
        #[command(flatten)]
        connection_options: ConnectionOptions,
    },
}

#[derive(Debug, Args)]
struct ConnectionOptions {
    /// Address to listen on
    #[arg(long, default_value = "127.0.0.1")]
    address: String,

    /// Port to listen on
    #[arg(long, default_value = "22")]
    port: u16,
}

fn main() {
    if let Err(e) = logging::init() {
        eprintln!("Failed to initialize logging: {e}");
    };

    let args = Arguments::parse();

    tracing::info!("Starting {} with args: {args:#?}", env!("CARGO_PKG_NAME"));
    match args.command {
        Command::Run { connection_options } => {
            let addr = format!("{}:{}", connection_options.address, connection_options.port);
            match std::net::TcpListener::bind(&addr) {
                Ok(listener) => {
                    let server = server::Server::new(listener);
                    if let Err(e) = server.run() {
                        tracing::error!("Server error: {e}");
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to bind to {}: {e}", addr);
                }
            }
        }
    }
}
