use std::os::fd::OwnedFd;

use smol::{
    io::{AsyncReadExt, AsyncWrite},
    process::Command,
};

use crate::{
    server::{self, OutputStream},
    session::channel::RemoteID,
};

pub struct Pty {
    state: PtyState,
}

pub enum PtyState {
    Ready {
        slave_fd: OwnedFd,
        master_fd: OwnedFd,
    },
    Running {
        task: smol::Task<anyhow::Result<()>>,
        writer: Box<dyn AsyncWrite + Send + Unpin>,
    },
}

pub struct PtySize {
    pub rows: u16,
    pub cols: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
}

impl Pty {
    pub fn try_open(size: PtySize) -> anyhow::Result<Self> {
        let size = nix::pty::Winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: size.pixel_width,
            ws_ypixel: size.pixel_height,
        };

        let pair = nix::pty::openpty(Some(&size), None)?;
        Ok(Self {
            state: PtyState::Ready {
                slave_fd: pair.slave,
                master_fd: pair.master,
            },
        })
    }

    pub fn close(self) {
        match self.state {
            PtyState::Running { task, .. } => {
                _ = task.cancel();
            }
            _ => {}
        }
    }

    pub fn spawn_command(
        &mut self,
        mut cmd: Command,
        channel: RemoteID,
        tx: smol::channel::Sender<server::Event>,
    ) -> anyhow::Result<()> {
        let (slave_fd, master_fd) = match &self.state {
            PtyState::Ready {
                slave_fd,
                master_fd,
            } => (slave_fd, master_fd),
            PtyState::Running { .. } => {
                anyhow::bail!("PTY is already running a command");
            }
        };

        // Spawn the shell command
        let mut child = cmd
            .stderr(slave_fd.try_clone()?)
            .stdout(slave_fd.try_clone()?)
            .stdin(slave_fd.try_clone()?)
            .spawn()?;

        let reader = {
            let file = std::fs::File::from(master_fd.try_clone()?);
            smol::Async::new(file)?
        };

        let writer = {
            let file = std::fs::File::from(master_fd.try_clone()?);
            smol::Async::new(file)?
        };

        // Spawn a task to read from the PTY and send output events
        let task = smol::spawn(async move {
            let mut reader = smol::io::BufReader::new(reader);
            let mut buf = [0u8; 1024];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => {
                        // EOF
                        break;
                    }
                    Ok(n) => {
                        let data = buf[..n].to_vec();
                        let event = server::Event::PtyOutput {
                            channel,
                            data,
                            stream: OutputStream::Stdout,
                        };

                        if tx.send(event).await.is_err() {
                            // Receiver dropped
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading from PTY: {}", e);
                        break;
                    }
                }
            }

            let status = child.status().await?;

            tracing::info!(
                "PTY command exited: {:?} (channel = {:?})",
                status.code(),
                channel
            );

            // Notify that the channel is closed
            tx.send(server::Event::PtyClosed { channel }).await?;

            Ok(())
        });

        self.state = PtyState::Running {
            task,
            writer: Box::new(writer),
        };

        Ok(())
    }

    pub fn writer_mut(&mut self) -> Option<&mut (dyn AsyncWrite + Send + Unpin)> {
        match &mut self.state {
            PtyState::Running { writer, .. } => Some(writer.as_mut()),
            _ => None,
        }
    }
}

impl Pty {}
