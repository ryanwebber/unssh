use std::os::fd::FromRawFd;

use portable_pty::ChildKiller;
use smol::io::{AsyncRead, AsyncWrite};

pub use portable_pty::CommandBuilder;

pub struct Pty {
    state: PtyState,
}

pub enum PtyState {
    Ready {
        pair: portable_pty::PtyPair,
    },
    Running {
        killer: Box<dyn ChildKiller + Send>,
        writer: Box<dyn AsyncWrite + Send + Unpin>,
        reader: Box<dyn AsyncRead + Send + Unpin>,
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
        let pty_system = portable_pty::native_pty_system();
        let pair = pty_system.openpty(portable_pty::PtySize {
            rows: size.rows,
            cols: size.cols,
            pixel_width: size.pixel_width,
            pixel_height: size.pixel_height,
        })?;

        Ok(Pty {
            state: PtyState::Ready { pair },
        })
    }

    pub fn spawn_command(&mut self, cmd: CommandBuilder) -> anyhow::Result<()> {
        let pair = match &self.state {
            PtyState::Ready { pair } => pair,
            PtyState::Running { .. } => {
                anyhow::bail!("PTY is already running a command");
            }
        };

        let Some(pty_fd) = pair.master.as_raw_fd() else {
            anyhow::bail!("Failed to get PTY master file descriptor");
        };

        let child = pair.slave.spawn_command(cmd)?;
        let killer = child.clone_killer();

        // Open the master fd as async reader and writer using the raw fd
        let reader = unsafe { std::fs::File::from_raw_fd(pty_fd) };
        let writer = unsafe { std::fs::File::from_raw_fd(pty_fd) };

        let async_writer = smol::Async::new(writer)?;
        let async_reader = smol::Async::new(reader)?;

        self.state = PtyState::Running {
            killer,
            writer: Box::new(async_writer),
            reader: Box::new(async_reader),
        };

        Ok(())
    }

    pub fn reader_mut(&mut self) -> Option<&mut (dyn AsyncRead + Send)> {
        match &mut self.state {
            PtyState::Running { reader, .. } => Some(reader.as_mut()),
            _ => None,
        }
    }

    pub fn writer_mut(&mut self) -> Option<&mut (dyn AsyncWrite + Send + Unpin)> {
        match &mut self.state {
            PtyState::Running { writer, .. } => Some(writer.as_mut()),
            _ => None,
        }
    }
}

impl Pty {}
