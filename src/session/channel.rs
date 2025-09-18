use smol::io::AsyncWrite;

use crate::{
    server,
    session::pty::{Pty, PtySize},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocalID(pub u32);

impl LocalID {
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RemoteID(pub u32);

impl RemoteID {
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

pub struct Channel {
    id: RemoteID,
    env: Vec<(String, String)>,
    pty: Option<Pty>,
}

impl Channel {
    pub fn new(id: RemoteID) -> Self {
        Self {
            id,
            env: Vec::new(),
            pty: None,
        }
    }

    pub fn remote_id(&self) -> RemoteID {
        self.id
    }

    pub fn close(self) {
        if let Some(pty) = self.pty {
            pty.close();
        }
    }

    pub fn set_env(&mut self, name: String, value: String) {
        self.env.push((name, value));
    }

    pub fn open_pty(&mut self, size: PtySize) -> anyhow::Result<()> {
        if self.pty.is_none() {
            let pty = Pty::try_open(size)?;
            self.pty = Some(pty);
            Ok(())
        } else {
            Ok(())
        }
    }

    pub fn spawn_shell(&mut self, tx: smol::channel::Sender<server::Event>) -> anyhow::Result<()> {
        let Some(ref mut pty) = self.pty else {
            anyhow::bail!("PTY not opened");
        };

        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());

        tracing::info!("Spawning shell: {}", shell);

        let mut cmd = smol::process::Command::new(&shell);
        for (name, value) in &self.env {
            cmd.env(name, value);
        }

        pty.spawn_command(cmd, self.id, tx)?;

        Ok(())
    }

    pub fn pty_writer_mut(&mut self) -> Option<&mut (dyn AsyncWrite + Send + Unpin)> {
        self.pty.as_mut().and_then(|pty| pty.writer_mut())
    }
}
