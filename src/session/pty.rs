use smol::io::AsyncWrite;

pub use portable_pty::CommandBuilder;

pub struct Pty {}

pub struct PtySize {
    pub rows: u16,
    pub cols: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
}

impl Pty {
    pub fn try_open(_: PtySize) -> anyhow::Result<Self> {
        Ok(Pty {})
    }

    pub fn spawn_command(&mut self, _: CommandBuilder) -> anyhow::Result<()> {
        Ok(())
    }

    pub fn writer_mut(&mut self) -> Option<&mut (dyn AsyncWrite + Send + Unpin)> {
        todo!()
    }
}

impl Pty {}
