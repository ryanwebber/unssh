use std::collections::HashMap;

use crate::session::channel::{Channel, LocalID, RemoteID};

pub mod channel;
pub mod pty;

const CHANNEL_ZERO: u32 = 9000;

pub struct Session {
    channels: HashMap<LocalID, Channel>,
}

impl Session {
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
        }
    }

    pub fn open_channel(&mut self, remote_id: RemoteID) -> (&Channel, LocalID) {
        let local_id = LocalID(CHANNEL_ZERO.wrapping_add(self.channels.len() as u32));
        let channel = self
            .channels
            .entry(local_id)
            .or_insert_with(|| Channel::new(remote_id));

        (channel, local_id)
    }

    pub fn channel_mut(&mut self, local_id: &LocalID) -> Option<&mut Channel> {
        self.channels.get_mut(local_id)
    }

    pub fn iter_readers_mut(
        &mut self,
    ) -> impl Iterator<Item = &mut (dyn smol::io::AsyncRead + Send)> {
        self.channels
            .values_mut()
            .filter_map(|ch| ch.pty_reader_mut())
    }
}
