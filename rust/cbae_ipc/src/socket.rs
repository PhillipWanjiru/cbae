//! Length-prefixed message framing over a Unix socket.
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

pub struct IpcSocket {
    stream: UnixStream,
}

impl IpcSocket {
    pub fn connect(path: &str) -> std::io::Result<Self> {
        Ok(Self { stream: UnixStream::connect(path)? })
    }

    /// Send a message — 4-byte LE length prefix + UTF-8 JSON payload.
    pub fn send(&mut self, msg: &str) -> std::io::Result<()> {
        let bytes  = msg.as_bytes();
        let length = (bytes.len() as u32).to_le_bytes();
        self.stream.write_all(&length)?;
        self.stream.write_all(bytes)?;
        Ok(())
    }

    /// Receive one message — reads length prefix then payload.
    pub fn recv(&mut self) -> std::io::Result<String> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        self.stream.read_exact(&mut payload)?;
        String::from_utf8(payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}
