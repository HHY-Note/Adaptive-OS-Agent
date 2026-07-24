// SPDX-License-Identifier: Apache-2.0

//! Shared bounded four-byte length framing for local Unix sockets.

use std::io::{self, Read};

const PREFIX_BYTES: usize = std::mem::size_of::<u32>();

/// Encodes one already-serialized body with a network-order length prefix.
pub(crate) fn encode(body: &[u8], max_frame_bytes: usize) -> io::Result<Vec<u8>> {
    if body.is_empty() || body.len() > max_frame_bytes {
        return Err(invalid_data("local frame exceeds configured limit"));
    }
    let length: u32 = body
        .len()
        .try_into()
        .map_err(|_| invalid_data("local frame exceeds u32"))?;
    let mut frame = Vec::with_capacity(PREFIX_BYTES + body.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(body);
    Ok(frame)
}

/// Incremental frame reader retaining partial socket reads across timeouts.
#[derive(Default)]
pub(crate) struct FrameReader {
    buffer: Vec<u8>,
}

impl FrameReader {
    /// Reads at most one complete frame while preserving any trailing bytes.
    pub(crate) fn read<R: Read>(
        &mut self,
        stream: &mut R,
        max_frame_bytes: usize,
    ) -> io::Result<Option<Vec<u8>>> {
        if let Some(frame) = self.take(max_frame_bytes)? {
            return Ok(Some(frame));
        }
        let mut chunk = [0_u8; 8192];
        match stream.read(&mut chunk) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(count) => self.buffer.extend_from_slice(&chunk[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
        if self.buffer.len() > max_frame_bytes.saturating_add(PREFIX_BYTES) {
            return Err(invalid_data("local frame buffer exceeded configured limit"));
        }
        self.take(max_frame_bytes)
    }

    #[cfg(test)]
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    pub(crate) fn take(&mut self, max_frame_bytes: usize) -> io::Result<Option<Vec<u8>>> {
        if self.buffer.len() < PREFIX_BYTES {
            return Ok(None);
        }
        let mut prefix = [0_u8; PREFIX_BYTES];
        prefix.copy_from_slice(&self.buffer[..PREFIX_BYTES]);
        let length = u32::from_be_bytes(prefix) as usize;
        if length == 0 || length > max_frame_bytes {
            return Err(invalid_data("invalid local frame length"));
        }
        let total = PREFIX_BYTES + length;
        if self.buffer.len() < total {
            return Ok(None);
        }
        let frame = self.buffer[PREFIX_BYTES..total].to_vec();
        self.buffer.drain(..total);
        Ok(Some(frame))
    }
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::{encode, FrameReader};

    #[test]
    fn preserves_partial_and_trailing_frames() {
        let first = encode(b"one", 16).unwrap();
        let second = encode(b"two", 16).unwrap();
        let mut reader = FrameReader::default();
        reader.push(&first[..2]);
        assert!(reader.take(16).unwrap().is_none());
        reader.push(&first[2..]);
        reader.push(&second);
        assert_eq!(reader.take(16).unwrap().unwrap(), b"one");
        assert_eq!(reader.take(16).unwrap().unwrap(), b"two");
    }
}
