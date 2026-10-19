// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! Bounded nonblocking private pipes. No background reader or writer exists.

use crate::wire::{self, Frame, ProtocolError, Result};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

const QUEUE_FRAMES: usize = 8;
const BLOCKED_LIMIT: Duration = Duration::from_millis(500);

pub fn nonblocking(file: &File) -> Result<()> {
    let fd = file.as_raw_fd();
    // SAFETY: fcntl only changes status flags on this held descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(ProtocolError);
    }
    Ok(())
}

struct Pending {
    bytes: Vec<u8>,
    offset: usize,
}

pub struct Transport {
    input: File,
    output: File,
    incoming: Vec<u8>,
    outgoing: VecDeque<Pending>,
    blocked_since: Option<Instant>,
    poisoned: bool,
}

impl Transport {
    pub fn new(input: File, output: File) -> Result<Self> {
        nonblocking(&input)?;
        nonblocking(&output)?;
        Ok(Self {
            input,
            output,
            incoming: Vec::new(),
            outgoing: VecDeque::new(),
            blocked_since: None,
            poisoned: false,
        })
    }

    fn refuse<T>(&mut self) -> Result<T> {
        self.poisoned = true;
        Err(ProtocolError)
    }

    /// Read only the current frame, without consuming a later command.
    pub fn receive(&mut self) -> Result<Option<Frame>> {
        if self.poisoned {
            return Err(ProtocolError);
        }
        loop {
            let target = if self.incoming.len() < 4 {
                4
            } else {
                let size = u32::from_be_bytes(self.incoming[..4].try_into().unwrap()) as usize;
                if size == 0 || size > wire::MAX_FRAME {
                    return self.refuse();
                }
                4 + size
            };
            if self.incoming.len() == target && target > 4 {
                let parsed = wire::parse(&self.incoming[4..]);
                self.incoming.clear();
                return match parsed {
                    Ok(frame) => Ok(Some(frame)),
                    Err(_) => self.refuse(),
                };
            }
            let mut chunk = [0; wire::MAX_DATA];
            let count = chunk.len().min(target - self.incoming.len());
            match self.input.read(&mut chunk[..count]) {
                Ok(0) => return self.refuse(),
                Ok(count) => self.incoming.extend_from_slice(&chunk[..count]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(_) => return self.refuse(),
            }
        }
    }

    pub fn enqueue(&mut self, frame: &Frame) -> Result<()> {
        if self.poisoned || self.outgoing.len() == QUEUE_FRAMES {
            return self.refuse();
        }
        let mut bytes = Vec::new();
        wire::Encoder::new(&mut bytes).encode(frame)?;
        self.outgoing.push_back(Pending { bytes, offset: 0 });
        self.blocked_since.get_or_insert_with(Instant::now);
        Ok(())
    }

    pub fn flush(&mut self, now: Instant) -> Result<()> {
        if self.poisoned {
            return Err(ProtocolError);
        }
        while let Some(front) = self.outgoing.front_mut() {
            match self.output.write(&front.bytes[front.offset..]) {
                Ok(0) => return self.refuse(),
                Ok(count) => {
                    front.offset += count;
                    self.blocked_since = Some(now);
                    if front.offset == front.bytes.len() {
                        self.outgoing.pop_front();
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return self.refuse(),
            }
        }
        if self.outgoing.is_empty() {
            self.blocked_since = None;
        } else if self
            .blocked_since
            .is_some_and(|since| now.saturating_duration_since(since) >= BLOCKED_LIMIT)
        {
            return self.refuse();
        }
        Ok(())
    }

    pub fn flushed(&self) -> bool {
        self.outgoing.is_empty()
    }

    /// A short poll lets the session owner observe lifecycle/deadline state.
    /// No pipe write, native wait or worker join is hidden inside this call.
    pub fn poll(&self, extra: &[(RawFd, i16)], timeout: Duration) -> Result<()> {
        let mut descriptors = vec![
            libc::pollfd {
                fd: self.input.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.output.as_raw_fd(),
                events: if self.flushed() { 0 } else { libc::POLLOUT },
                revents: 0,
            },
        ];
        descriptors.extend(extra.iter().map(|(fd, events)| libc::pollfd {
            fd: *fd,
            events: *events,
            revents: 0,
        }));
        let timeout_ms = timeout.as_millis().min(20) as i32;
        // SAFETY: descriptors is initialized and writable for its full length.
        let count = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                timeout_ms,
            )
        };
        if count < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(ProtocolError);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    fn files() -> (Transport, UnixStream, UnixStream) {
        let (host_write, peer_read) = UnixStream::pair().unwrap();
        let (peer_write, host_read) = UnixStream::pair().unwrap();
        (
            Transport::new(
                File::from(OwnedFd::from(peer_read)),
                File::from(OwnedFd::from(peer_write)),
            )
            .unwrap(),
            host_write,
            host_read,
        )
    }

    #[test]
    fn partial_frame_is_bounded_and_eof_poisons_without_blocking() {
        let (mut transport, mut writer, _reader) = files();
        writer.write_all(&[0, 0, 0, 10, b'{']).unwrap();
        assert!(transport.receive().unwrap().is_none());
        assert_eq!(transport.incoming.len(), 5);
        drop(writer);
        assert!(transport.receive().is_err());
        assert!(transport.poisoned);
        assert!(transport.receive().is_err());
    }

    #[test]
    fn oversized_header_refuses_before_payload_allocation() {
        let (mut transport, mut writer, _reader) = files();
        writer
            .write_all(&((wire::MAX_FRAME + 1) as u32).to_be_bytes())
            .unwrap();
        assert!(transport.receive().is_err());
        assert_eq!(transport.incoming.len(), 4);
    }

    #[test]
    fn output_queue_has_a_hard_count_and_stall_bound() {
        let (mut transport, _writer, _reader) = files();
        let size: libc::c_int = 4096;
        // SAFETY: sets a bounded socket buffer on this synthetic owned pair.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    transport.output.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&size as *const libc::c_int).cast(),
                    std::mem::size_of_val(&size) as libc::socklen_t,
                )
            },
            0
        );
        transport.outgoing.push_back(Pending {
            bytes: vec![0; wire::MAX_FRAME + 4],
            offset: 0,
        });
        let started = Instant::now();
        transport.blocked_since = Some(started);
        // Fill the nonblocking socket, then measure from the last successful
        // write. This is synthetic backpressure, with no contained process.
        transport.flush(started).unwrap();
        while transport.outgoing.len() < QUEUE_FRAMES {
            transport.outgoing.push_back(Pending {
                bytes: vec![0; wire::MAX_FRAME + 4],
                offset: 0,
            });
        }
        transport.flush(started).unwrap();
        assert!(transport.flush(started + BLOCKED_LIMIT).is_err());
    }
}
