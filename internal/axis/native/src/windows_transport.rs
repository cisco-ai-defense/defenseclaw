// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! TASK-only platform transport. Existing wire/frame/conversation stay shared.

pub use crate::windows_io::nonblocking;
use crate::windows_io::{Handle, Pipe, wait_handles};
use crate::wire::{self, Frame, ProtocolError, Result};
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

const QUEUE_FRAMES: usize = 8;
const BLOCKED_LIMIT: Duration = Duration::from_millis(500);
struct Pending {
    bytes: Vec<u8>,
    offset: usize,
}

pub struct Transport {
    input: Pipe,
    output: Pipe,
    incoming: Vec<u8>,
    outgoing: VecDeque<Pending>,
    blocked_since: Option<Instant>,
    poisoned: bool,
}

impl Transport {
    // The caller has already consumed the exact capability prefix from input.
    // No JSON byte was read by that prefix reader and no output prefix exists.
    pub fn new(input: Pipe, output: Pipe) -> Result<Self> {
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
    pub fn receive(&mut self) -> Result<Option<Frame>> {
        if self.poisoned {
            return Err(ProtocolError);
        }
        loop {
            let target = if self.incoming.len() < 4 {
                4
            } else {
                let size =
                    u32::from_be_bytes(self.incoming[..4].try_into().map_err(|_| ProtocolError)?)
                        as usize;
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
            let mut bytes = [0; wire::MAX_DATA];
            let count = bytes.len().min(target - self.incoming.len());
            match self.input.read(&mut bytes[..count]) {
                Ok(0) => return self.refuse(),
                Ok(count) => self.incoming.extend_from_slice(&bytes[..count]),
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
    pub fn poll(&self, extra: &[Handle], timeout: Duration) -> Result<()> {
        if extra.len() > 64 {
            return Err(ProtocolError);
        }
        let mut events = Vec::with_capacity(2 + extra.len());
        for event in self
            .input
            .wait_handle()
            .into_iter()
            .chain(self.output.wait_handle())
            .chain(extra.iter().copied())
        {
            if events.contains(&event) {
                return Err(ProtocolError);
            }
            events.push(event);
        }
        wait_handles(&events, timeout).map_err(|_| ProtocolError)
    }
    pub fn close(&mut self, deadline: Instant) -> Result<()> {
        self.poisoned = true;
        let input = self.input.close(deadline);
        let output = self.output.close(deadline);
        if input.is_err() || output.is_err() {
            Err(ProtocolError)
        } else {
            Ok(())
        }
    }
}
