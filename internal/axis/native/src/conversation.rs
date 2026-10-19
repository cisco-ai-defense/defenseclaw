// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! One serialized session's protocol admission; no native authority lives here.

use crate::wire::{Binding, Frame, Kind, ProtocolError, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    New,
    Preparing,
    Ready,
    Launching,
    Running,
    Stopping,
    Exited,
    Destroying,
    Destroyed,
    Closed,
}

pub struct Conversation {
    binding: Binding,
    phase: Phase,
    host_sequence: u64,
    peer_sequence: u64,
    last_request: u64,
    prepare: u64,
    launch: u64,
    wait: u64,
    destroy: u64,
    terminal: bool,
    input_eof: bool,
    exited: bool,
    output: u64,
    limit: u32,
}

impl Conversation {
    pub fn new(binding: Binding) -> Result<Self> {
        binding.validate()?;
        Ok(Self {
            binding,
            phase: Phase::New,
            host_sequence: 0,
            peer_sequence: 0,
            last_request: 0,
            prepare: 0,
            launch: 0,
            wait: 0,
            destroy: 0,
            terminal: false,
            input_eof: false,
            exited: false,
            output: 0,
            limit: 0,
        })
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn binding(&self) -> &Binding {
        &self.binding
    }

    fn refuse<T>(&mut self) -> Result<T> {
        self.phase = Phase::Closed;
        Err(ProtocolError)
    }

    fn valid(&self, frame: &Frame, previous: u64) -> bool {
        !matches!(self.phase, Phase::Closed | Phase::Destroyed)
            && previous.checked_add(1) == Some(frame.sequence)
            && frame.binding == self.binding
            && frame.validate().is_ok()
    }

    pub fn host(&mut self, frame: &Frame) -> Result<()> {
        if !self.valid(frame, self.host_sequence) || frame.request <= self.last_request {
            return self.refuse();
        }
        match frame.kind {
            Kind::Prepare if self.phase == Phase::New => {
                let plan = frame.plan.as_ref().ok_or(ProtocolError)?;
                self.prepare = frame.request;
                self.terminal = plan.terminal.is_some();
                self.limit = plan.output_limit;
                self.phase = Phase::Preparing;
            }
            Kind::Launch if self.phase == Phase::Ready => {
                self.launch = frame.request;
                self.phase = Phase::Launching;
            }
            Kind::Input
                if self.phase == Phase::Exited
                    || self.phase == Phase::Running && !self.input_eof => {}
            Kind::InputEof
                if self.phase == Phase::Exited
                    || self.phase == Phase::Running && !self.input_eof =>
            {
                self.input_eof = true;
            }
            Kind::Resize
                if matches!(self.phase, Phase::Running | Phase::Exited) && self.terminal => {}
            Kind::Wait
                if matches!(self.phase, Phase::Running | Phase::Stopping | Phase::Exited)
                    && self.wait == 0 =>
            {
                self.wait = frame.request;
            }
            Kind::Cancel if matches!(self.phase, Phase::Running | Phase::Exited) => {
                if self.phase != Phase::Exited {
                    self.phase = Phase::Stopping;
                }
            }
            Kind::Destroy
                if matches!(
                    self.phase,
                    Phase::Ready | Phase::Running | Phase::Stopping | Phase::Exited
                ) =>
            {
                self.destroy = frame.request;
                self.phase = Phase::Destroying;
            }
            _ => return self.refuse(),
        }
        self.host_sequence = frame.sequence;
        self.last_request = frame.request;
        Ok(())
    }

    pub fn peer(&mut self, frame: &Frame) -> Result<()> {
        if !self.valid(frame, self.peer_sequence) {
            return self.refuse();
        }
        match frame.kind {
            Kind::Prepared if self.phase == Phase::Preparing && frame.request == self.prepare => {
                self.phase = Phase::Ready;
            }
            Kind::Started if self.phase == Phase::Launching && frame.request == self.launch => {
                self.phase = Phase::Running;
            }
            Kind::Output
                if self.launch != 0
                    && !self.exited
                    && frame.request == self.launch
                    && matches!(
                        self.phase,
                        Phase::Running | Phase::Stopping | Phase::Destroying
                    ) =>
            {
                let data = frame.data.as_ref().ok_or(ProtocolError)?;
                if self.terminal && data.stream != "stdout"
                    || data.bytes.len() as u64 > u64::from(self.limit).saturating_sub(self.output)
                {
                    return self.refuse();
                }
                self.output += data.bytes.len() as u64;
            }
            Kind::Exited
                if self.launch != 0
                    && !self.exited
                    && frame.request == self.launch
                    && matches!(
                        self.phase,
                        Phase::Running | Phase::Stopping | Phase::Destroying
                    ) =>
            {
                self.exited = true;
                if self.phase != Phase::Destroying {
                    self.phase = Phase::Exited;
                }
            }
            Kind::Destroyed if self.phase == Phase::Destroying && frame.request == self.destroy => {
                self.phase = Phase::Destroyed;
            }
            Kind::Failed if frame.request <= self.last_request => {
                self.phase = Phase::Closed;
            }
            _ => return self.refuse(),
        }
        self.peer_sequence = frame.sequence;
        Ok(())
    }

    pub fn close(&mut self) {
        self.phase = Phase::Closed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Completion, Filesystem, Preparation};

    fn prepare() -> Frame {
        let plan = Preparation {
            backend: "bubblewrap".into(),
            argv: vec!["/guest/agent".into()],
            environment: vec![],
            workdir: "/guest/work".into(),
            filesystem: Filesystem {
                read: vec![],
                write: vec!["/guest/work".into()],
                deny: vec![],
            },
            offline: true,
            terminal: None,
            timeout_ms: 1000,
            output_limit: 1024,
        };
        Frame {
            version: 1,
            sequence: 1,
            request: 1,
            kind: Kind::Prepare,
            binding: Binding {
                session_id: "fixed".into(),
                session_digest: format!("sha256:{}", "a".repeat(64)),
                policy_digest: format!("sha256:{}", "b".repeat(64)),
                runtime_digest: format!("sha256:{}", "c".repeat(64)),
                harness_digest: format!("sha256:{}", "d".repeat(64)),
                preparation_hash: plan.hash().unwrap(),
            },
            plan: Some(plan),
            data: None,
            size: None,
            result: None,
            failure: None,
        }
    }

    #[test]
    fn prepared_handle_cannot_admit_duplicate_launch() {
        let mut frame = prepare();
        let mut state = Conversation::new(frame.binding.clone()).unwrap();
        state.host(&frame).unwrap();
        frame.kind = Kind::Prepared;
        frame.plan = None;
        state.peer(&frame).unwrap();
        frame.kind = Kind::Launch;
        frame.sequence = 2;
        frame.request = 2;
        state.host(&frame).unwrap();
        frame.sequence = 3;
        frame.request = 3;
        assert!(state.host(&frame).is_err());
        assert_eq!(state.phase(), Phase::Closed);
    }

    #[test]
    fn late_controls_do_not_reopen_exited_session_and_destroy_is_separate() {
        let mut frame = prepare();
        let mut state = Conversation::new(frame.binding.clone()).unwrap();
        state.host(&frame).unwrap();
        frame.plan = None;
        frame.kind = Kind::Prepared;
        state.peer(&frame).unwrap();
        frame.kind = Kind::Launch;
        frame.sequence = 2;
        frame.request = 2;
        state.host(&frame).unwrap();
        frame.kind = Kind::Started;
        state.peer(&frame).unwrap();
        frame.kind = Kind::Exited;
        frame.sequence = 3;
        frame.result = Some(Completion {
            exit_code: 23,
            timed_out: false,
            truncated: false,
        });
        state.peer(&frame).unwrap();
        frame.result = None;
        frame.kind = Kind::Cancel;
        frame.request = 3;
        state.host(&frame).unwrap();
        assert_eq!(state.phase(), Phase::Exited);
        frame.kind = Kind::Destroy;
        frame.sequence = 4;
        frame.request = 4;
        state.host(&frame).unwrap();
        frame.kind = Kind::Destroyed;
        state.peer(&frame).unwrap();
        assert_eq!(state.phase(), Phase::Destroyed);
    }
}
