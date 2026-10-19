// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! A single owner consumes preparation once and owns native execution and I/O.

use crate::conversation::{Conversation, Phase};
use crate::transport::{Transport, nonblocking};
#[cfg(target_os = "windows")]
use crate::windows_io::Pipe;
use crate::wire::{
    Binding, Completion, Data, Failure, FailureCode, Frame, Kind, MAX_DATA, Preparation,
    ProtocolError, Result, VERSION,
};
use std::collections::VecDeque;
#[cfg(target_os = "linux")]
use std::fs::File as Pipe;
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

const CONTROL_IDLE: Duration = Duration::from_secs(5);
const CLEANUP_LIMIT: Duration = Duration::from_secs(2);
const INPUT_LIMIT: usize = 4 * MAX_DATA;

/// Native implementations must retain the exact process object, never signal a
/// caller PID, and make these operations nonblocking. A terminal observation
/// includes backend teardown. Go independently owns the helper's outer custody.
pub trait Process {
    fn take_pipes(&mut self) -> Result<Pipes>;
    fn try_wait(&mut self) -> Result<Option<i32>>;
    fn stop(&mut self) -> Result<()>;
}

pub struct Pipes {
    pub input: Option<Pipe>,
    pub output: Option<Pipe>,
    pub error: Option<Pipe>,
}

pub trait Prepared {
    /// Ownership, including every admitted object and image, moves into launch.
    fn launch(self: Box<Self>) -> Result<Box<dyn Process>>;
}

pub trait Engine {
    fn prepare(&mut self, plan: &Preparation) -> Result<Box<dyn Prepared>>;
}

struct Active {
    process: Box<dyn Process>,
    pipes: Pipes,
    input: VecDeque<Vec<u8>>,
    input_offset: usize,
    input_bytes: usize,
    input_eof: bool,
    deadline: Instant,
    cleanup_deadline: Option<Instant>,
    status: Option<i32>,
    stopped: bool,
    timed_out: bool,
    truncated: bool,
    emitted: u64,
    limit: u64,
}

impl Active {
    fn new(mut process: Box<dyn Process>, plan: &Preparation, now: Instant) -> Result<Self> {
        let pipes = process.take_pipes()?;
        if pipes.input.is_none() || pipes.output.is_none() || pipes.error.is_none() {
            process.stop()?;
            return Err(ProtocolError);
        }
        for file in [&pipes.input, &pipes.output, &pipes.error]
            .into_iter()
            .flatten()
        {
            if nonblocking(file).is_err() {
                process.stop()?;
                return Err(ProtocolError);
            }
        }
        Ok(Self {
            process,
            pipes,
            input: VecDeque::new(),
            input_offset: 0,
            input_bytes: 0,
            input_eof: false,
            deadline: now + Duration::from_millis(u64::from(plan.timeout_ms)),
            cleanup_deadline: None,
            status: None,
            stopped: false,
            timed_out: false,
            truncated: false,
            emitted: 0,
            limit: u64::from(plan.output_limit),
        })
    }

    fn stop(&mut self, now: Instant, timeout: bool) -> Result<()> {
        self.pipes.input.take();
        self.input.clear();
        self.input_bytes = 0;
        self.input_offset = 0;
        self.input_eof = true;
        self.timed_out |= timeout;
        self.cleanup_deadline.get_or_insert(now + CLEANUP_LIMIT);
        if !self.stopped && self.status.is_none() {
            self.process.stop()?;
            self.stopped = true;
        }
        Ok(())
    }

    fn input(&mut self, bytes: Vec<u8>) -> Result<()> {
        // Conversation has already checked host InputEof ordering. A native
        // reader can close before its exit is observed; admitted late input is
        // then discarded without turning an ordinary EPIPE into protocol loss.
        if self.pipes.input.is_none() {
            return Ok(());
        }
        if self.input_eof {
            return Err(ProtocolError);
        }
        if bytes.len() > INPUT_LIMIT.saturating_sub(self.input_bytes) {
            return Err(ProtocolError);
        }
        self.input_bytes += bytes.len();
        self.input.push_back(bytes);
        Ok(())
    }

    fn flush_input(&mut self) -> Result<()> {
        if let Some(file) = &mut self.pipes.input {
            while let Some(front) = self.input.front() {
                match file.write(&front[self.input_offset..]) {
                    Ok(0) => return Err(ProtocolError),
                    Ok(count) => {
                        self.input_offset += count;
                        self.input_bytes -= count;
                        if self.input_offset == front.len() {
                            self.input.pop_front();
                            self.input_offset = 0;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    // A child that has stopped consuming stdin is ordinary.
                    Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                        self.pipes.input.take();
                        self.input.clear();
                        self.input_bytes = 0;
                        self.input_eof = true;
                        return Ok(());
                    }
                    Err(_) => return Err(ProtocolError),
                }
            }
        }
        if self.input_eof && self.input.is_empty() {
            self.pipes.input.take();
        }
        Ok(())
    }

    fn tick(&mut self, now: Instant) -> Result<()> {
        if self.status.is_none() {
            // A terminal result has no trusted exit timestamp. If the first
            // observation is late, conservatively classify it as timeout even
            // when try_wait can already return an exit status.
            if now >= self.deadline {
                self.stop(now, true)?;
            }
            self.status = self.process.try_wait()?;
            if self.status.is_some() {
                self.pipes.input.take();
                self.input.clear();
                self.input_bytes = 0;
                self.cleanup_deadline.get_or_insert(now + CLEANUP_LIMIT);
            }
        }
        if self.cleanup_deadline.is_some_and(|limit| now >= limit) && !self.complete() {
            return Err(ProtocolError);
        }
        self.flush_input()
    }

    fn read(&mut self, stderr: bool, now: Instant) -> Result<Option<Data>> {
        let stream = if stderr { "stderr" } else { "stdout" };
        let slot = if stderr {
            &mut self.pipes.error
        } else {
            &mut self.pipes.output
        };
        let Some(file) = slot.as_mut() else {
            return Ok(None);
        };
        let mut bytes = vec![0; MAX_DATA];
        let count = match file.read(&mut bytes) {
            Ok(0) => {
                slot.take();
                return Ok(None);
            }
            Ok(count) => count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(None);
            }
            Err(_) => return Err(ProtocolError),
        };
        let admitted = count.min(self.limit.saturating_sub(self.emitted) as usize);
        if count > admitted {
            self.truncated = true;
            self.stop(now, false)?;
        }
        self.emitted += admitted as u64;
        bytes.truncate(admitted);
        Ok((admitted != 0).then_some(Data {
            stream: stream.into(),
            bytes,
        }))
    }

    fn complete(&self) -> bool {
        self.status.is_some() && self.pipes.output.is_none() && self.pipes.error.is_none()
    }

    #[cfg(target_os = "linux")]
    fn poll_descriptors(&self, read_output: bool) -> Vec<(i32, i16)> {
        let mut descriptors = Vec::with_capacity(3);
        if read_output {
            for file in [&self.pipes.output, &self.pipes.error]
                .into_iter()
                .flatten()
            {
                descriptors.push((file.as_raw_fd(), libc::POLLIN));
            }
        }
        if !self.input.is_empty() {
            if let Some(file) = &self.pipes.input {
                descriptors.push((file.as_raw_fd(), libc::POLLOUT));
            }
        }
        descriptors
    }

    #[cfg(target_os = "windows")]
    fn poll_descriptors(&self, read_output: bool) -> Vec<crate::windows_io::Handle> {
        let mut events = Vec::with_capacity(3);
        if read_output {
            for pipe in [&self.pipes.output, &self.pipes.error]
                .into_iter()
                .flatten()
            {
                if let Some(event) = pipe.wait_handle() {
                    events.push(event);
                }
            }
        }
        if !self.input.is_empty() {
            if let Some(event) = self.pipes.input.as_ref().and_then(Pipe::wait_handle) {
                events.push(event);
            }
        }
        events
    }
}

pub struct Owner<E> {
    engine: E,
    transport: Transport,
    conversation: Option<Conversation>,
    sequence: u64,
    prepare: Option<Box<dyn Prepared>>,
    plan: Option<Preparation>,
    active: Option<Active>,
    launch_request: u64,
    destroy_request: Option<u64>,
    idle_deadline: Instant,
    finished: bool,
    read_stderr_next: bool,
}

impl<E: Engine> Owner<E> {
    pub fn new(engine: E, transport: Transport) -> Self {
        Self {
            engine,
            transport,
            conversation: None,
            sequence: 0,
            prepare: None,
            plan: None,
            active: None,
            launch_request: 0,
            destroy_request: None,
            idle_deadline: Instant::now() + CONTROL_IDLE,
            finished: false,
            read_stderr_next: false,
        }
    }

    fn frame(&mut self, kind: Kind, request: u64) -> Result<Frame> {
        self.sequence = self.sequence.checked_add(1).ok_or(ProtocolError)?;
        let binding: Binding = self
            .conversation
            .as_ref()
            .ok_or(ProtocolError)?
            .binding()
            .clone();
        Ok(Frame {
            version: VERSION,
            sequence: self.sequence,
            request,
            binding,
            kind,
            plan: None,
            data: None,
            size: None,
            result: None,
            failure: None,
        })
    }

    fn emit(&mut self, frame: Frame) -> Result<()> {
        self.conversation
            .as_mut()
            .ok_or(ProtocolError)?
            .peer(&frame)?;
        self.transport.enqueue(&frame)
    }

    fn fail(&mut self, request: u64, code: FailureCode) -> Result<()> {
        let mut frame = self.frame(Kind::Failed, request)?;
        frame.failure = Some(Failure { code });
        self.emit(frame)?;
        self.finished = true;
        Ok(())
    }

    fn command(&mut self, frame: Frame, now: Instant) -> Result<()> {
        if self.conversation.is_none() {
            self.conversation = Some(Conversation::new(frame.binding.clone())?);
        }
        let conversation = self.conversation.as_mut().ok_or(ProtocolError)?;
        let was_exited = conversation.phase() == Phase::Exited;
        conversation.host(&frame)?;
        self.idle_deadline = now + CONTROL_IDLE;
        match frame.kind {
            Kind::Prepare => {
                let plan = frame.plan.ok_or(ProtocolError)?;
                match self.engine.prepare(&plan) {
                    Ok(prepared) => {
                        self.prepare = Some(prepared);
                        self.plan = Some(plan);
                        let reply = self.frame(Kind::Prepared, frame.request)?;
                        self.emit(reply)?;
                    }
                    Err(_) => self.fail(frame.request, FailureCode::PreparationFailed)?,
                }
            }
            Kind::Launch => {
                let prepared = self.prepare.take().ok_or(ProtocolError)?;
                let plan = self.plan.as_ref().ok_or(ProtocolError)?;
                match prepared
                    .launch()
                    .and_then(|process| Active::new(process, plan, now))
                {
                    Ok(active) => {
                        self.active = Some(active);
                        self.launch_request = frame.request;
                        let reply = self.frame(Kind::Started, frame.request)?;
                        self.emit(reply)?;
                    }
                    Err(_) => self.fail(frame.request, FailureCode::LaunchFailed)?,
                }
            }
            Kind::Input if !was_exited => self
                .active
                .as_mut()
                .ok_or(ProtocolError)?
                .input(frame.data.ok_or(ProtocolError)?.bytes)?,
            Kind::InputEof if !was_exited => {
                self.active.as_mut().ok_or(ProtocolError)?.input_eof = true;
            }
            Kind::Cancel if !was_exited => self
                .active
                .as_mut()
                .ok_or(ProtocolError)?
                .stop(now, false)?,
            Kind::Destroy => {
                self.prepare.take();
                self.destroy_request = Some(frame.request);
                if let Some(active) = &mut self.active {
                    active.stop(now, false)?;
                }
            }
            Kind::Wait | Kind::Input | Kind::InputEof | Kind::Cancel => {}
            _ => return Err(ProtocolError),
        }
        Ok(())
    }

    fn tick(&mut self, now: Instant) -> Result<()> {
        if let Some(active) = &mut self.active {
            active.tick(now)?;
        }
        // Pending host frames propagate backpressure to the native pipe, rather
        // than filling eight frames before the transport's 500ms stall bound.
        // Alternate successful reads so a busy stdout cannot starve stderr.
        if self.transport.flushed() {
            for stderr in [self.read_stderr_next, !self.read_stderr_next] {
                if let Some(active) = &mut self.active {
                    if let Some(data) = active.read(stderr, now)? {
                        self.read_stderr_next = !stderr;
                        let mut reply = self.frame(Kind::Output, self.launch_request)?;
                        reply.data = Some(data);
                        self.emit(reply)?;
                        break;
                    }
                }
            }
        }
        if self.active.as_ref().is_some_and(Active::complete) {
            let active = self.active.take().ok_or(ProtocolError)?;
            let result = Completion {
                exit_code: active.status.ok_or(ProtocolError)?,
                timed_out: active.timed_out,
                truncated: active.truncated,
            };
            // Drop only after the native terminal observation and both pipe
            // EOFs. No unbounded worker/reader join occurs on this path.
            drop(active);
            let mut reply = self.frame(Kind::Exited, self.launch_request)?;
            reply.result = Some(result);
            self.emit(reply)?;
            self.idle_deadline = now + CONTROL_IDLE;
        }
        if let Some(request) = self.destroy_request {
            if self.active.is_none() {
                self.plan.take();
                let reply = self.frame(Kind::Destroyed, request)?;
                self.emit(reply)?;
                self.destroy_request = None;
                self.finished = true;
            }
        }
        if self.active.is_none() && !self.finished && now >= self.idle_deadline {
            return Err(ProtocolError);
        }
        Ok(())
    }

    fn contain_after_error(&mut self) -> Result<()> {
        self.prepare.take();
        let Some(mut active) = self.active.take() else {
            return Ok(());
        };
        active.stop(Instant::now(), false)?;
        let limit = Instant::now() + CLEANUP_LIMIT;
        loop {
            let now = Instant::now();
            active.tick(now)?;
            // During failure cleanup no bytes are forwarded or retained.
            active.read(false, now)?;
            active.read(true, now)?;
            if active.complete() {
                return Ok(());
            }
            if now >= limit {
                return Err(ProtocolError);
            }
            self.transport
                .poll(&active.poll_descriptors(true), Duration::from_millis(10))?;
        }
    }

    pub fn run(mut self) -> Result<()> {
        let result = (|| {
            loop {
                let now = Instant::now();
                self.transport.flush(now)?;
                if self.finished {
                    if self.transport.flushed() {
                        return Ok(());
                    }
                } else {
                    // Bound host work per tick so a full command pipe cannot
                    // starve native output, cancellation or the deadline.
                    for _ in 0..4 {
                        let Some(frame) = self.transport.receive()? else {
                            break;
                        };
                        self.command(frame, now)?;
                        if self.finished {
                            break;
                        }
                    }
                    self.tick(now)?;
                }
                let descriptors = self
                    .active
                    .as_ref()
                    .map(|active| active.poll_descriptors(self.transport.flushed()))
                    .unwrap_or_default();
                self.transport
                    .poll(&descriptors, Duration::from_millis(10))?;
            }
        })();
        if result.is_err() {
            self.contain_after_error()?;
        }
        result
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::wire::{Decoder, Encoder, Filesystem};
    use std::fs::File;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Counts {
        prepared: AtomicUsize,
        launched: AtomicUsize,
        stopped: AtomicUsize,
    }
    struct FakeEngine(Arc<Counts>);
    struct FakePrepared(Arc<Counts>);
    struct FakeProcess {
        counts: Arc<Counts>,
        pipes: Option<Pipes>,
        _reader: UnixStream,
        stopped: bool,
    }

    fn file(stream: UnixStream) -> File {
        File::from(OwnedFd::from(stream))
    }

    impl FakeProcess {
        fn new(counts: Arc<Counts>) -> Self {
            let (input, reader) = UnixStream::pair().unwrap();
            let (output, mut writer) = UnixStream::pair().unwrap();
            writer.write_all(b"fixed synthetic output").unwrap();
            drop(writer);
            let (error, writer) = UnixStream::pair().unwrap();
            drop(writer);
            Self {
                counts,
                pipes: Some(Pipes {
                    input: Some(file(input)),
                    output: Some(file(output)),
                    error: Some(file(error)),
                }),
                _reader: reader,
                stopped: false,
            }
        }
    }

    impl Engine for FakeEngine {
        fn prepare(&mut self, _: &Preparation) -> Result<Box<dyn Prepared>> {
            self.0.prepared.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(FakePrepared(self.0.clone())))
        }
    }
    impl Prepared for FakePrepared {
        fn launch(self: Box<Self>) -> Result<Box<dyn Process>> {
            self.0.launched.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(FakeProcess::new(self.0.clone())))
        }
    }
    impl Process for FakeProcess {
        fn take_pipes(&mut self) -> Result<Pipes> {
            self.pipes.take().ok_or(ProtocolError)
        }
        fn try_wait(&mut self) -> Result<Option<i32>> {
            Ok(self.stopped.then_some(23))
        }
        fn stop(&mut self) -> Result<()> {
            self.counts.stopped.fetch_add(1, Ordering::SeqCst);
            self.stopped = true;
            Ok(())
        }
    }

    fn plan(limit: u32) -> Preparation {
        Preparation {
            backend: "bubblewrap".into(),
            argv: vec!["/.defenseclaw/payload".into()],
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
            output_limit: limit,
        }
    }

    fn commands(plan: Preparation, kinds: &[Kind]) -> Vec<Frame> {
        let binding = Binding {
            session_id: "fixed".into(),
            session_digest: format!("sha256:{}", "a".repeat(64)),
            policy_digest: format!("sha256:{}", "b".repeat(64)),
            runtime_digest: format!("sha256:{}", "c".repeat(64)),
            harness_digest: format!("sha256:{}", "d".repeat(64)),
            preparation_hash: plan.hash().unwrap(),
        };
        kinds
            .iter()
            .enumerate()
            .map(|(index, kind)| Frame {
                version: VERSION,
                sequence: index as u64 + 1,
                request: index as u64 + 1,
                binding: binding.clone(),
                kind: *kind,
                plan: (*kind == Kind::Prepare).then(|| plan.clone()),
                data: None,
                size: None,
                result: None,
                failure: None,
            })
            .collect()
    }

    fn owner(
        kinds: &[Kind],
        limit: u32,
    ) -> (Owner<FakeEngine>, UnixStream, UnixStream, Arc<Counts>) {
        let (mut host_write, peer_read) = UnixStream::pair().unwrap();
        let (peer_write, host_read) = UnixStream::pair().unwrap();
        host_read
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        for frame in commands(plan(limit), kinds) {
            Encoder::new(&mut host_write).encode(&frame).unwrap();
        }
        let counts = Arc::new(Counts::default());
        (
            Owner::new(
                FakeEngine(counts.clone()),
                Transport::new(file(peer_read), file(peer_write)).unwrap(),
            ),
            host_write,
            host_read,
            counts,
        )
    }

    #[test]
    fn real_private_pipes_consume_once_and_correlate_destroy_after_exit() {
        let (owner, _writer, reader, counts) = owner(
            &[
                Kind::Prepare,
                Kind::Launch,
                Kind::InputEof,
                Kind::Wait,
                Kind::Destroy,
            ],
            1024,
        );
        owner.run().unwrap();
        let mut decoder = Decoder::new(reader);
        let frames: Vec<_> = (0..5).map(|_| decoder.decode().unwrap()).collect();
        assert_eq!(
            frames.iter().map(|frame| frame.kind).collect::<Vec<_>>(),
            [
                Kind::Prepared,
                Kind::Started,
                Kind::Output,
                Kind::Exited,
                Kind::Destroyed
            ]
        );
        assert_eq!(frames[2].request, 2);
        assert_eq!(frames[3].request, 2);
        assert_eq!(frames[4].request, 5);
        assert_eq!(frames[3].result.unwrap().exit_code, 23);
        assert_eq!(counts.prepared.load(Ordering::SeqCst), 1);
        assert_eq!(counts.launched.load(Ordering::SeqCst), 1);
        assert_eq!(counts.stopped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn replay_launch_contains_owned_process_without_second_execution() {
        let (owner, _writer, _reader, counts) =
            owner(&[Kind::Prepare, Kind::Launch, Kind::Launch], 1024);
        assert!(owner.run().is_err());
        assert_eq!(counts.launched.load(Ordering::SeqCst), 1);
        assert_eq!(counts.stopped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn output_cap_stops_and_marks_truncated_without_excess_bytes() {
        let (owner, _writer, reader, counts) =
            owner(&[Kind::Prepare, Kind::Launch, Kind::Destroy], 8);
        owner.run().unwrap();
        let mut decoder = Decoder::new(reader);
        let frames: Vec<_> = (0..5).map(|_| decoder.decode().unwrap()).collect();
        assert_eq!(frames[2].data.as_ref().unwrap().bytes.len(), 8);
        assert!(frames[3].result.unwrap().truncated);
        assert_eq!(counts.stopped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn deadline_and_input_backpressure_do_not_require_blocking_wait() {
        let counts = Arc::new(Counts::default());
        let mut plan = plan(1024);
        plan.timeout_ms = 1;
        let now = Instant::now();
        let mut active =
            Active::new(Box::new(FakeProcess::new(counts.clone())), &plan, now).unwrap();
        for _ in 0..4 {
            active.input(vec![b'x'; MAX_DATA]).unwrap();
        }
        assert!(active.input(vec![b'x']).is_err());
        active.tick(now + Duration::from_millis(2)).unwrap();
        assert!(active.timed_out);
        assert!(active.input.is_empty());
        assert!(active.pipes.input.is_none());
        assert_eq!(counts.stopped.load(Ordering::SeqCst), 1);
        active.tick(now + Duration::from_millis(3)).unwrap();
        assert_eq!(active.status, Some(23));
    }

    #[test]
    fn first_terminal_observation_after_deadline_is_conservatively_timed_out() {
        let counts = Arc::new(Counts::default());
        let mut plan = plan(1024);
        plan.timeout_ms = 1;
        let now = Instant::now();
        let mut process = FakeProcess::new(counts.clone());
        // Make a terminal result immediately available, but give the owner no
        // native evidence of an exit timestamp before its first late tick.
        process.stopped = true;
        let mut active = Active::new(Box::new(process), &plan, now).unwrap();
        active.tick(now + Duration::from_millis(2)).unwrap();
        assert_eq!(active.status, Some(23));
        assert!(active.timed_out);
        assert_eq!(counts.stopped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn native_closed_stdin_discards_admitted_input_but_host_eof_stays_strict() {
        let counts = Arc::new(Counts::default());
        let process = FakeProcess::new(counts.clone());
        process._reader.shutdown(std::net::Shutdown::Read).unwrap();
        let now = Instant::now();
        let mut active = Active::new(Box::new(process), &plan(1024), now).unwrap();
        active.input(b"before native close".to_vec()).unwrap();
        active.flush_input().unwrap();
        assert!(active.pipes.input.is_none());
        active.input(b"after native close".to_vec()).unwrap();
        assert_eq!(active.input_bytes, 0);
        assert!(active.input.is_empty());

        let (mut owner, _writer, _reader, _) = owner(&[], 1024);
        let mut frames = commands(
            plan(1024),
            &[Kind::Prepare, Kind::Launch, Kind::InputEof, Kind::Input],
        );
        owner.command(frames.remove(0), now).unwrap();
        owner.command(frames.remove(0), now).unwrap();
        owner.command(frames.remove(0), now).unwrap();
        let mut late = frames.remove(0);
        late.data = Some(Data {
            stream: "stdin".into(),
            bytes: b"after host EOF".to_vec(),
        });
        assert!(owner.command(late, now).is_err());
        assert_eq!(owner.conversation.as_ref().unwrap().phase(), Phase::Closed);
    }

    #[test]
    fn pending_host_output_backpressures_native_reads_without_poll_spin_and_resumes_fairly() {
        let (mut owner, _writer, reader, _) = owner(&[], 1024);
        let now = Instant::now();
        for frame in commands(plan(1024), &[Kind::Prepare, Kind::Launch]) {
            owner.command(frame, now).unwrap();
        }
        let (stderr, mut producer) = UnixStream::pair().unwrap();
        producer.write_all(b"fixed stderr").unwrap();
        drop(producer);
        let active = owner.active.as_mut().unwrap();
        active.pipes.error = Some(file(stderr));
        nonblocking(active.pipes.error.as_ref().unwrap()).unwrap();
        for index in 0..100 {
            owner.tick(now + Duration::from_millis(index)).unwrap();
            let active = owner.active.as_ref().unwrap();
            assert_eq!(active.emitted, 0);
            assert!(active.poll_descriptors(false).is_empty());
            assert_eq!(active.poll_descriptors(true).len(), 2);
        }
        owner.transport.flush(now).unwrap();
        assert!(owner.transport.flushed());
        owner.tick(now).unwrap();
        let stdout_bytes = owner.active.as_ref().unwrap().emitted;
        assert_eq!(stdout_bytes, b"fixed synthetic output".len() as u64);
        owner.tick(now).unwrap();
        assert_eq!(owner.active.as_ref().unwrap().emitted, stdout_bytes);
        owner.transport.flush(now).unwrap();
        owner.tick(now).unwrap();
        owner.transport.flush(now).unwrap();
        let mut decoder = Decoder::new(reader);
        let frames: Vec<_> = (0..4).map(|_| decoder.decode().unwrap()).collect();
        assert_eq!(frames[2].data.as_ref().unwrap().stream, "stdout");
        assert_eq!(frames[3].data.as_ref().unwrap().stream, "stderr");
        assert_eq!(frames[3].data.as_ref().unwrap().bytes, b"fixed stderr");
    }
}
