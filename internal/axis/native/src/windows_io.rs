// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! TASK-only Windows x86_64 raw-overlapped pipe draft. No thread or launcher.
//! Native structs are pointer-width-specific and statically size checked. The
//! existing lock/dependencies are unchanged: this module uses std only.

use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::io::{self, Read, Write};
use std::mem::{align_of, size_of};
use std::os::windows::io::{FromRawHandle, IntoRawHandle, OwnedHandle};
use std::time::{Duration, Instant};

pub(super) type Handle = usize;
const INVALID: Handle = usize::MAX;
const PENDING: u32 = 997;
const INCOMPLETE: u32 = 996;
const ABORTED: u32 = 995;
const BROKEN_PIPE: u32 = 109;
const NOT_CONNECTED: u32 = 233;
const NOT_FOUND: u32 = 1168;
const MAX_OPERATION: usize = 4 + crate::wire::MAX_FRAME;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Completion {
    Ready,
    Pending,
    TerminalError,
    Unknown,
}
fn completion(error: u32) -> Completion {
    match error {
        0 => Completion::Ready,
        INCOMPLETE => Completion::Pending,
        ABORTED | BROKEN_PIPE | NOT_CONNECTED => Completion::TerminalError,
        _ => Completion::Unknown,
    }
}

#[repr(C)]
pub(super) struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset_or_pointer: u64,
    event: Handle,
}

#[repr(C)]
pub(super) struct IoStatus {
    status_or_pointer: usize,
    pub(super) information: usize,
}

const _: () = assert!(size_of::<Handle>() == 8);
const _: () = assert!(size_of::<Overlapped>() == 32 && align_of::<Overlapped>() == 8);
const _: () = assert!(size_of::<IoStatus>() == 16);

#[link(name = "kernel32")]
unsafe extern "system" {
    fn ReadFile(
        file: Handle,
        buffer: *mut c_void,
        size: u32,
        done: *mut u32,
        operation: *mut Overlapped,
    ) -> i32;
    fn WriteFile(
        file: Handle,
        buffer: *const c_void,
        size: u32,
        done: *mut u32,
        operation: *mut Overlapped,
    ) -> i32;
    fn GetOverlappedResult(
        file: Handle,
        operation: *mut Overlapped,
        done: *mut u32,
        wait: i32,
    ) -> i32;
    fn CancelIoEx(file: Handle, operation: *mut Overlapped) -> i32;
    fn CreateEventW(security: *const c_void, manual: i32, initial: i32, name: *const u16)
    -> Handle;
    fn GetLastError() -> u32;
    fn GetFileType(file: Handle) -> u32;
    fn GetStdHandle(which: u32) -> Handle;
    pub(super) fn CloseHandle(handle: Handle) -> i32;
    pub(super) fn GetHandleInformation(handle: Handle, flags: *mut u32) -> i32;
    pub(super) fn SetHandleInformation(handle: Handle, mask: u32, flags: u32) -> i32;
    fn WaitForMultipleObjects(count: u32, handles: *const Handle, all: i32, millis: u32) -> u32;
    fn Sleep(millis: u32);
    fn ExitProcess(code: u32) -> !;
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationFile(
        file: Handle,
        status: *mut IoStatus,
        output: *mut c_void,
        size: u32,
        class: u32,
    ) -> i32;
}

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "private Windows pipe refused")
}
fn blocked() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "private Windows pipe pending")
}

fn suppress_foreign_iocp(event: Handle) -> io::Result<Handle> {
    if event == 0 || event == INVALID || event & 1 != 0 {
        return Err(refused());
    }
    Ok(event | 1)
}

// Never unwind/free an operation whose terminal completion is unknown. This
// fixed trusted peer fails itself while all storage is still live. The retained
// Go Job owner must then terminate/wait the workload tree. This is a failed
// session, never a successful Rust/Job cleanup observation.
pub(super) fn pending_fatal() -> ! {
    unsafe { ExitProcess(70) }
}

pub(super) struct Owned {
    raw: Handle,
}

impl Owned {
    pub(super) fn take_owned(handle: OwnedHandle) -> io::Result<Self> {
        let owned = Self {
            raw: handle.into_raw_handle() as Handle,
        };
        if owned.raw == 0
            || owned.raw == INVALID
            || unsafe { SetHandleInformation(owned.raw, 1, 0) } == 0
        {
            return Err(refused());
        }
        Ok(owned)
    }
    pub(super) fn into_owned(mut self) -> io::Result<OwnedHandle> {
        if self.raw == 0 || self.raw == INVALID {
            return Err(refused());
        }
        let raw = std::mem::replace(&mut self.raw, 0);
        Ok(unsafe { OwnedHandle::from_raw_handle(raw as *mut c_void) })
    }
    pub(super) fn take_inherited(raw: Handle) -> io::Result<Self> {
        if raw == 0 || raw == INVALID || raw > isize::MAX as usize {
            return Err(refused());
        }
        let owned = Self { raw };
        let mut flags = 0;
        if unsafe { GetHandleInformation(raw, &mut flags) } == 0
            || flags & 1 == 0
            || unsafe { SetHandleInformation(raw, 1, 0) } == 0
        {
            return Err(refused());
        }
        Ok(owned)
    }
    pub(super) fn raw(&self) -> Handle {
        self.raw
    }
    fn event() -> io::Result<Self> {
        let raw = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if raw == 0 || raw == INVALID {
            return Err(refused());
        }
        Ok(Self { raw })
    }
    pub(super) fn close(&mut self) -> io::Result<()> {
        if self.raw == 0 {
            return Ok(());
        }
        let raw = std::mem::replace(&mut self.raw, 0);
        if unsafe { CloseHandle(raw) } == 0 {
            return Err(refused());
        }
        Ok(())
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        if self.close().is_err() {
            pending_fatal();
        }
    }
}

enum Buffer {
    // Only the kernel mutates these cells while a read is pending. No byte is
    // observed by Rust until terminal completion is established.
    Read(Box<[UnsafeCell<u8>]>),
    Write(Box<[u8]>),
}
impl Buffer {
    fn len(&self) -> usize {
        match self {
            Self::Read(bytes) => bytes.len(),
            Self::Write(bytes) => bytes.len(),
        }
    }
    fn read_pointer(&self) -> *mut c_void {
        match self {
            Self::Read(bytes) => UnsafeCell::raw_get(bytes.as_ptr()).cast(),
            Self::Write(_) => unreachable!("fixed operation buffer role"),
        }
    }
    fn write_pointer(&self) -> *const c_void {
        match self {
            Self::Write(bytes) => bytes.as_ptr().cast(),
            Self::Read(_) => unreachable!("fixed operation buffer role"),
        }
    }
    fn same_write(&self, value: &[u8]) -> bool {
        matches!(self, Self::Write(bytes) if bytes.as_ref() == value)
    }
    // Called only after terminal completion and a bounded transferred count.
    fn completed_bytes(&self, count: usize) -> Vec<u8> {
        match self {
            Self::Read(bytes) => bytes[..count]
                .iter()
                .map(|cell| unsafe { *cell.get() })
                .collect(),
            Self::Write(bytes) => bytes[..count].to_vec(),
        }
    }
}
struct Operation {
    event: Owned,
    // Kernel writes may occur between FFI calls. No Rust reference to the inner
    // OVERLAPPED is formed until terminal completion; .get() passes its stable
    // address without claiming exclusive or immutable access to that storage.
    overlapped: Box<UnsafeCell<Overlapped>>,
    buffer: Buffer,
    pending: bool,
    writing: bool,
    completed: u32,
    error: u32,
}

impl Operation {
    fn new(buffer: Box<[u8]>, writing: bool) -> io::Result<Self> {
        if buffer.is_empty() || buffer.len() > MAX_OPERATION {
            return Err(refused());
        }
        let event = Owned::event()?;
        // The inherited file object may remain associated with the Go host's
        // IOCP even after File.Fd attempted disassociation. Microsoft documents
        // the event low bit as suppressing completion-port packets; Go1.26
        // internal/poll uses the same rule for externally associated handles.
        // Wait/close always use the separate untagged Owned event handle.
        let notification = suppress_foreign_iocp(event.raw())?;
        let overlapped = Box::new(UnsafeCell::new(Overlapped {
            internal: 0,
            internal_high: 0,
            offset_or_pointer: 0,
            event: notification,
        }));
        let buffer = if writing {
            Buffer::Write(buffer)
        } else {
            Buffer::Read(
                buffer
                    .into_vec()
                    .into_iter()
                    .map(UnsafeCell::new)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            )
        };
        Ok(Self {
            event,
            overlapped,
            buffer,
            pending: false,
            writing,
            completed: 0,
            error: 0,
        })
    }
    fn begin(&mut self, handle: Handle) {
        let ok = unsafe {
            if self.writing {
                WriteFile(
                    handle,
                    self.buffer.write_pointer(),
                    self.buffer.len() as u32,
                    std::ptr::null_mut(),
                    self.overlapped.get(),
                )
            } else {
                ReadFile(
                    handle,
                    self.buffer.read_pointer(),
                    self.buffer.len() as u32,
                    std::ptr::null_mut(),
                    self.overlapped.get(),
                )
            }
        };
        // No asynchronous result points into the movable Operation struct.
        // Even immediate success is observed through GetOverlappedResult;
        // the two native input pointers target independently stable Boxes.
        if ok != 0 {
            self.pending = true;
        } else {
            self.error = unsafe { GetLastError() };
            if self.error == 0 {
                self.error = 87;
            } // unknown refusal, never EOF/success
            self.pending = self.error == PENDING;
        }
    }
    fn poll(&mut self, handle: Handle) -> bool {
        if !self.pending {
            return true;
        }
        let ok =
            unsafe { GetOverlappedResult(handle, self.overlapped.get(), &mut self.completed, 0) };
        if ok != 0 {
            self.pending = false;
            self.error = 0;
            return true;
        }
        let error = unsafe { GetLastError() };
        if completion(error) == Completion::Pending {
            return false;
        }
        // These errors specifically report a completed/canceled/broken pipe
        // operation. An unknown query failure is not terminal-state proof.
        if completion(error) != Completion::TerminalError {
            pending_fatal();
        }
        self.error = error;
        self.pending = false;
        true
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        if self.pending {
            pending_fatal();
        }
    }
}

pub struct Pipe {
    handle: Owned,
    operation: Option<Operation>,
    writing: bool,
    poisoned: bool,
    cleanup_uncertain: bool,
}

impl Pipe {
    /// Own an exact inherited stdio endpoint, never a name, PID or fd guess.
    pub fn standard(which: u32, writing: bool) -> io::Result<Self> {
        if !matches!(
            (which as i32, writing),
            (-10, false) | (-11, true) | (-12, true)
        ) {
            return Err(refused());
        }
        let raw = unsafe { GetStdHandle(which) };
        Self::from_inherited(raw, writing)
    }
    pub fn from_inherited(raw: Handle, writing: bool) -> io::Result<Self> {
        let handle = Owned::take_inherited(raw)?;
        Self::from_pin(handle, writing)
    }
    // Future SDK-owned workload stdio is a typed ownership transfer, not an
    // inherited-flag fiction or a raw integer received through ordinary JSON.
    pub fn from_owned(handle: OwnedHandle, writing: bool) -> io::Result<Self> {
        Self::from_pin(Owned::take_owned(handle)?, writing)
    }
    fn from_pin(handle: Owned, writing: bool) -> io::Result<Self> {
        let raw = handle.raw();
        if unsafe { GetFileType(raw) } != 3 {
            return Err(refused());
        }
        // Same read-only FileModeInformation query as Go1.26 IsNonblock. Both
        // synchronous-mode bits must be absent before any ReadFile/WriteFile.
        let mut status = IoStatus {
            status_or_pointer: 0,
            information: 0,
        };
        let mut mode: u32 = 0;
        let result = unsafe {
            NtQueryInformationFile(raw, &mut status, (&mut mode as *mut u32).cast(), 4, 16)
        };
        if result as u32 == 0x103 {
            pending_fatal();
        }
        if result != 0 || status.information != 4 || mode & 0x30 != 0 {
            return Err(refused());
        }
        Ok(Self {
            handle,
            operation: None,
            writing,
            poisoned: false,
            cleanup_uncertain: false,
        })
    }
    fn advance(&mut self, bytes: &[u8], read_size: usize) -> io::Result<Option<(Vec<u8>, usize)>> {
        if self.poisoned {
            return Err(refused());
        }
        if self.operation.is_none() {
            let buffer = if self.writing {
                bytes.to_vec().into_boxed_slice()
            } else {
                vec![0; read_size].into_boxed_slice()
            };
            let mut operation = Operation::new(buffer, self.writing)?;
            operation.begin(self.handle.raw());
            self.operation = Some(operation);
        }
        let operation = self.operation.as_mut().ok_or_else(refused)?;
        // A queued write cannot be replaced while its kernel buffer is live.
        if self.writing && !operation.buffer.same_write(bytes) {
            self.poisoned = true;
            return Err(refused());
        }
        if !operation.poll(self.handle.raw()) {
            return Ok(None);
        }
        let mut operation = self.operation.take().ok_or_else(refused)?;
        if operation.event.close().is_err() {
            self.poisoned = true;
            self.cleanup_uncertain = true;
            return Err(refused());
        }
        let count = operation.completed as usize;
        if count > operation.buffer.len() {
            self.poisoned = true;
            return Err(refused());
        }
        if matches!(operation.error, BROKEN_PIPE | NOT_CONNECTED) {
            if !self.writing {
                return Ok(Some((Vec::new(), 0)));
            }
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "private peer pipe closed",
            ));
        }
        if operation.error != 0 {
            self.poisoned = true;
            return Err(refused());
        }
        Ok(Some((operation.buffer.completed_bytes(count), count)))
    }
    pub fn wait_handle(&self) -> Option<Handle> {
        self.operation
            .as_ref()
            .filter(|op| op.pending)
            .map(|op| op.event.raw())
    }
    pub fn close(&mut self, deadline: Instant) -> io::Result<()> {
        self.poisoned = true;
        if let Some(operation) = &mut self.operation {
            if operation.pending {
                let ok = unsafe { CancelIoEx(self.handle.raw(), operation.overlapped.get()) };
                if ok == 0 && unsafe { GetLastError() } != NOT_FOUND {
                    pending_fatal();
                }
                while !operation.poll(self.handle.raw()) {
                    if Instant::now() >= deadline {
                        pending_fatal();
                    }
                    wait_handles(&[operation.event.raw()], Duration::from_millis(1))?;
                }
            }
            if operation.event.close().is_err() {
                self.cleanup_uncertain = true;
            }
        }
        self.operation.take();
        if self.handle.close().is_err() {
            self.cleanup_uncertain = true;
        }
        if self.cleanup_uncertain {
            Err(refused())
        } else {
            Ok(())
        }
    }
}

impl Read for Pipe {
    fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
        if self.writing {
            return Err(refused());
        }
        if destination.is_empty() {
            return Ok(0);
        }
        match self.advance(&[], destination.len())? {
            None => Err(blocked()),
            Some((bytes, count)) if count <= destination.len() => {
                destination[..count].copy_from_slice(&bytes);
                Ok(count)
            }
            _ => Err(refused()),
        }
    }
}

impl Write for Pipe {
    fn write(&mut self, source: &[u8]) -> io::Result<usize> {
        if !self.writing {
            return Err(refused());
        }
        if source.is_empty() {
            return Ok(0);
        }
        match self.advance(source, 0)? {
            None => Err(blocked()),
            Some((_, count)) => Ok(count),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.operation.is_some() {
            Err(blocked())
        } else {
            Ok(())
        }
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        // A bounded cancellation attempt is part of drop; failure cannot free
        // pending buffers or turn into a long/unbounded native wait.
        if self
            .close(Instant::now() + Duration::from_millis(500))
            .is_err()
        {
            pending_fatal();
        }
    }
}

pub fn nonblocking(pipe: &Pipe) -> crate::wire::Result<()> {
    if pipe.poisoned {
        Err(crate::wire::ProtocolError)
    } else {
        Ok(())
    }
}

pub fn wait_handles(handles: &[Handle], timeout: Duration) -> io::Result<()> {
    let millis = timeout.as_millis().min(20) as u32;
    if handles.is_empty() {
        unsafe { Sleep(millis) };
        return Ok(());
    }
    if !valid_wait_handles(handles) {
        return Err(refused());
    }
    let result =
        unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, millis) };
    if result == 258 || result < handles.len() as u32 {
        Ok(())
    } else {
        Err(refused())
    }
}

fn valid_wait_handles(handles: &[Handle]) -> bool {
    handles.len() <= 64
        && handles.iter().enumerate().all(|(index, handle)| {
            *handle != 0 && *handle <= isize::MAX as usize && !handles[..index].contains(handle)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn read_buffer_storage_stays_stable_and_observation_follows_completion() {
        let buffer = Buffer::Read(vec![UnsafeCell::new(0), UnsafeCell::new(0)].into_boxed_slice());
        let native = buffer.read_pointer().cast::<u8>();
        let moved = Box::new(buffer);
        assert_eq!(native, moved.read_pointer().cast());
        // Synthetic native writer, no IO/API call. Observation occurs only
        // after this stand-in writer has completed both writes.
        unsafe {
            native.write(b'A');
            native.add(1).write(b'B');
        }
        assert_eq!(moved.completed_bytes(2), b"AB");
        let writing = Buffer::Write(Box::from(&b"fixed"[..]));
        assert!(writing.same_write(b"fixed"));
        assert!(!writing.same_write(b"other"));
    }
    #[test]
    fn completion_never_treats_cancel_request_as_terminal_proof() {
        assert_eq!(completion(0), Completion::Ready);
        assert_eq!(completion(INCOMPLETE), Completion::Pending);
        for status in [ABORTED, BROKEN_PIPE, NOT_CONNECTED] {
            assert_eq!(completion(status), Completion::TerminalError);
        }
        // CancelIoEx NOT_FOUND can race completion; it is not an observation
        // from GetOverlappedResult and never releases operation storage.
        for status in [NOT_FOUND, PENDING, 6, 87, u32::MAX] {
            assert_eq!(completion(status), Completion::Unknown);
        }
    }
    #[test]
    fn overlapped_event_suppresses_foreign_iocp_without_changing_owned_handle() {
        for owned in [4usize, 64, 0x1000, 0x12345678] {
            let tagged = suppress_foreign_iocp(owned).unwrap();
            assert_eq!(tagged, owned | 1);
            assert_eq!(tagged & !1, owned);
            assert_eq!(owned & 1, 0);
        }
        for invalid in [0usize, 1, 65, usize::MAX] {
            assert!(suppress_foreign_iocp(invalid).is_err());
        }
    }
    #[test]
    fn wait_set_is_bounded_unique_and_contains_no_pseudo_handle() {
        let handles = (1..=64).map(|index| index * 4).collect::<Vec<_>>();
        assert!(valid_wait_handles(&handles));
        let mut too_many = handles.clone();
        too_many.push(260);
        assert!(!valid_wait_handles(&too_many));
        for invalid in [vec![0], vec![usize::MAX], vec![4, 4]] {
            assert!(!valid_wait_handles(&invalid));
        }
    }
}

// Workload pairs differ from the Go-to-peer pair: only this peer's endpoint is
// overlapped. The ordinary workload receives a synchronous stdio endpoint.
#[repr(C)]
struct PipeSecurity {
    length: u32,
    descriptor: *mut c_void,
    inherit: i32,
}
const _: () = assert!(size_of::<PipeSecurity>() == 24);
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn GetCurrentProcessId() -> u32;
    fn CreateNamedPipeW(
        name: *const u16,
        access: u32,
        mode: u32,
        instances: u32,
        output: u32,
        input: u32,
        timeout: u32,
        security: *const PipeSecurity,
    ) -> Handle;
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: *const PipeSecurity,
        creation: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn ConnectNamedPipe(pipe: Handle, operation: *mut Overlapped) -> i32;
    fn GetNamedPipeClientProcessId(pipe: Handle, process: *mut u32) -> i32;
    fn GetNamedPipeServerProcessId(pipe: Handle, process: *mut u32) -> i32;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn GetTokenInformation(
        token: Handle,
        class: u32,
        buffer: *mut c_void,
        capacity: u32,
        used: *mut u32,
    ) -> i32;
    fn GetLengthSid(sid: *const c_void) -> u32;
    fn IsValidSid(sid: *const c_void) -> i32;
    fn ConvertSidToStringSidW(sid: *const c_void, value: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        value: *const u16,
        revision: u32,
        output: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
}
#[link(name = "rpcrt4")]
unsafe extern "system" {
    fn UuidCreate(uuid: *mut UuidBytes) -> i32;
}
#[repr(C, align(4))]
struct UuidBytes([u8; 16]);
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() && !unsafe { LocalFree(self.0) }.is_null() {
            pending_fatal();
        }
    }
}
fn pipe_descriptor() -> io::Result<Local> {
    let mut raw = 0;
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut raw) };
    let token = Owned { raw };
    if opened == 0 || raw == 0 || raw == INVALID {
        return Err(refused());
    }
    let mut buffer = [0usize; 128];
    let mut used = 0;
    if unsafe {
        GetTokenInformation(
            token.raw(),
            1,
            buffer.as_mut_ptr().cast(),
            size_of::<[usize; 128]>() as u32,
            &mut used,
        )
    } == 0
        || used < 16
        || used as usize > size_of::<[usize; 128]>()
    {
        return Err(refused());
    }
    let sid = buffer[0] as *const c_void;
    let start = buffer.as_ptr() as usize;
    let position = sid as usize;
    if position < start + 16
        || position
            .checked_add(8)
            .is_none_or(|n| n > start + used as usize)
        || unsafe { IsValidSid(sid) } == 0
    {
        return Err(refused());
    }
    let length = unsafe { GetLengthSid(sid) } as usize;
    if !(8..=68).contains(&length)
        || position
            .checked_add(length)
            .is_none_or(|n| n > start + used as usize)
    {
        return Err(refused());
    }
    let mut text = std::ptr::null_mut();
    let converted = unsafe { ConvertSidToStringSidW(sid, &mut text) };
    let text_owner = Local(text.cast());
    if converted == 0 || text.is_null() {
        return Err(refused());
    }
    let mut units = Vec::new();
    for index in 0..=184 {
        let unit = unsafe { *text.add(index) };
        if unit == 0 {
            break;
        }
        if index == 184 || !(unit == 83 || unit == 45 || (48..=57).contains(&unit)) {
            return Err(refused());
        }
        units.push(unit);
    }
    let sid = String::from_utf16(&units).map_err(|_| refused())?;
    if !sid.starts_with("S-1-") {
        return Err(refused());
    }
    let value = format!("O:{sid}D:P(A;;GA;;;{sid})(A;;GA;;;SY)");
    let value: Vec<_> = value.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = std::ptr::null_mut();
    let mut size = 0;
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            value.as_ptr(),
            1,
            &mut descriptor,
            &mut size,
        )
    } == 0
        || descriptor.is_null()
        || size == 0
    {
        if !descriptor.is_null() {
            drop(Local(descriptor));
        }
        return Err(refused());
    }
    drop(text_owner);
    Ok(Local(descriptor))
}
impl Pipe {
    pub fn workload_pair(parent_writes: bool) -> io::Result<(Self, OwnedHandle)> {
        let descriptor = pipe_descriptor()?;
        let mut random = UuidBytes([0u8; 16]);
        // UUID allocation is only an opaque local pipe name. Exact PID and the
        // protected owner+SYSTEM descriptor, not name secrecy, admit the pair.
        if unsafe { UuidCreate(&mut random) } != 0 {
            return Err(refused());
        }
        let mut name = String::from(r"\\.\pipe\defenseclaw-axis-workload-");
        for byte in random.0 {
            use std::fmt::Write;
            write!(&mut name, "{byte:02x}").map_err(|_| refused())?;
        }
        let name: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
        let security = PipeSecurity {
            length: size_of::<PipeSecurity>() as u32,
            descriptor: descriptor.0,
            inherit: 0,
        };
        let server = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                (if parent_writes { 2 } else { 1 }) | 0x40000000 | 0x80000,
                8,
                1,
                65536,
                65536,
                0,
                &security,
            )
        };
        if server == 0 || server == INVALID {
            return Err(refused());
        }
        let server = Owned { raw: server };
        let client = unsafe {
            CreateFileW(
                name.as_ptr(),
                if parent_writes {
                    0x80000000
                } else {
                    0x40000000
                },
                0,
                std::ptr::null(),
                3,
                0,
                0,
            )
        };
        if client == 0 || client == INVALID {
            return Err(refused());
        }
        let client = Owned { raw: client };
        let mut operation = Operation::new(vec![0].into_boxed_slice(), false)?;
        let connected = unsafe { ConnectNamedPipe(server.raw(), operation.overlapped.get()) };
        if connected == 0 {
            let error = unsafe { GetLastError() };
            if error == PENDING {
                operation.pending = true;
                let cancelled = unsafe { CancelIoEx(server.raw(), operation.overlapped.get()) };
                if cancelled == 0 && unsafe { GetLastError() } != NOT_FOUND {
                    pending_fatal();
                }
                let limit = Instant::now() + Duration::from_millis(500);
                while !operation.poll(server.raw()) {
                    if Instant::now() >= limit {
                        pending_fatal();
                    }
                    if wait_handles(&[operation.event.raw()], Duration::from_millis(1)).is_err() {
                        pending_fatal();
                    }
                }
                return Err(refused());
            }
            if error != 535 {
                return Err(refused());
            } // ERROR_PIPE_CONNECTED
        }
        operation.event.close()?;
        let mut client_pid = 0;
        let mut server_pid = 0;
        if unsafe { GetNamedPipeClientProcessId(server.raw(), &mut client_pid) } == 0
            || unsafe { GetNamedPipeServerProcessId(client.raw(), &mut server_pid) } == 0
            || client_pid != unsafe { GetCurrentProcessId() }
            || server_pid != client_pid
            || unsafe { SetHandleInformation(client.raw(), 1, 1) } == 0
        {
            return Err(refused());
        }
        let parent = Self::from_pin(server, parent_writes)?;
        Ok((parent, client.into_owned()?))
    }
}

#[cfg(test)]
mod workload_tests {
    use super::*;
    #[test]
    fn native_owned_workload_pair_transfers_and_cancels_without_a_child() {
        let (mut input, child) = Pipe::workload_pair(false).unwrap();
        let raw = std::os::windows::io::AsRawHandle::as_raw_handle(&child) as Handle;
        let value = [b'X'];
        let mut done = 0;
        assert_ne!(
            unsafe {
                WriteFile(
                    raw,
                    value.as_ptr().cast(),
                    1,
                    &mut done,
                    std::ptr::null_mut(),
                )
            },
            0
        );
        assert_eq!(done, 1);
        let limit = Instant::now() + Duration::from_millis(500);
        let mut got = [0];
        loop {
            match input.read(&mut got) {
                Ok(1) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < limit);
                    wait_handles(
                        &input.wait_handle().into_iter().collect::<Vec<_>>(),
                        Duration::from_millis(1),
                    )
                    .unwrap();
                }
                _ => panic!("fixed owned pipe transfer refused"),
            }
        }
        assert_eq!(got, value);
        // The open writer keeps this second read pending; cancellation must
        // observe terminal completion before the operation/event storage drops.
        assert_eq!(
            input.read(&mut got).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(input.wait_handle().is_some());
        input
            .close(Instant::now() + Duration::from_millis(500))
            .unwrap();
        drop(child);
    }
    #[test]
    fn native_sync_workload_end_is_never_adopted_as_overlapped() {
        let (mut parent, child) = Pipe::workload_pair(false).unwrap();
        assert!(Pipe::from_owned(child, false).is_err());
        parent
            .close(Instant::now() + Duration::from_millis(500))
            .unwrap();
    }
}
