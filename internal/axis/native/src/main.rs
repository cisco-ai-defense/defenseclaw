// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "linux")]
mod linux_entry {
    //! Private stdio entry point. No command/path/env option or customer activation.

    use defenseclaw_axis_native::linux::LinuxEngine;
    use defenseclaw_axis_native::owner::Owner;
    use defenseclaw_axis_native::transport::Transport;
    use std::fs::File;
    use std::os::fd::FromRawFd;

    fn run() -> Result<(), ()> {
        // The host creates this peer as init of a fresh outer PID namespace. Its
        // parent is outside that namespace and is therefore reported as PID zero.
        // Install parent-death handling here, rather than comparing a host PID in
        // Go's post-clone hook. Protocol EOF still refuses the earlier host-death
        // race; a creating-thread death may kill this peer early (availability).
        // SAFETY: these queries and prctl affect only this single-threaded peer.
        if unsafe { libc::getpid() != 1 || libc::getppid() != 0 }
            || unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0
        {
            return Err(());
        }
        defenseclaw_axis_native::namespace::setup()?;
        if std::env::args_os().len() != 1 {
            return Err(());
        }
        // No threads/library backend have started. The trusted factory supplies a
        // credential-free environment; remove any accidental inherited override
        // before native preparation. No value is logged or retained in a plan.
        let names: Vec<_> = std::env::vars_os().map(|(name, _)| name).collect();
        for name in names {
            // SAFETY: the peer is single threaded throughout its lifetime.
            unsafe { std::env::remove_var(name) };
        }
        // Mark every inherited nonstdio descriptor close-on-exec before any library
        // can open another. Preparation consumes only its exact fixed capability
        // table; the SDK selectively duplicates/passes owned mount/filter inputs.
        // SAFETY: close_range CLOEXEC only changes this child's descriptor flags.
        if unsafe {
            libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            )
        } < 0
        {
            return Err(());
        }
        // SAFETY: the private factory transfers ownership of stdin/stdout to this
        // entry point once. No Rust stdio wrapper is constructed for either one.
        let input = unsafe { File::from_raw_fd(0) };
        let output = unsafe { File::from_raw_fd(1) };
        let transport = Transport::new(input, output).map_err(|_| ())?;
        Owner::new(LinuxEngine, transport).run().map_err(|_| ())
    }

    pub(super) fn main() {
        // Diagnostics cannot hold process exit behind a blocked host stderr pipe.
        // SAFETY: only this peer's stderr status flags are changed.
        unsafe {
            let flags = libc::fcntl(2, libc::F_GETFL);
            if flags >= 0 {
                libc::fcntl(2, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        if run().is_err() {
            // A fixed diagnostic cannot disclose arguments, environment, policy or
            // host paths. The Go owner treats EOF/failure as containment required.
            const DIAGNOSTIC: &[u8] = b"axis_private_peer_failed\n";
            // SAFETY: fixed initialized bytes; one nonblocking best-effort write.
            unsafe { libc::write(2, DIAGNOSTIC.as_ptr().cast(), DIAGNOSTIC.len()) };
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    linux_entry::main()
}

#[cfg(target_os = "windows")]
fn main() {
    use defenseclaw_axis_native::owner::Owner;
    use defenseclaw_axis_native::transport::Transport;
    use defenseclaw_axis_native::windows::WindowsEngine;
    use defenseclaw_axis_native::windows_bootstrap::Prefix;
    use defenseclaw_axis_native::windows_io::{Pipe, wait_handles};
    use std::io::{self, Write};
    use std::time::{Duration, Instant};

    // No std::io stdin/stdout/stderr wrapper may issue synchronous IO on these
    // explicit inherited overlapped handles. The Go owner supplies exactly one
    // argv value and an explicit empty environment before loader startup.
    let mut diagnostic = match Pipe::standard((-12i32) as u32, true) {
        Ok(pipe) => pipe,
        Err(_) => std::process::exit(1),
    };
    let outcome = (|| {
        let values: Vec<_> = std::env::args_os().collect();
        if values != [std::ffi::OsString::from("defenseclaw-axis-peer")]
            || std::env::vars_os().next().is_some()
        {
            return Err(());
        }
        let mut input = Pipe::standard((-10i32) as u32, false).map_err(|_| ())?;
        let output = Pipe::standard((-11i32) as u32, true).map_err(|_| ())?;
        let prefix =
            Prefix::receive(&mut input, Instant::now() + Duration::from_secs(5)).map_err(|_| ())?;
        let capabilities = prefix.adopt().map_err(|_| ())?;
        let transport = Transport::new(input, output).map_err(|_| ())?;
        Owner::new(WindowsEngine::new(capabilities), transport)
            .run()
            .map_err(|_| ())
    })();
    if outcome.is_err() {
        const TEXT: &[u8] = b"axis_private_peer_failed\n";
        let limit = Instant::now() + Duration::from_millis(100);
        let mut offset = 0;
        while offset < TEXT.len() && Instant::now() < limit {
            match diagnostic.write(&TEXT[offset..]) {
                Ok(0) => break,
                Ok(count) => offset += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let events: Vec<_> = diagnostic.wait_handle().into_iter().collect();
                    if wait_handles(&events, Duration::from_millis(1)).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }
    let closed = diagnostic
        .close(Instant::now() + Duration::from_millis(500))
        .is_ok();
    if outcome.is_err() || !closed {
        std::process::exit(1);
    }
}
