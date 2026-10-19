// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! Explicit sparse Bubblewrap adapter. No native/auto/path-based fallback.

use crate::custody::PreparedFiles;
use crate::owner::{Engine, Pipes, Prepared, Process};
use crate::wire::{Preparation, ProtocolError, Result};
use axis_core::policy::Policy;
use mxc_sdk::v1::{MxcProcess, OwnedMount, PreparedOwnedBubblewrap};
use std::ffi::OsString;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};

pub struct LinuxEngine;

struct LinuxPrepared(PreparedOwnedBubblewrap);
struct LinuxProcess(MxcProcess);

fn policy(plan: &Preparation) -> Result<Policy> {
    // This versioned projection describes only this private offline slice.
    // It does not accept or claim translation of the full host resolver state.
    let policy: Policy = serde_json::from_value(serde_json::json!({
        "version": 1,
        "name": "defenseclaw-private-offline",
        "runtime": {"containment": "process", "provider": "mxc"},
        "filesystem": {
            "compatibility": "hard_requirement",
            "read_only": plan.filesystem.read,
            "read_write": plan.filesystem.write,
            "deny": [],
            "workspace_read_only": plan.filesystem.read.contains(&plan.workdir)
        },
        "process": {
            "max_processes": 0, "max_memory_mb": 0, "cpu_rate_percent": 0,
            "blocked_syscalls": ["socket", "socketpair"]
        },
        "network": {"mode": "block"}
    }))
    .map_err(|_| ProtocolError)?;
    policy.validate().map_err(|_| ProtocolError)?;
    Ok(policy)
}

fn sealed_filter(bytes: &[u8]) -> Result<File> {
    if bytes.is_empty() || bytes.len() > 1 << 20 || bytes.len() % 8 != 0 {
        return Err(ProtocolError);
    }
    // SAFETY: fixed NUL-terminated name and supported constant flags; takes no
    // caller path and creates an anonymous process-owned file only.
    let descriptor = unsafe {
        libc::memfd_create(
            c"defenseclaw-offline-filter".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if descriptor < 0 {
        return Err(ProtocolError);
    }
    // SAFETY: descriptor is newly returned and transferred to one File.
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    file.write_all(bytes).map_err(|_| ProtocolError)?;
    file.seek(SeekFrom::Start(0)).map_err(|_| ProtocolError)?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // SAFETY: seals only the newly created, still-owned filter file.
    if unsafe { libc::fcntl(descriptor, libc::F_ADD_SEALS, seals) } < 0 {
        return Err(ProtocolError);
    }
    Ok(file)
}

impl Engine for LinuxEngine {
    fn prepare(&mut self, plan: &Preparation) -> Result<Box<dyn Prepared>> {
        // Receive the fixed inherited table before a library or backend can
        // allocate descriptors. Guest strings never reopen a host object.
        let files = PreparedFiles::receive(plan)?;
        let policy = policy(plan)?;
        let filter = axis_sandbox::linux::seccomp::export_offline_mxc_bpf(&policy.process)
            .map_err(|_| ProtocolError)?;
        let filter = sealed_filter(&filter)?;
        // SAFETY: single-threaded peer, held admitted directory object. This
        // avoids retaining a caller host cwd while preparing native execution.
        if unsafe { libc::fchdir(files.cwd.file().as_raw_fd()) } < 0 {
            return Err(ProtocolError);
        }
        let mut mounts = Vec::with_capacity(files.read.len() + files.write.len());
        for (paths, objects, readonly) in [
            (&plan.filesystem.read, files.read, true),
            (&plan.filesystem.write, files.write, false),
        ] {
            for (path, object) in paths.iter().zip(objects) {
                mounts.push(
                    OwnedMount::new(object.into_file(), path.clone(), readonly)
                        .map_err(|_| ProtocolError)?,
                );
            }
        }
        let prepared = PreparedOwnedBubblewrap::new(
            files.bwrap.into_file(),
            files.payload.into_file(),
            filter,
            mounts,
            plan.argv.iter().map(OsString::from).collect(),
            plan.environment
                .iter()
                .map(|variable| {
                    (
                        OsString::from(&variable.name),
                        OsString::from(&variable.value),
                    )
                })
                .collect(),
            plan.workdir.clone(),
        )
        .map_err(|_| ProtocolError)?;
        Ok(Box::new(LinuxPrepared(prepared)))
    }
}

impl Prepared for LinuxPrepared {
    fn launch(self: Box<Self>) -> Result<Box<dyn Process>> {
        let process = self.0.spawn().map_err(|_| ProtocolError)?;
        Ok(Box::new(LinuxProcess(process)))
    }
}

impl Process for LinuxProcess {
    fn take_pipes(&mut self) -> Result<Pipes> {
        let pipes = self
            .0
            .take_native_stdio()
            .map_err(|_| ProtocolError)?
            .ok_or(ProtocolError)?;
        Ok(Pipes {
            input: pipes.stdin.map(File::from),
            output: pipes.stdout.map(File::from),
            error: pipes.stderr.map(File::from),
        })
    }
    fn try_wait(&mut self) -> Result<Option<i32>> {
        self.0.try_wait().map_err(|_| ProtocolError)
    }
    fn stop(&mut self) -> Result<()> {
        self.0.kill().map_err(|_| ProtocolError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn filter_is_sealed_and_readable_from_start_without_paths() {
        let expected = [0u8; 16];
        let mut file = sealed_filter(&expected).unwrap();
        let mut actual = Vec::new();
        file.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, expected);
        assert!(file.write_all(b"change").is_err());
        // SAFETY: size query/attempt only on this anonymous owned test file.
        assert_ne!(unsafe { libc::ftruncate(file.as_raw_fd(), 0) }, 0);
    }
}
