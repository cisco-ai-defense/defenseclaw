// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! Fixed FD3 namespace bootstrap, before any backend/control/workload. No setns.

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileExt, MetadataExt};

const NS_GET_USERNS: libc::c_ulong = 0xb701;
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
const SEALS: i32 = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
const ADMIN: u32 = 1 << 21;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity(u64, u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Proof {
    uid: u32,
    gid: u32,
    namespaces: [Identity; 3],
}

fn decode(bytes: &[u8]) -> Result<Proof, ()> {
    if bytes.len() != 64 || &bytes[..8] != b"DCAXNS01" {
        return Err(());
    }
    let number = |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let mut proof = Proof {
        uid: number(8),
        gid: number(12),
        namespaces: [Identity(0, 0); 3],
    };
    for (index, identity) in proof.namespaces.iter_mut().enumerate() {
        let offset = 16 + index * 16;
        *identity = Identity(
            u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()),
            u64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().unwrap()),
        );
        if identity.1 == 0 {
            return Err(());
        }
    }
    if proof.uid == 0 || proof.gid == 0 {
        return Err(());
    }
    Ok(proof)
}

fn identity(file: &File) -> Result<Identity, ()> {
    let metadata = file.metadata().map_err(|_| ())?;
    Ok(Identity(metadata.dev(), metadata.ino()))
}

fn open(path: &std::ffi::CStr, flags: i32) -> Result<File, ()> {
    // SAFETY: fixed initialized paths/flags; returned FD gets one owner.
    let fd = unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn namespaces() -> Result<[File; 3], ()> {
    let result = [
        open(c"/proc/self/ns/user", libc::O_RDONLY)?,
        open(c"/proc/self/ns/mnt", libc::O_RDONLY)?,
        open(c"/proc/self/ns/pid", libc::O_RDONLY)?,
    ];
    for (file, kind) in
        result
            .iter()
            .zip([libc::CLONE_NEWUSER, libc::CLONE_NEWNS, libc::CLONE_NEWPID])
    {
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // /proc/self selects currenttask even through an ancestor procfs. Only
        // kernel NSFS handles of the exact requested types are accepted.
        if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0
            || unsafe { stat.assume_init().f_type } != 0x6e736673
            || unsafe { libc::ioctl(file.as_raw_fd(), NS_GET_NSTYPE) } != kind
        {
            return Err(());
        }
    }
    Ok(result)
}

fn single_thread() -> Result<(), ()> {
    if unsafe { libc::syscall(libc::SYS_gettid) } != unsafe { libc::getpid() } as libc::c_long {
        return Err(());
    }
    let mut tasks = std::fs::read_dir("/proc/self/task").map_err(|_| ())?;
    if tasks.next().transpose().map_err(|_| ())?.is_none() || tasks.next().is_some() {
        return Err(());
    }
    Ok(())
}

fn mapping(bytes: &[u8], id: u32) -> bool {
    if id == 0 {
        return false;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let fields: Vec<_> = text.split_whitespace().collect();
    fields.len() == 3
        && fields
            .iter()
            .zip([id, id, 1])
            .all(|(text, expected)| text.parse::<u32>() == Ok(expected))
}

fn bounded(path: &str) -> Result<Vec<u8>, ()> {
    use std::io::Read;
    let mut result = Vec::new();
    File::open(path)
        .map_err(|_| ())?
        .take(129)
        .read_to_end(&mut result)
        .map_err(|_| ())?;
    if result.len() > 128 {
        return Err(());
    }
    Ok(result)
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn caps(startup: bool) -> Result<(), ()> {
    let mut header = CapHeader {
        version: 0x20080522,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } != 0 {
        return Err(());
    }
    let expected = if startup { ADMIN } else { 0 };
    if data
        != [
            CapData {
                effective: expected,
                permitted: expected,
                inheritable: expected,
            },
            CapData::default(),
        ]
        || unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET, 21, 0, 0) }
            != i32::from(startup)
    {
        return Err(());
    }
    Ok(())
}

fn drop_caps() -> Result<(), ()> {
    let header = CapHeader {
        version: 0x20080522,
        pid: 0,
    };
    let data = [CapData::default(); 2];
    // Only one thread exists, proved before/after; no backend/control is active.
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } != 0
        || unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        return Err(());
    }
    caps(false)
}

fn mount_proc() -> Result<(), ()> {
    // First mutation, after kernel-owned new USER/MNT/PID identity validation.
    // No mount in the parent namespace is changed or propagated back to it.
    if unsafe {
        libc::mount(
            c"".as_ptr(),
            c"/".as_ptr(),
            c"".as_ptr(),
            libc::MS_PRIVATE | libc::MS_REC,
            c"".as_ptr().cast(),
        )
    } != 0
    {
        return Err(());
    }
    let target = open(
        c"/proc",
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW,
    )?;
    let context = unsafe { libc::syscall(libc::SYS_fsopen, c"proc".as_ptr(), 1u32) };
    if context < 0 {
        return Err(());
    }
    let context = unsafe { File::from_raw_fd(context as i32) };
    // FSCONFIG_CMD_CREATE=6, FSMOUNT_CLOEXEC=1, attributes NOSUID|NODEV|NOEXEC.
    if unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            context.as_raw_fd(),
            6u32,
            std::ptr::null::<u8>(),
            std::ptr::null::<u8>(),
            0,
        )
    } != 0
    {
        return Err(());
    }
    let mount = unsafe {
        libc::syscall(
            libc::SYS_fsmount,
            context.as_raw_fd(),
            1u32,
            2u32 | 4u32 | 8u32,
        )
    };
    if mount < 0 {
        return Err(());
    }
    let mount = unsafe { File::from_raw_fd(mount as i32) };
    // MOVE_MOUNT_{F,T}_EMPTY_PATH=4,64; both arguments name owned FDs.
    if unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            mount.as_raw_fd(),
            c"".as_ptr(),
            target.as_raw_fd(),
            c"".as_ptr(),
            4u32 | 64u32,
        )
    } != 0
    {
        return Err(());
    }
    let mounted = open(
        c"/proc",
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW,
    )?;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(mounted.as_raw_fd(), stat.as_mut_ptr()) } != 0
        || unsafe { stat.assume_init().f_type } != 0x9fa0
    {
        return Err(());
    }
    Ok(())
}

/// Must run after PID1/PDEATHSIG admission and before any protocol/library work.
/// Caller exits its owned namespace on failure; there is no capability fallback.
pub fn setup() -> Result<(), ()> {
    if unsafe { libc::getpid() != 1 || libc::getppid() != 0 } {
        return Err(());
    }
    single_thread()?;
    // No asynchronous callback may execute while namespace startup cap exists.
    let mut all = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    let mut previous = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    if unsafe { libc::sigfillset(all.as_mut_ptr()) } != 0
        || unsafe { libc::sigprocmask(libc::SIG_SETMASK, all.as_ptr(), previous.as_mut_ptr()) } != 0
    {
        return Err(());
    }
    // FD3 is exact, sealed, fixed-length proof captured from parent kernel handles.
    let file = unsafe { File::from_raw_fd(3) };
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file()
        || metadata.len() != 64
        || unsafe { libc::fcntl(3, libc::F_GET_SEALS) } != SEALS
    {
        return Err(());
    }
    let mut bytes = [0; 64];
    if file.read_at(&mut bytes, 0).map_err(|_| ())? != bytes.len() {
        return Err(());
    }
    let proof = decode(&bytes)?;
    if unsafe { libc::getuid() } != proof.uid
        || unsafe { libc::geteuid() } != proof.uid
        || unsafe { libc::getgid() } != proof.gid
        || unsafe { libc::getegid() } != proof.gid
    {
        return Err(());
    }
    caps(true)?;
    let handles = namespaces()?;
    let user = identity(&handles[0])?;
    for (index, handle) in handles.iter().enumerate() {
        if identity(handle)? == proof.namespaces[index] {
            return Err(());
        }
        if index > 0 {
            let owner = unsafe { libc::ioctl(handle.as_raw_fd(), NS_GET_USERNS) };
            if owner < 0 {
                return Err(());
            }
            let owner = unsafe { File::from_raw_fd(owner) };
            if identity(&owner)? != user {
                return Err(());
            }
        }
    }
    if !mapping(&bounded("/proc/self/uid_map")?, proof.uid)
        || !mapping(&bounded("/proc/self/gid_map")?, proof.gid)
    {
        return Err(());
    }
    mount_proc()?;
    single_thread()?;
    drop_caps()?;
    let current = namespaces()?;
    for (before, after) in handles.iter().zip(&current) {
        if identity(before)? != identity(after)? {
            return Err(());
        }
    }
    let link = std::fs::read_link("/proc/self").map_err(|_| ())?;
    if link.as_os_str() != unsafe { libc::getpid() }.to_string().as_str() {
        return Err(());
    }
    // Restore signal delivery only after cap-zero and coherent proc verification.
    if unsafe { libc::sigprocmask(libc::SIG_SETMASK, previous.as_ptr(), std::ptr::null_mut()) } != 0
    {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn namespace_proof_and_maps_refuse_root_truncation_and_multiple_ids() {
        let mut bytes = [0; 64];
        bytes[..8].copy_from_slice(b"DCAXNS01");
        bytes[8..12].copy_from_slice(&1000u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&1001u32.to_le_bytes());
        for offset in [24, 40, 56] {
            bytes[offset] = 1;
        }
        assert!(decode(&bytes).is_ok());
        assert!(decode(&bytes[..63]).is_err());
        bytes[8..12].fill(0);
        assert!(decode(&bytes).is_err());
        assert!(mapping(b"1000 1000 1\n", 1000));
        for bytes in [
            b"1000 0 1".as_slice(),
            b"1000 1000 2",
            b"1000 1000 1\n1001 1001 1",
        ] {
            assert!(!mapping(bytes, 1000));
        }
    }
}
