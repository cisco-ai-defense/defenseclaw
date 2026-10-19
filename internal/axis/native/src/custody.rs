// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! Linux capability handoff. Guest path labels are never reopened on the host.
//!
//! The trusted factory supplies fd3=namespace proof (consumed before control),
//! fd4=bwrap image, fd5=payload image, fd6=cwd, then read/write objects. Deny masks and
//! overlapping destinations refuse until a qualified translation exists.
//! Images are immutable sealed memfds made from the host-admitted bytes. The
//! full authority, original image digests and resolver records stay in Go.

use crate::wire::{Preparation, ProtocolError, Result};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileExt, MetadataExt};

const FIRST_CAP: i32 = 4;
const IMAGE_BOUND: u64 = 512 << 20;
const SEALS: i32 = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectIdentity {
    pub device: u64,
    pub inode: u64,
    pub directory: bool,
}

pub struct HeldObject {
    file: File,
    identity: ObjectIdentity,
}

impl HeldObject {
    fn new(file: File) -> Result<Self> {
        let metadata = file.metadata().map_err(|_| ProtocolError)?;
        if !metadata.is_dir() && !metadata.is_file() {
            return Err(ProtocolError);
        }
        Ok(Self {
            identity: ObjectIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
                directory: metadata.is_dir(),
            },
            file,
        })
    }

    pub fn identity(&self) -> ObjectIdentity {
        self.identity
    }
    pub fn file(&self) -> &File {
        &self.file
    }
    pub fn into_file(self) -> File {
        self.file
    }
}

pub struct SealedImage(HeldObject);

impl SealedImage {
    fn new(file: File) -> Result<Self> {
        let object = HeldObject::new(file)?;
        let metadata = object.file.metadata().map_err(|_| ProtocolError)?;
        // SAFETY: F_GET_SEALS only queries this owned descriptor.
        let seals = unsafe { libc::fcntl(object.file.as_raw_fd(), libc::F_GET_SEALS) };
        let mut header = [0; 20];
        if metadata.is_dir()
            || metadata.len() < 20
            || metadata.len() > IMAGE_BOUND
            || metadata.mode() & 0o6000 != 0
            || seals < 0
            || seals & SEALS != SEALS
            || object
                .file
                .read_at(&mut header, 0)
                .map_err(|_| ProtocolError)?
                != header.len()
            || &header[..6] != b"\x7fELF\x02\x01"
            || u16::from_le_bytes([header[18], header[19]]) != 62
        {
            return Err(ProtocolError);
        }
        Ok(Self(object))
    }

    pub fn file(&self) -> &File {
        self.0.file()
    }
    pub fn into_file(self) -> File {
        self.0.into_file()
    }
}

pub struct PreparedFiles {
    pub bwrap: SealedImage,
    pub payload: SealedImage,
    pub cwd: HeldObject,
    pub read: Vec<HeldObject>,
    pub write: Vec<HeldObject>,
}

impl PreparedFiles {
    /// Transfer the factory's explicit child-owned capability table once.
    /// No native library, worker or backend may open descriptors before this.
    pub fn receive(plan: &Preparation) -> Result<Self> {
        let count = Self::count(plan)?;
        let mut files = Vec::with_capacity(count);
        for offset in 0..count {
            let descriptor = FIRST_CAP + i32::try_from(offset).map_err(|_| ProtocolError)?;
            // SAFETY: the private factory contract transfers precisely these
            // descriptors to this one-session child. A failed query owns none.
            if unsafe { libc::fcntl(descriptor, libc::F_GETFD) } < 0 {
                return Err(ProtocolError);
            }
            let file = unsafe { File::from_raw_fd(descriptor) };
            // Never leak a preparation capability through an unrelated exec.
            // The reviewed backend duplicates only its explicit mount inputs.
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(ProtocolError);
            }
            files.push(file);
        }
        Self::from_files(plan, files)
    }

    fn count(plan: &Preparation) -> Result<usize> {
        plan.validate()?;
        if plan.backend != "bubblewrap"
            || plan.terminal.is_some()
            || !plan.filesystem.deny.is_empty()
            || plan.argv[0] != "/.defenseclaw/payload"
        {
            return Err(ProtocolError);
        }
        let paths: Vec<_> = plan
            .filesystem
            .read
            .iter()
            .chain(&plan.filesystem.write)
            .collect();
        for (index, path) in paths.iter().enumerate() {
            if !normalized(path)
                || ["/proc", "/dev", "/.defenseclaw"]
                    .iter()
                    .any(|root| covers(path, root) || covers(root, path))
            {
                return Err(ProtocolError);
            }
            if paths[index + 1..]
                .iter()
                .any(|other| covers(path, other) || covers(other, path))
            {
                return Err(ProtocolError);
            }
        }
        Ok(3 + plan.filesystem.read.len() + plan.filesystem.write.len())
    }

    pub fn from_files(plan: &Preparation, files: Vec<File>) -> Result<Self> {
        if files.len() != Self::count(plan)? {
            return Err(ProtocolError);
        }
        let mut files = files.into_iter();
        let mut next = || files.next().ok_or(ProtocolError);
        let bwrap = SealedImage::new(next()?)?;
        let payload = SealedImage::new(next()?)?;
        let cwd = HeldObject::new(next()?)?;
        if !cwd.identity.directory {
            return Err(ProtocolError);
        }
        let mut objects = |count| -> Result<Vec<HeldObject>> {
            (0..count).map(|_| HeldObject::new(next()?)).collect()
        };
        let read = objects(plan.filesystem.read.len())?;
        let write = objects(plan.filesystem.write.len())?;
        // The initial peer admits only an exact cwd grant. More complex guest
        // mappings need their own object-relative native admission first.
        let granted_cwd = plan
            .filesystem
            .read
            .iter()
            .zip(&read)
            .chain(plan.filesystem.write.iter().zip(&write))
            .any(|(destination, object)| {
                destination == &plan.workdir && object.identity == cwd.identity
            });
        if !granted_cwd {
            return Err(ProtocolError);
        }
        Ok(Self {
            bwrap,
            payload,
            cwd,
            read,
            write,
        })
    }
}

fn normalized(path: &str) -> bool {
    path.starts_with('/')
        && path.len() > 1
        && path[1..]
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn covers(path: &str, other: &str) -> bool {
    other == path
        || other
            .strip_prefix(path)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Filesystem, Variable};
    use std::io::Write;

    fn image(sealed: bool) -> File {
        // Synthetic ELF header only. It is never executed by these tests.
        let fd = unsafe {
            libc::memfd_create(
                c"fixed-inert-native-image".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        assert!(fd >= 0);
        let mut file = unsafe { File::from_raw_fd(fd) };
        let mut bytes = [0; 20];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[18] = 62;
        file.write_all(&bytes).unwrap();
        if sealed {
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, SEALS) }, 0);
        }
        file
    }

    fn plan() -> Preparation {
        Preparation {
            backend: "bubblewrap".into(),
            argv: vec!["/.defenseclaw/payload".into()],
            environment: vec![Variable {
                name: "HOME".into(),
                value: "/guest/work".into(),
            }],
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
        }
    }

    #[test]
    fn prepared_capabilities_survive_host_name_replacement() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("original");
        std::fs::create_dir(&original).unwrap();
        let directory = File::open(&original).unwrap();
        let caps = vec![
            image(true),
            image(true),
            directory.try_clone().unwrap(),
            directory,
        ];
        let prepared = PreparedFiles::from_files(&plan(), caps).unwrap();
        let identity = prepared.cwd.identity();
        std::fs::rename(&original, root.path().join("moved")).unwrap();
        std::fs::create_dir(&original).unwrap();
        assert_eq!(
            prepared.cwd.file().metadata().unwrap().ino(),
            identity.inode
        );
        assert_ne!(
            File::open(original).unwrap().metadata().unwrap().ino(),
            identity.inode
        );
    }

    #[test]
    fn mutable_image_and_mismatched_cwd_objects_refuse() {
        let root = tempfile::tempdir().unwrap();
        let directory = File::open(root.path()).unwrap();
        let caps = vec![
            image(false),
            image(true),
            directory.try_clone().unwrap(),
            directory,
        ];
        assert!(PreparedFiles::from_files(&plan(), caps).is_err());
        let other = tempfile::tempdir().unwrap();
        let caps = vec![
            image(true),
            image(true),
            File::open(root.path()).unwrap(),
            File::open(other.path()).unwrap(),
        ];
        assert!(PreparedFiles::from_files(&plan(), caps).is_err());
    }

    #[test]
    fn untranslated_masks_overlaps_and_backends_refuse_before_capability_transfer() {
        let original = plan();
        for field in [
            "deny",
            "overlap",
            "synthetic",
            "root",
            "backend",
            "terminal",
            "payload",
        ] {
            let mut plan = original.clone();
            match field {
                "deny" => plan.filesystem.deny.push("/guest/work/secret".into()),
                "overlap" => plan.filesystem.read.push("/guest/work/nested".into()),
                "synthetic" => plan.filesystem.read.push("/proc/1".into()),
                "root" => plan.filesystem.read.push("/".into()),
                "backend" => plan.backend = "seatbelt".into(),
                "terminal" => {
                    plan.terminal = Some(crate::wire::Size {
                        rows: 24,
                        columns: 80,
                    })
                }
                "payload" => plan.argv[0] = "/unbound/agent".into(),
                _ => unreachable!(),
            }
            assert!(PreparedFiles::count(&plan).is_err(), "{field}");
        }
        assert!(PreparedFiles::count(&original).is_ok());
    }
}
