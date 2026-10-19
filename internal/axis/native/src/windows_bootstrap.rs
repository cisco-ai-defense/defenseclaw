// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! Exact host capability prefix. Strings, digests and handle numbers never
//! reopen a host path or confer policy authority. No native process is started.

use super::windows_io::{Handle, IoStatus, Owned, Pipe, pending_fatal, wait_handles};
use crate::wire::{Preparation, ProtocolError, Result};
use std::collections::HashSet;
use std::ffi::c_void;
use std::io::{self, Read};
use std::mem::size_of;
use std::os::windows::io::OwnedHandle;
use std::time::{Duration, Instant};

const MAGIC: &[u8; 16] = b"DCAXIS-WINCAP1\0\0";
const HEADER: usize = 56;
const RECORD: usize = 40;
const MAX_CAPS: usize = 514;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    volume: u64,
    file: [u8; 16],
}

#[repr(C)]
struct FileInformation {
    attributes: u32,
    creation: [u32; 2],
    access: [u32; 2],
    write: [u32; 2],
    volume_serial: u32,
    size_high: u32,
    size_low: u32,
    links: u32,
    index_high: u32,
    index_low: u32,
}

const _: () = assert!(size_of::<Identity>() == 24);
const _: () = assert!(size_of::<FileInformation>() == 52);

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileType(file: Handle) -> u32;
    fn GetFileInformationByHandle(file: Handle, info: *mut FileInformation) -> i32;
    fn GetFileInformationByHandleEx(file: Handle, class: u32, info: *mut c_void, size: u32) -> i32;
    fn GetVolumeInformationByHandleW(
        file: Handle,
        volume_name: *mut u16,
        volume_size: u32,
        serial: *mut u32,
        component: *mut u32,
        flags: *mut u32,
        filesystem_name: *mut u16,
        filesystem_size: u32,
    ) -> i32;
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryVolumeInformationFile(
        file: Handle,
        status: *mut IoStatus,
        output: *mut c_void,
        size: u32,
        class: u32,
    ) -> i32;
}

pub struct HeldObject {
    handle: Owned,
    identity: Identity,
    directory: bool,
}

impl HeldObject {
    fn receive(record: &Record) -> Result<Self> {
        let handle = Owned::take_inherited(record.raw).map_err(|_| ProtocolError)?;
        let raw = handle.raw();
        let mut info: FileInformation = unsafe { std::mem::zeroed() };
        let mut actual = Identity {
            volume: 0,
            file: [0; 16],
        };
        let mut filesystem = [0u16; 32];
        if unsafe { GetFileType(raw) } != 1
            || unsafe { GetFileInformationByHandle(raw, &mut info) } == 0
            || info.attributes & 0x400 != 0
            || (info.attributes & 0x10 != 0) != record.directory
            || !record.directory && info.links != 1
            || unsafe {
                GetFileInformationByHandleEx(raw, 18, (&mut actual as *mut Identity).cast(), 24)
            } == 0
            || actual != record.identity
            || unsafe {
                GetVolumeInformationByHandleW(
                    raw,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    filesystem.as_mut_ptr(),
                    32,
                )
            } == 0
            || filesystem[..5] != [78, 84, 70, 83, 0]
        {
            return Err(ProtocolError);
        }
        let mut status: IoStatus = unsafe { std::mem::zeroed() };
        let mut device = [0u32; 2];
        let query = unsafe {
            NtQueryVolumeInformationFile(raw, &mut status, device.as_mut_ptr().cast(), 8, 4)
        };
        if query as u32 == 0x103 {
            pending_fatal();
        }
        if query != 0 || status.information != 8 || device[0] != 7 || device[1] & 0x10 != 0 {
            return Err(ProtocolError);
        }
        Ok(Self {
            handle,
            identity: actual,
            directory: record.directory,
        })
    }
    pub fn handle(&self) -> Handle {
        self.handle.raw()
    }
    pub fn identity(&self) -> Identity {
        self.identity
    }
    pub fn is_directory(&self) -> bool {
        self.directory
    }
    pub fn into_handle(self) -> Result<OwnedHandle> {
        self.handle.into_owned().map_err(|_| ProtocolError)
    }
}

struct Record {
    raw: Handle,
    identity: Identity,
    directory: bool,
}

pub struct Prefix {
    digest: [u8; 32],
    reads: usize,
    writes: usize,
    records: Vec<Record>,
}

impl Prefix {
    fn count(header: &[u8]) -> Result<(usize, usize, usize)> {
        if header.len() != HEADER || &header[..16] != MAGIC || header[16..18] != 1u16.to_be_bytes()
        {
            return Err(ProtocolError);
        }
        let total =
            u16::from_be_bytes(header[18..20].try_into().map_err(|_| ProtocolError)?) as usize;
        let read =
            u16::from_be_bytes(header[20..22].try_into().map_err(|_| ProtocolError)?) as usize;
        let write =
            u16::from_be_bytes(header[22..24].try_into().map_err(|_| ProtocolError)?) as usize;
        if read > 256 || write > 256 || total != 2 + read + write || total > MAX_CAPS {
            return Err(ProtocolError);
        }
        Ok((total, read, write))
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER {
            return Err(ProtocolError);
        }
        let (total, reads, writes) = Self::count(&bytes[..HEADER])?;
        if bytes.len() != HEADER + total * RECORD {
            return Err(ProtocolError);
        }
        let digest = bytes[24..56].try_into().map_err(|_| ProtocolError)?;
        let mut seen = HashSet::with_capacity(total);
        let mut records = Vec::with_capacity(total);
        for (index, record) in bytes[HEADER..].chunks_exact(RECORD).enumerate() {
            let expected = if index == 0 {
                1
            } else if index == 1 {
                2
            } else if index < 2 + reads {
                3
            } else {
                4
            };
            let raw = u64::from_be_bytes(record[8..16].try_into().map_err(|_| ProtocolError)?);
            let identity = Identity {
                volume: u64::from_be_bytes(record[16..24].try_into().map_err(|_| ProtocolError)?),
                file: record[24..40].try_into().map_err(|_| ProtocolError)?,
            };
            if record[0] != expected
                || record[1] > 1
                || record[2..8] != [0; 6]
                || raw == 0
                || raw > isize::MAX as u64
                || !seen.insert(raw)
                || index == 0 && record[1] != 0
                || index == 1 && record[1] != 1
                || identity
                    == (Identity {
                        volume: 0,
                        file: [0; 16],
                    })
            {
                return Err(ProtocolError);
            }
            records.push(Record {
                raw: raw as Handle,
                identity,
                directory: record[1] == 1,
            });
        }
        Ok(Self {
            digest,
            reads,
            writes,
            records,
        })
    }
    pub fn receive(input: &mut Pipe, deadline: Instant) -> Result<Self> {
        let mut bytes = vec![0; HEADER];
        read_exact(input, &mut bytes, deadline)?;
        let (total, _, _) = Self::count(&bytes)?;
        bytes.resize(HEADER + total * RECORD, 0);
        read_exact(input, &mut bytes[HEADER..], deadline)?;
        Self::decode(&bytes)
    }
    pub fn adopt(self) -> Result<Capabilities> {
        let objects = self
            .records
            .iter()
            .map(HeldObject::receive)
            .collect::<Result<Vec<_>>>()?;
        Ok(Capabilities {
            digest: self.digest,
            reads: self.reads,
            writes: self.writes,
            objects,
        })
    }
}

fn read_exact(input: &mut Pipe, bytes: &mut [u8], deadline: Instant) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        if Instant::now() >= deadline {
            return Err(ProtocolError);
        }
        let amount = (bytes.len() - offset).min(crate::wire::MAX_DATA);
        match input.read(&mut bytes[offset..offset + amount]) {
            Ok(0) => return Err(ProtocolError),
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let handles = input.wait_handle().into_iter().collect::<Vec<_>>();
                wait_handles(&handles, Duration::from_millis(10)).map_err(|_| ProtocolError)?;
            }
            Err(_) => return Err(ProtocolError),
        }
    }
    Ok(())
}

pub struct Capabilities {
    digest: [u8; 32],
    reads: usize,
    writes: usize,
    objects: Vec<HeldObject>,
}

impl Capabilities {
    pub fn bind(&self, plan: &Preparation) -> Result<()> {
        plan.validate()?;
        let hash = plan.hash()?;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut expected = String::from("sha256:");
        for byte in self.digest {
            expected.push(HEX[(byte >> 4) as usize] as char);
            expected.push(HEX[(byte & 15) as usize] as char);
        }
        // Existing Frame::validate independently binds Preparation.hash() to
        // Binding.preparation_hash before Owner calls Engine.prepare(plan).
        if hash != expected
            || plan.backend != "windows_psec"
            || !plan.offline
            || plan.terminal.is_some()
            || !plan.filesystem.deny.is_empty()
            || plan.filesystem.read.len() != self.reads
            || plan.filesystem.write.len() != self.writes
        {
            return Err(ProtocolError);
        }
        let granted = plan
            .filesystem
            .read
            .iter()
            .chain(&plan.filesystem.write)
            .enumerate()
            .any(|(index, path)| {
                path == &plan.workdir
                    && self.objects[index + 2].identity == self.objects[1].identity
            });
        if !granted {
            return Err(ProtocolError);
        }
        Ok(())
    }
    // Deliberately no path accessor or process launch. WindowsEngine will take
    // these objects once through a separately reviewed SDK-held-capability API.
    pub fn into_objects(self) -> Vec<HeldObject> {
        self.objects
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn public_prefix() -> Vec<u8> {
        let mut data = vec![0u8; HEADER + 2 * RECORD];
        data[..16].copy_from_slice(MAGIC);
        data[16..18].copy_from_slice(&1u16.to_be_bytes());
        data[18..20].copy_from_slice(&2u16.to_be_bytes());
        for index in 0..2 {
            let record = &mut data[HEADER + index * RECORD..][..RECORD];
            record[0] = 1 + index as u8;
            record[1] = index as u8;
            record[8..16].copy_from_slice(&(64u64 + index as u64).to_be_bytes());
            record[16..24].copy_from_slice(&1u64.to_be_bytes());
            record[24] = 1 + index as u8;
        }
        data
    }
    #[test]
    fn prefix_only_pure_roundtrip_and_all_boundaries() {
        let data = public_prefix();
        assert!(Prefix::decode(&data).is_ok());
        for length in 0..data.len() {
            assert!(Prefix::decode(&data[..length]).is_err());
        }
        let mut trailing = data.clone();
        trailing.push(0);
        assert!(Prefix::decode(&trailing).is_err());
        for at in [
            0,
            16,
            18,
            20,
            22,
            HEADER,
            HEADER + 1,
            HEADER + 2,
            HEADER + RECORD,
        ] {
            let mut changed = data.clone();
            changed[at] = 255;
            assert!(Prefix::decode(&changed).is_err());
        }
        let mut alias = data.clone();
        let first = alias[HEADER + 8..HEADER + 16].to_vec();
        alias[HEADER + RECORD + 8..HEADER + RECORD + 16].copy_from_slice(&first);
        assert!(Prefix::decode(&alias).is_err());
    }
}
