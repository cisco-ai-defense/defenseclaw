// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Contributor-only PRIVATE refusal evidence and an existing descriptor/verifier
// reused for new fixture directories. Never format record bytes into an error,
// log, result, receipt or uploaded artifact. The record grants nothing.
use std::ffi::OsStr;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{IntoRawHandle, OwnedHandle};
use windows::Wdk::Storage::FileSystem::{
    NTCREATEFILE_CREATE_DISPOSITION, NTCREATEFILE_CREATE_OPTIONS, NtCreateFile,
};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetAce, GetLengthSid, GetSecurityDescriptorControl,
    GetTokenInformation, IsValidAcl, IsValidSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    PSID, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ACCESS_RIGHTS, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, WriteFile,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{PCWSTR, PWSTR};

use super::{
    attributes, bounded_wide, handle, owned, require_process_identity_context, sid_range, unicode,
};

const NAME: &str = "native-folder-refusal.private.bin";
const MAGIC: &[u8; 8] = b"DCNATIV1";
const COMPLETE: &[u8; 8] = b"COMPLETE";
const MAX_UNITS: usize = 2048;
const MAX_BYTES: usize = 8216;
const SYSTEM_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
type PrivateResult<T> = Result<T, ()>;

fn encode(caller: &OsStr, native: &OsStr) -> PrivateResult<Vec<u8>> {
    let mut result = MAGIC.to_vec();
    for value in [caller, native] {
        let units: Vec<_> = value.encode_wide().take(MAX_UNITS + 1).collect();
        if units.is_empty() || units.len() > MAX_UNITS || units.contains(&0) {
            return Err(());
        }
        result.extend((units.len() as u32).to_le_bytes());
        for unit in units {
            result.extend(unit.to_le_bytes());
        }
    }
    result.extend(COMPLETE);
    if result.len() > MAX_BYTES {
        return Err(());
    }
    Ok(result)
}

struct LocalDescriptor(PSECURITY_DESCRIPTOR);

impl LocalDescriptor {
    fn release(mut self) -> PrivateResult<()> {
        let pointer = std::mem::replace(&mut self.0, PSECURITY_DESCRIPTOR::default());
        if pointer.0.is_null() || unsafe { LocalFree(Some(HLOCAL(pointer.0))) }.is_invalid() {
            Ok(())
        } else {
            Err(())
        }
    }
}

impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        if !self.0.0.is_null() {
            unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
        }
    }
}

// DWORD alignment is required for native SID operations. No SID or descriptor
// implements Debug/Serialize or escapes the private writer.
struct UserSid(Vec<u32>);

impl UserSid {
    fn sid(&self) -> PSID {
        PSID(self.0.as_ptr().cast_mut().cast())
    }

    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.0.as_ptr().cast(), self.0.len() * 4) }
    }
}

fn current_user() -> PrivateResult<UserSid> {
    require_process_identity_context().map_err(|_| ())?;
    let mut raw = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) }.map_err(|_| ())?;
    let token = owned(raw).map_err(|_| ())?;
    let mut words = [0u64; 512];
    let mut returned = 0;
    unsafe {
        GetTokenInformation(
            handle(&token),
            TokenUser,
            Some(words.as_mut_ptr().cast()),
            size_of::<[u64; 512]>() as u32,
            &mut returned,
        )
    }
    .map_err(|_| ())?;
    if !(size_of::<TOKEN_USER>()..=size_of::<[u64; 512]>()).contains(&(returned as usize)) {
        return Err(());
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), returned as usize) };
    let mut pointer = [0; size_of::<usize>()];
    pointer.copy_from_slice(&bytes[..size_of::<usize>()]);
    let address = usize::from_ne_bytes(pointer);
    let range = sid_range(bytes, address).map_err(|_| ())?;
    if address % 4 != 0
        || range.start < size_of::<TOKEN_USER>()
        || range.len() > 68
        || range.len() % 4 != 0
    {
        return Err(());
    }
    let sid = PSID(address as *mut _);
    if !unsafe { IsValidSid(sid) }.as_bool() || unsafe { GetLengthSid(sid) } as usize != range.len()
    {
        return Err(());
    }
    let result = UserSid(
        bytes[range]
            .chunks_exact(4)
            .map(|word| u32::from_ne_bytes(word.try_into().unwrap()))
            .collect(),
    );
    if result.bytes() == SYSTEM_SID {
        return Err(());
    }
    require_process_identity_context().map_err(|_| ())?;
    Ok(result)
}

fn descriptor(user: &UserSid) -> PrivateResult<LocalDescriptor> {
    let mut text = PWSTR::null();
    if unsafe { ConvertSidToStringSidW(user.sid(), &mut text) }.is_err() {
        if !text.is_null() {
            unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
        }
        return Err(());
    }
    let units = unsafe { bounded_wide(text, 192) }.map_err(|_| ());
    let freed = unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) }.is_invalid();
    let units = units?;
    if !freed {
        return Err(());
    }
    let user = String::from_utf16(&units).map_err(|_| ())?;
    let sddl: Vec<_> = format!("O:{user}D:P(A;;FA;;;{user})(A;;FA;;;SY)")
        .encode_utf16()
        .chain([0])
        .collect();
    let mut result = LocalDescriptor(PSECURITY_DESCRIPTOR::default());
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            1,
            &mut result.0,
            None,
        )
    }
    .map_err(|_| ())?;
    Ok(result)
}

fn private_security(file: HANDLE, user: &UserSid) -> PrivateResult<()> {
    let mut owner = PSID::default();
    let mut acl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = LocalDescriptor(PSECURITY_DESCRIPTOR::default());
    let status = unsafe {
        GetSecurityInfo(
            file,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut acl),
            None,
            Some(&mut descriptor.0),
        )
    };
    let valid = (|| {
        if status.0 != 0
            || !unsafe { IsValidSid(owner) }.as_bool()
            || unsafe { GetLengthSid(owner) } > 68
        {
            return Err(());
        }
        let owner_bytes = unsafe {
            std::slice::from_raw_parts(owner.0.cast::<u8>(), GetLengthSid(owner) as usize)
        };
        if owner_bytes != user.bytes() || acl.is_null() || !unsafe { IsValidAcl(acl) }.as_bool() {
            return Err(());
        }
        let mut control = 0;
        let mut revision = 0;
        unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) }
            .map_err(|_| ())?;
        if control & 0x1004 != 0x1004
            || revision != 1
            || unsafe { (*acl).AceCount } != 2
            || unsafe { (*acl).AclSize } > 256
        {
            return Err(());
        }
        let mut user_seen = false;
        let mut system_seen = false;
        for index in 0..2 {
            let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
            unsafe { GetAce(acl, index, &mut ace) }.map_err(|_| ())?;
            let offset = (ace as usize).checked_sub(acl as usize).ok_or(())?;
            let available = usize::from(unsafe { (*acl).AclSize })
                .checked_sub(offset)
                .ok_or(())?;
            if available < 16 {
                return Err(());
            }
            let head = unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), 8) };
            let count = u16::from_le_bytes([head[2], head[3]]) as usize;
            let mask = u32::from_le_bytes(head[4..8].try_into().unwrap());
            if head[0] != 0
                || head[1] != 0
                || count < 16
                || count > available
                || mask != 0x001f_01ff
            {
                return Err(());
            }
            let sid = PSID(unsafe { ace.cast::<u8>().add(8) }.cast());
            let ace_bytes = unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), count) };
            let sid_body = sid_range(ace_bytes, sid.0 as usize).map_err(|_| ())?;
            if sid_body.start != 8
                || sid_body.end != count
                || !unsafe { IsValidSid(sid) }.as_bool()
                || unsafe { GetLengthSid(sid) } as usize != sid_body.len()
            {
                return Err(());
            }
            let bytes = unsafe {
                std::slice::from_raw_parts(sid.0.cast::<u8>(), GetLengthSid(sid) as usize)
            };
            if bytes == user.bytes() && !user_seen {
                user_seen = true;
            } else if bytes == SYSTEM_SID && !system_seen {
                system_seen = true;
            } else {
                return Err(());
            }
        }
        if user_seen && system_seen {
            Ok(())
        } else {
            Err(())
        }
    })();
    let released = descriptor.release();
    valid.and(released)
}

fn close(file: OwnedHandle) -> PrivateResult<()> {
    unsafe { CloseHandle(HANDLE(file.into_raw_handle())) }.map_err(|_| ())
}

fn create(root: &OwnedHandle, user: &UserSid) -> PrivateResult<OwnedHandle> {
    let descriptor = descriptor(user)?;
    let mut name: Vec<_> = NAME.encode_utf16().collect();
    let name = unicode(&mut name).map_err(|_| ())?;
    let mut attributes = attributes(handle(root), &name, 0x40 | 0x1000);
    attributes.SecurityDescriptor = descriptor.0.0.cast_const().cast();
    let mut raw = HANDLE::default();
    let mut status = IO_STATUS_BLOCK::default();
    let created = unsafe {
        NtCreateFile(
            &mut raw,
            FILE_ACCESS_RIGHTS(0x0012_0003),
            &attributes,
            &mut status,
            None,
            FILE_FLAGS_AND_ATTRIBUTES(0x80),
            FILE_SHARE_MODE(0),
            NTCREATEFILE_CREATE_DISPOSITION(2),
            NTCREATEFILE_CREATE_OPTIONS(0x0020_0060),
            None,
            0,
        )
    };
    if created.0 < 0 {
        return Err(());
    }
    let file = owned(raw).map_err(|_| ())?;
    let released = descriptor.release();
    if created.0 != 0 || status.Information != 2 || released.is_err() {
        let _ = close(file);
        return Err(());
    }
    Ok(file)
}

pub(super) fn create_fixture_directory(
    root: &OwnedHandle,
    component: &mut [u16],
) -> PrivateResult<OwnedHandle> {
    // Only the fully validated, root-bound ExpectedEnvironment calls this.
    // This local guard additionally makes the NT name one literal component.
    if component.is_empty()
        || component.len() > 128
        || matches!(&*component, [46] | [46, 46])
        || component.iter().any(|unit| [0, 47, 58, 92].contains(unit))
    {
        return Err(());
    }
    let user = current_user()?;
    let descriptor = descriptor(&user)?;
    let name = unicode(component).map_err(|_| ())?;
    let mut attributes = attributes(handle(root), &name, 0x40 | 0x1000);
    attributes.SecurityDescriptor = descriptor.0.0.cast_const().cast();
    let mut raw = HANDLE::default();
    let mut status = IO_STATUS_BLOCK::default();
    let created = unsafe {
        NtCreateFile(
            &mut raw,
            FILE_ACCESS_RIGHTS(0x0012_0081), // LIST | ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
            &attributes,
            &mut status,
            None,
            FILE_FLAGS_AND_ATTRIBUTES(0x10),
            FILE_SHARE_MODE(3),                 // reads/writes, no delete sharing
            NTCREATEFILE_CREATE_DISPOSITION(2), // FILE_CREATE, never OPEN_IF
            NTCREATEFILE_CREATE_OPTIONS(0x0020_0021),
            None,
            0,
        )
    };
    if created.0 < 0 {
        return Err(());
    }
    let file = owned(raw).map_err(|_| ())?;
    let released = descriptor.release();
    if created.0 != 0
        || status.Information != 2
        || released.is_err()
        || super::require_directory(&file).is_err()
        || private_security(handle(&file), &user).is_err()
    {
        let _ = close(file);
        return Err(());
    }
    Ok(file)
}

pub(super) fn capture(root: &OwnedHandle, caller: &OsStr, native: &OsStr) -> bool {
    // Only this boolean may leave the writer. Do not surface any inner error.
    (|| {
        let bytes = encode(caller, native)?;
        let user = current_user()?;
        let file = create(root, &user)?;
        let written = (|| {
            private_security(handle(&file), &user)?; // before the first byte
            let mut offset = 0;
            while offset < bytes.len() {
                let mut count = 0;
                unsafe {
                    WriteFile(
                        handle(&file),
                        Some(&bytes[offset..]),
                        Some(&mut count),
                        None,
                    )
                }
                .map_err(|_| ())?;
                if count == 0 || count as usize > bytes.len() - offset {
                    return Err(());
                }
                offset += count as usize;
            }
            Ok(())
        })();
        let closed = close(file);
        written.and(closed)
    })()
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;

    fn decode(bytes: &[u8]) -> PrivateResult<[Vec<u16>; 2]> {
        if bytes.len() > MAX_BYTES || !bytes.starts_with(MAGIC) {
            return Err(());
        }
        let mut offset = MAGIC.len();
        let mut result = [Vec::new(), Vec::new()];
        for field in &mut result {
            let end = offset.checked_add(4).ok_or(())?;
            let count =
                u32::from_le_bytes(bytes.get(offset..end).ok_or(())?.try_into().unwrap()) as usize;
            if count == 0 || count > MAX_UNITS {
                return Err(());
            }
            offset = end;
            let end = offset.checked_add(count * 2).ok_or(())?;
            *field = bytes
                .get(offset..end)
                .ok_or(())?
                .chunks_exact(2)
                .map(|unit| u16::from_le_bytes(unit.try_into().unwrap()))
                .collect();
            if field.contains(&0) {
                return Err(());
            }
            offset = end;
        }
        if bytes.get(offset..) != Some(COMPLETE.as_slice()) {
            return Err(());
        }
        Ok(result)
    }

    #[test]
    fn fixed_private_record_is_lossless_bounded_complete_and_not_authority() {
        let first = OsString::from_wide(&[67, 58, 92, 0xd800, 0x03bb]);
        let second = OsString::from_wide(&[68, 58, 92, 0xdc00, 0x96ea]);
        let bytes = encode(&first, &second).unwrap();
        assert_eq!(
            decode(&bytes).unwrap(),
            [
                first.encode_wide().collect::<Vec<_>>(),
                second.encode_wide().collect()
            ]
        );
        let maximum = OsString::from_wide(&vec![0xd800; MAX_UNITS]);
        let bytes = encode(&maximum, &maximum).unwrap();
        assert_eq!(bytes.len(), MAX_BYTES);
        assert!(decode(&bytes).is_ok());
        assert!(encode(OsStr::new(""), &maximum).is_err());
        assert!(encode(&OsString::from_wide(&[67, 0, 68]), &maximum).is_err());
        assert!(encode(&OsString::from_wide(&vec![65; MAX_UNITS + 1]), &maximum).is_err());
        for size in [0, 7, 8, 10, bytes.len() - 1] {
            assert!(decode(&bytes[..size]).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(decode(&extra).is_err());
        let mut oversized = bytes.clone();
        oversized[8..12].copy_from_slice(&2049u32.to_le_bytes());
        assert!(decode(&oversized).is_err());
        let mut nul = bytes.clone();
        nul[12..14].fill(0);
        assert!(decode(&nul).is_err());
    }

    #[test]
    fn private_record_create_is_exclusive_nonfollowing_and_owner_system_only() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("fixed-owned-root");
        std::fs::create_dir(&root).unwrap();
        let custody = super::super::pin_fixture_root(&root).unwrap();
        let held = custody.directories.last().unwrap();
        let caller = OsStr::new(r"C:\fixed-public-caller");
        let native = OsStr::new(r"D:\fixed-public-native");
        assert!(capture(held, caller, native));
        let path = root.join(NAME);
        let bytes = std::fs::read(&path).unwrap();
        assert!(decode(&bytes).is_ok());
        let inspection = std::fs::File::open(&path).unwrap();
        assert!(
            private_security(HANDLE(inspection.as_raw_handle()), &current_user().unwrap()).is_ok()
        );
        drop(inspection);
        assert!(!capture(held, native, caller));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        std::fs::remove_file(&path).unwrap();
        let canary = temp.path().join("fixed-public-target.txt");
        std::fs::write(&canary, b"fixed public data").unwrap();
        std::os::windows::fs::symlink_file(&canary, &path).unwrap();
        assert!(!capture(held, caller, native));
        assert_eq!(std::fs::read(&canary).unwrap(), b"fixed public data");
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(!capture(held, caller, native));
        drop(custody);
    }

    #[test]
    fn private_environment_subtree_is_exclusive_nonfollowing_private_and_pinned() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("fixed-owned-fixture");
        let local = root.join(r"home\AppData\Local");
        std::fs::create_dir_all(&local).unwrap();
        let custody = super::super::pin_fixture_root(&root).unwrap();
        let folder = local.join(r"Packages\fixed public λ+$\AC");
        let expected =
            super::super::ExpectedEnvironment::from_native_folder(&root, folder.as_os_str())
                .unwrap();
        assert!(!local.join("Packages").exists());
        let held = super::super::pin_private_directories(&custody, &expected).unwrap();
        assert_eq!(held.len(), 7);
        assert!(expected.temporary.is_dir());
        let user = current_user().unwrap();
        for file in &held[3..] {
            private_security(handle(file), &user).unwrap();
        }
        let moved = local.join("fixed-renamed-packages");
        assert_eq!(
            std::fs::rename(local.join("Packages"), &moved)
                .unwrap_err()
                .raw_os_error(),
            Some(32)
        );
        // The existing branch cannot be adopted, even with its exact safe DACL.
        assert!(super::super::pin_private_directories(&custody, &expected).is_err());
        drop(held);
        std::fs::rename(local.join("Packages"), &moved).unwrap();
        std::fs::remove_dir_all(&moved).unwrap();

        // A preexisting reparse target or regular file also cannot become the
        // fixture's new Packages. Both positive canaries remain unchanged.
        let outside = temp.path().join("fixed-public-target");
        std::fs::create_dir(&outside).unwrap();
        let canary = outside.join("fixed-public.txt");
        std::fs::write(&canary, b"fixed public data").unwrap();
        std::os::windows::fs::symlink_dir(&outside, local.join("Packages")).unwrap();
        assert!(super::super::pin_private_directories(&custody, &expected).is_err());
        assert_eq!(std::fs::read(&canary).unwrap(), b"fixed public data");
        assert!(!outside.join("fixed public λ+$").exists());
        std::fs::remove_dir(local.join("Packages")).unwrap();
        std::fs::write(local.join("Packages"), b"fixed public collision").unwrap();
        assert!(super::super::pin_private_directories(&custody, &expected).is_err());
        assert_eq!(
            std::fs::read(local.join("Packages")).unwrap(),
            b"fixed public collision"
        );
        std::fs::remove_file(local.join("Packages")).unwrap();

        // Reject a forged mapped branch before creating even Packages.
        let mut forged = expected;
        forged.local_app_data = outside.join("AC");
        assert!(super::super::pin_private_directories(&custody, &forged).is_err());
        assert!(!local.join("Packages").exists());
        drop(custody);
    }
}
