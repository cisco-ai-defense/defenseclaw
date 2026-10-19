// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! Standalone std-only fixed loader diagnostic. No SDK, user UI API, profile
//! API, network call, filesystem mutation or caller-selected DLL is accepted.

mod dll_startup_protocol;

#[cfg(all(windows, target_arch = "x86_64"))]
fn run() -> std::io::Result<()> {
    use dll_startup_protocol::{FixedDll, LoadResult};
    use std::ffi::{OsString, c_void};
    use std::io::Write;

    // These imports add only Kernel32 entry points to the std-only image.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
        fn GetLastError() -> u32;
        fn SetErrorMode(mode: u32) -> u32;
    }
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let case = match arguments.as_slice() {
        [selector] => FixedDll::from_selector(selector),
        _ => None,
    }
    .ok_or_else(|| std::io::Error::other("one fixed DLL selector is required"))?;
    let mut output = std::io::stdout().lock();
    output.write_all(case.start_marker().as_bytes())?;
    output.flush()?;
    let name: Vec<u16> = case.dll_name().encode_utf16().chain(Some(0)).collect();
    // SAFETY: fixed UTF-16 module names are NUL terminated, hFile is reserved
    // NULL, and SYSTEM32-only search excludes the fixture/CWD/PATH. Error
    // dialogs are disabled only for this owned diagnostic process. No flags
    // bypass DLL initialization, code authorization or sandbox enforcement.
    let result = unsafe {
        SetErrorMode(0x0001 | 0x0002 | 0x8000);
        let module = LoadLibraryExW(name.as_ptr(), std::ptr::null_mut(), 0x0000_0800);
        if module.is_null() {
            LoadResult::ReturnedError(GetLastError())
        } else {
            LoadResult::Loaded
        }
    };
    output.write_all(result.marker(case).as_bytes())?;
    output.flush()?;
    // The one loaded module stays mapped until this fresh process exits; no
    // exported User32/GDI32/Shell32 function is invoked by the diagnostic.
    Ok(())
}

fn main() {
    #[cfg(all(windows, target_arch = "x86_64"))]
    if let Err(error) = run() {
        eprintln!("fixed DLL diagnostic: {error}");
        std::process::exit(1);
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        eprintln!("this fixed DLL diagnostic requires native Windows x86_64");
        std::process::exit(2);
    }
}
