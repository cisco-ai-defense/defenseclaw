// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Fixed contributor payload: std only, no SDK or AXIS imports. It accepts no
// caller executable, script, host credential, destination or filesystem path.
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::thread;
use std::time::Duration;

const SENTINEL: &[u8] = b"fixed-public-synthetic-canary\n";

mod native_environment;

mod canonicalize_diagnostic {
    use super::SENTINEL;
    use std::ffi::c_void;
    use std::fs;
    use std::io::Read;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;

    type Handle = *mut c_void;
    const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
    const FILE_SHARE_READ_WRITE_DELETE: u32 = 0x0000_0007;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_NAME_OPENED: u32 = 0x0000_0008;
    const VOLUME_NAME_NT: u32 = 0x0000_0002;
    const PATH_BUFFER_UNITS: usize = 32_768;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        #[link_name = "CreateFileW"]
        fn create_file_w(
            name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *const c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: Handle,
        ) -> Handle;
        #[link_name = "GetFinalPathNameByHandleW"]
        fn get_final_path_name_by_handle_w(
            file: Handle,
            buffer: *mut u16,
            buffer_length: u32,
            flags: u32,
        ) -> u32;
        #[link_name = "CloseHandle"]
        fn close_handle(handle: Handle) -> i32;
        #[link_name = "GetLastError"]
        fn get_last_error() -> u32;
    }

    fn name_query(handle: Handle, operation: &str, flags: u32) {
        let mut buffer = [0u16; PATH_BUFFER_UNITS];
        // Query the same held directory object; never display or retain its path.
        let length = unsafe {
            get_final_path_name_by_handle_w(handle, buffer.as_mut_ptr(), buffer.len() as u32, flags)
        };
        if length == 0 {
            eprintln!("{operation} win32={}", unsafe { get_last_error() });
        } else if length as usize >= buffer.len() {
            eprintln!("{operation} result=oversize length={length}");
        } else {
            eprintln!("{operation} result=ok length={length}");
        }
    }

    pub(super) fn report(cwd: &Path) {
        let name: Vec<u16> = cwd.as_os_str().encode_wide().chain(Some(0)).collect();
        if name.len() > PATH_BUFFER_UNITS {
            eprintln!("FIXED_CANON_OPEN result=oversize");
            return;
        }
        // Match Rust 1.95's canonicalize directory open: access 0, full sharing,
        // OPEN_EXISTING and FILE_FLAG_BACKUP_SEMANTICS. No host path is printed.
        let handle = unsafe {
            create_file_w(
                name.as_ptr(),
                0,
                FILE_SHARE_READ_WRITE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            eprintln!("FIXED_CANON_OPEN win32={}", unsafe { get_last_error() });
        } else {
            eprintln!("FIXED_CANON_OPEN result=ok");
            name_query(handle, "FIXED_CANON_NORMALIZED_DOS", 0);
            name_query(handle, "FIXED_CANON_OPENED_DOS", FILE_NAME_OPENED);
            name_query(handle, "FIXED_CANON_NORMALIZED_NT", VOLUME_NAME_NT);
            if unsafe { close_handle(handle) } == 0 {
                eprintln!("FIXED_CANON_CLOSE win32={}", unsafe { get_last_error() });
            } else {
                eprintln!("FIXED_CANON_CLOSE result=ok");
            }
        }
        let seal = fs::File::open(cwd.join("fixture-seal")).and_then(|file| {
            let mut bytes = Vec::new();
            file.take((SENTINEL.len() + 1) as u64)
                .read_to_end(&mut bytes)?;
            Ok(bytes)
        });
        match seal {
            Ok(bytes) => eprintln!(
                "FIXED_CANON_SEAL_READ result=ok match={}",
                bytes.as_slice() == SENTINEL
            ),
            Err(error) => eprintln!(
                "FIXED_CANON_SEAL_READ win32={}",
                error.raw_os_error().unwrap_or(-1)
            ),
        }
    }
}

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match run(&args) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("fixed child failed: {error}");
            std::process::exit(1);
        }
    }
}

fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

fn fixed_io<T>(operation: &'static str, result: io::Result<T>) -> io::Result<T> {
    result.map_err(|error| io::Error::new(error.kind(), format!("{operation}: {error}")))
}

fn fixed_private_environment_path(actual: &OsStr, expected: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;

    fn disk_spelling(value: &OsStr) -> Option<Vec<u16>> {
        let raw: Vec<u16> = value.encode_wide().take(32_769).collect();
        if raw.len() > 32_768 {
            return None;
        }
        // The parent canonicalizes its fixed local fixture; Windows can return
        // the same cwd without the verbatim-disk prefix. Accept only that exact
        // spelling difference. No case folding, slash/dot/UNC/device/drive-map
        // normalization or filesystem lookup belongs in this test assertion.
        let path = raw.strip_prefix(&[92, 92, 63, 92]).unwrap_or(&raw);
        if path.len() < 3
            || !((b'A' as u16..=b'Z' as u16).contains(&path[0])
                || (b'a' as u16..=b'z' as u16).contains(&path[0]))
            || path[1..3] != [58, 92]
        {
            return None;
        }
        Some(path.to_vec())
    }

    match (disk_spelling(actual), disk_spelling(expected.as_os_str())) {
        (Some(actual), Some(expected)) => actual == expected,
        _ => false,
    }
}

fn fixed_environment_comparison(actual: &OsStr, expected: &Path) -> String {
    use std::os::windows::ffi::OsStrExt;

    // Diagnostic metadata only. Never include an environment value or a path.
    // Bound iteration even if a corrupted environment exceeds Windows' limit.
    let actual: Vec<u16> = actual.encode_wide().take(32_769).collect();
    let expected: Vec<u16> = expected.as_os_str().encode_wide().take(32_769).collect();
    let prefix = [92, 92, 63, 92];
    let a = actual.strip_prefix(&prefix).unwrap_or(&actual);
    let b = expected.strip_prefix(&prefix).unwrap_or(&expected);
    let fold_ascii = |unit: u16| {
        if (65..=90).contains(&unit) {
            unit + 32
        } else {
            unit
        }
    };
    let ascii_case_only = a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(left, right)| fold_ascii(*left) == fold_ascii(*right));
    let first_difference = a
        .iter()
        .zip(b)
        .position(|(left, right)| left != right)
        .unwrap_or(a.len().min(b.len()));
    format!(
        "actual_units={} expected_units={} actual_verbatim={} expected_verbatim={} ascii_case_only={} first_difference={}",
        actual.len(),
        expected.len(),
        actual.starts_with(&prefix),
        expected.starts_with(&prefix),
        ascii_case_only,
        first_difference,
    )
}

fn fixed_environment_location(actual: &OsStr, root: &Path) -> String {
    use std::os::windows::ffi::OsStrExt;

    // Lexical diagnostic flags only, never filesystem admission or a relaxed
    // environment assertion. Keep arbitrary values and component names private.
    fn units(value: &OsStr) -> Option<Vec<u16>> {
        let value: Vec<_> = value.encode_wide().take(32_769).collect();
        if value.len() > 32_768 {
            return None;
        }
        Some(
            value
                .strip_prefix(&[92, 92, 63, 92])
                .unwrap_or(&value)
                .to_vec(),
        )
    }
    let (Some(actual), Some(root)) = (units(actual), units(root.as_os_str())) else {
        return "classification=oversize".to_owned();
    };
    let below = |suffix: &str| {
        let mut prefix = root.clone();
        if !suffix.is_empty() {
            prefix.push(92);
            prefix.extend(suffix.encode_utf16());
        }
        actual.starts_with(&prefix)
            && (actual.len() == prefix.len() || actual.get(prefix.len()) == Some(&92))
    };
    let relative = actual
        .strip_prefix(root.as_slice())
        .and_then(|tail| tail.strip_prefix(&[92]));
    let parts: Vec<_> = relative
        .map(|tail| tail.split(|unit| *unit == 92).collect())
        .unwrap_or_default();
    let dot_or_slash =
        actual.contains(&47) || parts.iter().any(|part| *part == [46] || *part == [46, 46]);
    let final_temp = parts
        .last()
        .is_some_and(|part| *part == [84, 101, 109, 112]);
    format!(
        "lexical_fixture_prefix={} lexical_home_prefix={} lexical_local_app_data_prefix={} lexical_private_tmp_prefix={} lexical_packages_prefix={} relative_components={} dot_component_or_slash={} final_temp_component={}",
        below(""),
        below("home"),
        below(r"home\AppData\Local"),
        below("tmp"),
        below(r"home\AppData\Local\Packages"),
        parts.len(),
        dot_or_slash,
        final_temp,
    )
}

fn run(args: &[OsString]) -> Result<i32, Box<dyn std::error::Error>> {
    require(
        args.first().is_some_and(|arg| arg == "--fixed-child"),
        "fixed child selector required",
    )?;
    let mode = args.get(1).and_then(|arg| arg.to_str());
    if mode == Some("argv") {
        let expected: Vec<OsString> = [
            "--fixed-child",
            "argv",
            "",
            "a b",
            "a\"b",
            "tail\\",
            "λ-雪;$()`&|<>*?",
            "quoted space\\",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        require(args == expected, "literal Windows argv differs")?;
        println!("FIXED_ARGV_PASS");
        return Ok(0);
    }
    require(
        args.len() == 6,
        "only a fixed mode and four canary ports are accepted",
    )?;
    let ports: Vec<u16> = args[2..]
        .iter()
        .map(|port| {
            port.to_str()
                .ok_or_else(|| io::Error::other("invalid canary port encoding"))?
                .parse::<u16>()
                .map_err(io::Error::other)
        })
        .collect::<io::Result<_>>()?;
    require(ports.iter().all(|port| *port != 0), "zero canary port")?;
    match mode {
        Some("exit23") => {
            println!("FIXED_EXIT23_STARTED");
            return Ok(23);
        }
        Some("timeout") => {
            println!("FIXED_TIMEOUT_STARTED");
            thread::sleep(Duration::from_secs(30));
            return Ok(44);
        }
        Some("boundary" | "boundary-native-env") => {}
        _ => return Err(io::Error::other("unsupported fixed child mode").into()),
    }
    let cwd = fixed_io("private cwd lookup", std::env::current_dir())?;
    // DOS final-path queries can be denied independently of the granted file
    // operations. Record that compatibility result without making it a
    // prerequisite for this fixed fixture's boundary checks. These path labels
    // grant no authority: the native parent supplies the exact cwd and policy;
    // the fixed seal, fixture shape and private environment are checked below.
    match cwd.canonicalize() {
        Ok(_) => eprintln!("FIXED_CANONICALIZE result=ok"),
        Err(error) => {
            eprintln!(
                "FIXED_CANONICALIZE win32={}",
                error.raw_os_error().unwrap_or(-1)
            );
            canonicalize_diagnostic::report(&cwd);
        }
    }
    let workspace = cwd;
    require(
        workspace
            .file_name()
            .is_some_and(|name| name == "workspace"),
        "private cwd missing",
    )?;
    let root = workspace
        .parent()
        .ok_or_else(|| io::Error::other("fixture parent missing"))?;
    require(
        root.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("dc-axis-windows-psec-")),
        "unexpected fixture root",
    )?;
    require(
        fixed_io(
            "workspace seal read",
            fs::read(workspace.join("fixture-seal")),
        )? == SENTINEL,
        "fixture seal missing",
    )?;
    // No observation of the child's environment supplies these expectations.
    // The new selector blocks on an exact bounded parent frame and EOF before
    // its first environment assertion or mutation. The old selector retains
    // the original six strict fixture expectations for its distinct control.
    let native = if mode == Some("boundary-native-env") {
        Some(native_environment::ExpectedEnvironment::read_from(
            io::stdin().lock(),
            root,
        )?)
    } else {
        None
    };
    let temporary = native
        .as_ref()
        .map_or_else(|| root.join("tmp"), |value| value.temporary.clone());
    let temporary_alias = native
        .as_ref()
        .map_or_else(|| root.join("tmp"), |value| value.temporary_alias.clone());
    let local_app_data = native.as_ref().map_or_else(
        || root.join("home").join("AppData").join("Local"),
        |value| value.local_app_data.clone(),
    );
    let mut environment_matches = true;
    for (key, expected) in [
        ("HOME", root.join("home")),
        ("USERPROFILE", root.join("home")),
        ("TEMP", temporary),
        ("TMP", temporary_alias),
        ("APPDATA", root.join("home").join("AppData").join("Roaming")),
        ("LOCALAPPDATA", local_app_data),
    ] {
        let actual =
            std::env::var_os(key).ok_or_else(|| io::Error::other("private env missing"))?;
        if !fixed_private_environment_path(&actual, &expected) {
            eprintln!(
                "FIXED_PRIVATE_ENV_MISMATCH key={key} {}",
                fixed_environment_comparison(&actual, &expected),
            );
            eprintln!(
                "FIXED_PRIVATE_ENV_LOCATION key={key} {}",
                fixed_environment_location(&actual, root),
            );
            environment_matches = false;
        }
    }
    require(environment_matches, "private environment differs")?;
    if native.is_some() {
        println!("FIXED_NATIVE_ENV_BINDING_PASS");
    }
    require(
        std::env::var_os("OPENAI_API_KEY").is_none()
            && std::env::var_os("ANTHROPIC_API_KEY").is_none(),
        "credential environment present",
    )?;
    require(
        std::env::var_os("DC_AXIS_INHERIT_CANARY").is_none(),
        "parent-only inheritance canary reached child",
    )?;
    fixed_io(
        "workspace permitted write",
        fs::write(workspace.join("allowed-write"), b"fixed write"),
    )?;
    fixed_io(
        "outside-parent permitted sibling write",
        fs::write(
            root.join("outside-parent").join("allowed-sibling"),
            b"fixed parent-grant write",
        ),
    )?;
    let outside = root.join("outside-parent").join("outside.txt");
    require(
        fs::read(&outside).is_err_and(permission_denied),
        "outside read was not denied",
    )?;
    require(
        fs::write(&outside, b"unexpected").is_err_and(permission_denied),
        "outside write was not denied",
    )?;
    require(
        fs::read(root.join("readonly.txt"))? == SENTINEL,
        "read-only read failed",
    )?;
    require(
        fs::write(root.join("readonly.txt"), b"unexpected").is_err_and(permission_denied),
        "read-only write was not denied",
    )?;
    for (ip, port) in [
        (IpAddr::V4(Ipv4Addr::LOCALHOST), ports[0]),
        (IpAddr::V6(Ipv6Addr::LOCALHOST), ports[2]),
    ] {
        require(
            TcpStream::connect_timeout(&SocketAddr::new(ip, port), Duration::from_secs(1))
                .is_err_and(permission_denied),
            "contained TCP connect was not denied",
        )?;
    }
    for (bind, destination) in [
        ("0.0.0.0:0", format!("127.0.0.1:{}", ports[1])),
        ("[::]:0", format!("[::1]:{}", ports[3])),
    ] {
        match UdpSocket::bind(bind) {
            Ok(socket) => {
                if let Err(error) = socket.send_to(b"FIXED_CONTAINED_UDP", destination) {
                    require(permission_denied(error), "unexpected UDP error")?;
                }
            }
            Err(error) => require(permission_denied(error), "unexpected UDP bind error")?,
        }
    }
    println!("FIXED_BOUNDARIES_PASS");
    Ok(0)
}

fn permission_denied(error: io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied || error.raw_os_error() == Some(10013)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_environment_only_accepts_exact_local_disk_prefix_difference() {
        let expected = Path::new(r"C:\fixed-private\home");
        for actual in [r"C:\fixed-private\home", r"\\?\C:\fixed-private\home"] {
            assert!(fixed_private_environment_path(OsStr::new(actual), expected));
            assert!(fixed_private_environment_path(
                expected.as_os_str(),
                Path::new(r"\\?\C:\fixed-private\home")
            ));
        }
        for actual in [
            r"C:\real-home",
            r"D:\fixed-private\home",
            r"c:\fixed-private\home",
            r"C:/fixed-private/home",
            r"C:\fixed-private\.\home",
            r"C:\fixed-private\other\..\home",
            r"C:fixed-private\home",
            r"\\server\share\fixed-private\home",
            r"\\?\UNC\server\share\home",
            r"\\.\C:\fixed-private\home",
            r"\\?\GLOBALROOT\Device\fixed-private\home",
        ] {
            assert!(!fixed_private_environment_path(
                OsStr::new(actual),
                expected
            ));
        }
        let diagnostic =
            fixed_environment_comparison(OsStr::new(r"\\?\C:\fixed-private\HOME"), expected);
        assert!(
            diagnostic
                .contains("actual_verbatim=true expected_verbatim=false ascii_case_only=true")
        );
        assert!(!diagnostic.contains("fixed-private"));
        assert!(!diagnostic.contains("HOME"));
        let root = Path::new(r"C:\fixed-private");
        let diagnostic = fixed_environment_location(
            OsStr::new(
                r"\\?\C:\fixed-private\home\AppData\Local\Packages\synthetic-profile\AC\Temp",
            ),
            root,
        );
        assert_eq!(
            diagnostic,
            "lexical_fixture_prefix=true lexical_home_prefix=true lexical_local_app_data_prefix=true lexical_private_tmp_prefix=false lexical_packages_prefix=true relative_components=7 dot_component_or_slash=false final_temp_component=true"
        );
        assert!(!diagnostic.contains("synthetic-profile"));
        assert!(!diagnostic.contains("fixed-private"));
        assert!(
            fixed_environment_location(OsStr::new(r"C:\fixed-private\tmp"), root)
                .contains("lexical_private_tmp_prefix=true")
        );
        for actual in [
            r"C:\fixed-private-other\home\Temp",
            r"C:\other\home\Temp",
            r"D:\fixed-private\home\Temp",
        ] {
            assert!(
                fixed_environment_location(OsStr::new(actual), root)
                    .starts_with("lexical_fixture_prefix=false")
            );
        }
        assert!(
            fixed_environment_location(OsStr::new(r"C:\fixed-private\home\..\tmp"), root)
                .contains("dot_component_or_slash=true")
        );
    }
}
