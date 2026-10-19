// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail, ensure};
use axis_core::policy::{Compatibility, NetworkMode, Policy, RuntimeProvider};
use mxc_sdk::v1::{
    self, ContainerRequest, Containment, FilesystemPolicy, NetworkAction, NetworkEgressPolicy,
    NetworkIngressPolicy, NetworkPolicy, SpawnOptions, TelemetryConfig, WaitResult,
    configs::ProcessContainerConfig,
};
use std::fs;
use std::io::{self, Read};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Threading::WaitForSingleObject;

#[path = "dll_startup_protocol.rs"]
mod dll_startup_protocol;
#[path = "native_environment.rs"]
mod native_environment;
#[path = "native_identity.rs"]
mod native_identity;

const PREFIX: &str = "dc-axis-windows-psec-";
const SENTINEL: &[u8] = b"fixed-public-synthetic-canary\n";
const LIMIT: u64 = 64 * 1024;

pub fn run() -> Result<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let loader_only = args.as_slice() == ["--loader-only"];
    let dll_only = args.as_slice() == ["--dll-startup-only"];
    let claude_version_only = args.as_slice() == ["--claude-version-only"];
    let create_control_only = args.as_slice() == ["--claude-create-control-only"];
    let claude_only = claude_version_only || create_control_only;
    ensure!(
        args.is_empty() || loader_only || dll_only || claude_only,
        "only a fixed contributor mode selector is accepted"
    );
    ensure!(
        create_control_only == cfg!(feature = "fixed-claude-create-control"),
        "fixed build feature and contributor selector differ"
    );
    let system = PathBuf::from(std::env::var("SystemRoot")?).canonicalize()?;
    let caller = if args.is_empty() {
        Some(native_identity::CallerEnvironment::capture(&system)?)
    } else {
        None
    };
    let executable = std::env::current_exe()?.canonicalize()?;
    let temp_parent = std::env::temp_dir().canonicalize()?;
    let owned = tempfile::Builder::new()
        .prefix(PREFIX)
        .tempdir_in(&temp_parent)?;
    // Errors must preserve fixtures, including a failed Job-empty proof. Only
    // the explicit success path below may remove this known owned directory.
    let root = owned.keep().canonicalize()?;
    verify_fixture_root(&root, &temp_parent)?;
    eprintln!("owned contributor fixture: {}", root.display());
    let paths = Paths::create(&root, &system)?;
    if caller.is_none() {
        // Preserve the existing loader/DLL/Claude supervisor behavior. The
        // boundary mode instead validates and retains its exact private startup
        // values, avoiding a second path context after native DLL imports.
        let names: Vec<_> = std::env::vars_os().map(|(name, _)| name).collect();
        // SAFETY: environment mutation remains confined to this pre-thread stage.
        unsafe {
            for name in names {
                std::env::remove_var(name);
            }
            for (name, value) in paths.environment() {
                std::env::set_var(name, value);
            }
        }
    }
    // SAFETY: this Windows-only public marker is set before our Rust workers.
    // In boundary mode it is the only addition to the original eight values.
    unsafe {
        std::env::set_var("DC_AXIS_INHERIT_CANARY", "fixed-public");
    }
    if let Some(caller) = &caller {
        caller.require_unchanged()?;
    }
    std::env::set_current_dir(&paths.workspace)?;
    thread::spawn(|| {
        thread::sleep(Duration::from_secs(20));
        eprintln!("fixed contributor supervisor deadline exceeded");
        std::process::exit(124);
    });
    let mut dll_initialization_all_succeeded = false;
    if claude_only {
        // Supported only through the reviewed Go custody wrapper: it stages
        // this exact supervisor beside the one fixed signed local image and
        // holds both images against writes/rename and every ancestor name
        // against rename through wait. Directory contents remain mutable.
        // No caller path, command, argument or expected hash is accepted here.
        let payload = executable.with_file_name("claude-reviewed.exe");
        ensure!(
            fs::metadata(&payload)?.len() == 254_858_400,
            "fixed local image size differs"
        );
        run_case(&paths, &payload, "claude-version", &[0; 4], None)?;
    } else if dll_only {
        let payload = executable
            .with_file_name("defenseclaw-axis-windows-psec-dll-child.exe")
            .canonicalize()?;
        let mut completed = true;
        dll_initialization_all_succeeded = true;
        for case in dll_startup_protocol::CASES {
            let mode = format!("dll-{}", case.label());
            match run_case(&paths, &payload, &mode, &[0; 4], None) {
                Ok(loaded) => dll_initialization_all_succeeded &= loaded,
                Err(error) => {
                    completed = false;
                    dll_initialization_all_succeeded = false;
                    // Retain one bounded failure record even if native creation
                    // failed before a child marker. Continue the other fixed
                    // cases; timeout/cleanup/missing return never become success.
                    println!(
                        "{}",
                        serde_json::json!({"case": mode, "case_error": format!("{error:#}")})
                    );
                }
            }
        }
        ensure!(completed, "one or more fixed DLL cases did not complete");
    } else if loader_only {
        let payload = executable
            .with_file_name("defenseclaw-axis-windows-psec-loader-child.exe")
            .canonicalize()?;
        run_case(&paths, &payload, "loader", &[0; 4], None)?;
    } else {
        let payload = executable
            .with_file_name("defenseclaw-axis-windows-psec-boundary-child.exe")
            .canonicalize()?;
        let endpoints = Endpoints::new()?;
        let ports = endpoints.ports();
        run_case(&paths, &payload, "argv", &ports, caller.as_ref())?;
        run_case(&paths, &payload, "boundary", &ports, caller.as_ref())?;
        endpoints.require_no_contained_delivery()?;
        run_case(&paths, &payload, "exit23", &ports, caller.as_ref())?;
        run_case(&paths, &payload, "timeout", &ports, caller.as_ref())?;
    }
    ensure!(
        fs::read(&paths.outside)? == SENTINEL,
        "outside canary changed"
    );
    ensure!(
        fs::read(&paths.readonly)? == SENTINEL,
        "read-only canary changed"
    );
    // Verify the resolved absolute target before recursive fixture cleanup.
    verify_fixture_root(&root, &temp_parent)?;
    std::env::set_current_dir(&temp_parent)?;
    fs::remove_dir_all(&root)
        .context("remove verified owned fixture after all SDK handles stopped")?;
    ensure!(!root.exists(), "owned fixture remains");
    let checks = if create_control_only {
        vec![
            "constructed_launch_inputs_equal_except_psec_attribute",
            "fixed_signed_claude_version_output",
            "retained_direct_process_handles_signaled",
            "owned_fixture_removed",
        ]
    } else if claude_only {
        vec![
            "fixed_signed_claude_version_output",
            "retained_direct_process_handles_signaled",
            "owned_fixture_removed",
        ]
    } else if dll_only {
        vec![
            "three_fixed_dll_start_markers",
            "three_fixed_dll_return_observations",
            "retained_direct_process_handles_signaled",
            "owned_fixture_removed",
        ]
    } else if loader_only {
        vec![
            "separate_std_loader_marker",
            "exit23",
            "retained_direct_process_handles_signaled",
            "owned_fixture_removed",
        ]
    } else {
        vec![
            "literal_windows_argv",
            "private_environment",
            "allowed_write",
            "outside_read_write_denied",
            "readonly_write_denied",
            "loopback_ipv4_ipv6_tcp_udp",
            "exit23",
            "timeout",
            "retained_direct_process_handles_signaled",
            "owned_fixture_removed",
        ]
    };
    println!(
        "{}",
        serde_json::json!({
            "axis_commit": "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c",
            "mxc_commit": "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2",
            "translation_contract": "fixed-axis-hard-block-to-mxc-typed-1.0.0",
            "backend": if create_control_only { "uncontained_fixed_create_control" } else { "native_windows_psec_only" }, "production_qualification": false,
            "loader_only_diagnostic": loader_only, "checks": checks,
            "dll_startup_only_diagnostic": dll_only,
            "claude_version_only": claude_version_only,
            "claude_create_control_only": create_control_only,
            "psec_attribute_attached": !create_control_only,
            "control_reference_plan_executed": false,
            "dll_initialization_all_succeeded": dll_initialization_all_succeeded,
            "scope": if create_control_only { "UNCONTAINED fixed signed Claude --version creation control; PSEC constructed but not attached; constructed input equality only; no offline/UI/filesystem enforcement or runtime qualification" }
                else if claude_only { "fixed reviewed signed local Claude 2.1.292 --version only; no authentication, model, hook, terminal or customer runtime qualification" }
                else if dll_only { "three fixed System32 DLL initialization observations; returned load errors are not compatibility success; no UI, boundary or customer qualification" }
                else if loader_only { "separate std loader marker and exit23 only; no boundary, network or customer qualification" }
                else { "fixed offline canaries; no terminal, proxy, credentials, model or general resource audit" }
        })
    );
    Ok(0)
}

fn verify_fixture_root(root: &Path, temp_parent: &Path) -> Result<()> {
    ensure!(
        root.is_absolute() && root.parent() == Some(temp_parent),
        "fixture left private temp parent"
    );
    ensure!(
        root.file_name()
            .and_then(|p| p.to_str())
            .is_some_and(|p| p.starts_with(PREFIX)),
        "unexpected fixture identity"
    );
    Ok(())
}

struct Paths {
    workspace: PathBuf,
    home: PathBuf,
    temporary: PathBuf,
    outside: PathBuf,
    outside_parent: PathBuf,
    readonly: PathBuf,
    system: PathBuf,
}

impl Paths {
    fn create(root: &Path, system: &Path) -> Result<Self> {
        let result = Self {
            workspace: root.join("workspace"),
            home: root.join("home"),
            temporary: root.join("tmp"),
            outside: root.join("outside-parent").join("outside.txt"),
            outside_parent: root.join("outside-parent"),
            readonly: root.join("readonly.txt"),
            system: system.into(),
        };
        for directory in [
            &result.workspace,
            &result.home,
            &result.temporary,
            &result.outside_parent,
        ] {
            fs::create_dir(directory)?;
        }
        for directory in [
            result.home.join("AppData").join("Roaming"),
            result.home.join("AppData").join("Local"),
        ] {
            fs::create_dir_all(directory)?;
        }
        fs::write(&result.outside, SENTINEL)?;
        fs::write(&result.readonly, SENTINEL)?;
        fs::write(result.workspace.join("fixture-seal"), SENTINEL)?;
        Ok(result)
    }

    fn environment(&self) -> Vec<(String, String)> {
        [
            ("SYSTEMROOT", self.system.clone()),
            ("WINDIR", self.system.clone()),
            ("HOME", self.home.clone()),
            ("USERPROFILE", self.home.clone()),
            ("APPDATA", self.home.join("AppData").join("Roaming")),
            ("LOCALAPPDATA", self.home.join("AppData").join("Local")),
            ("TEMP", self.temporary.clone()),
            ("TMP", self.temporary.clone()),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_string_lossy().into_owned()))
        .collect()
    }

    fn policy(&self, executable: &Path, timeout: u64) -> Result<Policy> {
        let value = serde_json::json!({
            "version": 1, "name": "dc-windows-psec-fixed",
            "runtime": {"containment": "process", "provider": "mxc"},
            "filesystem": {"compatibility": "hard_requirement",
                "read_only": [executable, &self.readonly],
                "read_write": [&self.workspace, &self.home, &self.temporary, &self.outside_parent],
                "deny": [&self.outside]},
            "process": {"max_processes": 0, "max_memory_mb": 0, "cpu_rate_percent": 0,
                "identity": "backend_default", "child_processes": "allow", "timeout_sec": timeout},
            "network": {"mode": "block"}
        });
        Policy::from_yaml(&serde_json::to_string(&value)?).context("AXIS fixed policy validation")
    }
}

fn run_case(
    paths: &Paths,
    executable: &Path,
    mode: &str,
    ports: &[u16; 4],
    caller: Option<&native_identity::CallerEnvironment>,
) -> Result<bool> {
    if let Some(caller) = caller {
        caller.require_unchanged()?;
    }
    let timeout = match mode {
        "timeout" => 1,
        "claude-version" => 10,
        _ => 5,
    };
    let policy = paths.policy(executable, timeout)?;
    ensure!(
        policy.runtime.provider == RuntimeProvider::Mxc,
        "MXC required"
    );
    ensure!(
        matches!(
            policy.filesystem.compatibility,
            Compatibility::HardRequirement
        ),
        "hard filesystem required"
    );
    ensure!(
        matches!(policy.network.mode, NetworkMode::Block),
        "offline policy required"
    );
    let mut argv = vec![executable.as_os_str().to_owned()];
    let dll_case = dll_startup_protocol::CASES
        .into_iter()
        .find(|case| mode == format!("dll-{}", case.label()));
    if mode == "claude-version" {
        argv.push(std::ffi::OsString::from("--version"));
    } else if let Some(case) = dll_case {
        argv.push(std::ffi::OsString::from(case.selector()));
    } else if mode == "argv" {
        argv.extend(
            [
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
            .map(std::ffi::OsString::from),
        );
    } else if mode != "loader" {
        argv.extend(
            [
                "--fixed-child",
                if mode == "boundary" {
                    "boundary-native-env"
                } else {
                    mode
                },
            ]
            .into_iter()
            .map(std::ffi::OsString::from),
        );
        argv.extend(
            ports
                .iter()
                .map(|port| std::ffi::OsString::from(port.to_string())),
        );
    }
    let mut request = ContainerRequest::new("");
    request.containment = Containment::ProcessContainer(ProcessContainerConfig::default());
    request.filesystem = Some(FilesystemPolicy {
        readwrite_paths: policy.filesystem.read_write.clone(),
        readonly_paths: policy.filesystem.read_only.clone(),
        denied_paths: policy.filesystem.deny.clone(),
        clear_policy_on_exit: Some(true),
    });
    request.network = Some(NetworkPolicy {
        egress: Some(NetworkEgressPolicy {
            default: Some(NetworkAction::Deny),
            ..Default::default()
        }),
        ingress: Some(NetworkIngressPolicy {
            default: Some(NetworkAction::Deny),
            host_loopback: Some(NetworkAction::Deny),
        }),
        runtime_config: None,
    });
    request.timeout_ms = Some(u32::try_from(
        policy
            .process
            .timeout_sec
            .context("explicit timeout required")?
            * 1000,
    )?);
    request.working_directory = Some(paths.workspace.to_string_lossy().into_owned());
    request.environment = Some(paths.environment());
    request.inherit_default_environment = Some(false);
    let fixed_root = paths.home.parent().context("fixed home parent missing")?;
    let fixture_custody = if mode == "boundary" {
        Some(native_identity::pin_fixture_root(fixed_root)?)
    } else {
        None
    };
    let mut process = v1::spawn_windows_psec_argv(
        request,
        argv,
        SpawnOptions {
            telemetry: Some(TelemetryConfig {
                enabled: Some(false),
            }),
        },
    )?;
    if mode == "claude-version" {
        // This fixed offline invocation never accepts interactive input.
        drop(
            process
                .take_stdin()
                .context("fixed version stdin pipe missing")?,
        );
    }
    // Duplicate read/query+synchronize rights from the SDK's retained native
    // CreateProcess object. No integer PID lookup or token fallback is allowed.
    let observed = process
        .duplicate_query_process_handle()
        .context("same retained native process observation unavailable")?;
    let native = if let Some(fixture) = &fixture_custody {
        Some(native_identity::expected_from_child(
            &observed,
            fixture,
            fixed_root,
            caller.context("original private caller environment absent")?,
        )?)
    } else {
        None
    };
    let stdout = process.take_stdout().context("stdout pipe missing")?;
    let stderr = process.take_stderr().context("stderr pipe missing")?;
    let out = thread::spawn(move || bounded(stdout));
    let err = thread::spawn(move || bounded(stderr));
    // The new fixed child waits here before its first environment assertion or
    // mutation. Values originate solely from this same held child's native SID.
    let control = if let Some(native) = &native {
        (|| -> Result<()> {
            let mut stdin = process.take_stdin().context("identity stdin missing")?;
            native.expected.write_to(&mut stdin)?;
            drop(stdin); // exact frame followed by EOF
            Ok(())
        })()
    } else {
        Ok(())
    };
    let control_kill = if control.is_err() {
        process.kill()
    } else {
        Ok(())
    };
    let outcome = process.wait();
    let signaled =
        unsafe { WaitForSingleObject(HANDLE(observed.as_raw_handle()), 1000) } == WAIT_OBJECT_0;
    let output = out
        .join()
        .map_err(|_| anyhow::anyhow!("stdout reader panic"))??;
    let diagnostics = err
        .join()
        .map_err(|_| anyhow::anyhow!("stderr reader panic"))??;
    if dll_case.is_some() {
        let outcome_text = match &outcome {
            Ok(value) => format!("{value:?}"),
            Err(error) => format!("WaitError({error})"),
        };
        // Retain every actually available start/return/exit/timeout/error
        // observation before propagating a native wait or cleanup refusal.
        println!(
            "{}",
            serde_json::json!({"case": mode, "outcome": outcome_text, "direct_handle_signaled": signaled, "stdout": output, "stderr": diagnostics})
        );
    } else {
        ensure!(signaled, "retained direct process handle is not signaled");
    }
    control?;
    control_kill?;
    let outcome = outcome?;
    if let Some(case) = dll_case {
        ensure!(signaled, "retained DLL process handle is not signaled");
        ensure!(
            outcome == WaitResult::Exited(0),
            "fixed DLL child did not exit normally: {outcome:?}"
        );
        ensure!(diagnostics.is_empty(), "fixed DLL child wrote stderr");
        let observation = dll_startup_protocol::LoadResult::parse(case, &output)
            .context("fixed DLL start/return transcript differs")?;
        return Ok(observation == dll_startup_protocol::LoadResult::Loaded);
    }
    match mode {
        "claude-version" => {
            ensure!(
                outcome == WaitResult::Exited(0),
                "fixed Claude version failed: {outcome:?}"
            );
            ensure!(
                output == "2.1.292 (Claude Code)\n" || output == "2.1.292 (Claude Code)\r\n",
                "fixed Claude version transcript differs"
            );
            ensure!(diagnostics.is_empty(), "fixed Claude version wrote stderr");
        }
        "argv" => {
            ensure!(
                output == "FIXED_ARGV_PASS\n",
                "literal argv marker missing: {output:?} {diagnostics}"
            );
            ensure!(
                outcome == WaitResult::Exited(0),
                "literal argv case differs: {outcome:?}"
            );
        }
        "loader" => {
            ensure!(
                output == "FIXED_PSEC_LOADER_STARTED\n",
                "separate loader marker missing: {output:?} {diagnostics}"
            );
            ensure!(
                outcome == WaitResult::Exited(23),
                "separate loader exit differs: {outcome:?}"
            );
        }
        "boundary" => {
            ensure!(
                outcome == WaitResult::Exited(0),
                "boundary failed: {outcome:?}: {output} {diagnostics}"
            );
            ensure!(
                output.lines().any(|line| line == "FIXED_BOUNDARIES_PASS"),
                "boundary observations missing"
            );
            ensure!(
                native.is_some()
                    && output
                        .lines()
                        .any(|line| line == "FIXED_NATIVE_ENV_BINDING_PASS"),
                "same-child native environment assertion missing"
            );
        }
        "exit23" => {
            ensure!(
                output.lines().any(|line| line == "FIXED_EXIT23_STARTED"),
                "exit payload never started"
            );
            ensure!(
                outcome == WaitResult::Exited(23),
                "exit status differs: {outcome:?}"
            );
        }
        "timeout" => {
            ensure!(
                output.lines().any(|line| line == "FIXED_TIMEOUT_STARTED"),
                "timeout payload never started"
            );
            ensure!(
                outcome == WaitResult::TimedOut,
                "typed timeout missing: {outcome:?}"
            );
        }
        _ => bail!("unsupported fixed case"),
    }
    println!(
        "{}",
        serde_json::json!({"case": mode, "outcome": format!("{outcome:?}"), "direct_handle_signaled": signaled, "stdout": output, "stderr": diagnostics})
    );
    drop(process);
    Ok(true)
}

fn bounded(mut reader: Box<dyn Read + Send>) -> Result<String> {
    let mut bytes = Vec::new();
    reader.by_ref().take(LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= LIMIT,
        "fixed output exceeded its bound"
    );
    Ok(String::from_utf8(bytes)?)
}

struct Endpoints {
    tcp4: TcpListener,
    udp4: UdpSocket,
    tcp6: TcpListener,
    udp6: UdpSocket,
}

impl Endpoints {
    fn new() -> Result<Self> {
        let endpoints = Self {
            tcp4: TcpListener::bind("127.0.0.1:0")?,
            udp4: UdpSocket::bind("127.0.0.1:0")?,
            tcp6: TcpListener::bind("[::1]:0")?,
            udp6: UdpSocket::bind("[::1]:0")?,
        };
        for listener in [&endpoints.tcp4, &endpoints.tcp6] {
            let _control = TcpStream::connect(listener.local_addr()?)?;
            let _accepted = listener.accept()?;
            listener.set_nonblocking(true)?;
        }
        for socket in [&endpoints.udp4, &endpoints.udp6] {
            let address = socket.local_addr()?;
            let sender = UdpSocket::bind(SocketAddr::new(address.ip(), 0))?;
            sender.send_to(b"FIXED_HOST_CONTROL", address)?;
            socket.set_read_timeout(Some(Duration::from_secs(1)))?;
            let mut buffer = [0; 64];
            let (size, _) = socket.recv_from(&mut buffer)?;
            ensure!(
                &buffer[..size] == b"FIXED_HOST_CONTROL",
                "host UDP positive control failed"
            );
            socket.set_read_timeout(Some(Duration::from_millis(250)))?;
        }
        Ok(endpoints)
    }

    fn ports(&self) -> [u16; 4] {
        [
            self.tcp4.local_addr().unwrap().port(),
            self.udp4.local_addr().unwrap().port(),
            self.tcp6.local_addr().unwrap().port(),
            self.udp6.local_addr().unwrap().port(),
        ]
    }

    fn require_no_contained_delivery(&self) -> Result<()> {
        for listener in [&self.tcp4, &self.tcp6] {
            ensure!(
                listener
                    .accept()
                    .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock),
                "contained TCP delivery observed"
            );
        }
        for socket in [&self.udp4, &self.udp6] {
            let mut buffer = [0; 64];
            ensure!(
                socket.recv_from(&mut buffer).is_err_and(|error| matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                )),
                "contained UDP delivery observed"
            );
        }
        Ok(())
    }
}
