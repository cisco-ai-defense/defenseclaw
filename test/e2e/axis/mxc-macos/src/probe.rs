// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, anyhow, bail, ensure};
use axis_core::capability::{DependencyState, PlannerOptions, RuntimeProbeSnapshot};
use axis_core::capability_map::{BackendCapabilityMapId, host_dependency};
use axis_core::mxc_config::{
    MxcContainment, MxcNetworkDefaultPolicy, MxcPlatform, MxcProcessConfigOptions,
    build_mxc_process_config,
};
use axis_core::policy::Policy;
use axis_core::process_backend::{
    ProcessBackendNetworkMode, ProcessLaunchOptions, build_process_backend_execution_spec,
};
use mxc_sdk::v1::{
    self, ContainerRequest, Containment, FilesystemPolicy, MxcProcess, MxcPtyProcess, MxcPtySize,
    NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy, NetworkPolicy, SpawnOptions,
    SpawnWithPtyOptions, StreamCloser, TelemetryConfig, UiPolicy, WaitResult,
    configs::SeatbeltConfig,
};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::strict_profile;

const AXIS_COMMIT: &str = "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c";
const MXC_COMMIT: &str = "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2";
const PREFIX: &str = "dc-axis-mxc-macos-";
const SEAL: &[u8] = b"fixed-benign-macos-fixture-v1\n";
const READONLY: &[u8] = b"synthetic-readonly\n";
const DENIED: &[u8] = b"synthetic-denied\n";
const UNGRANTED: &[u8] = b"synthetic-ungranted\n";
const SUPERVISOR_ONLY_ENV: &str = "DC_AXIS_PARENT_ONLY_CANARY";
const LITERAL_ARGUMENTS: [&str; 6] = [
    "",
    "literal spaces",
    "quotes ' and \"",
    "metachar $HOME ; * ? [ ] | &",
    "unicode-λ-雪",
    "trailing\\",
];
const OUTPUT_LIMIT: usize = 64 * 1024;
const DIAGNOSTIC_INPUT_LIMIT: usize = 1200;
const SUPERVISOR_LIMIT: Duration = Duration::from_secs(15);

// MXC's generated Seatbelt profile adds these broad system reads regardless of
// FilesystemPolicy. Admit them explicitly in this synthetic AXIS policy; this
// experiment does not claim that normal DefenseClaw policies already do so.
// The generated profile also allows root data/ancestor metadata, TTY devices,
// and possibly the active Xcode bundle; those residual grants remain a parity
// gap and are documented in README.md.
const MXC_SYSTEM_READS: &[&str] = &[
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/libexec",
    "/usr/share",
    "/System",
    "/Library",
    "/private/var/db/timezone",
    "/private/var/db/dyld",
    "/private/var/select",
    "/private/etc",
];
const MXC_SYSTEM_RW_DEVICES: &[&str] = &["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"];

fn private_fixture() -> Result<tempfile::TempDir> {
    // Create the owner-only directory before placing any private payload in it.
    let owned = tempfile::Builder::new()
        .prefix(PREFIX)
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in("/private/tmp")?;
    let metadata = fs::symlink_metadata(owned.path())?;
    // SAFETY: geteuid is a read-only identity query.
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o7777 == 0o700,
        "private fixture ownership or mode differs before payload creation"
    );
    Ok(owned)
}

pub fn run() -> Result<i32> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args
        .first()
        .is_some_and(|arg| arg.as_os_str() == OsStr::new("--fixed-child"))
    {
        let case = match args.get(1).and_then(|arg| arg.to_str()) {
            Some("boundaries") => Case::Boundaries,
            Some("boundaries-strict") => Case::StrictBoundaries,
            Some("argv") => Case::Argv,
            Some("pipe") => Case::Pipe,
            Some("pty") => Case::Pty,
            Some("timeout") => Case::Timeout,
            Some("delayed") => Case::Delayed,
            _ => bail!("unknown fixed child case"),
        };
        ensure!(
            args == fixed_child_arguments(case),
            "fixed child argv differs"
        );
        return fixed_child(case);
    }
    let strict = match args.as_slice() {
        [] => false,
        [flag] if flag == "--strict-fixed" => true,
        _ => bail!("the probe accepts only the fixed strict selector"),
    };
    // SAFETY: geteuid is a read-only identity query with no pointer arguments.
    ensure!(
        unsafe { libc::geteuid() } != 0,
        "run as an unprivileged user"
    );
    let executable = std::env::current_exe()?.canonicalize()?;
    let owned = private_fixture()?;
    let paths = Paths::create(&owned.path().canonicalize()?)?;
    // A host-side positive control is necessary: a refused connection to an
    // absent listener would not show sandbox network enforcement.
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let _positive = std::net::TcpStream::connect(("127.0.0.1", port))?;
    if strict {
        // Host-only positive control. Never read, print or modify this known
        // nonsecret system file; the child must fail its open with EACCES/EPERM.
        ensure!(
            fs::metadata("/private/etc/hosts")?.is_file(),
            "host canary is not a file"
        );
        drop(fs::File::open("/private/etc/hosts")?);
    }
    private_supervisor_environment(&paths, port)?;
    ensure!(
        v1::available_backends()
            .iter()
            .any(|backend| backend.backend == "seatbelt"),
        "MXC Seatbelt is unavailable on this host"
    );
    run_piped(
        &paths,
        &executable,
        if strict {
            Case::StrictBoundaries
        } else {
            Case::Boundaries
        },
        port,
        strict,
    )?;
    run_piped(&paths, &executable, Case::Argv, port, strict)?;
    run_piped(&paths, &executable, Case::Pipe, port, strict)?;
    run_pty(&paths, &executable, port, strict)?;
    run_piped(&paths, &executable, Case::Timeout, port, strict)?;
    thread::sleep(Duration::from_secs(3));
    ensure!(
        !paths.late_marker.exists(),
        "a descendant survived the MXC timeout"
    );
    ensure!(
        fs::read(&paths.readonly)? == READONLY,
        "readonly canary changed"
    );
    ensure!(
        fs::read(&paths.denied_home)? == DENIED,
        "HOME denied canary changed"
    );
    ensure!(
        fs::read(&paths.denied_work)? == DENIED,
        "CWD denied canary changed"
    );
    ensure!(
        fs::read(&paths.ungranted)? == UNGRANTED,
        "ungranted canary changed"
    );
    ensure!(
        fs::read(paths.work.join("allowed-write"))? == b"fixed-benign-write\n",
        "CWD write missing"
    );
    ensure!(
        fs::read(paths.home.join("allowed-write"))? == b"fixed-benign-write\n",
        "HOME write missing"
    );
    drop(listener);
    let root = owned.path().to_owned();
    owned
        .close()
        .context("remove owned fixture after all SDK handles returned")?;
    ensure!(!root.exists(), "owned fixture cleanup was incomplete");
    println!(
        "{}",
        serde_json::json!({
            "axis_commit": AXIS_COMMIT, "mxc_commit": MXC_COMMIT,
            "containment": "mxc_sdk_v1_seatbelt", "bridge": "axis_policy_and_old_wire_admission_to_typed_mxc_v1",
            "seatbelt_profile": if strict { "reviewed_fixed_strict_override" } else { "mxc_generated_default" },
            "checks": ["explicit_footprint_admission", "private_home_and_cwd", "denied_read_write_metadata",
                "readonly_write_denied", "ungranted_read_denied", "loopback_network_denied_with_host_positive_control",
                "pipe_echo_exit_23", "pty_echo_resize_exit_23", "typed_timeout", "descendant_marker_absent",
                "literal_argv_preserved_without_shell",
                "owned_fixture_removed"],
            "scope": "fixed_benign_composite_contributor_experiment",
            "production_or_defenseclaw_provider_qualification": false,
            "exact_system_read_or_general_metadata_parity": false,
            "strict_host_canary_open_denied": strict
        })
    );
    Ok(0)
}

#[derive(Clone, Copy)]
enum Case {
    Boundaries,
    StrictBoundaries,
    Argv,
    Pipe,
    Pty,
    Timeout,
    Delayed,
}

impl Case {
    fn argument(self) -> &'static str {
        match self {
            Self::Boundaries => "boundaries",
            Self::StrictBoundaries => "boundaries-strict",
            Self::Argv => "argv",
            Self::Pipe => "pipe",
            Self::Pty => "pty",
            Self::Timeout => "timeout",
            Self::Delayed => "delayed",
        }
    }
}

fn fixed_child_arguments(case: Case) -> Vec<OsString> {
    let mut arguments = vec![
        OsString::from("--fixed-child"),
        OsString::from(case.argument()),
    ];
    if matches!(case, Case::Argv) {
        arguments.extend(LITERAL_ARGUMENTS.into_iter().map(OsString::from));
    }
    arguments
}

fn fixed_argv(executable: &Path, case: Case) -> Vec<OsString> {
    let mut argv = vec![executable.as_os_str().to_owned()];
    argv.extend(fixed_child_arguments(case));
    argv
}

struct Paths {
    root: PathBuf,
    work: PathBuf,
    home: PathBuf,
    temporary: PathBuf,
    readonly: PathBuf,
    denied_home: PathBuf,
    denied_work: PathBuf,
    ungranted: PathBuf,
    late_marker: PathBuf,
}

impl Paths {
    fn at(root: &Path) -> Self {
        let work = root.join("work");
        let home = root.join("home");
        Self {
            root: root.to_owned(),
            readonly: work.join("readonly"),
            denied_work: work.join("denied"),
            denied_home: home.join("denied"),
            ungranted: root.join("ungranted"),
            late_marker: work.join("late-marker"),
            temporary: root.join("tmp"),
            work,
            home,
        }
    }

    fn create(root: &Path) -> Result<Self> {
        let paths = Self::at(root);
        for dir in [&paths.work, &paths.home, &paths.temporary] {
            fs::DirBuilder::new().mode(0o700).create(dir)?;
        }
        write_new(&paths.work.join("fixture-seal"), SEAL)?;
        write_new(&paths.readonly, READONLY)?;
        write_new(&paths.denied_home, DENIED)?;
        write_new(&paths.denied_work, DENIED)?;
        write_new(&paths.ungranted, UNGRANTED)?;
        Ok(paths)
    }

    fn from_child() -> Result<Self> {
        let work = std::env::current_dir()?.canonicalize()?;
        ensure!(
            work.file_name().is_some_and(|name| name == "work"),
            "unexpected child cwd"
        );
        let root = work.parent().context("missing fixture parent")?;
        ensure!(
            root.parent() == Some(fs::canonicalize("/private/tmp")?.as_path()),
            "fixture is outside private temp parent"
        );
        ensure!(
            root.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(PREFIX)),
            "unexpected fixture name"
        );
        let metadata = fs::symlink_metadata(root)?;
        // SAFETY: geteuid is a read-only identity query.
        ensure!(
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o777 == 0o700,
            "fixture ownership or mode differs"
        );
        let paths = Self::at(root);
        ensure!(
            fs::read(paths.work.join("fixture-seal"))? == SEAL,
            "fixture seal differs"
        );
        Ok(paths)
    }

    fn environment(&self, port: u16) -> Result<Vec<(String, String)>> {
        Ok(vec![
            ("HOME".into(), text(&self.home)?.into()),
            ("TMPDIR".into(), text(&self.temporary)?.into()),
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("LANG".into(), "C".into()),
            ("TERM".into(), "xterm".into()),
            ("DC_MACOS_CANARY_PORT".into(), port.to_string()),
        ])
    }

    fn axis_policy(&self, executable: &Path, strict: bool) -> Result<Policy> {
        // Parse the fixed AXIS document first; dynamic fixture paths are
        // assigned as typed fields, never interpolated into YAML or Seatbelt.
        let mut policy = Policy::from_yaml(
            "\
version: 1
name: dc-mxc-macos-contributor
runtime: { containment: process, provider: mxc }
filesystem: { compatibility: hard_requirement }
process: { max_processes: 0, max_memory_mb: 0, cpu_rate_percent: 0 }
network: { mode: block }
",
        )?;
        policy.filesystem.read_only = if strict {
            strict_profile::runtime_read_paths()?
        } else {
            MXC_SYSTEM_READS.iter().map(|path| (*path).into()).collect()
        };
        policy.filesystem.read_only.push(text(executable)?.into());
        policy
            .filesystem
            .read_only
            .push(text(&self.readonly)?.into());
        policy.filesystem.read_write = [&self.work, &self.home, &self.temporary]
            .iter()
            .map(|path| text(path).map(str::to_owned))
            .collect::<Result<_>>()?;
        if strict {
            policy.filesystem.read_write.push("/dev/null".into());
        } else {
            policy
                .filesystem
                .read_write
                .extend(MXC_SYSTEM_RW_DEVICES.iter().map(|path| (*path).into()));
        }
        policy.filesystem.deny = [&self.denied_home, &self.denied_work]
            .iter()
            .map(|path| text(path).map(str::to_owned))
            .collect::<Result<_>>()?;
        policy.validate()?;
        Ok(policy)
    }

    fn request(
        &self,
        executable: &Path,
        case: Case,
        port: u16,
        strict: bool,
    ) -> Result<ContainerRequest> {
        ensure!(
            !matches!(case, Case::Delayed),
            "delayed child is never launched as a standalone request"
        );
        ensure!(
            strict || !matches!(case, Case::StrictBoundaries),
            "strict boundary requires strict profile"
        );
        // AXIS fb5 admits an inert fixed command token here; the executable
        // and arguments are supplied only to MXC's typed literal-argv seam.
        let command = "mxc-literal-policy-only-fixed";
        let policy = self.axis_policy(executable, strict)?;
        let environment: BTreeMap<_, _> = self.environment(port)?.into_iter().collect();
        // Host evidence is taken from MXC's read-only Seatbelt availability
        // probe. AXIS's planner still has the final word on the policy pair.
        let runtime = RuntimeProbeSnapshot::new()
            .with_dependency(host_dependency::MXC_EXECUTOR, DependencyState::Present)
            .with_dependency(host_dependency::MACOS_SEATBELT, DependencyState::Present);
        let launch = ProcessLaunchOptions {
            command: command.into(),
            args: Vec::new(),
            working_dir: Some(text(&self.work)?.into()),
            environment: environment.clone(),
            capture_output: true,
            timeout_sec: Some(if matches!(case, Case::Timeout) { 1 } else { 10 }),
        };
        let spec = build_process_backend_execution_spec(
            &policy,
            BackendCapabilityMapId::MxcMacosSeatbelt,
            launch,
            &runtime,
            &PlannerOptions::new(),
        )
        .context("AXIS rejected fixed MXC Seatbelt policy")?;
        ensure!(
            spec.network.mode == ProcessBackendNetworkMode::Block,
            "AXIS network posture changed"
        );
        ensure!(
            spec.resources.max_processes == 0
                && spec.resources.max_memory_mb == 0
                && spec.resources.cpu_rate_percent == 0,
            "resource claims are outside this experiment"
        );
        ensure!(
            spec.filesystem.read_only == policy.filesystem.read_only
                && spec.filesystem.read_write == policy.filesystem.read_write
                && spec.filesystem.deny == policy.filesystem.deny,
            "AXIS changed the fixed filesystem footprint"
        );
        // AXIS fb5 emits an older 0.6 JSON shape. Use its validation and
        // normalized plan, but never submit that wire document to MXC 1.0.1.
        let wire = build_mxc_process_config(command, &spec, MxcProcessConfigOptions::default())
            .context("AXIS MXC process config admission refused")?;
        ensure!(
            wire.process.command_line == command,
            "AXIS command binding changed"
        );
        ensure!(
            wire.containment == MxcContainment::Seatbelt && wire.platform == MxcPlatform::Macos,
            "AXIS selected a different containment or platform"
        );
        ensure!(
            wire.network.default_policy == MxcNetworkDefaultPolicy::Block
                && wire.network.proxy.is_none(),
            "AXIS emitted non-blocked network"
        );
        ensure!(
            wire.process.timeout
                == Some(if matches!(case, Case::Timeout) {
                    1_000
                } else {
                    10_000
                }),
            "AXIS changed the fixed timeout"
        );
        ensure!(
            wire.process.cwd.as_deref() == Some(text(&self.work)?),
            "AXIS changed the private working directory"
        );
        ensure!(
            wire.filesystem.readwrite_paths == spec.filesystem.read_write
                && wire.filesystem.readonly_paths == spec.filesystem.read_only
                && wire.filesystem.denied_paths == spec.filesystem.deny,
            "AXIS changed filesystem grants during config generation"
        );
        let env = wire
            .process
            .env
            .iter()
            .map(|entry| {
                let (name, value) = entry
                    .split_once('=')
                    .context("AXIS emitted malformed environment")?;
                Ok((name.to_owned(), value.to_owned()))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            env.len() == environment.len()
                && env.iter().cloned().collect::<BTreeMap<_, _>>() == environment,
            "AXIS changed the private environment"
        );
        let mut seatbelt = SeatbeltConfig::default();
        seatbelt.profile_override = if strict {
            Some(strict_profile::build_profile(
                &policy, &self.root, executable,
            )?)
        } else {
            None
        };
        seatbelt.gui_access = false;
        seatbelt.nested_pty = false;
        seatbelt.keychain_access = false;
        seatbelt.extra_mach_lookups.clear();
        let mut request = ContainerRequest::new("");
        request.containment = Containment::Seatbelt(seatbelt);
        request.filesystem = Some(FilesystemPolicy {
            readwrite_paths: wire.filesystem.readwrite_paths,
            readonly_paths: wire.filesystem.readonly_paths,
            denied_paths: wire.filesystem.denied_paths,
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
        request.ui = Some(UiPolicy::default());
        request.timeout_ms = wire.process.timeout;
        request.working_directory = wire.process.cwd;
        request.environment = Some(env);
        request.inherit_default_environment = Some(false);
        Ok(request)
    }
}

fn private_supervisor_environment(paths: &Paths, port: u16) -> Result<()> {
    let names: Vec<_> = std::env::vars_os().map(|(name, _)| name).collect();
    // SAFETY: called once before any SDK API or thread is started. The owned
    // fixture and host positive control have already been constructed.
    unsafe {
        for name in names {
            std::env::remove_var(name);
        }
        for (name, value) in paths.environment(port)? {
            std::env::set_var(name, value);
        }
        // A benign parent-only value makes inherited-environment isolation
        // observable even though the supervisor otherwise uses the same
        // minimal environment as the requested child.
        std::env::set_var(SUPERVISOR_ONLY_ENV, "fixed-public-parent-only");
    }
    Ok(())
}

fn verify_environment(paths: &Paths) -> Result<u16> {
    ensure!(
        std::env::var_os(SUPERVISOR_ONLY_ENV).is_none(),
        "supervisor-only environment reached the child"
    );
    let port: u16 = std::env::var("DC_MACOS_CANARY_PORT")?.parse()?;
    let expected = paths.environment(port)?;
    for (name, value) in &expected {
        ensure!(
            std::env::var(name).ok().as_ref() == Some(value),
            "private environment value differs for {name}"
        );
    }
    for (name, value) in std::env::vars_os() {
        let key = name.to_str().context("non-UTF8 environment key")?;
        if !expected.iter().any(|(allowed, _)| key == allowed) {
            verify_implicit_pwd(key, &value, &paths.work)?;
        }
    }
    Ok(port)
}

fn verify_implicit_pwd(key: &str, value: &OsStr, private_cwd: &Path) -> Result<()> {
    // Seatbelt's MXC runner sets PWD to the requested cwd after clearing env.
    ensure!(key == "PWD", "unexpected child environment key");
    ensure!(
        value == private_cwd.as_os_str(),
        "private PWD value differs"
    );
    Ok(())
}

fn fixed_child(case: Case) -> Result<i32> {
    let paths = Paths::from_child()?;
    let port = verify_environment(&paths)?;
    match case {
        Case::Argv => {
            ensure!(
                fs::read(&paths.readonly)? == READONLY,
                "argv granted read differs"
            );
            denied_errno(fs::read(&paths.ungranted), "argv ungranted read")?;
            println!("LITERAL_ARGV_OK");
            Ok(23)
        }
        Case::Boundaries | Case::StrictBoundaries => {
            ensure!(
                fs::read(&paths.readonly)? == READONLY,
                "readonly canary unreadable"
            );
            for dir in [&paths.work, &paths.home] {
                write_new(&dir.join("allowed-write"), b"fixed-benign-write\n")?;
            }
            denied_errno(fs::read(&paths.denied_home), "read denied HOME canary")?;
            denied_errno(fs::read(&paths.denied_work), "read denied CWD canary")?;
            denied_errno(
                fs::metadata(&paths.denied_home),
                "metadata denied HOME canary",
            )?;
            denied_errno(
                fs::metadata(&paths.denied_work),
                "metadata denied CWD canary",
            )?;
            for path in [&paths.denied_home, &paths.denied_work, &paths.readonly] {
                denied_errno(
                    OpenOptions::new().write(true).open(path),
                    "write protected canary",
                )?;
            }
            denied_errno(fs::read(&paths.ungranted), "read ungranted canary")?;
            if matches!(case, Case::StrictBoundaries) {
                denied_errno(
                    fs::File::open("/private/etc/hosts"),
                    "open fixed host canary",
                )?;
            }
            denied_errno(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(paths.root.join("ungranted-write")),
                "write ungranted sibling",
            )?;
            let target = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            denied_errno(
                std::net::TcpStream::connect_timeout(&target, Duration::from_secs(1)),
                "connect to ready loopback listener",
            )?;
            if matches!(case, Case::StrictBoundaries) {
                println!("STRICT_BOUNDARIES_OK");
            } else {
                println!("BOUNDARIES_OK");
            }
            Ok(23)
        }
        Case::Pipe => {
            let mut input = String::new();
            io::stdin().read_to_string(&mut input)?;
            ensure!(input == "fixed-benign-input\n", "pipe input differs");
            println!("PIPE_ECHO_OK");
            eprintln!("PIPE_STDERR_OK");
            Ok(23)
        }
        Case::Pty => {
            terminal_state(30, 100)?;
            println!("PTY_READY rows=30 cols=100");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().lock().read_line(&mut input)?;
            ensure!(input == "fixed-benign-input\n", "PTY input differs");
            terminal_state(40, 120)?;
            println!("PTY_ECHO_OK rows=40 cols=120");
            Ok(23)
        }
        Case::Timeout => {
            std::process::Command::new(std::env::current_exe()?)
                .args(["--fixed-child", "delayed"])
                .spawn()?;
            println!("TIMEOUT_READY");
            io::stdout().flush()?;
            thread::sleep(Duration::from_secs(30));
            bail!("timeout workload outlived its deadline")
        }
        Case::Delayed => {
            println!("DELAYED_READY");
            io::stdout().flush()?;
            thread::sleep(Duration::from_secs(3));
            write_new(&paths.late_marker, b"descendant-survived\n")?;
            Ok(0)
        }
    }
}

fn terminal_state(rows: u16, cols: u16) -> Result<()> {
    // SAFETY: POSIX identity/terminal queries use valid pointers and fd 0.
    unsafe {
        ensure!(libc::isatty(0) == 1, "child stdin is not a PTY");
        ensure!(
            libc::tcgetpgrp(0) == libc::getpgrp(),
            "child is not PTY foreground group"
        );
        let mut size: libc::winsize = std::mem::zeroed();
        ensure!(
            libc::ioctl(0, libc::TIOCGWINSZ, &mut size) == 0,
            "PTY size query failed"
        );
        ensure!(
            size.ws_row == rows && size.ws_col == cols,
            "child PTY dimensions differ"
        );
    }
    Ok(())
}

fn run_piped(paths: &Paths, executable: &Path, case: Case, port: u16, strict: bool) -> Result<()> {
    let mut process = v1::argv::spawn(
        paths.request(executable, case, port, strict)?,
        fixed_argv(executable, case),
        SpawnOptions {
            telemetry: disabled_telemetry(),
        },
    )
    .context("explicit MXC Seatbelt pipe spawn refused")?;
    let result: Result<()> = (|| -> Result<()> {
        let stdout = Capture::start(
            process.take_stdout().context("missing SDK stdout pipe")?,
            process.stdout_closer(),
        );
        let stderr = Capture::start(
            process.take_stderr().context("missing SDK stderr pipe")?,
            process.stderr_closer(),
        );
        if matches!(case, Case::Pipe) {
            let mut input = process.take_stdin().context("missing SDK stdin pipe")?;
            input.write_all(b"fixed-benign-input\n")?;
            drop(input);
        } else {
            drop(process.take_stdin());
        }
        let outcome = wait_process(&mut process);
        let output = stdout.finish();
        let errors = stderr.finish();
        let diagnostic = errors
            .as_ref()
            .map(|bytes| fixed_child_diagnostic(bytes))
            .unwrap_or_else(|_| "\"stderr capture failed\"".to_owned());
        let outcome = outcome.with_context(|| format!("fixed child stderr={diagnostic}"))?;
        let output = output.with_context(|| format!("fixed child stderr={diagnostic}"))?;
        let errors = errors?;
        (|| -> Result<()> {
            match case {
                Case::Argv => {
                    ensure!(
                        outcome == WaitResult::Exited(23),
                        "literal argv child did not exit 23"
                    );
                    ensure!(
                        contains(&output, b"LITERAL_ARGV_OK") && errors.is_empty(),
                        "literal argv acknowledgement missing"
                    );
                }
                Case::Boundaries => {
                    ensure!(
                        outcome == WaitResult::Exited(23),
                        "boundary child did not exit 23"
                    );
                    ensure!(
                        contains(&output, b"BOUNDARIES_OK") && errors.is_empty(),
                        "boundary acknowledgement missing"
                    );
                }
                Case::StrictBoundaries => {
                    ensure!(
                        outcome == WaitResult::Exited(23),
                        "strict boundary child did not exit 23"
                    );
                    ensure!(
                        contains(&output, b"STRICT_BOUNDARIES_OK") && errors.is_empty(),
                        "strict boundary acknowledgement missing"
                    );
                }
                Case::Pipe => {
                    ensure!(
                        outcome == WaitResult::Exited(23),
                        "pipe child did not exit 23"
                    );
                    ensure!(
                        contains(&output, b"PIPE_ECHO_OK") && contains(&errors, b"PIPE_STDERR_OK"),
                        "pipe echo or stderr missing"
                    );
                }
                Case::Timeout => {
                    ensure!(
                        outcome == WaitResult::TimedOut,
                        "MXC did not report a typed timeout"
                    );
                    ensure!(
                        contains(&output, b"TIMEOUT_READY") && contains(&output, b"DELAYED_READY"),
                        "timeout did not reach both live process stages"
                    );
                    ensure!(errors.is_empty(), "timeout child wrote stderr");
                }
                Case::Pty | Case::Delayed => bail!("invalid pipe case"),
            }
            Ok(())
        })()
        .with_context(|| format!("fixed child stderr={diagnostic}"))?;
        process.kill()?;
        process.kill()?;
        Ok(())
    })();
    if result.is_err() {
        let killed = process.kill();
        let waited = process.wait();
        if let Err(error) = killed {
            return result.context(format!("failed probe also failed SDK kill: {error}"));
        }
        if let Err(error) = waited {
            return result.context(format!("failed probe also failed SDK wait: {error}"));
        }
    }
    result.with_context(|| format!("fixed {} experiment", case.argument()))
}

fn run_pty(paths: &Paths, executable: &Path, port: u16, strict: bool) -> Result<()> {
    let terminal = v1::argv::spawn_with_pty(
        paths.request(executable, Case::Pty, port, strict)?,
        fixed_argv(executable, Case::Pty),
        SpawnWithPtyOptions {
            telemetry: disabled_telemetry(),
            size: terminal_size(30, 100),
        },
    )
    .context("explicit MXC Seatbelt PTY spawn refused")?;
    let result: Result<()> = (|| -> Result<()> {
        let reader = terminal.try_clone_reader()?;
        let output = Capture::start(reader, terminal.stdout_closer());
        let mut input = terminal.take_writer()?;
        output.require_marker(b"PTY_READY rows=30 cols=100", Duration::from_secs(5))?;
        terminal.resize(terminal_size(40, 120))?;
        let size = terminal.size()?;
        ensure!(
            size.rows == 40 && size.cols == 120,
            "SDK PTY resize readback differs"
        );
        input.write_all(b"fixed-benign-input\n")?;
        input.flush()?;
        drop(input);
        let outcome = wait_terminal(&terminal);
        let bytes = output.finish()?;
        let diagnostic = fixed_child_diagnostic(&bytes);
        ensure!(
            outcome.with_context(|| format!("fixed PTY output={diagnostic}"))?
                == WaitResult::Exited(23),
            "PTY child did not exit 23; fixed PTY output={diagnostic}"
        );
        ensure!(
            contains(&bytes, b"PTY_ECHO_OK rows=40 cols=120"),
            "PTY input/resize acknowledgement missing; fixed PTY output={diagnostic}"
        );
        terminal.kill()?;
        terminal.kill()?;
        Ok(())
    })();
    if result.is_err() {
        let killed = terminal.kill();
        let waited = terminal.wait();
        if let Err(error) = killed {
            return result.context(format!("failed PTY probe also failed SDK kill: {error}"));
        }
        if let Err(error) = waited {
            return result.context(format!("failed PTY probe also failed SDK wait: {error}"));
        }
    }
    result.context("fixed MXC-owned PTY experiment")
}

fn wait_process(process: &mut MxcProcess) -> Result<WaitResult> {
    let start = Instant::now();
    loop {
        match process.try_wait() {
            Ok(Some(_)) => return Ok(process.wait()?),
            Err(error) if error.kind() == io::ErrorKind::TimedOut => return Ok(process.wait()?),
            Err(error) => return Err(error.into()),
            Ok(None) => {}
        }
        if start.elapsed() >= SUPERVISOR_LIMIT {
            process.kill_for_timeout()?;
            let _ = process.wait();
            bail!("supervisor deadline exceeded; backend timeout was insufficient");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_terminal(terminal: &MxcPtyProcess) -> Result<WaitResult> {
    let start = Instant::now();
    loop {
        match terminal.try_wait() {
            Ok(Some(_)) => return Ok(terminal.wait()?),
            Err(error) if error.kind() == io::ErrorKind::TimedOut => return Ok(terminal.wait()?),
            Err(error) => return Err(error.into()),
            Ok(None) => {}
        }
        if start.elapsed() >= SUPERVISOR_LIMIT {
            terminal.kill_for_timeout()?;
            let _ = terminal.wait();
            bail!("supervisor PTY deadline exceeded");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

struct Capture {
    bytes: Arc<Mutex<Vec<u8>>>,
    completed: mpsc::Receiver<io::Result<()>>,
    reader: Option<JoinHandle<()>>,
    closer: Option<StreamCloser>,
}

impl Capture {
    fn start(mut stream: Box<dyn Read + Send>, closer: Option<StreamCloser>) -> Self {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&bytes);
        let (sender, completed) = mpsc::channel();
        let reader = thread::spawn(move || {
            let result = (|| {
                let mut buffer = [0u8; 4096];
                let mut overflow = false;
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(count) => {
                            let mut output = captured
                                .lock()
                                .map_err(|_| io::Error::other("capture mutex poisoned"))?;
                            let remaining = OUTPUT_LIMIT.saturating_sub(output.len());
                            output.extend_from_slice(&buffer[..count.min(remaining)]);
                            overflow |= count > remaining;
                        }
                        Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error),
                    }
                }
                if overflow {
                    return Err(io::Error::other("fixed child exceeded output limit"));
                }
                Ok(())
            })();
            let _ = sender.send(result);
        });
        Self {
            bytes,
            completed,
            reader: Some(reader),
            closer,
        }
    }

    fn require_marker(&self, marker: &[u8], limit: Duration) -> Result<()> {
        let start = Instant::now();
        while start.elapsed() < limit {
            if contains(
                &self
                    .bytes
                    .lock()
                    .map_err(|_| anyhow!("capture mutex poisoned"))?,
                marker,
            ) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(10));
        }
        let captured = self
            .bytes
            .lock()
            .map_err(|_| anyhow!("capture mutex poisoned"))?;
        bail!(
            "fixed child readiness acknowledgement missing; fixed output={}",
            fixed_child_diagnostic(captured.as_slice())
        )
    }

    fn finish(mut self) -> Result<Vec<u8>> {
        let result = match self.completed.recv_timeout(Duration::from_millis(500)) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Some(closer) = &self.closer {
                    closer.close();
                }
                self.completed
                    .recv_timeout(Duration::from_secs(2))
                    .context("SDK stream close did not unblock capture")?
            }
            Err(error) => return Err(error.into()),
        };
        if let Some(reader) = self.reader.take() {
            reader
                .join()
                .map_err(|_| anyhow!("capture thread panicked"))?;
        }
        result.context("bounded fixed child capture")?;
        let output = self
            .bytes
            .lock()
            .map_err(|_| anyhow!("capture mutex poisoned"))?
            .clone();
        Ok(output)
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        if let Some(closer) = &self.closer {
            closer.close();
        }
        if self.reader.as_ref().is_some_and(JoinHandle::is_finished) {
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
        }
    }
}

fn disabled_telemetry() -> Option<TelemetryConfig> {
    Some(TelemetryConfig {
        enabled: Some(false),
    })
}

fn terminal_size(rows: u16, cols: u16) -> MxcPtySize {
    MxcPtySize {
        rows,
        cols,
        ..MxcPtySize::default()
    }
}

fn denied_errno<T>(result: io::Result<T>, action: &str) -> Result<()> {
    match result {
        Err(error) if matches!(error.raw_os_error(), Some(libc::EPERM | libc::EACCES)) => Ok(()),
        Err(error) => bail!("{action} failed with the wrong errno: {error}"),
        Ok(_) => bail!("{action} unexpectedly succeeded"),
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}

fn text(path: &Path) -> Result<&str> {
    path.to_str().context("probe path is not UTF-8")
}

fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|part| part == needle)
}

fn fixed_child_diagnostic(bytes: &[u8]) -> String {
    // At most 1,200 input bytes expand to 7,200 JSON bytes even if every
    // byte becomes a six-byte control escape. The child has only fixed private
    // fixture data and an allowlisted environment.
    let clipped = &bytes[..bytes.len().min(DIAGNOSTIC_INPUT_LIMIT)];
    let encoded = serde_json::to_string(&String::from_utf8_lossy(clipped))
        .unwrap_or_else(|_| "\"stderr encoding failed\"".to_owned());
    if bytes.len() > clipped.len() {
        format!("{encoded} [truncated]")
    } else {
        encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn implicit_pwd_is_only_the_exact_private_cwd() {
        let cwd = Path::new("/private/tmp/fixed-private/work");
        assert!(
            verify_implicit_pwd("PWD", OsStr::new("/private/tmp/fixed-private/work"), cwd).is_ok()
        );
        assert!(verify_implicit_pwd("PWD", OsStr::new("/private/tmp/other/work"), cwd).is_err());
        for key in ["SHLVL", "_", SUPERVISOR_ONLY_ENV] {
            assert!(verify_implicit_pwd(key, cwd.as_os_str(), cwd).is_err());
        }
    }

    #[test]
    fn private_fixture_is_owner_only_before_payload_creation() {
        let owned = private_fixture().unwrap();
        let root = owned.path().to_owned();
        let metadata = fs::symlink_metadata(&root).unwrap();
        assert!(metadata.is_dir());
        // SAFETY: geteuid is a read-only identity query.
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        owned.close().unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn fixed_literal_argv_preserves_data() {
        let argv = fixed_argv(Path::new("/private/tmp/probe with ' quotes"), Case::Argv);
        assert_eq!(argv[0], OsString::from("/private/tmp/probe with ' quotes"));
        assert_eq!(argv[1], OsString::from("--fixed-child"));
        assert_eq!(argv[2], OsString::from("argv"));
        assert_eq!(
            argv[3..].to_vec(),
            LITERAL_ARGUMENTS.map(OsString::from).to_vec()
        );
        assert_eq!(fixed_child_arguments(Case::Boundaries).len(), 2);
    }
}
