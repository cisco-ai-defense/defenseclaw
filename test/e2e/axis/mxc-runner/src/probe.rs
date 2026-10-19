// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, anyhow, bail, ensure};
use axis_core::policy::Policy;
use axis_sandbox::linux::{landlock, seccomp};
use mxc_sdk::v1::{
    self, ContainerRequest, Containment, FilesystemPolicy, MxcProcess, MxcPtyProcess, MxcPtySize,
    NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy, NetworkPolicy, SpawnOptions,
    SpawnWithPtyOptions, StreamCloser, TelemetryConfig, WaitResult,
};
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const AXIS_COMMIT: &str = "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c";
const MXC_COMMIT: &str = "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2";
const PREFIX: &str = "dc-axis-mxc-";
const SEAL: &[u8] = b"defenseclaw-fixed-mxc-contributor-fixture-v1\n";
const READONLY: &[u8] = b"synthetic-readonly-canary\n";
const UNGRANTED: &[u8] = b"synthetic-ungranted-canary\n";
const OUTPUT_LIMIT: usize = 64 * 1024;
const DIAGNOSTIC_LIMIT: usize = 8 * 1024;
const PTY_GROUP_MARKER: &[u8] = b"PTY_GROUPS=";
const PTY_PHASES: [&str; 3] = ["initial", "resized", "continued"];
const PTY_SIGINT_ACK: &[u8] = b"PTY_SIGINT_ACK signal=SIGINT vintr=3 isig=true";
const LITERAL_ARGUMENTS: [&str; 6] = [
    "",
    "literal spaces",
    "quotes ' and \"",
    "metachar $HOME ; * ? [ ] | &",
    "unicode-λ-雪",
    "trailing\\",
];
const SUPERVISOR_LIMIT: Duration = Duration::from_secs(15);
static FIXED_SIGINT_RECEIVED: AtomicBool = AtomicBool::new(false);

pub fn run() -> Result<i32> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args
        .first()
        .is_some_and(|arg| arg.as_os_str() == OsStr::new("--fixed-child"))
    {
        let case = match args.get(1).and_then(|arg| arg.to_str()) {
            Some("boundaries") => Case::Boundaries,
            Some("argv") => Case::Argv,
            Some("pty") => Case::Pty,
            Some("timeout") => Case::Timeout,
            _ => bail!("unknown fixed child case"),
        };
        ensure!(
            args == fixed_child_arguments(case),
            "fixed child argv differs"
        );
        return fixed_child(case);
    }
    ensure!(
        args.is_empty(),
        "the probe accepts no command, path or policy arguments"
    );
    // This experiment is for rootless operation, without host setup mutations.
    // SAFETY: geteuid has no pointer arguments and does not mutate process state.
    ensure!(
        unsafe { libc::geteuid() } != 0,
        "run as an unprivileged user"
    );
    let abi = landlock_abi()?;
    let executable = std::env::current_exe()?.canonicalize()?;
    let owned = private_fixture()?;
    let paths = Paths::create(&owned.path().canonicalize()?)?;

    // Before invoking any SDK code or creating threads, remove credentials,
    // proxy overrides, dynamic-loader overrides and caller-selected tool paths
    // from the supervisor too. No inherited environment is logged or retained.
    private_supervisor_environment(&paths)?;
    run_piped(&paths, &executable, Case::Boundaries)?;
    run_piped(&paths, &executable, Case::Argv)?;
    let pty_groups = run_pty(&paths, &executable)?;
    run_piped(&paths, &executable, Case::Timeout)?;
    ensure!(
        fs::read(&paths.readonly)? == READONLY,
        "readonly canary changed"
    );
    ensure!(
        fs::read(paths.ungranted.join("canary"))? == UNGRANTED,
        "ungranted canary changed"
    );
    ensure!(
        !paths.ungranted.join("write-attempt").exists(),
        "ungranted write survived"
    );
    for directory in [&paths.workspace, &paths.home, &paths.temporary] {
        ensure!(
            fs::read(directory.join("allowed-write"))? == b"fixed-benign-write\n",
            "allowed write missing"
        );
    }
    let root = owned.path().to_owned();
    owned
        .close()
        .context("remove owned fixture after all SDK handles returned")?;
    ensure!(!root.exists(), "owned fixture cleanup was incomplete");
    println!(
        "{}",
        serde_json::json!({
            "axis_commit": AXIS_COMMIT, "mxc_commit": MXC_COMMIT,
            "containment": "mxc_sdk_v1_bubblewrap", "axis_child_guards": "landlock_and_offline_seccomp",
            "landlock_abi": abi, "filesystem": "hard_requirement", "network": "block",
            "pty_groups": pty_groups,
            "checks": ["private_home_and_environment", "allowed_writes", "outer_mxc_canary_visible_before_guards", "ungranted_read_and_write_eacces",
                "readonly_write_denied", "ipv4_ipv6_tcp_udp_socket_eperm", "exit_23", "pty_isatty_and_foreground",
                "pty_input_ack_and_resize", "pty_sigint_ack_and_continued_input", "typed_timeout", "direct_child_pidfd_exited",
                "handle_kill_after_wait_idempotent", "owned_fixture_removed", "literal_argv_preserved_without_shell"],
            "scope": "fixed_benign_contributor_experiment", "production_or_claude_qualification": false,
            "proxy_or_descendant_cleanup_qualification": false
        })
    );
    Ok(0)
}

#[derive(Clone, Copy)]
enum Case {
    Boundaries,
    Argv,
    Pty,
    Timeout,
}

impl Case {
    fn argument(self) -> &'static str {
        match self {
            Self::Boundaries => "boundaries",
            Self::Argv => "argv",
            Self::Pty => "pty",
            Self::Timeout => "timeout",
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
    workspace: PathBuf,
    home: PathBuf,
    temporary: PathBuf,
    readonly: PathBuf,
    ungranted: PathBuf,
}

fn private_fixture() -> Result<tempfile::TempDir> {
    // tempfile directories otherwise inherit the default 0777-and-umask mode.
    // Set the owner-only mode in mkdir itself, before creating any payload.
    let owned = tempfile::Builder::new()
        .prefix(PREFIX)
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")?;
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

impl Paths {
    fn at(root: &Path) -> Self {
        Self {
            root: root.to_owned(),
            workspace: root.join("workspace"),
            home: root.join("home"),
            temporary: root.join("tmp"),
            readonly: root.join("readonly"),
            ungranted: root.join("ungranted"),
        }
    }

    fn create(root: &Path) -> Result<Self> {
        let paths = Self::at(root);
        for directory in [
            &paths.workspace,
            &paths.home,
            &paths.temporary,
            &paths.ungranted,
        ] {
            fs::DirBuilder::new().mode(0o700).create(directory)?;
        }
        for directory in [
            paths.home.join(".config"),
            paths.home.join(".cache"),
            paths.home.join(".local/share"),
        ] {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)?;
        }
        write_new(&root.join("fixture-seal"), SEAL)?;
        write_new(&paths.readonly, READONLY)?;
        write_new(&paths.ungranted.join("canary"), UNGRANTED)?;
        Ok(paths)
    }

    fn from_child() -> Result<Self> {
        let workspace = std::env::current_dir()?.canonicalize()?;
        ensure!(
            workspace
                .file_name()
                .is_some_and(|name| name == "workspace"),
            "unexpected child cwd"
        );
        let root = workspace.parent().context("missing fixture parent")?;
        ensure!(
            root.parent() == Some(fs::canonicalize("/tmp")?.as_path()),
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
        ensure!(
            fs::read(root.join("fixture-seal"))? == SEAL,
            "fixture seal differs"
        );
        let paths = Self::at(root);
        for directory in [
            &paths.workspace,
            &paths.home,
            &paths.temporary,
            &paths.ungranted,
        ] {
            ensure!(
                fs::symlink_metadata(directory)?.is_dir()
                    && directory.canonicalize()? == *directory,
                "fixture directory is not canonical"
            );
        }
        verify_environment(&paths)?;
        Ok(paths)
    }

    fn environment(&self) -> Result<Vec<(String, String)>> {
        Ok(vec![
            ("HOME".into(), text(&self.home)?.into()),
            ("TMPDIR".into(), text(&self.temporary)?.into()),
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("LANG".into(), "C".into()),
            ("TERM".into(), "xterm".into()),
            (
                "XDG_CONFIG_HOME".into(),
                text(&self.home.join(".config"))?.into(),
            ),
            (
                "XDG_CACHE_HOME".into(),
                text(&self.home.join(".cache"))?.into(),
            ),
            (
                "XDG_DATA_HOME".into(),
                text(&self.home.join(".local/share"))?.into(),
            ),
        ])
    }

    fn request(&self, executable: &Path, case: Case) -> Result<ContainerRequest> {
        // The additive v1::argv seam requires an empty legacy command field.
        Ok(ContainerRequest {
            containment: Containment::Bubblewrap,
            filesystem: Some(FilesystemPolicy {
                // The entire synthetic fixture is visible read-only to MXC;
                // its explicit writable subdirectories override that mount.
                // The ungranted synthetic canary is deliberately writable at
                // the MXC layer so EACCES proves the inner AXIS restriction.
                readonly_paths: vec![text(&self.root)?.into(), text(executable)?.into()],
                readwrite_paths: [
                    &self.workspace,
                    &self.home,
                    &self.temporary,
                    &self.ungranted,
                ]
                .iter()
                .map(|path| text(path).map(str::to_owned))
                .collect::<Result<_>>()?,
                denied_paths: Vec::new(),
                clear_policy_on_exit: Some(true),
            }),
            network: Some(NetworkPolicy {
                egress: Some(NetworkEgressPolicy {
                    default: Some(NetworkAction::Deny),
                    ..Default::default()
                }),
                ingress: Some(NetworkIngressPolicy {
                    default: Some(NetworkAction::Deny),
                    host_loopback: Some(NetworkAction::Deny),
                }),
                runtime_config: None,
            }),
            timeout_ms: Some(if matches!(case, Case::Timeout) {
                1_000
            } else {
                10_000
            }),
            working_directory: Some(text(&self.workspace)?.into()),
            environment: Some(self.environment()?),
            inherit_default_environment: Some(false),
            ..ContainerRequest::new("")
        })
    }

    fn axis_policy(&self, executable: &Path) -> Result<Policy> {
        let mut readonly = vec![executable.to_owned(), self.readonly.clone()];
        // Grant only runtime installation paths. MXC's broader baseline /etc
        // mount is not granted by the AXIS child policy.
        for path in [
            "/usr",
            "/bin",
            "/lib",
            "/lib64",
            "/etc/ld.so.cache",
            "/dev/null",
        ] {
            if Path::new(path).exists() {
                readonly.push(PathBuf::from(path));
            }
        }
        let value = serde_json::json!({
            "version": 1, "name": "dc-mxc-offline-child",
            "runtime": {"containment": "process", "provider": "mxc"},
            "filesystem": {"compatibility": "hard_requirement", "read_only": readonly,
                "read_write": [&self.workspace, &self.home, &self.temporary]},
            // Resource limits are deliberately outside this experiment. MXC
            // owns the real configured wall-clock timeout.
            "process": {"max_processes": 0, "max_memory_mb": 0, "cpu_rate_percent": 0},
            "network": {"mode": "block"}
        });
        Policy::from_yaml(&serde_json::to_string(&value)?)
            .context("validate fixed AXIS child policy")
    }
}

fn private_supervisor_environment(paths: &Paths) -> Result<()> {
    let names: Vec<_> = std::env::vars_os().map(|(name, _)| name).collect();
    // SAFETY: this is called once, before any SDK API or thread is started.
    unsafe {
        for name in names {
            std::env::remove_var(name);
        }
        for (name, value) in paths.environment()? {
            std::env::set_var(name, value);
        }
        std::env::set_var("DC_AXIS_INHERIT_CANARY", "fixed-public");
    }
    Ok(())
}

fn verify_environment(paths: &Paths) -> Result<()> {
    ensure!(
        std::env::var_os("DC_AXIS_INHERIT_CANARY").is_none(),
        "parent-only inheritance canary reached child"
    );
    let expected = paths.environment()?;
    for (name, value) in &expected {
        ensure!(
            std::env::var(name).ok().as_ref() == Some(value),
            "private environment value differs for {name}"
        );
    }
    for (name, value) in std::env::vars_os() {
        let key = name.to_str().context("non-UTF8 environment key")?;
        if !expected.iter().any(|(allowed, _)| key == allowed) {
            verify_implicit_pwd(key, &value, &paths.workspace)?;
        }
    }
    Ok(())
}

fn verify_implicit_pwd(key: &str, value: &OsStr, private_cwd: &Path) -> Result<()> {
    // Bubblewrap sets PWD to --chdir after --clearenv, even for literal argv.
    ensure!(key == "PWD", "unexpected environment key");
    ensure!(
        value == private_cwd.as_os_str(),
        "private PWD value differs"
    );
    Ok(())
}

fn fixed_child(case: Case) -> Result<i32> {
    let paths = Paths::from_child()?;
    let executable = std::env::current_exe()?.canonicalize()?;
    let policy = paths.axis_policy(&executable)?;
    landlock_abi()?;
    if matches!(case, Case::Boundaries) {
        // Prove the outer MXC grant is present before AXIS removes access.
        ensure!(
            fs::read(paths.ungranted.join("canary"))? == UNGRANTED,
            "outer MXC canary read differs before AXIS guards"
        );
        let control = paths.ungranted.join("pre-guard-write-control");
        write_new(&control, b"fixed-public-control\n")?;
        fs::remove_file(control)?;
    }
    if matches!(case, Case::Pty) {
        establish_namespace_foreground_group()?;
        install_fixed_sigint_handler()?;
    }
    // SAFETY: PR_SET_NO_NEW_PRIVS has an integer value and unused zero args.
    // It affects only this already-contained fixed child and is irreversible.
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0,
        "setting no_new_privs failed: {}",
        io::Error::last_os_error()
    );
    landlock::apply_landlock(&policy.filesystem, &paths.workspace)
        .map_err(|error| anyhow!(error))?;
    seccomp::apply_offline_mxc_child_seccomp(&policy.process, matches!(case, Case::Pty))
        .map_err(|error| anyhow!(error))?;
    match case {
        Case::Argv => {
            ensure!(
                fs::read(&paths.readonly)? == READONLY,
                "argv granted read differs"
            );
            denied_errno(
                fs::read(paths.ungranted.join("canary")),
                &[libc::EACCES],
                "argv ungranted read",
            )?;
            println!("LITERAL_ARGV_OK");
            Ok(23)
        }
        Case::Boundaries => {
            ensure!(
                fs::read(&paths.readonly)? == READONLY,
                "granted read differs"
            );
            for directory in [&paths.workspace, &paths.home, &paths.temporary] {
                write_new(&directory.join("allowed-write"), b"fixed-benign-write\n")?;
            }
            denied_errno(
                fs::read(paths.ungranted.join("canary")),
                &[libc::EACCES],
                "ungranted read",
            )?;
            denied_errno(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(paths.ungranted.join("write-attempt")),
                &[libc::EACCES],
                "ungranted write",
            )?;
            denied_errno(
                OpenOptions::new().write(true).open(&paths.readonly),
                &[libc::EACCES, libc::EROFS],
                "readonly write",
            )?;
            for family in [libc::AF_INET, libc::AF_INET6] {
                for kind in [libc::SOCK_STREAM, libc::SOCK_DGRAM] {
                    // SAFETY: socket receives constant family/type/protocol.
                    let descriptor = unsafe { libc::socket(family, kind | libc::SOCK_CLOEXEC, 0) };
                    if descriptor >= 0 {
                        // SAFETY: a successful socket call returns a new fd.
                        drop(unsafe { OwnedFd::from_raw_fd(descriptor) });
                        bail!("IP socket creation was permitted");
                    }
                    ensure!(
                        io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
                        "IP socket denial was not EPERM"
                    );
                }
            }
            println!("BOUNDARIES_OK");
            Ok(23)
        }
        Case::Pty => {
            terminal_state(30, 100, "initial")?;
            require_terminal_interrupt_settings()?;
            ensure!(
                !FIXED_SIGINT_RECEIVED.load(Ordering::Relaxed),
                "SIGINT arrived before the owned PTY control-byte handshake"
            );
            println!("PTY_READY isatty=true foreground=true rows=30 cols=100");
            io::stdout().flush()?;
            require_fixed_sigint(&FIXED_SIGINT_RECEIVED, Duration::from_secs(3))?;
            // ECHOCTL can echo ^C without a newline. Begin the next owned
            // evidence record on its own line without changing terminal flags.
            println!();
            terminal_state(40, 120, "resized")?;
            require_terminal_interrupt_settings()?;
            println!("PTY_SIGINT_ACK signal=SIGINT vintr=3 isig=true");
            io::stdout().flush()?;
            let mut line = String::new();
            // Input is bounded even if the fixed supervisor is changed later.
            io::stdin().lock().take(128).read_line(&mut line)?;
            ensure!(
                line == "fixed-benign-input\n",
                "PTY input acknowledgement differs"
            );
            terminal_state(40, 120, "continued")?;
            println!(
                "PTY_ACK input=true rows=40 cols=120 foreground=true continued_after_sigint=true"
            );
            Ok(23)
        }
        Case::Timeout => {
            println!("TIMEOUT_READY");
            io::stdout().flush()?;
            loop {
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

extern "C" fn fixed_sigint_handler(_signal: libc::c_int) {
    // AtomicBool is lock-free on this x86_64-only contributor target. The
    // handler performs no allocation, I/O, locking or non-signal-safe calls.
    FIXED_SIGINT_RECEIVED.store(true, Ordering::Relaxed);
}

fn install_fixed_sigint_handler() -> Result<()> {
    require_terminal_interrupt_settings()?;
    FIXED_SIGINT_RECEIVED.store(false, Ordering::Relaxed);
    // SAFETY: this runs only in the new contained fixed PTY child, before
    // guards or threads. All C structs/sets are initialized and remain live
    // for the calls. Only that child's SIGINT disposition/mask are changed.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = fixed_sigint_handler as *const () as libc::sighandler_t;
        ensure!(
            libc::sigemptyset(&mut action.sa_mask) == 0,
            "initialize fixed SIGINT handler mask"
        );
        action.sa_flags = 0;
        ensure!(
            libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) == 0,
            "install fixed SIGINT handler: {}",
            io::Error::last_os_error()
        );
        let mut interrupt: libc::sigset_t = std::mem::zeroed();
        ensure!(
            libc::sigemptyset(&mut interrupt) == 0
                && libc::sigaddset(&mut interrupt, libc::SIGINT) == 0,
            "initialize fixed SIGINT unblock set"
        );
        let status = libc::pthread_sigmask(libc::SIG_UNBLOCK, &interrupt, std::ptr::null_mut());
        ensure!(
            status == 0,
            "unblock fixed child SIGINT: {}",
            io::Error::from_raw_os_error(status)
        );
    }
    Ok(())
}

fn require_terminal_interrupt_settings() -> Result<()> {
    // SAFETY: tcgetattr reads only the owned stdin terminal and writes into
    // valid initialized stack memory. The probe never changes host termios.
    let mut settings: libc::termios = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::tcgetattr(0, &mut settings) } == 0,
        "read owned PTY interrupt settings: {}",
        io::Error::last_os_error()
    );
    validate_interrupt_settings(settings.c_lflag, settings.c_cc[libc::VINTR])
}

fn validate_interrupt_settings(flags: libc::tcflag_t, interrupt: libc::cc_t) -> Result<()> {
    ensure!(
        flags & libc::ISIG != 0 && interrupt == 0x03,
        "owned PTY requires ISIG and VINTR=0x03"
    );
    Ok(())
}

fn require_fixed_sigint(received: &AtomicBool, limit: Duration) -> Result<()> {
    let start = Instant::now();
    while !received.load(Ordering::Relaxed) {
        ensure!(
            start.elapsed() < limit,
            "fixed child did not observe owned PTY SIGINT within deadline"
        );
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn establish_namespace_foreground_group() -> Result<()> {
    // MXC attaches the controlling PTY before Bubblewrap enters its PID
    // namespace. Establish a visible foreground group inside that namespace,
    // without detaching the session or dropping PID isolation. Block SIGTTOU
    // only for this trusted bootstrap operation and restore the prior mask.
    // SAFETY: all signal sets are initialized and pointers stay valid; this
    // fresh fixed child has not started any threads or untrusted code.
    unsafe {
        let mut blocked: libc::sigset_t = std::mem::zeroed();
        let mut previous: libc::sigset_t = std::mem::zeroed();
        ensure!(
            libc::sigemptyset(&mut blocked) == 0,
            "initialize signal mask"
        );
        ensure!(
            libc::sigaddset(&mut blocked, libc::SIGTTOU) == 0,
            "add terminal signal to bootstrap mask"
        );
        let status = libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous);
        ensure!(
            status == 0,
            "block bootstrap SIGTTOU: {}",
            io::Error::from_raw_os_error(status)
        );
        let configured = (|| -> Result<()> {
            ensure!(
                libc::setpgid(0, 0) == 0,
                "establish namespace process group: {}",
                io::Error::last_os_error()
            );
            let group = libc::getpgrp();
            ensure!(group > 0, "namespace process group must be positive");
            ensure!(
                libc::tcsetpgrp(0, group) == 0,
                "set namespace foreground group: {}",
                io::Error::last_os_error()
            );
            ensure!(
                libc::tcgetpgrp(0) == group,
                "namespace foreground group differs"
            );
            Ok(())
        })();
        let restored = libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
        ensure!(
            restored == 0,
            "restore bootstrap signal mask: {}",
            io::Error::from_raw_os_error(restored)
        );
        configured
    }
}

fn terminal_state(rows: u16, cols: u16, phase: &'static str) -> Result<()> {
    // SAFETY: all queries use the owned stdin fd and valid stack output memory.
    let (tty, foreground, group) =
        unsafe { (libc::isatty(0), libc::tcgetpgrp(0), libc::getpgrp()) };
    // Record these fixed numeric observations before refusing, including the
    // namespace-zero case that equality alone cannot distinguish.
    println!(
        "PTY_GROUPS={}",
        serde_json::json!({
            "phase": phase, "isatty": tty,
            "foreground_pgrp": foreground, "process_pgrp": group
        })
    );
    io::stdout().flush()?;
    ensure!(
        tty == 1 && foreground > 0 && group > 0 && foreground == group,
        "PTY requires positive matching groups: isatty={tty} foreground_pgrp={foreground} process_pgrp={group}"
    );
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ writes a winsize to the supplied stack pointer.
    ensure!(
        unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut size) } == 0,
        "PTY size query failed"
    );
    ensure!(
        size.ws_row == rows && size.ws_col == cols,
        "child PTY dimensions differ"
    );
    Ok(())
}

fn run_piped(paths: &Paths, executable: &Path, case: Case) -> Result<()> {
    let mut process = v1::argv::spawn(
        paths.request(executable, case)?,
        fixed_argv(executable, case),
        SpawnOptions {
            telemetry: disabled_telemetry(),
        },
    )
    .context("explicit MXC Bubblewrap spawn refused")?;
    let result = (|| {
        let tracked = TrackedChild::new(process.id())?;
        ensure!(
            process.warnings().is_empty(),
            "MXC returned policy or execution warnings"
        );
        let stdout = Capture::start(
            process.take_stdout().context("missing SDK stdout pipe")?,
            process.stdout_closer(),
        );
        let stderr = Capture::start(
            process.take_stderr().context("missing SDK stderr pipe")?,
            process.stderr_closer(),
        );
        drop(process.take_stdin());
        let outcome = wait_process(&mut process)?;
        ensure!(
            process.warnings().is_empty(),
            "MXC returned teardown warnings"
        );
        let output = stdout.finish()?;
        let errors = stderr.finish()?;
        if !errors.is_empty() {
            // This child receives only our synthetic fixture and private
            // environment. Preserve its actual refusal without dumping host
            // environment, unbounded output or terminal control characters.
            eprintln!(
                "AXIS_MXC_FIXED_CHILD_DIAGNOSTIC={}",
                fixed_child_diagnostic(case, &outcome, &errors)
            );
        }
        ensure!(errors.is_empty(), "fixed child wrote stderr");
        match case {
            Case::Argv => {
                ensure!(
                    matches!(outcome, WaitResult::Exited(23)),
                    "literal argv child exit was not 23"
                );
                ensure!(
                    contains(&output, b"LITERAL_ARGV_OK"),
                    "literal argv acknowledgement missing"
                );
            }
            Case::Boundaries => {
                ensure!(
                    matches!(outcome, WaitResult::Exited(23)),
                    "boundary child exit was not 23"
                );
                ensure!(
                    contains(&output, b"BOUNDARIES_OK"),
                    "boundary acknowledgement missing"
                );
            }
            Case::Timeout => {
                ensure!(
                    matches!(outcome, WaitResult::TimedOut),
                    "MXC did not report its typed timeout"
                );
                ensure!(
                    contains(&output, b"TIMEOUT_READY"),
                    "timeout occurred before guarded payload readiness"
                );
            }
            Case::Pty => bail!("PTY case cannot use pipes"),
        }
        tracked.require_exited()?;
        // SDK-owned handle cleanup after wait must not signal a reused raw PID.
        process.kill()?;
        process.kill()?;
        Ok(())
    })();
    if result.is_err() {
        let killed = process.kill();
        let waited = process.wait();
        ensure!(
            killed.is_ok() && waited.is_ok(),
            "failed probe also failed tracked SDK cleanup"
        );
    }
    result.with_context(|| format!("fixed {} experiment", case.argument()))
}

fn run_pty(paths: &Paths, executable: &Path) -> Result<serde_json::Value> {
    let terminal = v1::argv::spawn_with_pty(
        paths.request(executable, Case::Pty)?,
        fixed_argv(executable, Case::Pty),
        SpawnWithPtyOptions {
            telemetry: disabled_telemetry(),
            size: terminal_size(30, 100),
        },
    )
    .context("explicit MXC Bubblewrap PTY spawn refused")?;
    let result = (|| {
        let tracked = TrackedChild::new(terminal.id())?;
        ensure!(
            terminal.warnings().is_empty(),
            "MXC returned PTY policy or execution warnings"
        );
        // Register the cloned reader before asking for its interrupt handle.
        let reader = terminal.try_clone_reader()?;
        let output = Capture::start(reader, terminal.stdout_closer());
        let mut input = terminal.take_writer()?;
        if let Err(error) = output.require_marker(
            b"PTY_READY isatty=true foreground=true rows=30 cols=100",
            Duration::from_secs(5),
        ) {
            output.emit_pty_diagnostic();
            return Err(error);
        }
        terminal.resize(terminal_size(40, 120))?;
        let size = terminal.size()?;
        ensure!(
            size.rows == 40 && size.cols == 120,
            "SDK PTY resize readback differs"
        );
        // VINTR is interpreted by this owned terminal's line discipline.
        // No numeric PID/process-group signal is issued by the supervisor.
        input.write_all(&[0x03])?;
        input.flush()?;
        if let Err(error) = output.require_marker(PTY_SIGINT_ACK, Duration::from_secs(4)) {
            output.emit_pty_diagnostic();
            return Err(error);
        }
        input.write_all(b"fixed-benign-input\n")?;
        input.flush()?;
        let outcome = wait_terminal(&terminal).inspect_err(|_| output.emit_pty_diagnostic())?;
        let bytes = output.finish()?;
        let acknowledged = contains(
            &bytes,
            b"PTY_ACK input=true rows=40 cols=120 foreground=true continued_after_sigint=true",
        );
        if !matches!(outcome, WaitResult::Exited(23)) || !acknowledged {
            eprintln!(
                "AXIS_MXC_FIXED_PTY_DIAGNOSTIC={}",
                fixed_pty_diagnostic(&bytes)
            );
        }
        ensure!(
            matches!(outcome, WaitResult::Exited(23)),
            "PTY child exit was not 23"
        );
        ensure!(
            terminal.warnings().is_empty(),
            "MXC returned PTY teardown warnings"
        );
        ensure!(acknowledged, "PTY input/resize acknowledgement missing");
        let groups = pty_group_evidence(&bytes).inspect_err(|_| {
            eprintln!(
                "AXIS_MXC_FIXED_PTY_DIAGNOSTIC={}",
                fixed_pty_diagnostic(&bytes)
            );
        })?;
        tracked.require_exited()?;
        terminal.kill()?;
        terminal.kill()?;
        Ok(groups)
    })();
    if result.is_err() {
        let killed = terminal.kill();
        let waited = terminal.wait();
        ensure!(
            killed.is_ok() && waited.is_ok(),
            "failed PTY probe also failed tracked SDK cleanup"
        );
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
            bail!("supervisor deadline exceeded; backend timeout was not sufficient");
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
    completed: mpsc::Receiver<Result<(), io::Error>>,
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
                        // Linux PTY readers conventionally return EIO at EOF.
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
        bail!("fixed child readiness acknowledgement missing");
    }

    fn emit_pty_diagnostic(&self) {
        if let Ok(bytes) = self.bytes.lock() {
            eprintln!(
                "AXIS_MXC_FIXED_PTY_DIAGNOSTIC={}",
                fixed_pty_diagnostic(&bytes)
            );
        }
    }

    fn finish(mut self) -> Result<Vec<u8>> {
        // Prefer natural EOF so the final ACK is not truncated. After a process
        // exit, close the SDK stream if an inherited descriptor keeps it open.
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
        // An error path must not block forever joining a broken SDK reader.
        // The SDK process handle is killed and waited by its enclosing scope.
        if self.reader.as_ref().is_some_and(JoinHandle::is_finished) {
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
        }
    }
}

struct TrackedChild(OwnedFd);

impl TrackedChild {
    fn new(id: u32) -> Result<Self> {
        ensure!(id > 0, "MXC did not expose its direct child identity");
        // SAFETY: pidfd_open binds an existing SDK-owned direct child, before
        // this caller performs any wait/reap. No numeric PID is ever signaled.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, id, 0) };
        ensure!(
            descriptor >= 0,
            "pidfd_open failed: {}",
            io::Error::last_os_error()
        );
        // SAFETY: a successful pidfd_open returned a new owned descriptor.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(descriptor as i32) }))
    }

    fn require_exited(&self) -> Result<()> {
        let mut pollfd = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll receives one initialized, valid stack pollfd.
        ensure!(
            unsafe { libc::poll(&mut pollfd, 1, 2_000) } == 1
                && pollfd.revents & (libc::POLLIN | libc::POLLHUP) != 0,
            "tracked direct MXC child survived SDK wait"
        );
        Ok(())
    }
}

fn landlock_abi() -> Result<i64> {
    // SAFETY: VERSION with null attrs and zero size is a read-only ABI query.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0,
            1,
        )
    };
    ensure!(
        abi >= 3,
        "Landlock ABI >= 3 is required; no guard downgrade is permitted"
    );
    Ok(abi as i64)
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
        pixel_width: 0,
        pixel_height: 0,
    }
}

fn fixed_child_diagnostic(case: Case, outcome: &WaitResult, errors: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "scope": "fixed_synthetic_private_environment_contributor_child",
        "case": case.argument(),
        "outcome": format!("{outcome:?}"),
        "captured_stderr_bytes": errors.len(),
        "truncated": errors.len() > DIAGNOSTIC_LIMIT,
        "stderr": String::from_utf8_lossy(&errors[..errors.len().min(DIAGNOSTIC_LIMIT)])
    })
}

fn fixed_pty_diagnostic(output: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "scope": "fixed_synthetic_private_environment_contributor_child",
        "case": "pty", "captured_output_bytes": output.len(),
        "truncated": output.len() > DIAGNOSTIC_LIMIT,
        "output": String::from_utf8_lossy(&output[..output.len().min(DIAGNOSTIC_LIMIT)])
    })
}

fn pty_group_evidence(output: &[u8]) -> Result<serde_json::Value> {
    let observations = output
        .split(|byte| *byte == b'\n')
        .filter_map(|line| line.strip_prefix(PTY_GROUP_MARKER))
        .map(|value| {
            serde_json::from_slice::<serde_json::Value>(value)
                .context("invalid fixed PTY group evidence")
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        observations.len() == PTY_PHASES.len(),
        "fixed PTY group evidence is incomplete"
    );
    for (observation, phase) in observations.iter().zip(PTY_PHASES) {
        ensure!(
            observation["phase"] == phase && observation["isatty"] == 1,
            "fixed PTY group phase differs"
        );
        let foreground = observation["foreground_pgrp"].as_i64().unwrap_or(0);
        let group = observation["process_pgrp"].as_i64().unwrap_or(0);
        ensure!(
            foreground > 0 && group > 0 && foreground == group,
            "fixed PTY evidence requires positive matching groups"
        );
    }
    Ok(serde_json::Value::Array(observations))
}

fn denied_errno<T>(result: io::Result<T>, allowed: &[i32], action: &str) -> Result<()> {
    match result {
        Err(error)
            if error
                .raw_os_error()
                .is_some_and(|code| allowed.contains(&code)) =>
        {
            Ok(())
        }
        _ => bail!("{action} did not return the required denial"),
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

fn text(path: &Path) -> Result<&str> {
    path.to_str().context("probe path is not UTF-8")
}

fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|part| part == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn implicit_pwd_is_only_the_exact_private_cwd() {
        let cwd = Path::new("/tmp/fixed-private/workspace");
        assert!(
            verify_implicit_pwd("PWD", OsStr::new("/tmp/fixed-private/workspace"), cwd).is_ok()
        );
        assert!(verify_implicit_pwd("PWD", OsStr::new("/tmp/other/workspace"), cwd).is_err());
        for key in ["SHLVL", "_", "DC_AXIS_INHERIT_CANARY"] {
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
    fn fixed_literal_argv_preserves_data_and_rejects_extra_arguments() {
        let argv = fixed_argv(Path::new("/tmp/probe with ' quotes"), Case::Argv);
        assert_eq!(argv[0], OsString::from("/tmp/probe with ' quotes"));
        assert_eq!(argv[1], OsString::from("--fixed-child"));
        assert_eq!(argv[2], OsString::from("argv"));
        assert_eq!(
            argv[3..].to_vec(),
            LITERAL_ARGUMENTS.map(OsString::from).to_vec()
        );
        assert_eq!(fixed_child_arguments(Case::Boundaries).len(), 2);
    }

    #[test]
    fn unrelated_errno_is_not_a_denial_success() {
        assert!(
            denied_errno::<()>(
                Err(io::Error::from_raw_os_error(libc::ENOENT)),
                &[libc::EACCES],
                "read"
            )
            .is_err()
        );
        assert!(denied_errno::<()>(Ok(()), &[libc::EACCES], "read").is_err());
        assert!(
            denied_errno::<()>(
                Err(io::Error::from_raw_os_error(libc::EACCES)),
                &[libc::EACCES],
                "read"
            )
            .is_ok()
        );
    }

    #[test]
    fn fixed_child_diagnostics_are_bounded_and_json_escaped() {
        let mut errors = vec![0; DIAGNOSTIC_LIMIT];
        errors.extend_from_slice(b"not-in-diagnostic");
        let diagnostic = fixed_child_diagnostic(Case::Boundaries, &WaitResult::Exited(1), &errors);
        assert_eq!(diagnostic["case"], "boundaries");
        assert_eq!(diagnostic["outcome"], "Exited(1)");
        assert_eq!(diagnostic["truncated"], true);
        assert_eq!(
            diagnostic["stderr"].as_str().unwrap().len(),
            DIAGNOSTIC_LIMIT
        );
        let encoded = diagnostic.to_string();
        assert!(encoded.contains("\\u0000"));
        assert!(!encoded.contains('\0'));
        assert!(!encoded.contains("not-in-diagnostic"));
        let pty = fixed_pty_diagnostic(&errors);
        assert_eq!(pty["truncated"], true);
        assert_eq!(pty["output"].as_str().unwrap().len(), DIAGNOSTIC_LIMIT);
        let encoded = pty.to_string();
        assert!(encoded.contains("\\u0000"));
        assert!(!encoded.contains('\0'));
        assert!(!encoded.contains("not-in-diagnostic"));
    }

    #[test]
    fn pty_group_evidence_refuses_zero_namespace_ids() {
        for (foreground, group, accepted) in [
            (7, 7, true),
            (0, 0, false),
            (0, 7, false),
            (7, 0, false),
            (7, 8, false),
            (-1, -1, false),
        ] {
            let output = PTY_PHASES
                .map(|phase| {
                    format!(
                        "PTY_GROUPS={}\r\n",
                        serde_json::json!({
                            "phase": phase, "isatty": 1,
                            "foreground_pgrp": foreground, "process_pgrp": group
                        })
                    )
                })
                .concat();
            assert_eq!(pty_group_evidence(output.as_bytes()).is_ok(), accepted);
        }
    }

    #[test]
    fn pty_group_records_require_a_line_boundary_after_terminal_echo() {
        let records = PTY_PHASES.map(|phase| {
            format!(
                "PTY_GROUPS={}\r\n",
                serde_json::json!({
                    "phase": phase, "isatty": 1,
                    "foreground_pgrp": 2, "process_pgrp": 2
                })
            )
        });
        // The real terminal echoed ^C immediately before the resized record.
        // Preserve strict record parsing: the fixed child must delimit its own
        // output rather than accepting arbitrary leading terminal data.
        let undelimited = format!("{}^C{}{}", records[0], records[1], records[2]);
        assert!(pty_group_evidence(undelimited.as_bytes()).is_err());
        let delimited = format!("{}^C\r\n{}{}", records[0], records[1], records[2]);
        assert!(pty_group_evidence(delimited.as_bytes()).is_ok());
    }

    #[test]
    fn fixed_sigint_requires_interrupt_mode_and_control_byte_three() {
        assert!(validate_interrupt_settings(libc::ISIG, 0x03).is_ok());
        assert!(validate_interrupt_settings(0, 0x03).is_err());
        assert!(validate_interrupt_settings(libc::ISIG, 0).is_err());
        assert!(validate_interrupt_settings(libc::ISIG, 0x04).is_err());
    }

    #[test]
    fn fixed_sigint_wait_cannot_succeed_without_observed_flag() {
        assert!(require_fixed_sigint(&AtomicBool::new(false), Duration::ZERO).is_err());
        assert!(require_fixed_sigint(&AtomicBool::new(true), Duration::ZERO).is_ok());
    }
}
