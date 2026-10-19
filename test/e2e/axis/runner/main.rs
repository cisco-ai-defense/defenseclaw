// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! Contributor-only example overlay for the exact pinned AXIS workspace.
//! Build with that workspace's unchanged Cargo.lock; do not activate in a product.

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("AXIS native offline probe requires Linux; no workload executed");
    std::process::ExitCode::from(2)
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    match linux::main() {
        Ok(code) => std::process::ExitCode::from(code),
        Err(error) => {
            eprintln!("AXIS_NATIVE_OFFLINE_FAILED: {error:#}");
            std::process::ExitCode::from(2)
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{Context, Result, bail, ensure};
    use axis_core::policy::Policy;
    use axis_core::types::SandboxId;
    use axis_sandbox::{Sandbox, SandboxConfig};
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};

    const SOURCE_COMMIT: &str = "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c";
    const OUTPUT_LIMIT: u64 = 64 * 1024;
    const ENV_KEYS: [&str; 8] = [
        "HOME",
        "PATH",
        "LANG",
        "TERM",
        "TMPDIR",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
    ];

    pub fn main() -> Result<u8> {
        let args: Vec<String> = std::env::args().collect();
        if args.get(1).map(String::as_str) == Some("--payload") {
            return payload(&args[2..]);
        }
        ensure!(
            args.len() == 1,
            "this fixed offline probe accepts no user options"
        );
        // SAFETY: geteuid has no preconditions and reads process identity only.
        ensure!(
            unsafe { libc::geteuid() } != 0,
            "use a disposable unprivileged Linux account"
        );
        let landlock_abi = require_landlock()?;
        let owned_root = tempfile::Builder::new()
            .prefix("dc-axis-native-")
            .tempdir()?;
        let paths = ProbePaths::new(owned_root.path())?;
        let executable = std::env::current_exe()?.canonicalize()?;

        let private_environment = paths.environment()?;
        let inherited_keys: Vec<_> = std::env::vars_os().map(|(key, _)| key).collect();
        // SAFETY: this synchronous entry point has not started any threads or a
        // Tokio runtime. AXIS preparation consults process environment as well
        // as child configuration, so replace both with the same private set.
        unsafe {
            for key in inherited_keys {
                std::env::remove_var(key);
            }
            for (key, value) in private_environment {
                std::env::set_var(key, value);
            }
        }
        std::env::set_current_dir(&paths.workspace)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            run_probe(&paths, &executable, "boundaries", 23, 10).await?;
            run_probe(&paths, &executable, "timeout", -1, 1).await
        })?;
        let removed_path = owned_root.path().to_owned();
        owned_root
            .close()
            .context("remove owned offline probe files")?;
        ensure!(!removed_path.exists(), "owned probe files survived cleanup");
        println!(
            "{}",
            serde_json::json!({
                "source_commit": SOURCE_COMMIT,
                "provider": "axis_native",
                "filesystem": "hard_requirement",
                "network": "block",
                "landlock_abi": landlock_abi,
                "checks": ["private_home_and_cwd", "file_read_denied_eacces", "file_write_denied_eacces",
                    "readonly_write_denied_eacces", "ipv4_ipv6_tcp_udp_socket_denied_eperm",
                    "child_exit_23", "configured_timeout", "tracked_child_stopped", "repeated_destroy", "owned_file_cleanup"],
                "scope": "benign_offline_probe_only",
                "claude_or_production_certification": false
            })
        );
        Ok(0)
    }

    fn require_landlock() -> Result<i64> {
        // SAFETY: the version query takes a null attr, zero length and the
        // documented VERSION flag. It creates no ruleset or host policy.
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
            "Landlock ABI >= 3 is required; no filesystem fallback is admitted"
        );
        Ok(abi as i64)
    }

    struct ProbePaths {
        home: PathBuf,
        workspace: PathBuf,
        temporary: PathBuf,
        readable: PathBuf,
        ungranted: PathBuf,
    }

    impl ProbePaths {
        fn new(root: &Path) -> Result<Self> {
            let paths = Self {
                home: root.join("home"),
                workspace: root.join("workspace"),
                temporary: root.join("tmp"),
                readable: root.join("readonly-probe.txt"),
                ungranted: root.join("ungranted"),
            };
            for directory in [
                &paths.home,
                &paths.workspace,
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
            write_new(&paths.readable, b"synthetic-readonly-probe\n")?;
            write_new(
                &paths.ungranted.join("sentinel.txt"),
                b"synthetic-ungranted-probe\n",
            )?;
            Ok(paths)
        }

        fn environment(&self) -> Result<Vec<(String, String)>> {
            Ok(vec![
                ("HOME".into(), utf8(&self.home)?.into()),
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("LANG".into(), "C".into()),
                ("TERM".into(), "dumb".into()),
                ("TMPDIR".into(), utf8(&self.temporary)?.into()),
                (
                    "XDG_CONFIG_HOME".into(),
                    utf8(&self.home.join(".config"))?.into(),
                ),
                (
                    "XDG_CACHE_HOME".into(),
                    utf8(&self.home.join(".cache"))?.into(),
                ),
                (
                    "XDG_DATA_HOME".into(),
                    utf8(&self.home.join(".local/share"))?.into(),
                ),
            ])
        }

        fn policy(&self, executable: &Path, name: &str, timeout: u64) -> Result<Policy> {
            let mut readonly = vec![executable.to_owned(), self.readable.clone()];
            for system in [
                "/usr",
                "/lib",
                "/lib64",
                "/bin",
                "/etc/ld.so.cache",
                "/dev/null",
            ] {
                if Path::new(system).exists() {
                    readonly.push(system.into());
                }
            }
            // JSON is a YAML subset and quotes every generated path. All policy
            // choices are fixed here; neither auto nor MXC can be selected.
            let value = serde_json::json!({
                "version": 1, "name": format!("dc-native-offline-{name}"),
                "runtime": {"containment": "process", "provider": "axis_native"},
                "filesystem": {"compatibility": "hard_requirement", "read_only": readonly,
                    "read_write": [&self.workspace, &self.home, &self.temporary]},
                "process": {"max_processes": 0, "max_memory_mb": 0, "cpu_rate_percent": 0,
                    "timeout_sec": timeout},
                "network": {"mode": "block"}
            });
            Policy::from_yaml(&serde_json::to_string(&value)?)
                .context("validate fixed native offline policy")
        }
    }

    async fn run_probe(
        paths: &ProbePaths,
        executable: &Path,
        kind: &str,
        expected_exit: i32,
        timeout: u64,
    ) -> Result<()> {
        let config = SandboxConfig {
            id: SandboxId::new(),
            policy: paths.policy(executable, kind, timeout)?,
            command: utf8(executable)?.into(),
            args: vec![
                "--payload".into(),
                kind.into(),
                utf8(&paths.workspace)?.into(),
                utf8(&paths.home)?.into(),
                utf8(&paths.temporary)?.into(),
                utf8(&paths.readable)?.into(),
                utf8(&paths.ungranted)?.into(),
            ],
            working_dir: Some(paths.workspace.clone()),
            workspace_dir: paths.workspace.clone(),
            env: paths.environment()?,
            proxy_port: 0,
            proxy_addr: None,
            connect_attribution: None,
            capture_output: true,
            interactive_terminal: false,
            pty_bridge_helper: None,
            timeout_sec: Some(timeout),
            backend_preflight: Default::default(),
            startup_trace: None,
        };
        let mut sandbox = Sandbox::create(config).context("native sandbox creation refused")?;
        if let Err(start_error) = sandbox.start() {
            let cleanup = sandbox.destroy();
            bail!("native sandbox launch refused: {start_error}; cleanup={cleanup:?}");
        }
        let tracked = if kind == "timeout" {
            let tracking = sandbox
                .pid
                .context("started sandbox omitted PID")
                .and_then(track_process);
            match tracking {
                Ok(process) => Some(process),
                Err(error) => {
                    let cleanup = sandbox.destroy();
                    bail!("could not track timeout workload: {error}; cleanup={cleanup:?}");
                }
            }
        } else {
            None
        };
        // Do not cancel this future: the upstream wait owns the child and its
        // configured timeout. External test runners must also bound this tool.
        let outcome = sandbox.wait().await;
        let cleanup = sandbox.destroy();
        let repeated_cleanup = sandbox.destroy();
        let code = outcome.context("native child wait failed")?;
        cleanup.context("native cleanup failed")?;
        repeated_cleanup.context("native repeated cleanup failed")?;
        ensure!(
            code == expected_exit,
            "{kind} child exit differed: expected {expected_exit}, observed {code}; diagnostics withheld"
        );
        let marker = if kind == "timeout" {
            "AXIS_NATIVE_TIMEOUT_READY\n"
        } else {
            "AXIS_NATIVE_BOUNDARIES_OK\n"
        };
        ensure!(
            read_bounded(&paths.workspace.join("stdout.log"))? == marker,
            "{kind} payload did not complete its required checks; diagnostics withheld"
        );
        ensure!(
            read_bounded(&paths.workspace.join("stderr.log"))?.is_empty(),
            "{kind} payload reported an error; diagnostics withheld"
        );
        if let Some(tracked) = tracked {
            ensure!(
                process_exited(&tracked)?,
                "tracked timeout workload survived wait/destroy"
            );
        }
        Ok(())
    }

    fn payload(args: &[String]) -> Result<u8> {
        ensure!(args.len() == 6, "invalid internal payload arguments");
        let workspace = Path::new(&args[1]);
        ensure!(
            std::env::current_dir()?.as_path() == workspace,
            "payload CWD differs"
        );
        ensure!(
            std::env::var_os("HOME").as_deref() == Some(Path::new(&args[2]).as_os_str()),
            "payload HOME differs"
        );
        ensure!(
            std::env::var_os("TMPDIR").as_deref() == Some(Path::new(&args[3]).as_os_str()),
            "payload temporary directory differs"
        );
        ensure!(
            std::env::vars_os()
                .all(|(key, _)| key.to_str().is_some_and(|key| ENV_KEYS.contains(&key))),
            "unexpected inherited environment key; diagnostics withheld"
        );
        if args[0] == "timeout" {
            println!("AXIS_NATIVE_TIMEOUT_READY");
            std::io::stdout().flush()?;
            loop {
                std::thread::park();
            }
        }
        ensure!(args[0] == "boundaries", "unknown internal payload");
        require_eacces(
            fs::read(Path::new(&args[5]).join("sentinel.txt")),
            "ungranted read",
        )?;
        require_eacces(
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(Path::new(&args[5]).join("must-not-exist.txt")),
            "ungranted write",
        )?;
        require_eacces(
            OpenOptions::new().append(true).open(&args[4]),
            "read-only write",
        )?;
        ensure!(
            fs::read(&args[4])? == b"synthetic-readonly-probe\n",
            "allowed read differs"
        );
        for domain in [libc::AF_INET, libc::AF_INET6] {
            for kind in [libc::SOCK_STREAM, libc::SOCK_DGRAM] {
                // SAFETY: socket() accepts these fixed domain/type values. No
                // bind, connect, DNS, send, or outbound packet is attempted.
                let fd = unsafe { libc::socket(domain, kind | libc::SOCK_CLOEXEC, 0) };
                if fd >= 0 {
                    // SAFETY: fd is the newly created socket owned here.
                    unsafe {
                        libc::close(fd);
                    }
                    bail!("IP socket creation was not denied");
                }
                ensure!(
                    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
                    "IP socket denial was not EPERM"
                );
            }
        }
        write_new(
            &workspace.join("allowed-probe.txt"),
            b"synthetic-workspace-probe\n",
        )?;
        write_new(
            &Path::new(&args[2]).join("allowed-state.txt"),
            b"synthetic-home-probe\n",
        )?;
        println!("AXIS_NATIVE_BOUNDARIES_OK");
        std::io::stdout().flush()?;
        Ok(23)
    }

    fn require_eacces<T>(outcome: std::io::Result<T>, stage: &str) -> Result<()> {
        match outcome {
            Err(error) if error.raw_os_error() == Some(libc::EACCES) => Ok(()),
            _ => bail!("{stage} did not fail with EACCES; diagnostics withheld"),
        }
    }

    fn write_new(path: &Path, content: &[u8]) -> Result<()> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?
            .write_all(content)?;
        Ok(())
    }

    fn read_bounded(path: &Path) -> Result<String> {
        let mut bytes = Vec::new();
        File::open(path)?
            .take(OUTPUT_LIMIT + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= OUTPUT_LIMIT,
            "probe output exceeded its limit"
        );
        String::from_utf8(bytes).context("probe output was not UTF-8")
    }

    fn utf8(path: &Path) -> Result<&str> {
        path.to_str().context("probe paths must be UTF-8")
    }

    fn track_process(pid: u32) -> Result<OwnedFd> {
        // SAFETY: pidfd_open with flags zero returns a new owned descriptor.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        ensure!(fd >= 0, "could not track timeout workload with pidfd");
        // SAFETY: the successful syscall returned a unique owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }

    fn process_exited(process: &OwnedFd) -> Result<bool> {
        let mut descriptor = libc::pollfd {
            fd: process.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd is provided; timeout zero only observes
        // the tracked process. No numeric PID or process group is signalled.
        let count = unsafe { libc::poll(&mut descriptor, 1, 0) };
        ensure!(count >= 0, "pidfd exit observation failed");
        Ok(count == 1 && descriptor.revents & libc::POLLIN != 0)
    }
}
