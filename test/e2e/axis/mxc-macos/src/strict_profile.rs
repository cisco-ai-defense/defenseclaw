// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//! Fixed contributor experiment only. This is not a general Seatbelt policy compiler.
//! MXC still owns sandbox_init, shell execution, PTY, timeout and process cleanup.

use anyhow::{Context, Result, ensure};
use axis_core::policy::{
    ChildProcessPolicy, Compatibility, GpuPolicy, InferencePolicy, NetworkMode, Policy,
    ProcessIdentity, RuntimeContainment, RuntimeProvider, SshPolicy,
};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const FIXED_POLICY_NAME: &str = "dc-mxc-macos-contributor";
const REQUIRED_SHELL_SELECTOR: &str = "/private/var/select/sh";
const REQUIRED_SHELL_TARGET: &str = "/bin/bash";
const REQUIRED_RUNTIME_READS: &[&str] = &[
    "/bin/sh",
    REQUIRED_SHELL_TARGET,
    "/usr/lib",
    "/System/Library",
];
const OPTIONAL_RUNTIME_READS: &[&str] = &["/private/var/db/dyld"];
const REQUIRED_RUNTIME_READWRITE: &[&str] = &["/dev/null"];
const REQUIRED_RUNTIME_READONLY: &[&str] = &["/dev/urandom"];

/// Exact, reviewed system paths required by this fixed Rust and `/bin/sh`
/// workload. No user-selected path or MXC-generated blanket system grant is
/// accepted here. An optional dyld cache location is included only if present.
pub fn runtime_read_paths() -> Result<Vec<String>> {
    let mut result = Vec::new();
    for path in REQUIRED_RUNTIME_READS {
        ensure!(
            Path::new(path).exists(),
            "required macOS runtime path is unavailable"
        );
        result.push((*path).into());
    }
    validate_fixed_shell_selector()?;
    result.push(REQUIRED_SHELL_SELECTOR.into());
    for path in OPTIONAL_RUNTIME_READS {
        if Path::new(path).exists() {
            result.push((*path).into());
        }
    }
    result.extend(REQUIRED_RUNTIME_READONLY.iter().map(|path| (*path).into()));
    Ok(result)
}

fn validate_fixed_shell_selector() -> Result<()> {
    let selector = Path::new(REQUIRED_SHELL_SELECTOR);
    let target = Path::new(REQUIRED_SHELL_TARGET);
    for path in [selector, target] {
        for ancestor in path.ancestors().skip(1) {
            let metadata =
                fs::symlink_metadata(ancestor).context("inspect fixed shell ancestor")?;
            ensure!(
                metadata.file_type().is_dir()
                    && metadata.uid() == 0
                    && metadata.mode() & 0o022 == 0,
                "fixed shell ancestor is not a root-owned nonwritable directory"
            );
        }
    }
    let selector_metadata =
        fs::symlink_metadata(selector).context("inspect fixed shell selector")?;
    ensure!(
        selector_metadata.file_type().is_symlink() && selector_metadata.uid() == 0,
        "fixed shell selector is not a root-owned symlink"
    );
    ensure!(
        fs::read_link(selector)
            .context("read fixed shell selector")?
            .as_path()
            == Path::new(REQUIRED_SHELL_TARGET),
        "fixed shell selector names an unreviewed target"
    );
    let target_metadata = fs::symlink_metadata(target).context("inspect fixed shell target")?;
    ensure!(
        target_metadata.file_type().is_file()
            && target_metadata.uid() == 0
            && target_metadata.mode() & 0o022 == 0
            && target_metadata.mode() & 0o005 == 0o005,
        "fixed shell target is not a root-owned ordinary readable executable"
    );
    ensure!(
        fs::canonicalize(selector)
            .context("canonicalize fixed shell selector")?
            .as_path()
            == target
            && fs::canonicalize(target)
                .context("canonicalize fixed shell target")?
                .as_path()
                == target,
        "fixed shell selector or target resolves through an unreviewed alias"
    );
    Ok(())
}

/// Compile only the owned fixture and the fixed runtime subset admitted by
/// AXIS. Paths are canonicalized and safely quoted, but a general provider
/// needs broader path-object and policy equivalence work.
pub fn build_profile(policy: &Policy, fixture_root: &Path, executable: &Path) -> Result<String> {
    policy.validate().context("validate fixed strict policy")?;
    ensure!(policy.version == 1, "strict probe policy version changed");
    ensure!(
        policy.name == FIXED_POLICY_NAME,
        "strict probe policy identity changed"
    );
    ensure!(
        policy.runtime.containment == RuntimeContainment::Process,
        "strict probe containment changed"
    );
    ensure!(
        policy.runtime.provider == RuntimeProvider::Mxc,
        "strict probe provider changed"
    );
    ensure!(
        policy.amd.is_none()
            && serde_json::to_value(&policy.inference)?
                == serde_json::to_value(InferencePolicy::default())?
            && serde_json::to_value(&policy.gpu)? == serde_json::to_value(GpuPolicy::default())?
            && serde_json::to_value(&policy.ssh)? == serde_json::to_value(SshPolicy::default())?,
        "strict probe received an unsupported feature policy"
    );
    ensure!(
        matches!(&policy.network.mode, NetworkMode::Block) && policy.network.policies.is_empty(),
        "strict probe requires blocked network without endpoint exceptions"
    );
    ensure!(
        matches!(
            &policy.filesystem.compatibility,
            Compatibility::HardRequirement
        ) && !policy.filesystem.workspace_read_only,
        "strict probe filesystem posture changed"
    );
    ensure!(
        policy.process.max_processes == 0
            && policy.process.effective_max_processes() == 0
            && policy.process.max_memory_mb == 0
            && policy.process.cpu_rate_percent == 0
            && policy.process.run_as_user.is_none()
            && policy.process.blocked_syscalls.is_empty()
            && policy.process.timeout_sec.is_none()
            && policy.process.identity == ProcessIdentity::BackendDefault
            && policy.process.child_processes == ChildProcessPolicy::Allow,
        "strict probe received unsupported process requirements"
    );
    let root = fs::canonicalize(fixture_root).context("canonicalize owned fixture")?;
    ensure!(root.is_dir(), "strict fixture root is not a directory");
    let exe = fs::canonicalize(executable).context("canonicalize probe executable")?;
    ensure!(exe.is_file(), "probe executable is not a regular file");
    let owned_rw = [root.join("work"), root.join("home"), root.join("tmp")]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let owned_ro = [root.join("work/readonly")]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let owned_deny = [root.join("work/denied"), root.join("home/denied")]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let runtime_read_raw = runtime_read_paths()?;
    let runtime_ro = runtime_read_raw
        .iter()
        .map(|path| canonical_system_path(path))
        .collect::<Result<BTreeSet<_>>>()?;
    let runtime_rw = REQUIRED_RUNTIME_READWRITE
        .iter()
        .map(|path| canonical_system_path(path))
        .collect::<Result<BTreeSet<_>>>()?;
    let expected_readonly_raw = runtime_read_raw
        .into_iter()
        .chain(
            owned_ro
                .iter()
                .chain([&exe])
                .map(|path| policy_path_text(path))
                .collect::<Result<Vec<_>>>()?,
        )
        .collect::<BTreeSet<_>>();
    let expected_readwrite_raw = owned_rw
        .iter()
        .map(|path| policy_path_text(path))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .chain(
            REQUIRED_RUNTIME_READWRITE
                .iter()
                .map(|path| (*path).to_owned()),
        )
        .collect::<BTreeSet<_>>();
    let expected_deny_raw = owned_deny
        .iter()
        .map(|path| policy_path_text(path))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        policy.filesystem.read_only.len() == expected_readonly_raw.len()
            && policy
                .filesystem
                .read_only
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                == expected_readonly_raw,
        "strict probe read list differs from the fixed source paths"
    );
    ensure!(
        policy.filesystem.read_write.len() == expected_readwrite_raw.len()
            && policy
                .filesystem
                .read_write
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                == expected_readwrite_raw,
        "strict probe write list differs from the fixed source paths"
    );
    ensure!(
        policy.filesystem.deny.len() == expected_deny_raw.len()
            && policy
                .filesystem
                .deny
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                == expected_deny_raw,
        "strict probe deny list differs from the fixed source paths"
    );

    let mut readonly = BTreeSet::new();
    let mut readwrite = BTreeSet::new();
    let mut denied = BTreeSet::new();
    for raw in &policy.filesystem.read_only {
        let path = canonical_policy_path(raw, &root)?;
        ensure!(
            path == exe || owned_ro.contains(&path) || runtime_ro.contains(&path),
            "strict probe read grant is outside its fixed footprint"
        );
        readonly.insert(path);
    }
    for raw in &policy.filesystem.read_write {
        let path = canonical_policy_path(raw, &root)?;
        ensure!(
            owned_rw.contains(&path) || runtime_rw.contains(&path),
            "strict probe write grant is outside its fixed footprint"
        );
        readwrite.insert(path);
    }
    for raw in &policy.filesystem.deny {
        let path = canonical_policy_path(raw, &root)?;
        ensure!(
            owned_deny.contains(&path),
            "strict probe deny path is outside its fixed footprint"
        );
        denied.insert(path);
    }
    ensure!(
        readwrite
            == owned_rw
                .union(&runtime_rw)
                .cloned()
                .collect::<BTreeSet<_>>(),
        "strict probe is missing an owned write directory or exact runtime device"
    );
    ensure!(
        readonly
            == runtime_ro
                .union(&owned_ro)
                .cloned()
                .chain([exe.clone()])
                .collect::<BTreeSet<_>>(),
        "strict probe is missing an owned read file, executable or runtime read path"
    );
    ensure!(
        denied == owned_deny,
        "strict probe is missing a denied canary"
    );

    let mut profile = String::from("(version 1)\n(deny default)\n");
    profile.push_str("(allow process-fork)\n(allow process-exec)\n");
    profile.push_str("(allow signal (target same-sandbox))\n(allow sysctl-read)\n");
    // `/` data is an exact literal needed by the loader; there is no subtree
    // read grant and no unfiltered metadata grant.
    profile.push_str("(allow file-read-data (literal \"/\"))\n");
    let mut metadata = BTreeSet::from([PathBuf::from("/")]);
    for path in readonly.iter().chain(readwrite.iter()).chain(denied.iter()) {
        for ancestor in path.ancestors().skip(1) {
            metadata.insert(ancestor.to_path_buf());
        }
    }
    // The fixed selector is a symlink. It needs exact metadata access on the
    // link and its ancestors in addition to read access on the selected shell.
    metadata.extend(
        Path::new(REQUIRED_SHELL_SELECTOR)
            .ancestors()
            .map(Path::to_path_buf),
    );
    for path in metadata {
        writeln!(
            profile,
            "(allow file-read-metadata (literal {}))",
            path_literal(&path)?
        )?;
    }
    for path in readonly {
        let kind = if path.is_dir() { "subpath" } else { "literal" };
        writeln!(
            profile,
            "(allow file-read* ({kind} {}))",
            path_literal(&path)?
        )?;
    }
    writeln!(
        profile,
        "(allow file-read* (literal {}))",
        scheme_literal(REQUIRED_SHELL_SELECTOR)?
    )?;
    for path in readwrite {
        let kind = if path.is_dir() { "subpath" } else { "literal" };
        writeln!(
            profile,
            "(allow file-read* file-write* ({kind} {}))",
            path_literal(&path)?
        )?;
    }
    // The outer MXC PTY uses a host-selected /dev/ttysNNN node. This is the
    // only regex in the profile; it cannot name a general filesystem subtree.
    profile.push_str("(allow file-read* file-write* file-ioctl\n");
    profile.push_str("    (literal \"/dev/tty\")\n    (regex #\"^/dev/ttys[0-9]+$\"))\n");
    profile.push_str("(deny network-bind network-outbound)\n");
    for path in &owned_ro {
        writeln!(
            profile,
            "(deny file-write* (literal {}))",
            path_literal(path)?
        )?;
    }
    for path in denied {
        writeln!(
            profile,
            "(deny file-read* file-read-metadata file-write* (literal {}))",
            path_literal(&path)?
        )?;
    }
    Ok(profile)
}

fn canonical_system_path(raw: &str) -> Result<PathBuf> {
    validate_path_text(raw)?;
    fs::canonicalize(raw).with_context(|| "canonicalize fixed macOS runtime path")
}

fn canonical_policy_path(raw: &str, fixture_root: &Path) -> Result<PathBuf> {
    validate_path_text(raw)?;
    let path = fs::canonicalize(raw).context("canonicalize admitted policy path")?;
    if Path::new(raw).starts_with(fixture_root) {
        // A user-owned symlink could retarget between profile construction and
        // spawn; this fixed fixture refuses every alias instead of following it.
        ensure!(
            Path::new(raw) == path.as_path(),
            "owned fixture path contains a symlink or alias"
        );
    }
    Ok(path)
}

fn policy_path_text(path: &Path) -> Result<String> {
    Ok(path
        .to_str()
        .context("fixed policy path is not UTF-8")?
        .to_owned())
}

fn validate_path_text(raw: &str) -> Result<()> {
    ensure!(
        raw.starts_with('/'),
        "Seatbelt policy path must be absolute"
    );
    ensure!(
        !raw.chars().any(char::is_control),
        "Seatbelt policy path contains a control character"
    );
    ensure!(
        raw.split('/')
            .skip(1)
            .all(|part| !part.is_empty() && part != "." && part != ".."),
        "Seatbelt policy path contains an ambiguous component"
    );
    Ok(())
}

fn path_literal(path: &Path) -> Result<String> {
    scheme_literal(path.to_str().context("Seatbelt path is not UTF-8")?)
}

fn scheme_literal(raw: &str) -> Result<String> {
    ensure!(
        !raw.chars().any(char::is_control),
        "Seatbelt literal contains a control character"
    );
    let mut literal = String::with_capacity(raw.len() + 2);
    literal.push('"');
    for c in raw.chars() {
        match c {
            '\\' => literal.push_str("\\\\"),
            '"' => literal.push_str("\\\""),
            other => literal.push(other),
        }
    }
    literal.push('"');
    Ok(literal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn quotes_scheme_literals_and_rejects_controls() {
        assert_eq!(scheme_literal("a\\b\"c").unwrap(), "\"a\\\\b\\\"c\"");
        for bad in ["nul\0suffix", "line\nfeed", "tab\tvalue"] {
            assert!(scheme_literal(bad).is_err());
            assert!(validate_path_text(&format!("/tmp/{bad}")).is_err());
        }
        assert!(validate_path_text("/tmp/../etc").is_err());
        assert!(validate_path_text("/tmp//item").is_err());
        assert!(validate_path_text("relative/path").is_err());
    }

    #[test]
    fn rejects_owned_symlink_aliases() {
        let owned = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(owned.path()).unwrap();
        fs::create_dir(root.join("target")).unwrap();
        symlink(root.join("target"), root.join("alias")).unwrap();
        assert!(canonical_policy_path(root.join("alias").to_str().unwrap(), &root).is_err());
        symlink("/bin/sh", root.join("escape")).unwrap();
        assert!(canonical_policy_path(root.join("escape").to_str().unwrap(), &root).is_err());
    }

    #[test]
    fn profile_has_only_explicit_runtime_and_fixture_grants() {
        let owned = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(owned.path()).unwrap();
        for dir in ["work", "home", "tmp"] {
            fs::create_dir(root.join(dir)).unwrap();
        }
        for file in ["work/readonly", "work/denied", "home/denied", "probe"] {
            fs::write(root.join(file), b"synthetic\n").unwrap();
        }
        let mut policy = Policy::from_yaml(
            "\
version: 1
name: dc-mxc-macos-contributor
runtime: { containment: process, provider: mxc }
filesystem: { compatibility: hard_requirement }
process: { max_processes: 0, max_memory_mb: 0, cpu_rate_percent: 0 }
network: { mode: block }
",
        )
        .unwrap();
        policy.filesystem.read_only = runtime_read_paths().unwrap();
        policy.filesystem.read_only.extend(
            [root.join("probe"), root.join("work/readonly")]
                .iter()
                .map(|path| path.to_str().unwrap().to_owned()),
        );
        policy.filesystem.read_write = [root.join("work"), root.join("home"), root.join("tmp")]
            .iter()
            .map(|path| path.to_str().unwrap().to_owned())
            .collect();
        policy.filesystem.read_write.push("/dev/null".into());
        policy.filesystem.deny = [root.join("work/denied"), root.join("home/denied")]
            .iter()
            .map(|path| path.to_str().unwrap().to_owned())
            .collect();
        let profile = build_profile(&policy, &root, &root.join("probe")).unwrap();
        assert!(profile.starts_with("(version 1)\n(deny default)\n"));
        assert!(profile.contains("(deny network-bind network-outbound)"));
        assert!(profile.contains("(allow file-read-data (literal \"/\"))"));
        assert!(profile.contains("(allow file-read* (literal \"/private/var/select/sh\"))"));
        assert!(profile.contains("(allow file-read* (literal \"/bin/bash\"))"));
        assert!(!profile.contains("(allow file-read* (subpath \"/private/var/select/sh\"))"));
        assert!(!profile.contains("(allow file-read* (subpath \"/bin\"))"));
        assert!(profile.contains("(regex #\"^/dev/ttys[0-9]+$\")"));
        assert!(!profile.contains("(allow file-read* (subpath \"/\"))"));
        assert!(!profile.contains("(allow file-read-metadata)"));
        assert!(!profile.contains("(allow mach-lookup"));
        assert!(!profile.contains("(allow network"));
        assert!(!profile.contains("(subpath \"/private/etc\")"));
        assert!(!profile.contains("(subpath \"/dev/fd\")"));

        policy
            .filesystem
            .read_only
            .retain(|path| path != REQUIRED_SHELL_SELECTOR);
        assert!(build_profile(&policy, &root, &root.join("probe")).is_err());
        policy
            .filesystem
            .read_only
            .push(REQUIRED_SHELL_SELECTOR.into());
        policy
            .filesystem
            .read_only
            .retain(|path| path != REQUIRED_SHELL_TARGET);
        assert!(build_profile(&policy, &root, &root.join("probe")).is_err());
        policy
            .filesystem
            .read_only
            .push(REQUIRED_SHELL_TARGET.into());
        policy.filesystem.read_only.push("/private/etc".into());
        assert!(build_profile(&policy, &root, &root.join("probe")).is_err());
        policy.filesystem.read_only.pop();
        policy.filesystem.deny.pop();
        assert!(build_profile(&policy, &root, &root.join("probe")).is_err());
        policy
            .filesystem
            .deny
            .push(root.join("home/denied").to_str().unwrap().into());
        policy.network.mode = NetworkMode::Allow;
        assert!(build_profile(&policy, &root, &root.join("probe")).is_err());
    }
}
