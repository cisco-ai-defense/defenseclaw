# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Verify/extract the fixed contributor Windows bundle; never execute it."""

import argparse
import hashlib
import json
import pathlib
import subprocess
import urllib.request
import zipfile

AXIS = "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c"
MXC = "1736b48398c3fe4d1315b2311c0951cc893eb3ae"
PATCHES = [
    "0001-wxc-processcontainer-resource-limits.patch",
    "0002-wxc-job-list-resource-assignment.patch",
    "0003-axis-wfp-strict-proxy.patch",
]
BINARIES = {"axis.exe", "axisd.exe", "wxc-exec.exe"}
OPTIONAL_BINARIES = {"axis-ssh-proxy.exe", "axis-wfp-broker.exe"}


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def patch_targets(path):
    return {line.removeprefix("+++ b/") for line in path.read_text().splitlines() if line.startswith("+++ b/")}


def relative_file(root, name):
    path = pathlib.PurePosixPath(name)
    require(
        not path.is_absolute()
        and bool(path.parts)
        and all(part not in {".", ".."} for part in path.parts)
        and "\\" not in name
        and ":" not in name,
        "unsafe bundle path",
    )
    target = root.joinpath(*path.parts)
    require(target.resolve().is_relative_to(root.resolve()), "bundle path leaves extraction root")
    return target


def verify(
    artifact_dir,
    output,
    axis_source,
    workflow_commit,
    variant="baseline",
    reviewed_overlay=None,
    reviewed_axis_relay=None,
    reviewed_mxc_relay=None,
):
    platform = "windows" if variant == "baseline" else "windows-" + variant
    archive_name = f"axis-source-{platform}-x86_64-{AXIS}.zip"
    archive = artifact_dir / archive_name
    fields = (artifact_dir / f"{archive_name}.sha256").read_text(encoding="utf-8-sig").split()
    require(len(fields) == 2 and fields[1] == archive_name, "unexpected archive checksum entry")
    require(sha(archive) == fields[0], "Windows archive checksum mismatch")
    require(not output.exists(), "use a fresh extraction directory")
    with zipfile.ZipFile(archive) as bundle:
        require(len(bundle.infolist()) <= 64, "unexpected archive entry count")
        total = 0
        names = set()
        for member in bundle.infolist():
            require(member.filename not in names, "duplicate archive entry")
            names.add(member.filename)
            path = relative_file(output, member.filename)
            require(path.relative_to(output).parts[0] == archive_name[:-4], "unexpected payload root")
            require(member.file_size <= 128 * 1024 * 1024, "oversized archive member")
            require((member.external_attr >> 16) & 0o170000 != 0o120000, "archive symlink refused")
            total += member.file_size
        require(total <= 384 * 1024 * 1024, "oversized Windows payload")
        bundle.extractall(output)
    payload = output / archive_name[:-4]
    sums = {}
    for line in (payload / "SHA256SUMS").read_text(encoding="utf-8-sig").splitlines():
        digest, name = line.split("  ", 1)
        require(name not in sums and len(digest) == 64, "invalid checksum inventory")
        file = relative_file(payload, name)
        require(file.is_file() and sha(file) == digest, f"payload checksum mismatch: {name}")
        sums[name] = digest
    actual = {p.relative_to(payload).as_posix() for p in payload.rglob("*") if p.is_file()}
    require(actual == set(sums) | {"SHA256SUMS"}, "checksum inventory does not cover the exact payload")
    manifest = json.loads((payload / "BUILD.json").read_text(encoding="utf-8-sig"))
    require(
        manifest["purpose"] == "contributor_source_build_only" and manifest["support_certification"] is False,
        "unexpected build purpose",
    )
    require(
        manifest["axis_source"]["commit"] == AXIS and manifest["mxc_source"]["commit"] == MXC, "source commit mismatch"
    )
    require(manifest["build"]["workflow_commit"] == workflow_commit, "workflow source mismatch")
    require(manifest["build"]["toolchain"] == "1.95.0", "unexpected Rust toolchain")
    overlay = manifest["axis_source"].get("contributor_overlay")
    axis_relay = manifest["axis_source"].get("contributor_relay_overlay")
    mxc_relay = manifest["mxc_source"].get("contributor_relay_overlay")
    relay_overlays = None
    if variant == "baseline":
        require(
            manifest.get("variant", "baseline") == "baseline"
            and overlay is None
            and axis_relay is None
            and mxc_relay is None,
            "an overlaid build cannot be accepted as baseline",
        )
    else:
        require(manifest.get("variant") == variant, "exact inherited-console manifest variant required")
        require(reviewed_overlay is not None and reviewed_overlay.is_file(), "the locally reviewed overlay is required")
        require(
            overlay is not None
            and overlay["path"] == "AXIS_INHERITED_CONSOLE.patch"
            and overlay["kind"] == "windows_inherited_console_experiment",
            "unexpected inherited-console overlay contract",
        )
        require(
            sha(relative_file(payload, overlay["path"])) == overlay["sha256"] == sha(reviewed_overlay),
            "retained overlay differs from the locally reviewed patch",
        )
        axis_patch_files = [str(reviewed_overlay)]
        if variant == "inherited-console-relay":
            for entry, reviewed, name, targets in [
                (
                    axis_relay,
                    reviewed_axis_relay,
                    "AXIS_CONSOLE_CTRL_C_RELAY.patch",
                    {"crates/axis-sandbox/src/windows/mxc.rs"},
                ),
                (
                    mxc_relay,
                    reviewed_mxc_relay,
                    "MXC_CONSOLE_CTRL_C_RELAY.patch",
                    {"src/core/wxc/src/main.rs", "src/backends/appcontainer/common/src/sandbox_tracking.rs"},
                ),
            ]:
                require(
                    reviewed is not None and reviewed.is_file(),
                    "both locally reviewed Ctrl-C relay overlays are required",
                )
                require(
                    entry is not None
                    and entry["path"] == name
                    and entry["kind"] == "windows_console_ctrl_c_relay_experiment",
                    "unexpected Ctrl-C relay overlay contract",
                )
                require(
                    sha(relative_file(payload, name)) == entry["sha256"] == sha(reviewed),
                    "retained relay overlay differs from the locally reviewed patch",
                )
                require(patch_targets(reviewed) == targets, "unexpected relay patch source scope")
            relay_overlays = {"axis": axis_relay, "mxc": mxc_relay}
            axis_patch_files.append(str(reviewed_axis_relay))
        else:
            require(
                axis_relay is None and mxc_relay is None,
                "relay overlays cannot be accepted as the earlier inherited-console variant",
            )
        subprocess.run(["git", "-C", str(axis_source), "apply", "--check", *axis_patch_files], check=True)
    require(
        subprocess.check_output(["git", "-C", str(axis_source), "rev-parse", "HEAD"], text=True).strip() == AXIS,
        "review checkout is not the pinned AXIS source",
    )
    for name in ["Cargo.lock", "Cargo.toml", "rust-toolchain.toml", "LICENSE"]:
        require(
            sha(payload / "axis-source" / name) == sha(axis_source / name), f"AXIS source metadata mismatch: {name}"
        )
    require(
        sha(payload / "axis-source/Cargo.lock") == manifest["axis_source"]["cargo_lock_sha256"],
        "AXIS lock manifest mismatch",
    )
    require(
        sha(payload / "axis-source/rust-toolchain.toml") == manifest["axis_source"]["toolchain_file_sha256"],
        "toolchain manifest mismatch",
    )
    require(sha(payload / "TOOLCHAIN.txt") == manifest["build"]["toolchain_output_sha256"], "toolchain output mismatch")
    require(
        "rustc 1.95.0 " in (payload / "TOOLCHAIN.txt").read_text(encoding="utf-8-sig"),
        "compiler output is not Rust 1.95.0",
    )
    mxc_source_files = []
    for name in ["src/Cargo.lock", "LICENSE.md"]:
        with urllib.request.urlopen(
            f"https://raw.githubusercontent.com/microsoft/mxc/{MXC}/{name}", timeout=30
        ) as response:
            reference = response.read(4 * 1024 * 1024 + 1)
        require(len(reference) <= 4 * 1024 * 1024, "oversized MXC source reference")
        file = payload / "mxc-source" / pathlib.PurePosixPath(name).name
        # Windows Git may check these text blobs out as CRLF. Preserve and
        # verify the exact packaged digest, and independently require byte
        # equality with the pinned Git blob after only CRLF normalization.
        require(
            file.read_bytes().replace(b"\r\n", b"\n") == reference.replace(b"\r\n", b"\n"),
            f"MXC source metadata mismatch: {name}",
        )
        mxc_source_files.append(
            {
                "path": name,
                "packaged_sha256": sha(file),
                "git_blob_sha256": hashlib.sha256(reference).hexdigest(),
                "comparison": "exact_after_CRLF_to_LF_only",
            }
        )
    require(
        sha(payload / "mxc-source/Cargo.lock") == manifest["mxc_source"]["cargo_lock_sha256"],
        "MXC lock manifest mismatch",
    )
    patch_entries = manifest["mxc_source"]["patches"]
    require([pathlib.PurePosixPath(p["path"]).name for p in patch_entries] == PATCHES, "unexpected patch inventory")
    for entry in patch_entries:
        file = relative_file(payload, entry["path"])
        require(
            sha(file) == entry["sha256"] == sha(axis_source / "third_party/mxc/patches" / file.name),
            f"reviewed patch mismatch: {file.name}",
        )
    binaries = manifest["binaries"]
    names = [pathlib.PurePosixPath(entry["path"]).name for entry in binaries]
    require(
        len(names) == len(set(names)) and BINARIES <= set(names) <= BINARIES | OPTIONAL_BINARIES,
        "unexpected binary inventory",
    )
    require({p.name for p in (payload / "bin").iterdir()} == set(names), "unlisted binary present")
    for entry in binaries:
        require(entry["path"] == "bin/" + pathlib.PurePosixPath(entry["path"]).name, "binary outside bin directory")
        file = relative_file(payload, entry["path"])
        require(
            file.stat().st_size == entry["size_bytes"] and sha(file) == entry["sha256"],
            f"binary digest mismatch: {file.name}",
        )
    return {
        "verified": True,
        "variant": variant,
        "contributor_overlay": overlay,
        "contributor_relay_overlays": relay_overlays,
        "payload": str(payload),
        "archive_sha256": sha(archive),
        "workflow_commit": workflow_commit,
        "axis_commit": AXIS,
        "mxc_commit": MXC,
        "mxc_source_files": mxc_source_files,
        "binaries": binaries,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=pathlib.Path, required=True)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    parser.add_argument("--axis-source", type=pathlib.Path, required=True)
    parser.add_argument("--workflow-commit", required=True)
    parser.add_argument(
        "--variant", choices=["baseline", "inherited-console", "inherited-console-relay"], default="baseline"
    )
    parser.add_argument("--reviewed-overlay", type=pathlib.Path)
    parser.add_argument("--reviewed-axis-relay", type=pathlib.Path)
    parser.add_argument("--reviewed-mxc-relay", type=pathlib.Path)
    args = parser.parse_args()
    print(
        json.dumps(
            verify(
                args.artifact_dir.resolve(),
                args.output_dir.resolve(),
                args.axis_source.resolve(),
                args.workflow_commit,
                args.variant,
                args.reviewed_overlay.resolve() if args.reviewed_overlay else None,
                args.reviewed_axis_relay.resolve() if args.reviewed_axis_relay else None,
                args.reviewed_mxc_relay.resolve() if args.reviewed_mxc_relay else None,
            ),
            indent=2,
        )
    )
