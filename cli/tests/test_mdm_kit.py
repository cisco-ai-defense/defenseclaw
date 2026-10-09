# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Contracts for the MDM deployment kit (packaging/mdm).

Each script ships as a standalone file an MDM uploads on its own, so shared
helpers are copied rather than sourced; these checks keep the copies
identical, keep the Windows Intune-facing scripts runnable in Windows
PowerShell 5.1, keep every result on the lifecycle-result schema, and check the
optional release signing helpers.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MDM = ROOT / "packaging" / "mdm"
SCHEMA = MDM / "contract" / "lifecycle-result.schema.json"
UNIX_SCRIPTS = ("defenseclaw-enterprise.sh", "detect.sh", "uninstall.sh")
WINDOWS_SHARED = (
    MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1",
    MDM / "windows" / "detect.ps1",
    MDM / "windows" / "uninstall.ps1",
    MDM / "intune" / "windows" / "Install-DefenseClawIntune.ps1",
    MDM / "intune" / "windows" / "Remediate-Detect.ps1",
    MDM / "intune" / "windows" / "Remediate-Fix.ps1",
)
# Scripts Intune runs inside its 32-bit Windows PowerShell 5.1 host.
WINDOWS_51 = [path for path in WINDOWS_SHARED if path.name != "Invoke-DefenseClawEnterprise.ps1"]
SHARED_BEGIN = "# region DefenseClaw MDM shared helpers"
SHARED_END = "# endregion DefenseClaw MDM shared helpers"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _shell_function(text: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}$", text, re.MULTILINE | re.DOTALL)
    if not match:
        match = re.search(rf"^{re.escape(name)}\(\) \{{[^\n]*\}}$", text, re.MULTILINE)
    assert match, f"{name} not found"
    return match.group(0)


def _schema_validator():
    jsonschema = pytest.importorskip("jsonschema")
    return jsonschema.Draft202012Validator(json.loads(_text(SCHEMA)))


def test_every_mdm_script_is_ascii() -> None:
    # Windows PowerShell 5.1 reads BOM-less files as the ANSI code page, and
    # MDM consoles show uploaded scripts; ASCII avoids both problems.
    for path in sorted(MDM.rglob("*")):
        if path.suffix in {".sh", ".ps1"}:
            data = path.read_bytes()
            assert all(byte < 0x80 for byte in data), f"{path.relative_to(ROOT)} has non-ASCII bytes"
            assert b"\r\n" not in data, f"{path.relative_to(ROOT)} has CRLF line endings"


def _shared_region(text: str) -> str:
    start = text.index(SHARED_BEGIN)
    end = text.index(SHARED_END) + len(SHARED_END)
    return text[start:end]


def test_copied_helpers_are_identical() -> None:
    for name in UNIX_SCRIPTS:
        linux = _text(MDM / "linux" / name).splitlines()
        macos = _text(MDM / "macos" / name).splitlines()
        assert len(linux) == len(macos), name
        assert [(a, b) for a, b in zip(linux, macos) if a != b] == [(
            "DC_SCRIPT_OS=linux # linux | darwin - the only line that differs between the copies",
            "DC_SCRIPT_OS=darwin # linux | darwin - the only line that differs between the copies",
        )], name
    scripts = {name: _text(MDM / "linux" / name) for name in UNIX_SCRIPTS}
    for function in ("dc_platform", "dc_stat_uid", "dc_stat_mode", "dc_trusted_path"):
        assert len({_shell_function(text, function) for text in scripts.values()}) == 1, function
    for function in ("dc_json_escape", "dc_log", "dc_busy_output"):
        wrapper = _shell_function(scripts["defenseclaw-enterprise.sh"], function)
        assert wrapper == _shell_function(scripts["uninstall.sh"], function), function
    canonical = _shared_region(_text(MDM / "windows" / "detect.ps1"))
    drifted = [path.name for path in WINDOWS_SHARED if _shared_region(_text(path)) != canonical]
    assert not drifted, f"copy the shared region from packaging/mdm/windows/detect.ps1 into {drifted}"


def test_intune_entrypoints_refuse_constrained_language_before_native_helpers() -> None:
    entrypoints = {
        MDM / "intune" / "windows" / "Install-DefenseClawIntune.ps1": "1603",
        MDM / "windows" / "detect.ps1": "1",
        MDM / "intune" / "windows" / "Remediate-Detect.ps1": "1",
    }
    for path, exit_code in entrypoints.items():
        entry = _text(path).split("# region DefenseClaw MDM shared helpers", 1)[0]
        guard = "if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {"
        assert guard in entry, path
        assert entry.index(guard) < entry.index("Set-StrictMode"), path
        assert f"exit {exit_code}" in entry.split(guard, 1)[1], path


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize("os_dir", ["linux", "macos"])
@pytest.mark.parametrize("name", UNIX_SCRIPTS)
def test_unix_scripts_parse_and_lint(os_dir: str, name: str) -> None:
    path = MDM / os_dir / name
    assert os.access(path, os.X_OK), f"{path} must be executable"
    assert _text(path).startswith("#!/bin/sh\n")
    for shell in ("sh", "dash", "bash"):
        if shutil.which(shell):
            subprocess.run([shell, "-n", str(path)], check=True)
    if shutil.which("shellcheck"):
        subprocess.run(["shellcheck", "-s", "sh", "-S", "warning", str(path)], check=True)


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize("os_dir", ["linux", "macos"])
def test_same_version_package_reinstalls_when_a_required_binary_is_damaged(tmp_path: Path, os_dir: str) -> None:
    wrapper = _text(MDM / os_dir / "defenseclaw-enterprise.sh")
    check = _shell_function(wrapper, "dc_binaries_damaged")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    names = ("defenseclaw-gateway", "defenseclaw-hook", "defenseclaw-sensor-helper")
    for name in names:
        (bin_dir / name).write_bytes(b"binary")
    for name in names:
        path = bin_dir / name
        for damaged in (None, b""):
            path.unlink()
            if damaged is not None:
                path.write_bytes(damaged)
            script = f"DC_GATEWAY='{bin_dir / 'defenseclaw-gateway'}'\n{check}\ndc_binaries_damaged"
            result = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=10)
            assert result.returncode == 0, (os_dir, name, damaged, result.stderr)
            path.write_bytes(b"binary")
    result = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=10)
    assert result.returncode == 1, os_dir


def test_unix_wrapper_never_passes_credentials_on_the_command_line() -> None:
    text = _text(MDM / "linux" / "defenseclaw-enterprise.sh")
    assert 'enterprise secret set --name "$DC_SECRET_NAME" --from-stdin --lock-wait 10m --json >' in text
    # The value reaches the lifecycle through a pipe, never a staged file
    # that a killed run would leave behind (GAP-0632).
    assert "printf '%s' \"$secret_data\" |" in text
    assert '$DC_STAGE/secret"' not in text
    assert "--from-file" not in text
    # The inline-config block warns against credentials and there is no
    # inline-secret setting.
    assert "DC_SECRET_VALUE" not in text
    assert "Never put credentials here" in text


def _run(args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, input=stdin, capture_output=True, text=True, env={}, timeout=60)


def _host_os_dir() -> str:
    return "macos" if os.uname().sysname == "Darwin" else "linux"


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_wrapper_failures_are_schema_results() -> None:
    validator = _schema_validator()
    host = _host_os_dir()
    other = "linux" if host == "macos" else "macos"
    wrapper = str(MDM / host / "defenseclaw-enterprise.sh")
    cases = [
        ([wrapper, "--action", "bogus"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--source", "/nonexistent.deb"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--sha256", "xyz"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--config-stdin", "--secret-name", "k", "--secret-stdin"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--secret-name", "Bad_Name", "--secret-stdin"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--action", "status", "--config-stdin"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--source-url", "http://example.com/x.tar.gz", "--sha256", "0" * 64], 2 if os.geteuid() == 0 else 1, None),
        ([str(MDM / other / "defenseclaw-enterprise.sh")], 2, "mdm_wrong_platform"),
    ]
    if os.geteuid() != 0:
        cases.append(([wrapper], 1, "mdm_not_root"))
        cases.append(([str(MDM / host / "uninstall.sh")], 1, "mdm_not_root"))
    for args, code, error in cases:
        result = _run(args)
        assert result.returncode == code, (args, result.stdout, result.stderr)
        documents = [line for line in result.stdout.splitlines() if line.strip()]
        assert len(documents) == 1, (args, result.stdout)
        document = json.loads(documents[0])
        errors = sorted(validator.iter_errors(document), key=str)
        assert not errors, (args, [e.message for e in errors])
        assert document["exit_code"] == code
        assert document["platform"] == ("darwin" if host == "macos" else "linux") or error == "mdm_wrong_platform"
        if error:
            assert [e["code"] for e in document["errors"]] == [error], (args, document)


@pytest.mark.skipif(os.name != "posix", reason="POSIX file descriptors")
@pytest.mark.parametrize("name", UNIX_SCRIPTS)
def test_intune_repeated_file_descriptor_is_not_an_argument(name: str) -> None:
    path = MDM / _host_os_dir() / name
    descriptor = os.open(path, os.O_RDONLY)
    try:
        script = f"/proc/self/fd/{descriptor}"
        result = subprocess.run(["sh", script, script], pass_fds=(descriptor,), capture_output=True, text=True, timeout=30)
    finally:
        os.close(descriptor)
    assert "unknown argument" not in result.stderr + result.stdout


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize("os_dir", ["linux", "macos"])
def test_unix_wrapper_creates_a_traversable_log_directory(os_dir: str, tmp_path: Path) -> None:
    # The wrapper runs under umask 077. On macOS its log parent
    # /Library/Logs/Cisco also holds the gateway's own log, which launchd opens
    # as the service account; a 0700 parent kept the gateway from starting.
    layout = _shell_function(_text(MDM / os_dir / "defenseclaw-enterprise.sh"), "dc_layout")
    log = tmp_path / "Logs" / "Cisco" / "DefenseClaw" / "mdm-wrapper.log"
    script = f"umask 077\nDC_SCRIPT_OS=darwin\nDC_LOG='{log}'\n{layout}\ndc_layout\n"
    result = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    for directory in (log.parent.parent, log.parent):
        assert directory.stat().st_mode & 0o777 == 0o755, directory


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize(
    ("http", "code", "reason"),
    [(302, 0, "redirected (HTTP 302)"), (404, 22, "HTTP 404"), (0, 5, "proxy lookup failed (curl exit 5)")],
)
def test_unix_download_reports_status_without_url_query(
    http: int, code: int, reason: str, tmp_path: Path
) -> None:
    curl = tmp_path / "curl"
    curl.write_text(
        "#!/bin/sh\n"
        "while [ \"$#\" -gt 0 ]; do\n"
        "  case \"$1\" in\n"
        "    -D) header=$2; shift 2 ;;\n"
        "    -o) output=$2; shift 2 ;;\n"
        "    *) shift ;;\n"
        "  esac\n"
        "done\n"
        "printf 'HTTP/2 %s\\n' \"$DC_TEST_HTTP\" >\"$header\"\n"
        ": >\"$output\"\n"
        "exit \"$DC_TEST_CODE\"\n",
        encoding="utf-8",
    )
    curl.chmod(0o755)
    download = _shell_function(_text(MDM / "linux" / "defenseclaw-enterprise.sh"), "dc_download")
    script = (
        f'DC_STAGE="{tmp_path}"\nDC_HTTPS_PROXY=""\n{download}\n'
        f'dc_download "https://example.test/a.deb?sig=private" "{tmp_path / "a.deb"}" '
        '|| printf "%s\\n" "$DC_DOWNLOAD_ERROR"\n'
    )
    env = {"PATH": f"{tmp_path}:/usr/bin:/bin", "DC_TEST_HTTP": str(http), "DC_TEST_CODE": str(code)}
    result = subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True, check=True)
    assert reason in result.stdout and "private" not in result.stdout + result.stderr


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_lifecycle_retries_only_busy(tmp_path: Path) -> None:
    retry = _shell_function(_text(MDM / "linux" / "defenseclaw-enterprise.sh"), "dc_run_lifecycle_retry")
    script = f'''DC_TEST_COUNT="{tmp_path / "count"}"
dc_log() {{ :; }}
sleep() {{ :; }}
dc_run_lifecycle() {{
    count=$(cat "$DC_TEST_COUNT" 2>/dev/null || echo 0)
    count=$((count + 1))
    echo "$count" >"$DC_TEST_COUNT"
    [ "$count" -ge 2 ] || return 75
}}
{retry}
dc_run_lifecycle_retry ignored
'''
    result = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
    assert result.returncode == 0 and (tmp_path / "count").read_text().strip() == "2"


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_detect_busy_is_a_retry_signal() -> None:
    report = _shell_function(_text(MDM / "linux" / "detect.sh"), "dc_report")
    result = subprocess.run(["sh", "-c", f'DC_FORMAT=exit\n{report}\ndc_report 0 busy busy'], capture_output=True, text=True)
    assert result.returncode == 75 and "busy" in result.stderr


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_detect_reports_an_interrupted_package_unhealthy(tmp_path: Path) -> None:
    # A power loss in the postinst left dpkg half-configured while the
    # services ran, and detect --require-healthy still reported healthy, so
    # Intune never ran the wrapper and apt stayed blocked (GAP-0930).
    check = _shell_function(_text(MDM / "linux" / "detect.sh"), "dc_package_interrupted")
    stub = tmp_path / "dpkg-query"
    stub.write_text('#!/bin/sh\nprintf "%s" "$DC_TEST_STATUS"\n', encoding="utf-8")
    stub.chmod(0o755)
    for status, interrupted in (("install ok half-configured", True), ("install ok installed", False)):
        env = {"PATH": f"{tmp_path}:/usr/bin:/bin", "DC_TEST_STATUS": status}
        result = subprocess.run(
            ["sh", "-c", f"DC_SCRIPT_OS=linux\n{check}\ndc_package_interrupted"], capture_output=True, text=True, env=env
        )
        assert result.returncode == 0 and ("half-configured" in result.stdout) == interrupted, (status, result.stdout)


_PACKAGE_TOOL_STUBS = {
    # Each stub answers the queries dc_install_package makes and records any
    # install in $DC_TEST_LOG.
    "dpkg-deb": """case "$3" in Package) echo defenseclaw-enterprise ;; Version) echo "$DC_TEST_VERSION" ;; Architecture) echo amd64 ;; esac""",
    "dpkg": """case "$1" in --print-architecture) echo amd64 ;; -i) echo "dpkg -i" >>"$DC_TEST_LOG" ;; esac""",
    "dpkg-query": "exit 1",
    "rpm": """case "$1" in
    -qp) case "$3" in *NAME*) echo defenseclaw-enterprise ;; *) echo "$DC_TEST_VERSION" ;; esac ;;
    -q) exit 1 ;;
    -U) echo "rpm -U" >>"$DC_TEST_LOG" ;;
esac""",
    "pkgutil": """case "$1" in
    --expand) mkdir -p "$3" && printf '<pkg-ref id="com.cisco.defenseclaw.enterprise" version="%s" onConclusion="none">x.pkg</pkg-ref>\\n' "$DC_TEST_VERSION" >"$3/Distribution" ;;
    *) exit 1 ;;
esac""",
    "installer": 'echo "installer -pkg" >>"$DC_TEST_LOG"',
}


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize(
    ("source", "package_version", "pin", "installs"),
    [
        ("defenseclaw-enterprise.deb", "1.5.0", "1.4.0", False),
        ("defenseclaw-enterprise.deb", "1.4.0", "v1.4.0", True),
        ("defenseclaw-enterprise.deb", "1:1.4.0~rc1-1", "1.4.0-rc1", True),
        ("defenseclaw-enterprise.deb", "1.0.901~SNAPSHOT-d03042625", "1.0.901-SNAPSHOT-d03042625", True),
        ("defenseclaw-enterprise.deb", "1.4.0~rc1", "1.4.0", False),
        ("defenseclaw-enterprise.rpm", "1.5.0-1", "1.4.0", False),
        ("defenseclaw-enterprise.rpm", "1.4.0~rc1-1", "1.4.0-rc1", True),
        ("defenseclaw-enterprise.pkg", "1.5.0", "1.4.0", False),
        ("defenseclaw-enterprise.pkg", "1.4.0-rc1", "1.4.0", False),
        ("defenseclaw-enterprise.pkg", "1.4.0", "1.4.0", True),
        ("defenseclaw-enterprise.deb", "1.5.0", "", True),
    ],
)
def test_unix_wrapper_checks_the_product_version_before_the_package_manager(
    source: str, package_version: str, pin: str, installs: bool, tmp_path: Path
) -> None:
    # The package's maintainer scripts apply the deployment as soon as the
    # package manager installs it, so a --product-version mismatch must stop
    # the wrapper before dpkg, rpm or installer runs.
    text = _text(MDM / "linux" / "defenseclaw-enterprise.sh")
    functions = "\n".join(
        _shell_function(text, name)
        for name in ("dc_busy_output", "dc_require_product_version", "dc_package_release_version", "dc_install_package")
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in _PACKAGE_TOOL_STUBS.items():
        stub = bin_dir / name
        stub.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
        stub.chmod(0o755)
    log = tmp_path / "install.log"
    script = f"""
DC_SCRIPT_OS={"darwin" if source.endswith(".pkg") else "linux"}
DC_EXIT_FAILURE=1 DC_EXIT_INVALID=2 DC_EXIT_BUSY=75
DC_LINUX_PACKAGE=defenseclaw-enterprise DC_MACOS_PACKAGE_ID=com.cisco.defenseclaw.enterprise
DC_PRODUCT_VERSION='{pin}' DC_STAGE='{tmp_path}' DC_STAGED_SOURCE='{tmp_path / source}'
dc_fail_result() {{ echo "FAIL $2: $3"; exit "$1"; }}
dc_log() {{ :; }}
dc_extract_payload() {{ :; }}
{functions}
dc_install_package
echo installed-ok
"""
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "DC_TEST_VERSION": package_version, "DC_TEST_LOG": str(log)}
    for shell in ("sh", "bash"):
        if log.exists():
            log.unlink()
        result = subprocess.run([shell, "-c", script], env=env, capture_output=True, text=True, timeout=30)
        if installs:
            assert result.returncode == 0 and "installed-ok" in result.stdout, (shell, result.stdout, result.stderr)
            assert log.exists(), (shell, "the package manager did not run")
        else:
            assert result.returncode == 1, (shell, result.stdout, result.stderr)
            assert "FAIL mdm_version_mismatch" in result.stdout, (shell, result.stdout)
            assert not log.exists(), (shell, "the package manager ran before the version check", log.read_text())


# GAP-0752: on a CIS host (/tmp and /var/tmp noexec) the payload's gateway
# could not run from the wrapper's /var/tmp staging folder, and the result was
# mdm_lifecycle_no_result with the shell's "Permission denied". The wrapper
# now stages in a root-only folder of its own and names a noexec mount.
@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_wrapper_names_a_noexec_staging_mount(tmp_path: Path) -> None:
    text = _text(MDM / "linux" / "defenseclaw-enterprise.sh")
    assert "DC_STAGE_PARENT=/var/lib/defenseclaw-mdm" in text
    functions = "\n".join(_shell_function(text, name) for name in ("dc_noexec_mount", "dc_extract_payload"))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    findmnt = bin_dir / "findmnt"
    findmnt.write_text("#!/bin/sh\necho '/var/tmp rw,nosuid,nodev,noexec,relatime'\n", encoding="utf-8")
    findmnt.chmod(0o755)
    source = tmp_path / "src"
    source.mkdir()
    gateway = source / "defenseclaw-gateway"
    gateway.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    gateway.chmod(0o644)  # what a noexec mount makes of an executable
    archive = tmp_path / "payload.tar.gz"
    subprocess.run(["tar", "-czf", str(archive), "-C", str(source), "defenseclaw-gateway"], check=True)
    stage = tmp_path / "stage"
    stage.mkdir()
    script = f"""
DC_SCRIPT_OS=linux DC_EXIT_FAILURE=1 DC_STAGE='{stage}' DC_STAGED_SOURCE='{archive}'
dc_fail_result() {{ echo "FAIL $2: $3"; exit "$1"; }}
chown() {{ :; }}
{functions}
dc_extract_payload
echo extracted
"""
    result = subprocess.run(["sh", "-c", script], env={"PATH": f"{bin_dir}:/usr/bin:/bin"}, capture_output=True, text=True, timeout=30)
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert "FAIL mdm_staging_noexec" in result.stdout and "/var/tmp is mounted noexec" in result.stdout, result.stdout


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize("failure", ["disk_full", "downgrade"])
def test_macos_wrapper_names_why_the_package_step_failed(failure: str, tmp_path: Path) -> None:
    # The Installer only says "The upgrade failed": a full data volume is
    # refused before it runs (GAP-0539), and a refused downgrade reports the
    # result the preinstall wrote, naming both versions (GAP-0538).
    text = _text(MDM / "macos" / "defenseclaw-enterprise.sh")
    functions = "\n".join(
        _shell_function(text, name)
        for name in ("dc_busy_output", "dc_require_product_version", "dc_require_free_space",
                     "dc_package_script_result", "dc_install_package")
    )
    stubs = dict(_PACKAGE_TOOL_STUBS)
    stubs["pkgutil"] = """case "$1" in
    --expand) mkdir -p "$3/x.pkg" && printf '<pkg-ref id="com.cisco.defenseclaw.enterprise" version="1.0.2" onConclusion="none">x.pkg</pkg-ref>\\n' >"$3/Distribution"
        echo '<payload numberOfFiles="4" installKBytes="300000"/>' >"$3/x.pkg/PackageInfo" ;;
    *) exit 1 ;;
esac"""
    stubs["df"] = 'printf "Filesystem 1024-blocks Used Available Capacity Mounted\\n/dev/disk3 9000000 8000000 %s 90%% /\\n" "$DC_TEST_FREE"'
    stubs["installer"] = """echo "installer -pkg" >>"$DC_TEST_LOG"
printf '{"ok":false,"errors":[{"code":"downgrade_refused","message":"DefenseClaw 1.0.3 is installed; refusing to downgrade to 1.0.2"}]}\\n' >"$DC_TEST_RESULT"
echo "installer: The upgrade failed."
exit 1"""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in stubs.items():
        stub = bin_dir / name
        stub.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
        stub.chmod(0o755)
    log, result_file = tmp_path / "install.log", tmp_path / "last-package-result.json"
    script = f"""
DC_SCRIPT_OS=darwin
DC_EXIT_FAILURE=1 DC_EXIT_INVALID=2 DC_EXIT_BUSY=75
DC_LINUX_PACKAGE=defenseclaw-enterprise DC_MACOS_PACKAGE_ID=com.cisco.defenseclaw.enterprise
DC_PRODUCT_VERSION='' DC_STAGE='{tmp_path}' DC_STAGED_SOURCE='{tmp_path / "defenseclaw-enterprise.pkg"}'
DC_INSTALL_ROOT='{tmp_path / "opt" / "cisco" / "defenseclaw"}' DC_PACKAGE_RESULT='{result_file}' DC_RESULT=''
dc_fail_result() {{ echo "FAIL $2: $3"; exit "$1"; }}
dc_log() {{ :; }}
dc_extract_payload() {{ :; }}
dc_emit_result() {{ cat "$DC_RESULT"; }}
{functions}
dc_install_package
echo installed-ok
"""
    free = "150000" if failure == "disk_full" else "9000000"
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "DC_TEST_FREE": free, "DC_TEST_LOG": str(log),
           "DC_TEST_RESULT": str(result_file)}
    result = subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 1, (result.stdout, result.stderr)
    if failure == "disk_full":
        assert "FAIL mdm_disk_full" in result.stdout and "MB is free" in result.stdout, result.stdout
        assert not log.exists(), "the installer ran on a full volume"
    else:
        assert "downgrade_refused" in result.stdout and "refusing to downgrade to 1.0.2" in result.stdout, result.stdout


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_detect_formats_without_an_installation() -> None:
    if os.geteuid() == 0 and Path("/opt/defenseclaw/bin/defenseclaw-gateway").exists():
        pytest.skip("a deployment is installed on this host")
    detect = str(MDM / _host_os_dir() / "detect.sh")
    result = _run([detect])
    assert result.returncode == 1 and result.stdout == ""
    value = "not-installed" if os.geteuid() == 0 else "unknown"
    assert _run([detect, "--format", "value"]).stdout == f"{value}\n"
    assert _run([detect, "--format", "jamf"]).stdout == f"<result>{value}</result>\n"
    assert _run([detect, "--format", "yaml"]).returncode == 2


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_detect_rejects_malformed_minimum_version() -> None:
    detect = str(MDM / _host_os_dir() / "detect.sh")
    for value in ("", "abc", "1.x.0"):
        result = _run([detect, "--min-version", value])
        assert result.returncode == 2 and not result.stdout


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="requires a standard user")
def test_unix_detect_standard_user_reports_unknown() -> None:
    detect = str(MDM / _host_os_dir() / "detect.sh")
    assert _run([detect, "--format", "value"]).stdout == "unknown\n"


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_detect_reads_top_level_fields_of_the_indented_lifecycle_result() -> None:
    # The lifecycle prints indented JSON; detect.sh must read the top-level
    # "installed" and version fields from it, and a nested "ok" must never
    # answer for the top-level one.
    text = _text(MDM / "linux" / "detect.sh")
    functions = "\n".join(_shell_function(text, name) for name in ("dc_json_top", "dc_json_field", "dc_json_true"))
    indented = json.dumps({
        "schema_version": 2, "ok": False, "installed": True, "installed_version": "1.2.3",
        "services": [{"name": "gateway", "ok": True}], "errors": [{"code": "x", "message": "a \"quoted\" : value"}],
    }, indent=2)
    script = functions + """
doc=$(cat)
dc_json_true "$doc" installed && echo installed
dc_json_true "$doc" ok && echo ok-true
echo "version=$(dc_json_field "$doc" installed_version)"
"""
    for shell in ("sh", "dash", "bash"):
        if not shutil.which(shell):
            continue
        result = subprocess.run([shell, "-c", script], input=indented, capture_output=True, text=True, check=True)
        assert result.stdout.splitlines() == ["installed", "version=1.2.3"], (shell, result.stdout)


def test_windows_shared_helpers_never_trust_environment_paths() -> None:
    region = _shared_region(_text(WINDOWS_SHARED[0]))
    code = "\n".join(line for line in region.splitlines() if not line.lstrip().startswith("#"))
    assert "$env:ProgramFiles" not in code and "$env:SystemRoot" not in code
    assert "[Microsoft.Win32.RegistryView]::Registry64" in region
    assert "$env:PSModulePath = Join-Path $PSHOME 'Modules'" in region
    for variable in ("DOTNET_", "COMPLUS_", "CORECLR_", "COR_PROFILER", "PSMODULEPATH"):
        assert variable in region


def test_windows_shared_helpers_start_the_cli_outside_the_install() -> None:
    # GAP-1684: a CLI started with its working directory in InstallRoot\bin
    # holds that folder open, so the uninstall could not retire InstallRoot
    # and failed 1603 halfway, on every retry too.
    region = _shared_region(_text(WINDOWS_SHARED[0]))
    assert "$info.WorkingDirectory = [System.Environment]::SystemDirectory" in region
    assert "GetDirectoryName($FilePath)" not in region


def test_intune_package_resolves_output_before_using_dotnet_paths() -> None:
    script = _text(MDM / "intune" / "windows" / "New-DefenseClawIntunePackage.ps1")
    assert script.index("$OutputDirectory = [IO.Path]::GetFullPath") < script.index("$content = Join-Path")


def test_intune_package_rejects_inline_key_before_copying_setup() -> None:
    script = _text(MDM / "intune" / "windows" / "New-DefenseClawIntunePackage.ps1")
    assert script.index("if ($configText -match") < script.index("New-Item -ItemType Directory -Path $content")


# PowerShell 7 / .NET Core only constructs that break Windows PowerShell 5.1.
PS7_ONLY = [
    (re.compile(r"\?\?"), "null-coalescing ??"),
    (re.compile(r"\?\.[A-Za-z]"), "null-conditional ?."),
    (re.compile(r"\)\s*(&&|\|\|)\s*"), "pipeline chain operators"),
    (re.compile(r"ForEach-Object\s+-Parallel"), "ForEach-Object -Parallel"),
    (re.compile(r"\bToHexString\b"), "[Convert]::ToHexString"),
    (re.compile(r"\bIsPathFullyQualified\b"), "Path.IsPathFullyQualified"),
    (re.compile(r"\]::HashData\("), "static HashData"),
    (re.compile(r"FileSystemAclExtensions"), "FileSystemAclExtensions"),
    (re.compile(r"\bProcessPath\b"), "Environment.ProcessPath"),
    (re.compile(r"\$\w+\.ArgumentList\b"), "ProcessStartInfo.ArgumentList"),
    (re.compile(r"^#Requires -Version 7", re.MULTILINE), "#Requires 7"),
]


@pytest.mark.parametrize("path", WINDOWS_51, ids=lambda p: p.name)
def test_intune_facing_windows_scripts_run_in_powershell_51(path: Path) -> None:
    text = _text(path)
    for pattern, label in PS7_ONLY:
        assert not pattern.search(text), f"{path.name} uses {label}, which Windows PowerShell 5.1 lacks"
    assert "Set-StrictMode -Version 2.0" in text


def test_generic_windows_wrapper_requires_powershell_7() -> None:
    text = _text(MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1")
    assert "#Requires -Version 7.4" in text
    for guard in (
        "unsupported_architecture",
        "powershell_constrained_language",
        "loader_environment_present",
        "powershell7_untrusted",
        "mdm_not_elevated",
    ):
        assert guard in text
    # Credentials only through stdin or an administrator-only file.
    assert "'--from-stdin'" in text and "-StandardInputPath $secret" in text
    assert "-RequireAdminOnly" in text


def _pwsh7() -> str | None:
    candidates = [shutil.which("pwsh.exe")]
    program_files = os.environ.get("ProgramFiles")
    if program_files:
        candidates.append(str(Path(program_files) / "PowerShell" / "7" / "pwsh.exe"))
    return next((c for c in candidates if c and Path(c).is_file()), None)


_ANCESTOR_PROBE = r"""
$ErrorActionPreference = 'Stop'
__FUNCTIONS__
function New-ProbeDirectory([string]$Path, [string]$Sddl) {
    $security = [System.Security.AccessControl.DirectorySecurity]::new()
    $security.SetSecurityDescriptorSddlForm($Sddl)
    [System.IO.FileSystemAclExtensions]::Create([System.IO.DirectoryInfo]::new($Path), $security)
}
function New-ProbeFile([string]$Path) {
    [System.IO.File]::WriteAllText($Path, "deployment_mode: managed_enterprise`n")
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
    Set-Acl -LiteralPath $Path -AclObject $acl
}
$adminOnly = 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
$root = Join-Path ([Environment]::GetFolderPath('Windows')) ('Temp\dc-mdm-ancestors-' + [Guid]::NewGuid().ToString('N'))
try {
    New-ProbeDirectory $root $adminOnly
    New-ProbeDirectory (Join-Path $root 'good') $adminOnly
    New-ProbeFile (Join-Path $root 'good\config.yaml')
    # Authenticated Users may modify (and so rename) this folder; the file in
    # it is still administrator-only.
    New-ProbeDirectory (Join-Path $root 'open') 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1301bf;;;AU)'
    New-ProbeFile (Join-Path $root 'open\config.yaml')
    $null = New-Item -ItemType Junction -Path (Join-Path $root 'link') -Target (Join-Path $root 'good')
    # Whether the folders above the probe root are themselves administrator-only.
    $result = [ordered]@{ host = [bool](Test-WrapperAdminOnlyAncestors -Path (Join-Path $root 'probe')) }
    foreach ($name in 'good', 'open', 'link') {
        $file = Join-Path $root "$name\config.yaml"
        $result[$name] = [ordered]@{
            item = [bool](Test-DefenseClawAdminOnlyItem -Path $file)
            ancestors = [bool](Test-WrapperAdminOnlyAncestors -Path $file)
        }
    }
    $result | ConvertTo-Json -Compress
} finally {
    $link = Join-Path $root 'link'
    if (Test-Path -LiteralPath $link) { [System.IO.Directory]::Delete($link) }
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
"""


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL behaviour")
def test_generic_windows_wrapper_checks_every_folder_above_config_and_secret(tmp_path: Path) -> None:
    # An account that can rename a folder above an administrator-only config
    # can swap the file between the ACL check and the copy, so the wrapper
    # checks the whole chain like the Unix dc_trusted_path.
    engine = _pwsh7()
    assert engine, "Windows CI must provide PowerShell 7"
    text = _text(MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1")
    start = text.index("function Test-WrapperAdminOnlyAncestors {")
    ancestors = text[start : text.index("\nfunction Copy-WrapperInput", start)]
    probe = tmp_path / "ancestor-probe.ps1"
    probe.write_text(_ANCESTOR_PROBE.replace("__FUNCTIONS__", _shared_region(text) + "\n" + ancestors), encoding="utf-8")
    result = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(probe)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    verdicts = json.loads(result.stdout.strip().splitlines()[-1])
    assert verdicts["good"]["item"] and verdicts["open"]["item"], verdicts
    if not verdicts["host"]:
        pytest.skip("a folder above the probe root is not administrator-only on this host")
    assert verdicts["good"]["ancestors"] is True, verdicts
    assert verdicts["open"]["ancestors"] is False, verdicts
    assert verdicts["link"]["ancestors"] is False, verdicts


_REMEDIATION_PROBE = r"""
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
__FUNCTIONS__
$guardianDown = '{"errors":[{"code":"lifecycle_error","message":"guardian not running"}],"services":[' +
    '{"name":"DefenseClawGateway","kind":"gateway","state":"running","required":true},' +
    '{"name":"DefenseClawHookGuardian","kind":"guardian","state":"stopped","start_mode":"disabled","required":true},' +
    '{"name":"DefenseClawHookEnumerator","kind":"enumerator","state":"running","required":true},' +
    '{"name":"DefenseClawSensorHelper","kind":"sensor_helper","state":"running","required":true}]}'
$gatewayDown = $guardianDown.Replace('"DefenseClawGateway","kind":"gateway","state":"running"', '"DefenseClawGateway","kind":"gateway","state":"stopped"')
$busy = '{"errors":[{"code":"lifecycle_busy","message":"another run"}],"services":[]}'
@{
    detect = (Format-DefenseClawVerifyFailure -Json $guardianDown)
    busy = ($null -eq (Format-DefenseClawVerifyFailure -Json $busy))
    fix = @(Get-DefenseClawStoppedSideServices -Json $guardianDown)
    fix_gateway_down = @(Get-DefenseClawStoppedSideServices -Json $gatewayDown).Count
} | ConvertTo-Json -Compress
"""


@pytest.mark.skipif(os.name != "nt", reason="runs the Intune remediation helpers")
def test_intune_remediation_names_the_stopped_service_and_restarts_only_it(tmp_path: Path) -> None:
    # GAP-0574: Detect named only lifecycle_error, and Fix re-applied the
    # whole deployment for a stopped guardian, so every user's hooks failed
    # closed for 99 seconds. Detect names the service; Fix starts only the
    # stopped guardian or enumerator while the gateway runs.
    engine = shutil.which("powershell.exe") or _pwsh7()
    assert engine, "Windows CI must provide Windows PowerShell 5.1 or PowerShell 7"
    functions = []
    for name, function in (("Remediate-Detect.ps1", "Format-DefenseClawVerifyFailure"),
                           ("Remediate-Fix.ps1", "Get-DefenseClawStoppedSideServices")):
        text = _text(MDM / "intune" / "windows" / name)
        start = text.index(f"function {function} {{")
        functions.append(text[start : text.index("\ntry {", start)])
    probe = tmp_path / "remediation-probe.ps1"
    probe.write_text(_REMEDIATION_PROBE.replace("__FUNCTIONS__", "\n".join(functions)), encoding="utf-8")
    result = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(probe)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    verdicts = json.loads(result.stdout.strip().splitlines()[-1])
    assert "DefenseClawHookGuardian is stopped (start disabled)" in verdicts["detect"], verdicts
    assert verdicts["busy"] is True, verdicts
    assert verdicts["fix"] == ["DefenseClawHookGuardian"] or verdicts["fix"] == "DefenseClawHookGuardian", verdicts
    assert verdicts["fix_gateway_down"] == 0, verdicts


@pytest.mark.skipif(os.name != "nt", reason="runs the Windows wrapper")
def test_generic_windows_wrapper_refuses_a_product_version_pin_for_a_staged_setup(tmp_path: Path) -> None:
    # Setup takes no version pin; a -ProductVersion given with -SetupPath
    # used to be accepted and silently ignored.
    engine = _pwsh7()
    assert engine, "Windows CI must provide PowerShell 7"
    result = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1"),
         "-SetupPath", str(tmp_path / "DefenseClawSetup-Enterprise-Standalone-x64.exe"), "-Sha256", "0" * 64,
         "-ProductVersion", "1.4.0"],
        capture_output=True, text=True, timeout=120, check=False,
    )
    document = json.loads([line for line in result.stdout.splitlines() if line.startswith("{")][-1])
    codes = [error["code"] for error in document["errors"]]
    host_refusals = {"mdm_not_elevated", "powershell7_untrusted", "unsupported_architecture", "powershell_constrained_language", "loader_environment_present"}
    if host_refusals.intersection(codes):
        pytest.skip(f"this host cannot run the wrapper: {document['errors'][0]['message']}")
    assert result.returncode == 1639, result.stdout
    assert codes == ["mdm_invalid_arguments"], document
    assert "-ProductVersion applies only to the installed CLI" in document["errors"][0]["message"], document


_PUBLIC_TEXT_PROBE = r"""
$ErrorActionPreference = 'Stop'
__FUNCTION__
$staged = 'C:\Windows\Temp\defenseclaw-mdm-0123456789abcdef0123456789abcdef\config.yaml'
$doc = [ordered]@{
    schema_version = 2
    next_step = "Next step: run DefenseClaw Setup as LocalSystem: DefenseClawSetup-Enterprise-Standalone-x64.exe /ensure CONFIG=$staged JSON=1."
    config = $staged
} | ConvertTo-Json -Compress
[ordered]@{
    plain = ConvertTo-WrapperPublicText -Text $doc -Staged $staged -Public 'C:\Staging\config.yaml'
    spaced = ConvertTo-WrapperPublicText -Text $doc -Staged $staged -Public 'C:\Admin Configs\config.yaml'
    stdin = ConvertTo-WrapperPublicText -Text $doc -Staged $staged -Public ''
    raw = ConvertTo-WrapperPublicText -Text "failed; CONFIG=$staged JSON=1" -Staged $staged -Public 'C:\Staging\config.yaml'
} | ConvertTo-Json -Compress
"""


@pytest.mark.skipif(os.name != "nt", reason="runs PowerShell 7")
def test_generic_windows_wrapper_names_the_administrators_config_in_its_result(tmp_path: Path) -> None:
    engine = _pwsh7()
    assert engine, "Windows CI must provide PowerShell 7"
    text = _text(MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1")
    start = text.index("function ConvertTo-WrapperPublicText {")
    function = text[start : text.index("\nfunction Write-LifecycleResult", start)]
    probe = tmp_path / "public-text-probe.ps1"
    probe.write_text(_PUBLIC_TEXT_PROBE.replace("__FUNCTION__", function), encoding="utf-8")
    result = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(probe)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    out = json.loads(result.stdout.strip().splitlines()[-1])
    plain = json.loads(out["plain"])
    assert "/ensure CONFIG=C:\\Staging\\config.yaml JSON=1" in plain["next_step"], plain
    assert plain["config"] == "C:\\Staging\\config.yaml", plain
    assert "defenseclaw-mdm-" not in out["plain"], out["plain"]
    spaced = json.loads(out["spaced"])
    assert '/ensure CONFIG="C:\\Admin Configs\\config.yaml" JSON=1' in spaced["next_step"], spaced
    stdin = json.loads(out["stdin"])
    assert "/ensure CONFIG=<config.yaml> JSON=1" in stdin["next_step"], stdin
    assert out["raw"] == "failed; CONFIG=C:\\Staging\\config.yaml JSON=1", out["raw"]


def test_windows_scripts_never_concatenate_into_an_argument_list() -> None:
    # PowerShell's comma operator binds tighter than +, so
    # @('/' + $action, 'JSON=1') is the single argument "/ensure JSON=1". The
    # generic wrapper built its Setup command line that way, and Setup refused
    # every -SetupPath run with "unexpected positional argument" (exit 1639).
    pattern = re.compile(r"@\(\s*'[^']*'\s*\+\s*\$\w+\s*,")
    for path in sorted((MDM / "windows").glob("*.ps1")) + sorted((MDM / "intune" / "windows").glob("*.ps1")):
        assert not pattern.search(_text(path)), path.name
    assert "$arguments = @(('/' + $normalizedAction), 'JSON=1')" in _text(
        MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1"
    )


@pytest.mark.skipif(os.name == "nt", reason="the release jobs run the signing helpers with bash on Linux and macOS")
def test_signing_helpers_refuse_without_credentials(tmp_path: Path) -> None:
    sign = MDM / "signing" / "authenticode-sign.sh"
    target = tmp_path / "file.exe"
    target.write_bytes(b"MZ")
    result = subprocess.run(["bash", str(sign), str(target)], capture_output=True, text=True,
                            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
    assert result.returncode != 0 and "AUTHENTICODE_PFX" in result.stderr
    builder = ROOT / "packaging" / "windows" / "standalone" / "build-setup.sh"
    result = subprocess.run(["bash", str(builder), "--version", "1.0.0", "--payload-dir", str(tmp_path),
                             "--sign-command", str(sign)], capture_output=True, text=True)
    assert result.returncode == 1 and "exclusive" in result.stderr
    for path in (sign, MDM / "signing" / "build-macos-release.sh"):
        if shutil.which("shellcheck"):
            subprocess.run(["shellcheck", "-S", "warning", str(path)], check=True)


# The macOS app job needs these five for every release (release.yaml).
_MACOS_APP_SECRETS = {
    "MACOS_DEVELOPER_ID_P12_BASE64": "cDEy",
    "MACOS_DEVELOPER_ID_P12_PASSWORD": "password",
    "MACOS_NOTARY_KEY_BASE64": "a2V5",
    "MACOS_NOTARY_KEY_ID": "key-id",
    "MACOS_NOTARY_ISSUER_ID": "issuer-id",
}


@pytest.mark.skipif(os.name == "nt", reason="the release job runs the pkg builder with bash on macOS")
@pytest.mark.parametrize(
    ("secrets", "code", "message"),
    [
        ({}, 0, "::notice title=Unsigned macOS enterprise package::"),
        # The app's secrets alone do not ask for a signed pkg.
        (_MACOS_APP_SECRETS, 0, "::notice title=Unsigned macOS enterprise package::"),
        (
            {"MACOS_INSTALLER_SIGNING_IDENTITY": "Developer ID Installer: Example"},
            1,
            "MACOS_INSTALLER_SIGNING_IDENTITY needs MACOS_DEVELOPER_ID_P12_BASE64 and MACOS_SIGNING_IDENTITY",
        ),
        (
            {**_MACOS_APP_SECRETS, "MACOS_INSTALLER_SIGNING_IDENTITY": "Developer ID Installer: Example"},
            1,
            "MACOS_INSTALLER_SIGNING_IDENTITY needs MACOS_DEVELOPER_ID_P12_BASE64 and MACOS_SIGNING_IDENTITY",
        ),
        ({"MACOS_INSTALLER_P12_BASE64": "cDEy"}, 1, "MACOS_INSTALLER_P12_BASE64 is set without"),
        ({"MACOS_NOTARY_KEY_BASE64": "a2V5"}, 1, "Set all three MACOS_NOTARY_* secrets or none of them"),
    ],
)
def test_macos_enterprise_pkg_is_signed_only_with_its_installer_identity(
    tmp_path: Path, secrets: dict[str, str], code: int, message: str
) -> None:
    script = tmp_path / "packaging" / "mdm" / "signing" / "build-macos-release.sh"
    script.parent.mkdir(parents=True)
    shutil.copy2(MDM / "signing" / "build-macos-release.sh", script)
    builder = tmp_path / "scripts" / "build-macos-enterprise-pkg.sh"
    builder.parent.mkdir()
    builder.write_text(
        "#!/usr/bin/env bash\nset -eu\n"
        'while [ "$#" -gt 0 ]; do case "$1" in --version) v=$2; shift ;; --dist-dir) d=$2; shift ;; esac; shift; done\n'
        ': > "$d/defenseclaw-enterprise-$v-darwin-arm64.pkg"\n',
        encoding="utf-8",
    )
    builder.chmod(0o755)
    out = tmp_path / "out"
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "RUNNER_TEMP": str(tmp_path), **secrets}
    result = subprocess.run(
        ["bash", str(script), "1.2.3", str(out)], env=env, capture_output=True, text=True, timeout=60
    )
    assert result.returncode == code, result.stdout + result.stderr
    assert message in result.stdout + result.stderr
    assert (out / "defenseclaw-enterprise-1.2.3-darwin-arm64.pkg").is_file() == (code == 0)


def test_remediate_fix_does_not_report_a_missing_scanner_runtime_as_healthy() -> None:
    """GAP-0631: the installed CLI's ensure succeeds with a
    scanner_runtime_unavailable warning while verify keeps failing; the
    remediation reports it as not repaired, exits 1603 and keeps the warning's
    text, which names Setup /repair."""

    text = (MDM / "intune" / "windows" / "Remediate-Fix.ps1").read_text(encoding="utf-8")
    branch = text[text.index("$runtime = @($document.warnings)") :]
    branch = branch[: branch.index("elseif ($document.ok -and $document.noop)")]
    assert "$_.code -eq 'scanner_runtime_unavailable'" in branch
    assert "$code = 1603" in branch
    assert "$($runtime.message)" in branch
