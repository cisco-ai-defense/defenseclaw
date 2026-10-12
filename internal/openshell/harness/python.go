// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"encoding/base64"
	"path"
	"strings"
)

// Python harnesses (Hermes, OpenHands, OmniGent) are PyPI packages. Each is
// installed with the community base's uv (digest-pinned with the base) as a
// root-owned `uv tool` under InstallRoot, on a private python-build-standalone
// interpreter at an exact version:
//
//   - The interpreter is the harness's alone, so the provider profile that
//     pins an LLM credential to its realpath does not also hand the
//     credential to the base image's shared Python.
//   - Dependency resolution is cut off at pythonExcludeNewer, so a rebuild
//     resolves the same versions the pin was reviewed with, not whatever a
//     dependency published since.
//   - uv reads no user or project configuration (UV_NO_CONFIG) and its cache
//     is removed after the install.
//
// PyPI publishes no detached checksums for these packages; the exact
// version pin, the resolution cutoff and the image's post-build digest
// record are the integrity boundary.
const (
	// pythonHarnessVersion is the exact CPython the Python harnesses run on:
	// Hermes needs >=3.11,<3.14, OpenHands 3.12.*, OmniGent >=3.12.
	pythonHarnessVersion = "3.12.13"
	// pythonExcludeNewer is the dependency resolution cutoff (uv
	// --exclude-newer), the date the pins below were reviewed.
	pythonExcludeNewer = "2026-09-27T00:00:00Z"
)

// uvTool describes one root-owned uv tool install.
type uvTool struct {
	// harness names the install root.
	harness string
	// dist is the PyPI distribution.
	dist string
	// commands are entry points linked into /usr/local/bin; the first is
	// the harness command.
	commands []string
	// versionCheck is a shell command that prints exactly the installed
	// version (run in /tmp with HOME in a scratch directory).
	versionCheck string
	// extra is appended to the install step (after the version check).
	extra string
}

func (u uvTool) root() string { return path.Join(InstallRootBase, u.harness) }

// toolDir is the uv tool environment of the distribution.
func (u uvTool) toolDir() string { return path.Join(u.root(), "tools", u.dist) }

// interpreter is the tool environment's python, whose realpath is the
// private interpreter.
func (u uvTool) interpreter() string { return path.Join(u.toolDir(), "bin", "python") }

// networkBinaries prints the realpath of the harness interpreter: every
// model request of a Python harness leaves from it.
func (u uvTool) networkBinaries() string {
	return `readlink -f ` + shellQuote(u.interpreter())
}

// installSteps renders the Dockerfile RUN step for version.
func (u uvTool) installSteps(displayName, version string) []InstallStep {
	root := u.root()
	var links strings.Builder
	for _, cmd := range u.commands {
		links.WriteString(`ln -sfn "$root/bin/` + cmd + `" /usr/local/bin/` + cmd + `; `)
	}
	run := `set -eu; root=` + shellQuote(root) + `; ` +
		`install -d -o root -g root -m 0755 "$root"; ` +
		`export UV_NO_CONFIG=1 UV_PYTHON_INSTALL_DIR="$root/python" UV_TOOL_DIR="$root/tools" UV_TOOL_BIN_DIR="$root/bin" ` +
		`UV_PYTHON_BIN_DIR="$root/python/bin" UV_CACHE_DIR=/tmp/defenseclaw-uv-cache UV_PYTHON_PREFERENCE=only-managed UV_LINK_MODE=copy; ` +
		`uv python install ` + shellQuote(pythonHarnessVersion) + `; ` +
		`uv tool install --python ` + shellQuote(pythonHarnessVersion) + ` --exclude-newer ` + shellQuote(pythonExcludeNewer) + ` ` +
		shellQuote(u.dist+"=="+version) + `; ` +
		links.String() +
		`rm -rf /tmp/defenseclaw-uv-cache; ` +
		`chown -R root:root "$root"; chmod -R go-w "$root"; ` +
		`py="$(readlink -f ` + shellQuote(u.interpreter()) + `)"; ` +
		`case "$py" in "$root"/python/*) ;; *) echo "` + displayName + ` interpreter $py is not the private one under $root/python" >&2; exit 1 ;; esac; ` +
		`got="$(cd /tmp && HOME=/tmp/defenseclaw-version-home ` + u.versionCheck + ` 2>/dev/null)"; rm -rf /tmp/defenseclaw-version-home; ` +
		`[ "$got" = ` + shellQuote(version) + ` ] || { echo "` + displayName + ` '$got' is not the pinned ` + version + `" >&2; exit 1; }; ` +
		pyShimInstall(u.interpreter(), root, displayName, pyShim{name: pyPeerNameShimName, source: pyPeerNameShim})
	if u.extra != "" {
		run += "; " + u.extra
	}
	return []InstallStep{{
		Comment: "Install " + displayName + " " + version + " from PyPI as a root-owned uv tool on a private CPython " + pythonHarnessVersion,
		Run:     run,
	}}
}

// pyPeerNameShimName is the root-owned module every Python harness's tool
// environment imports at start (pyPeerNameShim).
const pyPeerNameShimName = "defenseclaw_peername"

// pyPeerNameShim keeps TLS working for a Python harness on Linux before
// 5.19 (RHEL 9's 5.14 among them). There OpenShell 0.1 brokers the
// workload's sockets in its legacy read-only mode and answers getpeername()
// on a connected one with EOPNOTSUPP, as it cannot write into the
// workload's memory safely on those kernels (NVIDIA/OpenShell #4058; main
// stops brokering getpeername in #4150, after 0.1.2). CPython's ssl module
// calls getpeername() before every handshake and treats any error but
// ENOTCONN as fatal, so every HTTPS request of the harness failed with
// "[Errno 95] Operation not supported": Hermes' model calls on Bedrock
// ended in "Connection error.". The broker gives EOPNOTSUPP only for a
// socket it holds as connected (it says ENOTCONN otherwise, and the kernel
// never answers EOPNOTSUPP for an inet socket), so the shim answers that
// one error with the unspecified address of the socket's family, the peer
// being unknown; every other answer is the kernel's. Drop it with the
// OpenShell pin that carries #4150.
const pyPeerNameShim = `"""DefenseClaw: TLS for a sandboxed Python harness on Linux before 5.19.

OpenShell 0.1 answers getpeername() on a connection it relays with
EOPNOTSUPP on those kernels, and the ssl module asks for the peer before
every handshake; answer that one refusal with the unspecified address.
"""
import errno as _errno
import socket as _socket

_getpeername = _socket.socket.getpeername


def _defenseclaw_getpeername(self):
    try:
        return _getpeername(self)
    except OSError as e:
        if e.errno != _errno.EOPNOTSUPP:
            raise
        if self.family == _socket.AF_INET:
            return ("0.0.0.0", 0)
        if self.family == _socket.AF_INET6:
            return ("::", 0, 0, 0)
        raise


_defenseclaw_getpeername.__wrapped__ = _getpeername
_socket.socket.getpeername = _defenseclaw_getpeername
`

// WorkloadPythonStep is the image step that gives the workload's own
// Python, the image's python3 on PATH and /usr/bin/python3, the fix of
// pyPeerNameShim: pip, and any other HTTPS client written in Python, failed
// with "[Errno 95] Operation not supported" in a sandbox on Linux before
// 5.19 (GAP-0196). The shim goes into each interpreter's standard library,
// imported from its sitecustomize module, so the venvs made from it (a
// project's .venv) load it too. It is a compatibility fix, not a control: the
// workload may change it. A base image whose Python cannot take it builds
// on without it.
func WorkloadPythonStep() InstallStep {
	return InstallStep{
		Comment: "TLS for the workload's own Python on Linux before 5.19 (OpenShell answers getpeername with EOPNOTSUPP there)",
		Run:     workloadPythonRun(`"$(command -v python3 || true)" /usr/bin/python3`),
	}
}

// workloadPythonRun is WorkloadPythonStep's command for the interpreters
// pythons (shell words).
func workloadPythonRun(pythons string) string {
	shim := base64.StdEncoding.EncodeToString([]byte(pyPeerNameShim))
	hook := base64.StdEncoding.EncodeToString([]byte("\ntry:\n    import " + pyPeerNameShimName + "\nexcept Exception:\n    pass\n"))
	return `set -eu; for py in ` + pythons + `; do [ -n "$py" ] && [ -x "$py" ] || continue; { ` +
		`lib="$("$py" -I -S -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')" && [ -d "$lib" ] && ` +
		`printf '%s' ` + shim + ` | base64 -d >"$lib/` + pyPeerNameShimName + `.py" && ` +
		`{ grep -qs ` + pyPeerNameShimName + ` "$lib/sitecustomize.py" || printf '%s' ` + hook + ` | base64 -d >>"$lib/sitecustomize.py"; }; ` +
		`} || echo "DefenseClaw: $py keeps failing HTTPS on Linux before 5.19 (no getpeername fix)" >&2; done`
}

// pythonStartupScrub is the launcher fragment that drops every PYTHON*
// variable before a Python harness starts. The uv tool entry points run the
// interpreter without -I, so it reads them: PYTHONPATH names directories
// searched before the root-owned site-packages (a sitecustomize module there
// is imported at every start), PYTHONHOME and PYTHONUSERBASE move the
// standard library and user site, PYTHONSTARTUP runs a file,
// PYTHONPYCACHEPREFIX loads compiled code from a directory the workload can
// write, and PYTHONWARNINGS and PYTHONBREAKPOINT import the modules they
// name. OpenShell runs the connect and exec shells as login shells, which
// read start-up files in the workload-writable HOME, so one exported line
// there would run code inside the next harness start. It is the Python
// counterpart of launcherScrubbedEnv, and like it relies on the launcher
// running under bash (${!prefix@} lists the variables with a prefix).
const pythonStartupScrub = `# The Python interpreter reads PYTHON* variables at start-up (PYTHONPATH can
# import a sitecustomize module from the workload-writable HOME).
for name in ${!PYTHON@}; do
  unset "$name"
done
unset name
`
