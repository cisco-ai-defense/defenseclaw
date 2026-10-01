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
		`[ "$got" = ` + shellQuote(version) + ` ] || { echo "` + displayName + ` '$got' is not the pinned ` + version + `" >&2; exit 1; }`
	if u.extra != "" {
		run += "; " + u.extra
	}
	return []InstallStep{{
		Comment: "Install " + displayName + " " + version + " from PyPI as a root-owned uv tool on a private CPython " + pythonHarnessVersion,
		Run:     run,
	}}
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
