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
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// The sandbox's egress proxy environment.
//
// OpenShell 0.1.1 drops every *_PROXY variable and NODE_USE_ENV_PROXY passed
// at `sandbox create --env` (the gateway stores them, the workload never
// sees them), so Spec.Env passes the proxy URL and its bypass list as
// openshell.EnvEgressURL and openshell.EnvEgressBypass as well, and one
// shell fragment, egressEnvScript, exports the standard variables from them
// wherever a process starts:
//
//   - every harness launcher runs it first (launcherPreamble), so the
//     harness and every tool it runs use the proxy;
//   - SandboxProfilePath runs it for login shells: the `sandbox connect`
//     shell and `openshell sandbox exec` without --no-login-shell (which
//     OpenShell runs as `bash -lc`);
//   - SandboxEnvPath runs it for `defenseclaw-gateway sandbox exec`, which
//     OpenShell starts without a login shell.
//
// SandboxProfilePath and SandboxEnvPath also put ShimDir first on PATH,
// where the harness command starts its launcher, so typing the harness name
// in a connect or exec shell gets the launcher's protections. A user
// start-up file can reset PATH after the profile ran (the community base
// image's ~/.bashrc does), so for bash the profile also defines, and
// exports, a function of the harness command's name that runs the shim.
// A process started by absolute path, from an emptied environment (env -i)
// or through `openshell sandbox exec --no-login-shell` directly gets
// neither, and a harness run nested inside a tool call inherits the proxy
// but not the launcher's per-start checks. The proxy is a convenience path,
// not the boundary: OpenShell refuses direct egress the policy does not
// allow either way.
const (
	// SandboxProfilePath is the root-owned login-shell profile fragment
	// /etc/profile sources.
	SandboxProfilePath = "/etc/profile.d/defenseclaw-sandbox.sh"
	// SandboxEnvPath is the root-owned command wrapper that
	// `defenseclaw-gateway sandbox exec` starts every command through.
	SandboxEnvPath = LauncherDir + "/sandbox-env"
	// ShimDir holds the root-owned shim that starts the harness command
	// through its launcher.
	ShimDir = connector.SandboxLibDir + "/shims"
)

// egressEnvScript exports the egress proxy settings from
// openshell.EnvEgressURL and openshell.EnvEgressBypass. It is POSIX sh (the
// profile fragment runs in whatever login shell starts). A well-formed
// http:// proxy URL replaces any proxy settings the caller's environment
// carries, so every process started through it goes through the DefenseClaw
// proxy; without one (the strict profile), or with a URL carrying anything
// but URL characters, the caller's environment is left alone. NO_PROXY
// defaults to the ingress host, which hooks reach directly.
const egressEnvScript = `# OpenShell drops the standard proxy variables passed at sandbox creation;
# DefenseClaw passes them under its own names.
case "${` + openshell.EnvEgressURL + `:-}" in
  http://*[!A-Za-z0-9:@._/-]*) ;;
  http://?*)
    HTTPS_PROXY="$` + openshell.EnvEgressURL + `"; HTTP_PROXY="$` + openshell.EnvEgressURL + `"
    https_proxy="$` + openshell.EnvEgressURL + `"; http_proxy="$` + openshell.EnvEgressURL + `"
    NODE_USE_ENV_PROXY=1
    NO_PROXY="${` + openshell.EnvEgressBypass + `:-` + connector.SandboxIngressHost + `}"; no_proxy="$NO_PROXY"
    export HTTPS_PROXY HTTP_PROXY https_proxy http_proxy NODE_USE_ENV_PROXY NO_PROXY no_proxy
    ;;
esac
`

// shimPathScript puts ShimDir first on PATH, once.
const shimPathScript = `case ":${PATH:-}:" in
  *:` + ShimDir + `:*) ;;
  *) PATH="` + ShimDir + `${PATH:+:$PATH}"; export PATH ;;
esac
`

// profile is the login-shell profile fragment: the egress proxy, the shim
// directory first on PATH, and for bash (outside POSIX mode, which refuses
// command names like cursor-agent as function names) an exported function
// of the harness command's name, which survives a later PATH reset and
// reaches child bash shells. The launchers run under bash -p, which imports
// no functions.
func (s *Spec) profile() string {
	return `# defenseclaw-sandbox-profile v1
# DefenseClaw sandbox shell environment (OpenShell sandbox images,
# root-owned). Login shells get the egress proxy settings every harness
# launcher exports, and the harness command starts its launcher.
` + egressEnvScript + shimPathScript + `if [ -n "${BASH_VERSION:-}" ] && ! shopt -oq posix 2>/dev/null; then
  eval '` + s.Command + `() { ` + s.ShimPath() + ` "$@"; }; export -f ` + s.Command + `' 2>/dev/null || true
fi
`
}

var sandboxEnvLauncher = `#!/bin/bash -p
# defenseclaw-sandbox-env v1
# DefenseClaw sandbox command environment (OpenShell sandbox images,
# root-owned). ` + "`defenseclaw-gateway sandbox exec`" + ` starts every command through
# it: OpenShell runs those without a login shell, so this gives them the
# environment the harness launchers set up (system directories first on
# PATH, the egress proxy, the harness shim) and execs the command without
# the shell start-up variables.
set -u
if [ "$#" -eq 0 ]; then
  echo "usage: sandbox-env COMMAND [ARGUMENT]..." >&2
  exit 2
fi
` + launcherPreamble + shimPathScript + launcherExec(`"$@"`)

// ShellFiles are the root-owned files every overlay image carries next to
// the launcher: the login-shell profile fragment, the `sandbox exec` command
// wrapper and the harness command's shim.
func (s *Spec) ShellFiles() []connector.SandboxFile {
	return []connector.SandboxFile{
		{Path: SandboxProfilePath, Mode: 0o644, Owner: connector.SandboxOwnerRoot, Data: []byte(s.profile())},
		{Path: SandboxEnvPath, Mode: 0o755, Owner: connector.SandboxOwnerRoot, Data: []byte(sandboxEnvLauncher)},
		{Path: s.ShimPath(), Mode: 0o755, Owner: connector.SandboxOwnerRoot, Data: []byte(s.shim())},
	}
}

// ShimPath is the shim of the harness command.
func (s *Spec) ShimPath() string { return ShimDir + "/" + s.Command }

func (s *Spec) shim() string {
	return "#!/bin/sh\n# defenseclaw-sandbox-shim v1\n# Starts " + s.DisplayName +
		" through its DefenseClaw launcher (OpenShell sandbox images, root-owned).\nexec " +
		s.LauncherPath() + " \"$@\"\n"
}
