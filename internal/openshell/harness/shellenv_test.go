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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

const testEgressProxy = "http://dcx-0123456789abcdef:0123abcd@host.openshell.internal:18972"

// shellEnvRecord is a shell fragment that prints the proxy variables and
// PATH, one NAME=value per line ("<unset>" when absent).
const shellEnvRecord = `for v in HTTPS_PROXY HTTP_PROXY https_proxy http_proxy NODE_USE_ENV_PROXY NO_PROXY no_proxy PATH BASH_ENV NODE_OPTIONS; do
  eval "printf '%s=%s\n' \"\$v\" \"\${$v-<unset>}\""
done
`

func shellEnvLines(out string) map[string]string {
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			got[key] = value
		}
	}
	return got
}

func shellFile(t *testing.T, spec *Spec, path string) connector.SandboxFile {
	t.Helper()
	for _, f := range spec.ShellFiles() {
		if f.Path == path {
			return f
		}
	}
	t.Fatalf("%s shell files lack %s", spec.Name, path)
	return connector.SandboxFile{}
}

// TestScriptsParse keeps every launcher and shell file valid for the shell
// that runs it: the launchers and wrappers under bash -p, the profile
// fragment for POSIX sh (a login shell may be dash), the supervisor for
// Python, the network-binary probe for sh; and every shim starts its
// launcher.
func TestScriptsParse(t *testing.T) {
	parses := func(t *testing.T, what, sh, script string) {
		t.Helper()
		if _, err := os.Stat(sh); err != nil {
			return
		}
		cmd := exec.Command(sh, "-n")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s under %s: %v\n%s", what, sh, err, out)
		}
	}
	for _, name := range Names() {
		spec, _ := Get(name)
		files := append([]connector.SandboxFile{spec.Launcher()}, spec.ShellFiles()...)
		for _, f := range files {
			data := string(f.Data)
			if f.Owner != connector.SandboxOwnerRoot {
				t.Errorf("%s %s is not root-owned", name, f.Path)
			}
			switch {
			case strings.HasPrefix(data, "#!/usr/bin/python3 "):
				// The supervisor: check it compiles, when Python is here.
				if _, err := os.Stat("/usr/bin/python3"); err == nil {
					cmd := exec.Command("/usr/bin/python3", "-I", "-S", "-c", "import sys; compile(sys.stdin.read(), 'dc_supervisor.py', 'exec')")
					cmd.Stdin = strings.NewReader(data)
					if out, err := cmd.CombinedOutput(); err != nil {
						t.Errorf("%s %s does not compile: %v\n%s", name, f.Path, err, out)
					}
				}
			case strings.HasPrefix(data, "#!/bin/bash"):
				if !strings.HasPrefix(data, "#!/bin/bash -p\n") {
					t.Errorf("%s %s must run under bash -p", name, f.Path)
				}
				parses(t, name+" "+f.Path, "/bin/bash", data)
			default:
				parses(t, name+" "+f.Path, "/bin/sh", data)
			}
		}
		parses(t, name+" network-binary probe", "/bin/sh", spec.Probe().NetworkBinaries)
		// The command becomes a file name and a shell function name.
		if !regexp.MustCompile(`^[a-z][a-z0-9-]*$`).MatchString(spec.Command) {
			t.Errorf("%s command %q is not a plain name", name, spec.Command)
		}
		shim := shellFile(t, spec, spec.ShimPath())
		if spec.ShimPath() != ShimDir+"/"+spec.Command || !strings.Contains(string(shim.Data), "\nexec "+spec.LauncherPath()+" \"$@\"\n") {
			t.Errorf("%s shim does not start %s:\n%s", name, spec.LauncherPath(), shim.Data)
		}
	}
}

// TestSandboxProfileExportsTheProxy sources the login-shell profile the
// way /etc/profile does: the DefenseClaw proxy replaces the caller's, a
// malformed one and a strict sandbox (no proxy) leave the caller's
// environment alone, and the shim directory leads PATH once.
func TestSandboxProfileExportsTheProxy(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is required")
	}
	profile := filepath.Join(t.TempDir(), "defenseclaw-sandbox.sh")
	if err := os.WriteFile(profile, shellFile(t, ClaudeCode, SandboxProfilePath).Data, 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(env ...string) map[string]string {
		t.Helper()
		cmd := exec.Command("/bin/sh", "-c", ". "+profile+"\n. "+profile+"\n"+shellEnvRecord)
		cmd.Env = append([]string{"PATH=/usr/bin:/bin"}, env...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("profile: %v\n%s", err, out)
		}
		return shellEnvLines(string(out))
	}
	bypass := "api.anthropic.com,host.openshell.internal"
	got := run("HTTPS_PROXY=http://elsewhere:1", openshell.EnvEgressURL+"="+testEgressProxy, openshell.EnvEgressBypass+"="+bypass)
	for key, want := range map[string]string{
		"HTTPS_PROXY": testEgressProxy, "HTTP_PROXY": testEgressProxy, "https_proxy": testEgressProxy, "http_proxy": testEgressProxy,
		"NODE_USE_ENV_PROXY": "1", "NO_PROXY": bypass, "no_proxy": bypass, "PATH": ShimDir + ":/usr/bin:/bin",
	} {
		if got[key] != want {
			t.Errorf("%s = %q, want %q", key, got[key], want)
		}
	}
	// Sourcing prints nothing (a POSIX sh, or bash in POSIX mode, never sees
	// the function definition).
	quiet := exec.Command("/bin/sh", "-c", ". "+profile)
	quiet.Env = []string{"PATH=/usr/bin:/bin"}
	if out, err := quiet.CombinedOutput(); err != nil || len(out) != 0 {
		t.Errorf("sourcing the profile under /bin/sh: %v %q", err, out)
	}
	// Bash: the harness command is a function that runs the shim, survives
	// a start-up file that resets PATH, and reaches child bash shells.
	if _, err := os.Stat("/bin/bash"); err == nil {
		for _, name := range Names() {
			spec, _ := Get(name)
			file := filepath.Join(t.TempDir(), "profile.sh")
			if err := os.WriteFile(file, shellFile(t, spec, SandboxProfilePath).Data, 0o644); err != nil {
				t.Fatal(err)
			}
			script := ". " + file + "\nPATH=/usr/bin:/bin\ntype -t " + spec.Command + "; /bin/bash -c 'type -t " + spec.Command + "; declare -f " + spec.Command + "'"
			cmd := exec.Command("/bin/bash", "-c", script)
			cmd.Env = []string{"PATH=/usr/bin:/bin"}
			out, err := cmd.CombinedOutput()
			if err != nil || !strings.HasPrefix(string(out), "function\nfunction\n") || !strings.Contains(string(out), spec.ShimPath()+" \"$@\"") {
				t.Errorf("%s: bash login shell: %v\n%s", name, err, out)
			}
		}
	}
	if got := run(openshell.EnvEgressURL + "=" + testEgressProxy); got["NO_PROXY"] != connector.SandboxIngressHost {
		t.Errorf("NO_PROXY without a bypass list = %q", got["NO_PROXY"])
	}
	for _, env := range [][]string{
		{"HTTPS_PROXY=http://elsewhere:1", openshell.EnvEgressURL + "=http://x y@host:1"},
		{"HTTPS_PROXY=http://elsewhere:1"},
	} {
		got := run(env...)
		if got["HTTPS_PROXY"] != "http://elsewhere:1" || got["https_proxy"] != "<unset>" || got["NODE_USE_ENV_PROXY"] != "<unset>" {
			t.Errorf("%v: the caller's proxy settings changed: %v", env, got)
		}
	}
}

// TestSandboxShellsTakeTheHostTimeZone: the login-shell profile and the
// sandbox exec wrapper (the launchers share its preamble) export TZ from
// the host's zone when this system has the zone's file and TZ is unset;
// an unknown zone, a path and a caller's TZ are left alone (cert
// copilot:F10: the sandbox ran on UTC).
func TestSandboxShellsTakeTheHostTimeZone(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	if _, err := os.Stat("/usr/share/zoneinfo/UTC"); err != nil {
		t.Skip("this system has no /usr/share/zoneinfo/UTC")
	}
	dir := t.TempDir()
	profile := filepath.Join(dir, "profile.sh")
	wrapper := filepath.Join(dir, "sandbox-env")
	if err := os.WriteFile(profile, shellFile(t, Copilot, SandboxProfilePath).Data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrapper, shellFile(t, Copilot, SandboxEnvPath).Data, 0o755); err != nil {
		t.Fatal(err)
	}
	const record = `printf 'TZ=%s\n' "${TZ-<unset>}"`
	for _, c := range []struct {
		env  []string
		want string
	}{
		{[]string{openshell.EnvHostTimeZone + "=UTC"}, "UTC"},
		{[]string{openshell.EnvHostTimeZone + "=Nowhere/Zone"}, "<unset>"},
		{[]string{openshell.EnvHostTimeZone + "=../../../etc/passwd"}, "<unset>"},
		{[]string{openshell.EnvHostTimeZone + "=/etc/localtime"}, "<unset>"},
		{[]string{openshell.EnvHostTimeZone + "=UTC", "TZ=Asia/Tokyo"}, "Asia/Tokyo"},
		{nil, "<unset>"},
	} {
		env := append([]string{"PATH=/usr/bin:/bin"}, c.env...)
		login := exec.Command("/bin/sh", "-c", ". "+profile+"\n"+record)
		login.Env = env
		wrapped := exec.Command(wrapper, "/bin/sh", "-c", record)
		wrapped.Env = env
		for what, cmd := range map[string]*exec.Cmd{"login shell": login, "sandbox exec": wrapped} {
			out, err := cmd.CombinedOutput()
			if got := shellEnvLines(string(out))["TZ"]; err != nil || got != c.want {
				t.Errorf("%s with %v: TZ = %q (%v), want %q\n%s", what, c.env, got, err, c.want, out)
			}
		}
	}
}

// TestSandboxEnvRunsTheCommand starts a command through the sandbox exec
// wrapper: it gets the launchers' environment (shim directory, then the
// system directories, first on PATH; the DefenseClaw proxy; no shell
// start-up or Node loader variables) and its own arguments, and the wrapper
// refuses to run without a command.
func TestSandboxEnvRunsTheCommand(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	dir := t.TempDir()
	wrapper := filepath.Join(dir, "sandbox-env")
	if err := os.WriteFile(wrapper, shellFile(t, Codex, SandboxEnvPath).Data, 0o755); err != nil {
		t.Fatal(err)
	}
	startup := filepath.Join(dir, "startup")
	if err := os.WriteFile(startup, []byte("echo sourced-startup-file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(wrapper, "/bin/sh", "-c", shellEnvRecord+`printf 'ARGS=%s\n' "$*"`, "sh", "one", "two words")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "BASH_ENV=" + startup, "NODE_OPTIONS=--require=/tmp/x.js",
		openshell.EnvEgressURL + "=" + testEgressProxy, openshell.EnvEgressBypass + "=host.openshell.internal"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sandbox-env: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "sourced-startup-file") {
		t.Errorf("a start-up file ran:\n%s", out)
	}
	got := shellEnvLines(string(out))
	for key, want := range map[string]string{
		"HTTPS_PROXY": testEgressProxy, "http_proxy": testEgressProxy, "NODE_USE_ENV_PROXY": "1", "NO_PROXY": "host.openshell.internal",
		"PATH": ShimDir + ":" + LauncherSystemPATH + ":/usr/bin:/bin", "BASH_ENV": "<unset>", "NODE_OPTIONS": "<unset>", "ARGS": "one two words",
	} {
		if got[key] != want {
			t.Errorf("%s = %q, want %q", key, got[key], want)
		}
	}
	bare := exec.Command(wrapper)
	bare.Env = []string{"PATH=/usr/bin:/bin"}
	if out, err := bare.CombinedOutput(); err == nil || !strings.Contains(string(out), "usage: sandbox-env") {
		t.Errorf("sandbox-env without a command: %v\n%s", err, out)
	}
}
