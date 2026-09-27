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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// launcherEnv runs spec's launcher with the pinned binary replaced by a stub
// that records the environment it received (one NAME=value per line), and
// returns the exit code, the record and the launcher's output.
func launcherEnv(t *testing.T, spec *Spec, env []string) (int, string, string) {
	t.Helper()
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	dir := t.TempDir()
	record := filepath.Join(dir, "record")
	stub := filepath.Join(dir, "stub")
	if err := os.WriteFile(stub, []byte("#!/bin/bash\n/usr/bin/env >"+record+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(dir, "launch")
	script := strings.ReplaceAll(string(spec.Launcher().Data), "/usr/local/bin/"+spec.Command, stub)
	if err := os.WriteFile(launcher, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(launcher)
	cmd.Dir = dir
	cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=" + dir}, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("launcher: %v\n%s", err, out)
	}
	got, _ := os.ReadFile(record)
	return code, "\n" + string(got), string(out)
}

// TestLaunchersScrubShellStartupEnv starts every launcher with the shell
// start-up variables an agent could export from ~/.bashrc and a PATH that
// puts its own directory first, plus the DefenseClaw proxy variables: the
// harness must receive none of the former (SHELLOPTS=noexec would even stop
// the stub, a bash script, from recording anything), the system directories
// first on PATH, and the standard proxy variables exported from the
// DefenseClaw ones in place of the caller's.
func TestLaunchersScrubShellStartupEnv(t *testing.T) {
	proxy := "http://b1:secret@host.openshell.internal:18972"
	noProxy := "api.anthropic.com,host.openshell.internal"
	for _, name := range Names() {
		spec, _ := Get(name)
		t.Run(name, func(t *testing.T) {
			agentBin := t.TempDir()
			startup := filepath.Join(t.TempDir(), "startup")
			if err := os.WriteFile(startup, []byte("echo sourced-startup-file\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			code, got, out := launcherEnv(t, spec, []string{
				"BASH_ENV=" + startup, "ENV=" + startup, "BASHOPTS=extglob", "SHELLOPTS=noexec",
				"CDPATH=/tmp", "GLOBIGNORE=*", "PATH=" + agentBin + ":/usr/bin:/bin",
				"HTTPS_PROXY=http://elsewhere:1", "no_proxy=*",
				openshell.EnvEgressURL + "=" + proxy, openshell.EnvEgressBypass + "=" + noProxy,
			})
			if code != 0 || !strings.Contains(got, "\nPATH=") {
				t.Fatalf("the stub never ran: exit %d\n%s", code, out)
			}
			if strings.Contains(out, "sourced-startup-file") {
				t.Errorf("a start-up file ran:\n%s", out)
			}
			for _, v := range []string{"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "CDPATH", "GLOBIGNORE"} {
				if strings.Contains(got, "\n"+v+"=") {
					t.Errorf("%s reached the harness:\n%s", v, got)
				}
			}
			if !strings.Contains(got, "\nPATH="+LauncherSystemPATH+":"+agentBin+":") {
				t.Errorf("PATH does not lead with the system directories:\n%s", got)
			}
			for _, want := range []string{
				"HTTPS_PROXY=" + proxy, "HTTP_PROXY=" + proxy, "https_proxy=" + proxy, "http_proxy=" + proxy,
				"NODE_USE_ENV_PROXY=1", "NO_PROXY=" + noProxy, "no_proxy=" + noProxy,
			} {
				if !strings.Contains(got, "\n"+want+"\n") {
					t.Errorf("missing %s:\n%s", want, got)
				}
			}
		})
	}
}

// TestLaunchersLeaveProxyAloneWithoutEgress keeps a strict-profile sandbox
// (no DefenseClaw proxy) free of proxy settings.
func TestLaunchersLeaveProxyAloneWithoutEgress(t *testing.T) {
	for _, name := range Names() {
		spec, _ := Get(name)
		code, got, out := launcherEnv(t, spec, nil)
		if code != 0 || !strings.Contains(got, "\nPATH=") {
			t.Fatalf("%s: exit %d\n%s", name, code, out)
		}
		for _, v := range []string{"HTTPS_PROXY", "https_proxy", "NODE_USE_ENV_PROXY", "NO_PROXY"} {
			if strings.Contains(got, "\n"+v+"=") {
				t.Errorf("%s: %s set without a DefenseClaw proxy:\n%s", name, v, got)
			}
		}
	}
}
