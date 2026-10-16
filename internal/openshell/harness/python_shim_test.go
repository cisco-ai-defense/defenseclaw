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

//go:build !windows

package harness

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// writeScript writes an executable shell script.
func writeScript(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// run runs argv and returns its combined output.
func run(t *testing.T, env []string, argv ...string) string {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%q: %v\n%s", argv, err, out)
	}
	return string(out)
}

// #1238: python3 on the agent's PATH ran the base image's interpreter while
// pip installed into the workload venv. The image step installs python3
// and python shims in a directory ahead of /usr/local/bin that run the
// venv's versioned interpreter by its absolute path (never themselves), and
// fall back to the base interpreter when the venv is gone.
func TestWorkloadPythonShimRunsTheVenvInterpreter(t *testing.T) {
	root := t.TempDir()
	venv, dir, base := filepath.Join(root, "sandbox", ".venv"), filepath.Join(root, "usr", "local", "sbin"), filepath.Join(root, "usr", "local", "bin", "python3")
	// The venv's python3 answers the version query; python3.14 is the
	// interpreter the shim must run.
	writeScript(t, filepath.Join(venv, "bin", "python3"), `case "$*" in *version_info*) echo 3.14 ;; *) echo "unversioned venv python3 $*" ;; esac`+"\n")
	writeScript(t, filepath.Join(venv, "bin", "python3.14"), `echo "venv $0 $*"`+"\n")
	writeScript(t, base, `echo "base $*"`+"\n")
	step := workloadPythonShimRun(venv, dir, base+" /nonexistent/python3")
	run(t, nil, "sh", "-c", step)
	for _, name := range []string{"python3", "python"} {
		shim := filepath.Join(dir, name)
		st, err := os.Stat(shim)
		if err != nil || st.Mode().Perm() != 0o755 {
			t.Fatalf("%s: %v, mode %v", shim, err, st)
		}
		// On a PATH that would find the shim again, it still runs the venv.
		got := run(t, []string{"PATH=" + dir + ":" + filepath.Dir(base) + ":/usr/bin:/bin"}, shim, "-m", "pip", "install", "x")
		if want := "venv " + filepath.Join(venv, "bin", "python3.14") + " -m pip install x\n"; got != want {
			t.Fatalf("%s -m pip = %q, want %q", name, got, want)
		}
	}
	// A venv the agent removed leaves the base interpreter.
	if err := os.RemoveAll(venv); err != nil {
		t.Fatal(err)
	}
	if got := run(t, nil, filepath.Join(dir, "python3"), "-V"); got != "base -V\n" {
		t.Fatalf("without the venv python3 = %q, want the base interpreter", got)
	}
	// A second build step, or a base image with a program of its own at a
	// shim's path, keeps what is there.
	writeScript(t, filepath.Join(venv, "bin", "python3"), "echo 3.14\n")
	writeScript(t, filepath.Join(venv, "bin", "python3.14"), "echo venv\n")
	if out := run(t, nil, "sh", "-c", step); !strings.Contains(out, "has its own") {
		t.Fatalf("an existing shim was not kept: %q", out)
	}
}

// A base image without the workload venv builds on, with no shim.
func TestWorkloadPythonShimWithoutAVenv(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "sbin")
	run(t, nil, "sh", "-c", workloadPythonShimRun(filepath.Join(root, "no-venv"), dir, "/usr/bin/python3"))
	if _, err := os.Stat(filepath.Join(dir, "python3")); !os.IsNotExist(err) {
		t.Fatalf("a shim without a venv: %v", err)
	}
}

// The shims are first on the harness's PATH and off the hooks' PATH: the
// agent's python3 is the venv's, a hook's the system's.
func TestWorkloadPythonShimPaths(t *testing.T) {
	launcher := strings.Split(LauncherSystemPATH, ":")
	if launcher[0] != WorkloadPythonShimDir {
		t.Fatalf("LauncherSystemPATH %s does not start with %s", LauncherSystemPATH, WorkloadPythonShimDir)
	}
	if slices.Contains(strings.Split(connector.SandboxHookPATH, ":"), WorkloadPythonShimDir) {
		t.Fatalf("the hooks' PATH %s holds %s", connector.SandboxHookPATH, WorkloadPythonShimDir)
	}
	if WorkloadVenv != "/sandbox/.venv" {
		t.Fatalf("WorkloadVenv = %s", WorkloadVenv)
	}
	step := WorkloadPythonShimStep().Run
	for _, want := range []string{"venv='/sandbox/.venv'", "dir='/usr/local/sbin'", `py="$venv/bin/python$v"`, "/usr/local/bin/python3 /usr/bin/python3"} {
		if !strings.Contains(step, want) {
			t.Errorf("the step lacks %q:\n%s", want, step)
		}
	}
}
