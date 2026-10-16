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
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-2:GAP-0013 (#1238, reopened on rc.1): python3 on the agent's
// PATH ran the venv, but a bare `pip install requests` in Claude Code's
// Bash tool exited 127, because the venv's bin is not on the harness's
// PATH. The image step installs pip and pip3 shims beside the python3 one
// that run the same interpreter's pip.
func TestWorkloadPipShimRunsTheVenvPip(t *testing.T) {
	root := t.TempDir()
	venv, dir, base := filepath.Join(root, "sandbox", ".venv"), filepath.Join(root, "usr", "local", "sbin"), filepath.Join(root, "usr", "local", "bin", "python3")
	writeScript(t, filepath.Join(venv, "bin", "python3"), `case "$*" in *version_info*) echo 3.14 ;; *) echo "unversioned venv python3 $*" ;; esac`+"\n")
	writeScript(t, filepath.Join(venv, "bin", "python3.14"), `echo "venv $0 $*"`+"\n")
	writeScript(t, base, `echo "base $*"`+"\n")
	run(t, nil, "sh", "-c", workloadPythonShimRun(venv, dir, base))

	// The agent's tool shell: the harness's PATH order, with the shim
	// directory first and no venv bin on it.
	path := "PATH=" + dir + ":" + filepath.Dir(base) + ":/usr/bin:/bin"
	for _, name := range []string{"pip", "pip3"} {
		shim := filepath.Join(dir, name)
		st, err := os.Stat(shim)
		if err != nil || st.Mode().Perm() != 0o755 {
			t.Fatalf("%s: %v, mode %v", shim, err, st)
		}
		got := run(t, []string{path}, "sh", "-c", name+" install requests")
		if want := "venv " + filepath.Join(venv, "bin", "python3.14") + " -m pip install requests\n"; got != want {
			t.Fatalf("%s install = %q, want the venv interpreter's pip %q", name, got, want)
		}
	}
	// python3 and pip resolve to the same interpreter.
	if py, pip := run(t, []string{path}, "sh", "-c", "python3 -m pip -V"), run(t, []string{path}, "sh", "-c", "pip -V"); py != pip {
		t.Fatalf("python3 -m pip = %q, pip = %q: two environments", py, pip)
	}
	// A venv the agent removed leaves the base interpreter's pip.
	if err := os.RemoveAll(venv); err != nil {
		t.Fatal(err)
	}
	if got := run(t, nil, filepath.Join(dir, "pip"), "-V"); got != "base -m pip -V\n" {
		t.Fatalf("without the venv pip = %q, want the base interpreter's pip", got)
	}
}

// A venv without pip gets the python shims but no pip shim, which would
// only fail; a base image's own pip at a shim's path is kept.
func TestWorkloadPipShimNeedsTheVenvPip(t *testing.T) {
	root := t.TempDir()
	venv, dir := filepath.Join(root, "venv"), filepath.Join(root, "sbin")
	writeScript(t, filepath.Join(venv, "bin", "python3"), "echo 3.14\n")
	writeScript(t, filepath.Join(venv, "bin", "python3.14"), `case "$*" in *"import pip"*) exit 1 ;; esac; echo venv`+"\n")
	if out := run(t, nil, "sh", "-c", workloadPythonShimRun(venv, dir, "")); !strings.Contains(out, "has no pip") {
		t.Fatalf("no notice for a venv without pip: %q", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "python3")); err != nil {
		t.Fatalf("python3 shim: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "pip")); !os.IsNotExist(err) {
		t.Fatalf("a pip shim for a venv without pip: %v", err)
	}

	writeScript(t, filepath.Join(venv, "bin", "python3.14"), "echo venv\n")
	writeScript(t, filepath.Join(dir, "pip3"), "echo own pip3\n")
	if err := os.Remove(filepath.Join(dir, "python3")); err != nil {
		t.Fatal(err)
	}
	if out := run(t, nil, "sh", "-c", workloadPythonShimRun(venv, dir, "")); !strings.Contains(out, "has its own "+filepath.Join(dir, "pip3")) {
		t.Fatalf("the base image's own pip3 was not kept: %q", out)
	}
	if got := run(t, nil, filepath.Join(dir, "pip3")); got != "own pip3\n" {
		t.Fatalf("pip3 = %q, want the base image's own", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "pip")); err != nil {
		t.Fatalf("pip shim: %v", err)
	}
}

// The image step names pip, and every harness image gets it (the step is
// one for all of them: image renderDockerfile adds it after each harness's
// own install steps).
func TestWorkloadPythonShimStepNamesPip(t *testing.T) {
	step := WorkloadPythonShimStep()
	if !strings.Contains(step.Comment, "pip and pip3") || !strings.Contains(step.Run, "for name in pip pip3;") {
		t.Fatalf("the step does not install the pip shims:\n%s\n%s", step.Comment, step.Run)
	}
}
