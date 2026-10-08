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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestWorkloadPythonStep (GAP-0196): the image step puts the shim into the
// standard library of the workload's own interpreter, imported from its
// sitecustomize (appended to one the base image has, once), so pip and
// every venv made from it load it; an interpreter that cannot take it does
// not stop the build.
func TestWorkloadPythonStep(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the step runs in Linux image builds")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required")
	}
	dir := t.TempDir()
	lib := filepath.Join(dir, "lib")
	if err := os.Mkdir(lib, 0o755); err != nil {
		t.Fatal(err)
	}
	// A python3 whose standard library is lib, and one that answers nothing.
	fake := filepath.Join(dir, "python3")
	broken := filepath.Join(dir, "broken")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho "+lib+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(broken, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lib, "sitecustomize.py"), []byte("BASE = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := workloadPythonRun(shellQuote(broken) + " " + shellQuote(fake) + " " + shellQuote(fake))
	if out, err := exec.Command("sh", "-c", run).CombinedOutput(); err != nil || !strings.Contains(string(out), broken+" keeps failing HTTPS") {
		t.Fatalf("step = %v:\n%s", err, out)
	}
	site, err := os.ReadFile(filepath.Join(lib, "sitecustomize.py"))
	if err != nil || !strings.HasPrefix(string(site), "BASE = 1\n") || strings.Count(string(site), "import "+pyPeerNameShimName) != 1 {
		t.Fatalf("sitecustomize.py = %q, %v", site, err)
	}
	out, err := exec.Command(python, "-I", "-S", "-c", "import sys; sys.path.insert(0, sys.argv[1]); import sitecustomize, socket; print(socket.socket.getpeername.__name__)", lib).CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "_defenseclaw_getpeername" {
		t.Fatalf("sitecustomize import = %v, %q", err, out)
	}
}

// TestPythonPeerNameShim runs the shim every Python harness imports at
// start against a getpeername() that answers as OpenShell's legacy broker
// does on Linux before 5.19 (EOPNOTSUPP): the ssl module wraps the socket
// instead of failing with Errno 95, an ENOTCONN still reaches the caller,
// and every Python harness's install writes the shim.
func TestPythonPeerNameShim(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the shim runs in Linux sandboxes")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, pyPeerNameShimName+".py"), []byte(pyPeerNameShim), 0o644); err != nil {
		t.Fatal(err)
	}
	script := `import errno, socket, ssl, sys
sys.path.insert(0, sys.argv[1])
answer = errno.EOPNOTSUPP
def broker(self):
    raise OSError(answer, "broker")
socket.socket.getpeername = broker
import ` + pyPeerNameShimName + `
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    print(s.getpeername())
    tls = ssl.create_default_context().wrap_socket(s, server_hostname="example.invalid", do_handshake_on_connect=False)
    print("wrapped")
    tls.close()
answer = errno.ENOTCONN
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    try:
        s.getpeername()
    except OSError as e:
        print("enotconn" if e.errno == errno.ENOTCONN else e)
`
	out, err := exec.Command(python, "-I", "-c", script, dir).CombinedOutput()
	if got, want := strings.TrimSpace(string(out)), "('0.0.0.0', 0)\nwrapped\nenotconn"; err != nil || got != want {
		t.Fatalf("shim run = %v, output %q, want %q", err, got, want)
	}
	if run := WorkloadPythonStep().Run; !strings.Contains(run, `"$(command -v python3 || true)" /usr/bin/python3`) {
		t.Fatalf("the workload Python step does not cover the image's python3: %s", run)
	}
	for _, spec := range []*Spec{Hermes, OpenHands, OmniGent} {
		steps, err := spec.InstallSteps("")
		if err != nil || len(steps) != 1 {
			t.Fatalf("%s install steps = %v, %v", spec.Name, steps, err)
		}
		for _, want := range []string{
			base64.StdEncoding.EncodeToString([]byte(pyPeerNameShim)),
			`printf 'import ` + pyPeerNameShimName + `\n' >"$site/` + pyPeerNameShimName + `.pth"`,
		} {
			if !strings.Contains(steps[0].Run, want) {
				t.Fatalf("the %s install does not write %q", spec.Name, want)
			}
		}
	}
}
