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
	"strings"
	"testing"
)

// TestHermesSuspendShim runs the Ctrl-Z shim the Hermes image imports at
// start: Hermes' own suspend call, os.kill(0, SIGTSTP), returns with the
// supervisor's notice instead of raising (the sandbox refuses it), and
// every other kill() is untouched.
func TestHermesSuspendShim(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, hermesSuspendModuleName+".py"), []byte(hermesSuspendModule), 0o644); err != nil {
		t.Fatal(err)
	}
	script := `import os, signal, sys
sys.path.insert(0, sys.argv[1])
import ` + hermesSuspendModuleName + `
assert os.kill(0, signal.SIGTSTP) is None
os.kill(os.getpid(), 0)
try:
    os.kill(-1 << 30, signal.SIGTERM)
except (OSError, OverflowError):
    print("other kills unchanged")
`
	cmd := exec.Command(python, "-I", "-c", script, dir)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) != "other kills unchanged" {
		t.Fatalf("shim run = %v, stdout %q, stderr %q", err, out, stderr.String())
	}
	if !strings.Contains(stderr.String(), "defenseclaw: Ctrl-Z cannot suspend a harness in an OpenShell sandbox") {
		t.Fatalf("stderr %q lacks the notice", stderr.String())
	}
	// The install writes the shim and its .pth into the tool environment.
	steps, err := Hermes.InstallSteps("")
	if err != nil || len(steps) != 1 {
		t.Fatalf("install steps = %v, %v", steps, err)
	}
	run := steps[0].Run
	for _, want := range []string{
		base64.StdEncoding.EncodeToString([]byte(hermesSuspendModule)),
		hermesSuspendModuleName + ".py", `printf 'import ` + hermesSuspendModuleName + `\n'`, hermesSuspendModuleName + ".pth",
	} {
		if !strings.Contains(run, want) {
			t.Fatalf("the Hermes install does not write %q:\n%s", want, run)
		}
	}
	if strings.Contains(run, "\n") {
		t.Fatal("the Hermes install step spans lines (a Dockerfile RUN is one line)")
	}
}
