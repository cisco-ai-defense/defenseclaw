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

// TestOpenCodeRefusalSaysHowToRemoveTheFileFromTheHost (cert
// opencode:OC-10): the launcher's refusal of a file inside the sandbox says
// how to remove it from the user's machine, with the sandbox's name and the
// path quoted for the shell (the printed rm removes exactly that file); a
// name that is not a sandbox name is not printed, and a refusal of
// something that is not a file keeps the plain advice.
func TestOpenCodeRefusalSaysHowToRemoveTheFileFromTheHost(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home, proj := filepath.Join(root, "home"), filepath.Join(root, "work", "proj")
	for _, dir := range []string{home, proj} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	planted := filepath.Join(home, ".config", "opencode", "plugins", "dce2e planted.js")
	writeFile(t, planted, []byte("export const Planted = async () => ({});\n"))
	l := newLauncher(t, OpenCode)
	const lead = "Remove it and start OpenCode again. From your machine: "

	r := l.run(t, proj, []string{"HOME=" + home, openshell.EnvSandboxName + "=oc-cert"}, "run", "hi")
	start := "defenseclaw sandbox start oc-cert && defenseclaw sandbox exec oc-cert -- rm "
	at := strings.Index(r.output, lead+start)
	end := strings.Index(r.output, ", then defenseclaw sandbox connect oc-cert.")
	if r.exit != 2 || r.started() || at < 0 || end < at {
		t.Fatalf("exit %d, want a refusal with the host commands:\n%s", r.exit, r.output)
	}
	// The printed path, run as a shell word, names the planted file.
	word := r.output[at+len(lead+start) : end]
	if out, err := exec.Command("/bin/bash", "-c", "rm "+word).CombinedOutput(); err != nil {
		t.Fatalf("rm %s: %v\n%s", word, err, out)
	}
	if _, err := os.Stat(planted); !os.IsNotExist(err) {
		t.Fatalf("the printed rm %s left the planted file (%v)", word, err)
	}

	writeFile(t, planted, []byte("export const Planted = async () => ({});\n"))
	r = l.run(t, proj, []string{"HOME=" + home, openshell.EnvSandboxName + "=x; rm -rf ~"}, "run", "hi")
	if r.exit != 2 || !strings.Contains(r.output, "defenseclaw sandbox exec <sandbox> -- rm ") || strings.Contains(r.output, "rm -rf") {
		t.Fatalf("exit %d, want the placeholder for a name that is not a sandbox name:\n%s", r.exit, r.output)
	}

	if err := os.Remove(planted); err != nil {
		t.Fatal(err)
	}
	r = l.run(t, proj, []string{"HOME=" + home, openshell.EnvSandboxName + "=oc-cert", `OPENCODE_CONFIG_CONTENT={"plugin":["p"]}`}, "run", "hi")
	if r.exit != 2 || !strings.Contains(r.output, "refusing to start OpenCode: OPENCODE_CONFIG_CONTENT registers plugins") ||
		!strings.HasSuffix(strings.TrimSpace(r.output), "Remove it and start OpenCode again.") {
		t.Fatalf("exit %d, want the plain advice for a refusal that names no file:\n%s", r.exit, r.output)
	}
}
