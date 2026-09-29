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
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// TestKiroInstallPreSeedsItsEmbeddingModel: the Kiro image unpacks the
// embedding model Kiro CLI 2.24.1 otherwise downloads at a new sandbox's
// first start, into the image HOME where Kiro looks for it, with every file
// pinned to the digest the pinned binary accepts.
func TestKiroInstallPreSeedsItsEmbeddingModel(t *testing.T) {
	steps, err := Kiro.InstallSteps("")
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 2 {
		t.Fatalf("Kiro has %d install steps, want the archive and the model", len(steps))
	}
	run := steps[1].Run
	if kiroModel.Dir != connector.SandboxHomeDir+"/.semantic_search/models/all-MiniLM-L6-v2" {
		t.Fatalf("model directory %s is not where Kiro looks for it", kiroModel.Dir)
	}
	for _, want := range []string{
		"url=" + shellQuote(kiroModel.URL), "dir=" + shellQuote(kiroModel.Dir),
		"curl -fsSL --proto '=https' --tlsv1.2", shellQuote(SupervisorInterpreter) + " -I -S",
		shellQuote("model.safetensors=90868376=53aa51172d142c89d9012cce15ae4d6cc0ca6895895114379cacb4fab128d9db"),
		shellQuote("tokenizer.json=466247=be50c3628f2bf5bb5e3a7f17b1f74611b2561a3a27eeab05e5aa30f411572037"),
	} {
		if !strings.Contains(run, want) {
			t.Errorf("model step lacks %q:\n%s", want, run)
		}
	}
	if strings.Contains(run, "\n") {
		t.Error("the model step spans lines; a Dockerfile RUN must stay one line")
	}
	shParses(t, "model step", run)
	for _, f := range kiroModel.Files {
		if !sha256HexRE.MatchString(f.SHA256) || f.Size <= 0 || strings.ContainsAny(f.Name, "/=") {
			t.Errorf("invalid Kiro model pin %+v", f)
		}
	}
}

// TestZipModelInstallChecksEveryFile runs a model step against a fake curl
// serving archives the test builds: only the pinned files, with the pinned
// sizes and digests, are written; any other archive fails the build and
// writes nothing; without the interpreter the step leaves the model to the
// harness and downloads nothing.
func TestZipModelInstallChecksEveryFile(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required")
	}
	for _, tool := range []string{"base64", "mktemp", "install"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is required", tool)
		}
	}
	weights, vocab := bytes.Repeat([]byte("w"), 4096), []byte(`{"vocab":{}}`)
	pin := zipModelPin{URL: "https://models.example/m.zip", Files: []zipModelFile{
		{Name: "model.safetensors", Size: int64(len(weights)), SHA256: sha256Hex(weights)},
		{Name: "tokenizer.json", Size: int64(len(vocab)), SHA256: sha256Hex(vocab)},
	}}
	pinned := map[string][]byte{"model.safetensors": weights, "tokenizer.json": vocab}
	for name, tc := range map[string]struct {
		members map[string][]byte
		python  string
		failure string
		skipped bool
	}{
		"pinned files":     {members: pinned},
		"extra member":     {members: map[string][]byte{"model.safetensors": weights, "tokenizer.json": vocab, "../evil": vocab}, failure: "model archive holds"},
		"missing member":   {members: map[string][]byte{"model.safetensors": weights}, failure: "model archive holds"},
		"other bytes":      {members: map[string][]byte{"model.safetensors": bytes.Repeat([]byte("x"), 4096), "tokenizer.json": vocab}, failure: "is not the pinned"},
		"other size":       {members: map[string][]byte{"model.safetensors": weights[:100], "tokenizer.json": vocab}, failure: "bytes, not the pinned"},
		"no interpreter":   {members: pinned, python: "/nonexistent/python3", skipped: true},
		"download failure": {failure: "curl: download failed"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			served := filepath.Join(dir, "served.zip")
			if tc.members != nil {
				var buf bytes.Buffer
				zw := zip.NewWriter(&buf)
				for member, data := range tc.members {
					w, err := zw.Create(member)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := w.Write(data); err != nil {
						t.Fatal(err)
					}
				}
				if err := zw.Close(); err != nil {
					t.Fatal(err)
				}
				writeFile(t, served, buf.Bytes())
			}
			// The fake curl copies the served archive to -o's file, and
			// fails as curl -f does when there is none.
			bin := filepath.Join(dir, "bin")
			if err := os.MkdirAll(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			writeExecutable(t, filepath.Join(bin, "curl"), "#!/bin/sh\necho called >"+shellQuote(dir+"/curl-called")+"\n"+
				"while [ $# -gt 0 ]; do if [ \"$1\" = -o ]; then out=\"$2\"; shift; fi; shift; done\n"+
				"[ -f "+shellQuote(served)+" ] || { echo 'curl: download failed' >&2; exit 22; }\n"+
				"cp "+shellQuote(served)+" \"$out\"\n")
			interp := python
			if tc.python != "" {
				interp = tc.python
			}
			target := filepath.Join(dir, "home", ".semantic_search", "models", "m")
			cmd := exec.Command("/bin/sh", "-c", pin.installRun(target, interp))
			cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "TMPDIR=" + dir}
			out, err := cmd.CombinedOutput()
			if tc.failure != "" {
				if err == nil || !strings.Contains(string(out), tc.failure) {
					t.Fatalf("the step passed or failed for another reason: %v\n%s", err, out)
				}
				for _, f := range pin.Files {
					if _, err := os.Stat(filepath.Join(target, f.Name)); err == nil {
						t.Errorf("%s was written from a refused archive", f.Name)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("model step: %v\n%s", err, out)
			}
			if tc.skipped {
				if !strings.Contains(string(out), "is not pre-seeded") {
					t.Errorf("the skipped step did not say so:\n%s", out)
				}
				if _, err := os.Stat(filepath.Join(dir, "curl-called")); err == nil {
					t.Error("the step downloaded a model it cannot unpack")
				}
				return
			}
			for _, f := range pin.Files {
				path := filepath.Join(target, f.Name)
				got, err := os.ReadFile(path)
				if err != nil || sha256Hex(got) != f.SHA256 {
					t.Errorf("%s: %v (sha256 %s, want %s)", f.Name, err, sha256Hex(got), f.SHA256)
				}
				if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o644 {
					t.Errorf("%s: mode %v, err %v", f.Name, info.Mode().Perm(), err)
				}
			}
			if entries, _ := os.ReadDir(target); len(entries) != len(pin.Files) {
				t.Errorf("the model directory holds %d entries, want %d: %v", len(entries), len(pin.Files), entries)
			}
		})
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
