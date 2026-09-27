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

package image

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

func testSpec(h *harness.Spec) BuildSpec {
	return BuildSpec{Harness: h, UID: 1000, GID: 1000, IngressPort: 18971, DefenseClawVersion: "1.2.3", Repository: "e-defenseclaw-sandbox"}
}

func mustContext(t *testing.T, spec BuildSpec) *Context {
	t.Helper()
	c, err := NewContext(spec)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	return c
}

func TestContextTarIsDeterministic(t *testing.T) {
	for _, h := range []*harness.Spec{harness.ClaudeCode, harness.Codex} {
		first := mustContext(t, testSpec(h))
		second := mustContext(t, testSpec(h))
		a, err := first.Tar()
		if err != nil {
			t.Fatal(err)
		}
		b, err := second.Tar()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) || first.ContentHash != second.ContentHash || first.Tag != second.Tag {
			t.Fatalf("%s: context is not deterministic", h.Name)
		}
		if !regexp.MustCompile(`^e-defenseclaw-sandbox:` + h.Name + `-[0-9a-f]{16}-u1000$`).MatchString(first.Tag) {
			t.Fatalf("tag = %s", first.Tag)
		}

		tr := tar.NewReader(bytes.NewReader(a))
		var names []string
		files := map[string]ContextFile{}
		for _, f := range first.Files {
			files[f.Name] = f
		}
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			names = append(names, hdr.Name)
			if !hdr.ModTime.Equal(contextEpoch) || hdr.Uname != "" || hdr.Gname != "" {
				t.Fatalf("%s: non-deterministic header %+v", hdr.Name, hdr)
			}
			if hdr.Typeflag == tar.TypeDir {
				if hdr.Mode != 0o755 || hdr.Uid != 0 || hdr.Gid != 0 {
					t.Fatalf("dir %s header %+v", hdr.Name, hdr)
				}
				continue
			}
			want, ok := files[hdr.Name]
			if !ok {
				t.Fatalf("unexpected entry %s", hdr.Name)
			}
			body, _ := io.ReadAll(tr)
			if !bytes.Equal(body, want.Data) || hdr.Mode != int64(want.Mode) || hdr.Uid != want.UID || hdr.Gid != want.GID {
				t.Fatalf("%s: header/body mismatch (mode %o uid %d)", hdr.Name, hdr.Mode, hdr.Uid)
			}
		}
		for i := 1; i < len(names); i++ {
			if names[i-1] >= names[i] {
				t.Fatalf("entries not sorted: %s before %s", names[i-1], names[i])
			}
		}
		if names[0] != "Dockerfile" {
			t.Fatalf("first entry = %s", names[0])
		}
	}
}

func TestContentHashCoversEveryInput(t *testing.T) {
	base := mustContext(t, testSpec(harness.ClaudeCode))
	mutations := map[string]func(*BuildSpec){
		"uid":        func(s *BuildSpec) { s.UID = 1001 },
		"gid":        func(s *BuildSpec) { s.GID = 1001 },
		"ingress":    func(s *BuildSpec) { s.IngressPort = 18981 },
		"dc-version": func(s *BuildSpec) { s.DefenseClawVersion = "1.2.4" },
		"base":       func(s *BuildSpec) { s.BaseImage = "ghcr.io/example/base@sha256:" + strings.Repeat("a", 64) },
		"harness":    func(s *BuildSpec) { s.HarnessVersion = "2.1.160" },
	}
	for name, mutate := range mutations {
		spec := testSpec(harness.ClaudeCode)
		mutate(&spec)
		c := mustContext(t, spec)
		if c.ContentHash == base.ContentHash || c.Tag == base.Tag {
			t.Errorf("%s does not change the content hash", name)
		}
	}
	same := testSpec(harness.ClaudeCode)
	same.FailMode = "closed"
	if mustContext(t, same).ContentHash != base.ContentHash {
		t.Error("explicit closed fail mode must equal the default")
	}
	repo := testSpec(harness.ClaudeCode)
	repo.Repository = "other/repo"
	if c := mustContext(t, repo); c.ContentHash != base.ContentHash || !strings.HasPrefix(c.Tag, "other/repo:") {
		t.Error("the repository names the image but is not a content input")
	}
}

func TestNewContextRefusesUnsafeSpecs(t *testing.T) {
	cases := map[string]struct {
		mutate func(*BuildSpec)
		want   error
	}{
		"codex-base-0.117":   {func(s *BuildSpec) { s.Harness = harness.Codex; s.HarnessVersion = "0.117.0" }, ErrUnknownContract},
		"claude-old":         {func(s *BuildSpec) { s.HarnessVersion = "2.1.10" }, ErrUnknownContract},
		"no-harness":         {func(s *BuildSpec) { s.Harness = nil }, nil},
		"tag-base":           {func(s *BuildSpec) { s.BaseImage = "ghcr.io/nvidia/openshell-community/sandboxes/base:latest" }, nil},
		"root-uid":           {func(s *BuildSpec) { s.UID = 0 }, nil},
		"root-gid":           {func(s *BuildSpec) { s.GID = 0 }, nil},
		"bad-repo":           {func(s *BuildSpec) { s.Repository = "Upper/Case" }, nil},
		"repo-with-tag":      {func(s *BuildSpec) { s.Repository = "repo:tag" }, nil},
		"bad-dc-version":     {func(s *BuildSpec) { s.DefenseClawVersion = "1.0 beta" }, nil},
		"missing-dc-version": {func(s *BuildSpec) { s.DefenseClawVersion = "" }, nil},
		"bad-ingress":        {func(s *BuildSpec) { s.IngressPort = 0 }, nil},
		"fail-open":          {func(s *BuildSpec) { s.FailMode = "open" }, nil},
		"unknown-fail-mode":  {func(s *BuildSpec) { s.FailMode = "observe" }, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			spec := testSpec(harness.ClaudeCode)
			tc.mutate(&spec)
			_, err := NewContext(spec)
			if err == nil {
				t.Fatal("unsafe spec rendered")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDockerfileShape(t *testing.T) {
	c := mustContext(t, testSpec(harness.ClaudeCode))
	df := string(c.Dockerfile)
	for _, want := range []string{
		"FROM " + openshell.DefaultBaseImage + "\n",
		"USER root\n",
		`io.defenseclaw.hook-contract="claudecode-hooks-v1"`,
		"COPY --chown=1000:1000 --chmod=0600 files/sandbox/.claude.json /sandbox/.claude.json\n",
		"COPY --chown=0:0 --chmod=0644 files" + connector.ClaudeCodeSandboxDropInPath + " " + connector.ClaudeCodeSandboxDropInPath + "\n",
		"COPY --chown=0:0 --chmod=0755 files" + harness.ClaudeCodeLauncherPath + " " + harness.ClaudeCodeLauncherPath + "\n",
		"chown -R 1000:1000 /sandbox",
		"install -d -o root -g root -m 0755 /work",
		"\nUSER sandbox\n",
	} {
		if !strings.Contains(df, want) {
			t.Errorf("Dockerfile lacks %q", want)
		}
	}
	for _, f := range c.ImageFiles {
		if !strings.Contains(df, " files"+f.Path+" "+f.Path+"\n") {
			t.Errorf("no COPY for %s", f.Path)
		}
	}
	for _, forbidden := range []string{"ARG ", "ADD ", "# syntax", "curl -fsSL", LabelContentHash} {
		if strings.Contains(df, forbidden) {
			t.Errorf("Dockerfile contains %q", forbidden)
		}
	}
	if !strings.HasSuffix(df, "USER sandbox\n") {
		t.Error("Dockerfile must end as the unprivileged image user")
	}
	wantDirs := []string{"/etc/claude-code", "/etc/claude-code/managed-settings.d", "/usr/local/lib/defenseclaw", "/usr/local/lib/defenseclaw/bin", "/usr/local/lib/defenseclaw/hooks"}
	if strings.Join(c.Dirs, " ") != strings.Join(wantDirs, " ") {
		t.Fatalf("dirs = %v", c.Dirs)
	}
}

// goodProbeOutput synthesizes what a correct image prints for c.
func goodProbeOutput(c *Context) string {
	var b strings.Builder
	b.WriteString("noise before the header\n" + probeSchema + "\n")
	for _, f := range c.ImageFiles {
		sum := sha256.Sum256(f.Data)
		fmt.Fprintf(&b, "file %s %o %d %d %s\n", f.Path, uint32(f.Mode), f.UID, f.GID, hex.EncodeToString(sum[:]))
	}
	for _, d := range c.Dirs {
		fmt.Fprintf(&b, "dir %s 755 0 0\n", d)
	}
	digest := strings.Repeat("ab", 32)
	for _, bin := range c.Artifacts.Binaries {
		fmt.Fprintf(&b, "bin %s /usr/bin/%s %s\n", bin.Name, bin.Name, digest)
	}
	switch c.Spec.Harness.Name {
	case "claudecode":
		fmt.Fprintf(&b, "version %s (Claude Code)\n", c.HarnessVersion)
		fmt.Fprintf(&b, "net /opt/defenseclaw-harness/claudecode/bin/claude %s\n", digest)
	case "codex":
		fmt.Fprintf(&b, "version codex-cli %s\n", c.HarnessVersion)
		fmt.Fprintf(&b, "net /opt/defenseclaw-harness/codex/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-arm64/vendor/aarch64-unknown-linux-musl/bin/codex %s\n", digest)
	}
	b.WriteString("end\n")
	return b.String()
}

func TestParseProbeAndVerify(t *testing.T) {
	for _, h := range []*harness.Spec{harness.ClaudeCode, harness.Codex} {
		c := mustContext(t, testSpec(h))
		res, err := ParseProbe([]byte(goodProbeOutput(c)), h.Probe().VersionRE)
		if err != nil {
			t.Fatalf("%s: ParseProbe: %v", h.Name, err)
		}
		if err := c.Verify(res); err != nil {
			t.Fatalf("%s: Verify: %v", h.Name, err)
		}
		if res.HarnessVersion != c.HarnessVersion || len(res.NetworkBinary) != 1 || len(res.Binaries) != len(c.Artifacts.Binaries) {
			t.Fatalf("%s: parsed %+v", h.Name, res)
		}
	}
}

func TestVerifyRejectsDrift(t *testing.T) {
	c := mustContext(t, testSpec(harness.ClaudeCode))
	hook := connector.SandboxHookDir + "/claude-code-hook.sh"
	mutations := map[string]func(string) string{
		"missing-file":   func(s string) string { return dropLine(s, "file "+hook+" ") },
		"tampered-file":  func(s string) string { return replaceField(s, "file "+hook+" ", 5, strings.Repeat("0", 64)) },
		"writable-hook":  func(s string) string { return replaceField(s, "file "+hook+" ", 2, "777") },
		"user-owned":     func(s string) string { return replaceField(s, "file "+hook+" ", 3, "1000") },
		"preseed-root":   func(s string) string { return replaceField(s, "file /sandbox/.claude.json ", 3, "0") },
		"dir-writable":   func(s string) string { return replaceField(s, "dir "+connector.SandboxHookDir+" ", 2, "775") },
		"dir-missing":    func(s string) string { return dropLine(s, "dir /etc/claude-code/managed-settings.d ") },
		"no-jq":          func(s string) string { return dropLine(s, "bin jq ") },
		"wrong-version":  func(s string) string { return strings.Replace(s, "version 2.1.156", "version 2.1.157", 1) },
		"no-net-binary":  func(s string) string { return dropLine(s, "net ") },
		"version-absent": func(s string) string { return strings.Replace(s, "version 2.1.156 (Claude Code)", "version", 1) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			out := mutate(goodProbeOutput(c))
			if out == goodProbeOutput(c) {
				t.Fatal("mutation did not apply")
			}
			res, err := ParseProbe([]byte(out), harness.ClaudeCode.Probe().VersionRE)
			if err != nil {
				return
			}
			if err := c.Verify(res); err == nil {
				t.Fatal("drifted image verified")
			}
		})
	}
}

func TestParseProbeIsStrict(t *testing.T) {
	c := mustContext(t, testSpec(harness.Codex))
	good := goodProbeOutput(c)
	for name, out := range map[string]string{
		"no-header":      strings.Replace(good, probeSchema+"\n", "", 1),
		"no-end":         strings.Replace(good, "end\n", "", 1),
		"after-end":      good + "file /x 644 0 0 " + strings.Repeat("a", 64) + "\n",
		"unknown-record": strings.Replace(good, "end\n", "surprise 1\nend\n", 1),
		"bad-digest":     strings.Replace(good, "end\n", "net /usr/bin/x nothex\nend\n", 1),
		"bad-mode":       strings.Replace(good, "end\n", "dir /x 9z9 0 0\nend\n", 1),
		"path-injection": strings.Replace(good, "end\n", "bin x /usr/bin/x;rm "+strings.Repeat("a", 64)+"\nend\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseProbe([]byte(out), harness.Codex.Probe().VersionRE); err == nil {
				t.Fatal("malformed probe output parsed")
			}
		})
	}
}

func TestProbeRunArgsAreOffline(t *testing.T) {
	c := mustContext(t, testSpec(harness.ClaudeCode))
	args := probeRunArgs(c)
	joined := strings.Join(args, " ")
	for _, want := range []string{"run --rm --network none", "--user 1000:1000", "-e HOME=/sandbox", "-e DISABLE_AUTOUPDATER=1", "--entrypoint /bin/sh " + c.Tag + " -c"} {
		if !strings.Contains(joined, want) {
			t.Errorf("probe argv lacks %q", want)
		}
	}
	if !strings.Contains(args[len(args)-1], "printf 'end\\n'") {
		t.Error("probe script must print the end marker")
	}
}

func dropLine(s, prefix string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, prefix) {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// replaceField replaces whitespace field index field (0 is the record kind)
// of the line starting with prefix.
func replaceField(s, prefix string, field int, value string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, prefix) {
			fields := strings.Fields(line)
			fields[field] = value
			lines[i] = strings.Join(fields, " ")
		}
	}
	return strings.Join(lines, "\n")
}
