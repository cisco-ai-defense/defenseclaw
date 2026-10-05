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

package image

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

// testOwner is the store owner of testSpec and testStore.
const testOwner = "e0e0e0e0e0e0e0e0"

func testSpec(h *harness.Spec) BuildSpec {
	return BuildSpec{Harness: h, UID: 1000, GID: 1000, IngressPort: 18971, DefenseClawVersion: "1.2.3", Repository: "e-defenseclaw-sandbox", Owner: testOwner}
}

// testStore is an empty store whose owner is testOwner.
func testStore(t *testing.T) *Store {
	t.Helper()
	return testStoreOwnedBy(t, testOwner)
}

func testStoreOwnedBy(t *testing.T, owner string) *Store {
	t.Helper()
	store := NewStore(t.TempDir())
	if err := os.MkdirAll(filepath.Dir(store.Path()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.Path(), []byte(`{"version":1,"owner":"`+owner+`","images":[]}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return store
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
	for _, name := range harness.Names() {
		h, _ := harness.Get(name)
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
		"owner":      func(s *BuildSpec) { s.Owner = "f0f0f0f0f0f0f0f0" },
		"base":       func(s *BuildSpec) { s.BaseImage = "ghcr.io/example/base@sha256:" + strings.Repeat("a", 64) },
	}
	for name, mutate := range mutations {
		spec := testSpec(harness.ClaudeCode)
		mutate(&spec)
		c := mustContext(t, spec)
		if c.ContentHash == base.ContentHash || c.Tag == base.Tag {
			t.Errorf("%s does not change the content hash", name)
		}
	}
	// Every harness has a single pinned release, so another version cannot
	// render; the version is hashed all the same.
	if bumped := withHarnessVersion(t, base, "2.1.160"); bumped.ContentHash == base.ContentHash || bumped.Tag == base.Tag {
		t.Error("the harness version does not change the content hash")
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
		"no-owner":           {func(s *BuildSpec) { s.Owner = "" }, nil},
		"bad-owner":          {func(s *BuildSpec) { s.Owner = "../other" }, nil},
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
	wantDirs := []string{"/etc/claude-code", "/etc/claude-code/managed-settings.d", "/usr/local/lib/defenseclaw", "/usr/local/lib/defenseclaw/bin", "/usr/local/lib/defenseclaw/hooks", "/usr/local/lib/defenseclaw/shims"}
	if strings.Join(c.Dirs, " ") != strings.Join(wantDirs, " ") {
		t.Fatalf("dirs = %v", c.Dirs)
	}
}

// GAP-0030: the image names the run-as uid, so whoami works in the sandbox:
// the base image's sandbox user takes the uid and gid unless an entry has
// them already, and a second run changes nothing.
func TestRunAsUserStepNamesTheUID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the step runs in the Linux image; it uses GNU sed")
	}
	dir := t.TempDir()
	passwd, group := filepath.Join(dir, "passwd"), filepath.Join(dir, "group")
	for p, data := range map[string]string{
		passwd: "root:x:0:0:root:/root:/bin/bash\nsandbox:x:998:998:Sandbox:/home/sandbox:/bin/bash\n",
		group:  "root:x:0:\nsandbox:x:998:\n",
	} {
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if out, err := exec.Command("sh", "-c", runAsUserStep(1005, 1005, passwd, group)).CombinedOutput(); err != nil {
			t.Fatalf("step: %v %s", err, out)
		}
	}
	gotP, _ := os.ReadFile(passwd)
	gotG, _ := os.ReadFile(group)
	if !strings.Contains(string(gotP), "\nsandbox:x:1005:1005:Sandbox:/sandbox:/bin/bash\n") || !strings.Contains(string(gotG), "\nsandbox:x:1005:\n") {
		t.Fatalf("passwd = %q, group = %q", gotP, gotG)
	}
}

// TestDockerfileAnswersLocalhost pins AG-MAC-F1: an image for the MicroVM
// driver resolves localhost without /etc/hosts, which a MicroVM boots
// empty. The pinned nss-myhostname .deb of the build architecture is
// downloaded, checked with sha256sum -c and installed with dpkg -i as
// root, without a package index, before the harness is installed (so the
// harness's own version check already runs with it); it is asked right
// after files and before dns, and the build fails unless it answers
// localhost with 127.0.0.1. An image for the docker driver, whose sandboxes
// get Docker's /etc/hosts, has no such step: its Dockerfile, content hash
// and tag are what they were before MicroVM images, and its build needs no
// network beyond the harness's own pinned downloads.
func TestDockerfileAnswersLocalhost(t *testing.T) {
	step := localhostStep()
	for _, name := range harness.Names() {
		h, _ := harness.Get(name)
		docker := mustContext(t, testSpec(h))
		spec := testSpec(h)
		spec.MicroVM = true
		vm := mustContext(t, spec)
		if df := string(docker.Dockerfile); strings.Contains(df, "myhostname") || strings.Contains(df, "nsswitch") {
			t.Fatalf("%s: the docker driver's Dockerfile answers localhost itself:\n%s", name, df)
		}
		if vm.ContentHash == docker.ContentHash || vm.Tag == docker.Tag {
			t.Fatalf("%s: the MicroVM image shares the docker image's content hash %s (tag %s)", name, vm.ContentHash, vm.Tag)
		}
		df := string(vm.Dockerfile)
		at := strings.Index(df, step)
		if at < 0 || strings.Count(df, step) != 1 {
			t.Fatalf("%s: Dockerfile carries the localhost step %d times:\n%s", name, strings.Count(df, step), df)
		}
		// The MicroVM Dockerfile is the docker one with the step added.
		if strings.Replace(df, step, "", 1) != string(docker.Dockerfile) {
			t.Fatalf("%s: the MicroVM Dockerfile differs from the docker one by more than the localhost step:\n%s", name, df)
		}
		root, user := strings.Index(df, "USER root\n"), strings.LastIndex(df, "\nUSER sandbox\n")
		steps, err := h.InstallSteps(h.DefaultVersion)
		if err != nil {
			t.Fatal(err)
		}
		if root < 0 || root > at || user < at || len(steps) == 0 || strings.Index(df, "RUN "+steps[0].Run+"\n") < at {
			t.Fatalf("%s: the localhost step is not a root step before the harness install:\n%s", name, df)
		}
	}
	// Every architecture's pinned file, by URL and sha256, checked before
	// it is installed.
	if len(openshell.NSSMyhostnameDebs) != 2 {
		t.Fatalf("pinned architectures = %v", openshell.NSSMyhostnameDebs)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		deb, ok := openshell.NSSMyhostnameDebs[arch]
		if !ok {
			t.Fatalf("no pinned libnss-myhostname for %s", arch)
		}
		want := arch + ") want=" + shQuote(deb.SHA256) + "; urls=" + shQuote(strings.Join(deb.URLs, " ")) + " ;; "
		if !strings.Contains(step, want) {
			t.Errorf("localhost step lacks the %s pin %q:\n%s", arch, want, step)
		}
	}
	for _, want := range []string{
		// dpkg needs ldconfig and start-stop-daemon, which the base's
		// PATH leaves out.
		"RUN set -eu; PATH=" + connector.SandboxHookPATH + "; if ! getent -s hosts:myhostname hosts localhost >/dev/null 2>&1; then ",
		`arch="$(dpkg --print-architecture)"; case "$arch" in `,
		`*) echo "libnss-myhostname ` + openshell.NSSMyhostnameVersion + ` is pinned for amd64 and arm64 only, not $arch" >&2; exit 1 ;; esac; `,
		`curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$deb" "$url" && printf '%s  %s\n' "$want" "$deb" | sha256sum -c --status - && { ok=1; break; }; `,
		`[ -n "$ok" ] || { echo "could not download the pinned libnss-myhostname ` + openshell.NSSMyhostnameVersion + ` for $arch" >&2; exit 1; }; `,
		`dpkg -i "$deb"; rm -rf "$tmp"; fi; `,
		// The postinst appends myhostname after dns: it moves right after files.
		`s/[[:space:]]+myhostname([[:space:]]|$)/\1/g;s/^hosts:([[:space:]]+)files([[:space:]]|$)/hosts:\1files myhostname\2/`,
		`grep -Eq '^hosts:[[:space:]]+files myhostname([[:space:]]|$)' /etc/nsswitch.conf || `,
		`getent -s hosts:myhostname ahosts localhost | grep -q '^127\.0\.0\.1[[:space:]]' || `,
	} {
		if !strings.Contains(step, want) {
			t.Errorf("localhost step lacks %q:\n%s", want, step)
		}
	}
	// Only the pinned file and only loopback names: no package index, no
	// hosts file written and no resolver added.
	run := step[strings.Index(step, "\nRUN ")+1:]
	for _, forbidden := range []string{"apt-get", "apt ", "/etc/hosts", "/etc/resolv.conf", "nameserver", "mdns", "resolve "} {
		if strings.Contains(run, forbidden) {
			t.Errorf("localhost step contains %q", forbidden)
		}
	}
}

// The docker driver's content hash leaves the MicroVM flag out, so it is
// what it was before MicroVM images: the hash input carries "microvm"
// only for an image for the MicroVM driver.
func TestContentHashNamesOnlyMicroVMImages(t *testing.T) {
	for _, microVM := range []bool{false, true} {
		raw, err := json.Marshal(hashInput{Owner: testOwner, MicroVM: microVM})
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(string(raw), `"microvm"`); got != microVM {
			t.Fatalf("hash input for microVM=%t: %s", microVM, raw)
		}
	}
}

// TestContextCarriesShellEnvironment: every image carries the login-shell
// profile, the sandbox exec wrapper and the harness shim, root-owned, and
// leaves the system /etc/profile.d directory alone.
func TestContextCarriesShellEnvironment(t *testing.T) {
	for _, name := range harness.Names() {
		spec, _ := harness.Get(name)
		c := mustContext(t, testSpec(spec))
		want := map[string]os.FileMode{harness.SandboxProfilePath: 0o644, harness.SandboxEnvPath: 0o755, spec.ShimPath(): 0o755}
		for _, f := range c.ImageFiles {
			mode, ok := want[f.Path]
			if !ok {
				continue
			}
			if f.Owner != connector.SandboxOwnerRoot || f.UID != 0 || f.Mode != mode {
				t.Errorf("%s: %s owner %s uid %d mode %v", name, f.Path, f.Owner, f.UID, f.Mode)
			}
			delete(want, f.Path)
		}
		if len(want) > 0 {
			t.Errorf("%s image lacks %v", name, want)
		}
		if slices.Contains(c.Dirs, "/etc/profile.d") {
			t.Errorf("%s image re-owns /etc/profile.d", name)
		}
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
		realpath := "/usr/bin/" + bin.Name
		if bin.Role == connector.SandboxBinaryHarness {
			realpath = c.Spec.Harness.InstallRoot() + "/bin/" + bin.Name
		}
		fmt.Fprintf(&b, "bin %s %s %s 755 0 0\n", bin.Name, realpath, digest)
	}
	for _, name := range c.ImageBinaries {
		fmt.Fprintf(&b, "bin %s %s.12 %s 755 0 0\n", name, name, digest)
	}
	switch c.Spec.Harness.Name {
	case "claudecode":
		fmt.Fprintf(&b, "version %s (Claude Code)\n", c.HarnessVersion)
		fmt.Fprintf(&b, "net /opt/defenseclaw-harness/claudecode/bin/claude %s 755 0 0\n", digest)
	case "codex":
		fmt.Fprintf(&b, "version codex-cli %s\n", c.HarnessVersion)
		fmt.Fprintf(&b, "net /opt/defenseclaw-harness/codex/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-arm64/vendor/aarch64-unknown-linux-musl/bin/codex %s 755 0 0\n", digest)
	}
	b.WriteString("end\n")
	return b.String()
}

// TestHookOnlyHarnessContexts renders the OpenCode, Copilot CLI and Amp
// overlays: the pinned install, the connector's managed or user-scope hook
// registration with its owner, and the launcher.
func TestHookOnlyHarnessContexts(t *testing.T) {
	for _, tc := range []struct {
		h        *harness.Spec
		contract string
		files    map[string]int // in-image path -> expected uid
		install  string
	}{
		{harness.OpenCode, "opencode-hooks-v1", map[string]int{
			connector.OpenCodeSandboxManagedConfigPath: 0,
			connector.OpenCodeSandboxPluginPath:        0,
			harness.OpenCodeLauncherPath:               0,
		}, "'opencode-ai@1.18.31'"},
		{harness.Copilot, "copilot-hooks-v2", map[string]int{
			connector.CopilotSandboxPolicyPath:                 0,
			connector.CopilotSandboxManagedSettingsPath:        0,
			connector.SandboxHookDir + "/copilot-hook.sh":      0,
			connector.SandboxHomeDir + "/.copilot/config.json": 1000,
			harness.CopilotLauncherPath:                        0,
		}, "'@github/copilot@1.0.88'"},
		{harness.Amp, "amp-plugin-v1", map[string]int{
			connector.AmpSandboxPluginPath: 1000,
			harness.AmpLauncherPath:        0,
		}, "'@ampcode/cli@0.0.1785334225-g9abe75'"},
	} {
		t.Run(tc.h.Name, func(t *testing.T) {
			c := mustContext(t, testSpec(tc.h))
			if c.Contract != tc.contract || c.Artifacts.TamperTier != tc.h.TamperTier {
				t.Fatalf("contract %s tier %s", c.Contract, c.Artifacts.TamperTier)
			}
			got := map[string]int{}
			for _, f := range c.ImageFiles {
				got[f.Path] = f.UID
			}
			for path, uid := range tc.files {
				if owner, ok := got[path]; !ok || owner != uid {
					t.Errorf("%s: uid %d present %t, want uid %d", path, owner, ok, uid)
				}
			}
			if !strings.Contains(string(c.Dockerfile), tc.install) || !strings.Contains(string(c.Dockerfile), "sha256sum") {
				t.Fatalf("Dockerfile lacks the pinned install:\n%s", c.Dockerfile)
			}
		})
	}
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
		if res.HarnessVersion != c.HarnessVersion || len(res.NetworkBinary) != 1 || len(res.Binaries) != len(c.Artifacts.Binaries)+len(c.ImageBinaries) {
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
		"no-mktemp":      func(s string) string { return dropLine(s, "bin mktemp ") },
		"jq-in-home":     func(s string) string { return replaceField(s, "bin jq ", 2, "/sandbox/.local/bin/jq") },
		"curl-in-tmp":    func(s string) string { return replaceField(s, "bin curl ", 2, "/tmp/curl") },
		"sed-user-owned": func(s string) string { return replaceField(s, "bin sed ", 5, "1000") },
		"tr-group-owned": func(s string) string { return replaceField(s, "bin tr ", 6, "1000") },
		"head-writable":  func(s string) string { return replaceField(s, "bin head ", 4, "775") },
		"claude-in-work": func(s string) string { return replaceField(s, "bin claude ", 2, "/work/proj/claude") },
		// The supervisor's interpreter runs in place of every interactive
		// harness a terminal session starts.
		"python-in-home": func(s string) string {
			return replaceField(s, "bin "+harness.SupervisorInterpreter+" ", 2, "/sandbox/.local/bin/python3")
		},
		"python-user-owned": func(s string) string {
			return replaceField(s, "bin "+harness.SupervisorInterpreter+" ", 5, "1000")
		},
		"net-user-owned": func(s string) string { return replaceField(s, "net ", 4, "1000") },
		"net-writable":   func(s string) string { return replaceField(s, "net ", 3, "757") },
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

// TestVerifyAllowsAnImageWithoutPython3: a base image without the
// supervisor's interpreter still verifies (the launcher execs the harness
// without the supervisor), and the probe asks for it at the path the
// launcher execs.
func TestVerifyAllowsAnImageWithoutPython3(t *testing.T) {
	c := mustContext(t, testSpec(harness.ClaudeCode))
	if !slices.Contains(c.ImageBinaries, harness.SupervisorInterpreter) {
		t.Fatalf("image binaries %v lack %s", c.ImageBinaries, harness.SupervisorInterpreter)
	}
	if script := probeScript(c); !strings.Contains(script, "if [ -x "+shQuote(harness.SupervisorInterpreter)+" ]") {
		t.Fatalf("the probe does not look for %s:\n%s", harness.SupervisorInterpreter, script)
	}
	out := strings.Replace(dropLine(goodProbeOutput(c), "bin "+harness.SupervisorInterpreter+" "), "end\n", "nobin "+harness.SupervisorInterpreter+"\nend\n", 1)
	res, err := ParseProbe([]byte(out), harness.ClaudeCode.Probe().VersionRE)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(res); err != nil {
		t.Fatalf("an image without %s failed: %v", harness.SupervisorInterpreter, err)
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
		"path-injection": strings.Replace(good, "end\n", "bin x /usr/bin/x;rm "+strings.Repeat("a", 64)+" 755 0 0\nend\n", 1),
		"bin-no-owner":   strings.Replace(good, "end\n", "bin x /usr/bin/x "+strings.Repeat("a", 64)+"\nend\n", 1),
		"net-no-owner":   strings.Replace(good, "end\n", "net /usr/bin/x "+strings.Repeat("a", 64)+"\nend\n", 1),
		"bin-bad-owner":  strings.Replace(good, "end\n", "bin x /usr/bin/x "+strings.Repeat("a", 64)+" 755 root 0\nend\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseProbe([]byte(out), harness.Codex.Probe().VersionRE); err == nil {
				t.Fatal("malformed probe output parsed")
			}
		})
	}
}

// TestProbeScriptResolvesToolsOnTheHookPATH runs the probe script on this
// host with a workload-style PATH that shadows jq and curl: the hook tools
// must still resolve on the baked hook PATH, while the harness resolves on
// the workload PATH (where the image installs it).
func TestProbeScriptResolvesToolsOnTheHookPATH(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the probe script uses GNU stat and readlink")
	}
	for _, tool := range []string{"/usr/bin/jq", "/usr/bin/curl", "/usr/bin/sha256sum"} {
		if _, err := os.Stat(tool); err != nil {
			t.Skipf("%s is required", tool)
		}
	}
	c := mustContext(t, testSpec(harness.ClaudeCode))
	shadow := t.TempDir()
	for _, name := range []string{"jq", "curl", "claude"} {
		if err := os.WriteFile(filepath.Join(shadow, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("/bin/sh", "-c", probeScript(c))
	cmd.Env = []string{"PATH=" + shadow + ":/usr/local/bin:/usr/bin:/bin"}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("probe script: %v", err)
	}
	res, err := ParseProbe(out, harness.ClaudeCode.Probe().VersionRE)
	if err != nil {
		t.Fatalf("ParseProbe: %v\n%s", err, out)
	}
	for _, name := range []string{"jq", "curl"} {
		if got := res.Binaries[name].Realpath; strings.HasPrefix(got, shadow) || !strings.HasPrefix(got, "/usr/") {
			t.Errorf("%s resolved to %q, not on the hook PATH", name, got)
		}
	}
	if got := res.Binaries["claude"].Realpath; got != filepath.Join(shadow, "claude") {
		t.Errorf("claude resolved to %q, want the workload PATH entry", got)
	}
	if err := c.Verify(res); err == nil || !strings.Contains(err.Error(), "binary claude resolves to "+shadow) {
		t.Errorf("Verify accepted a harness binary the workload owns: %v", err)
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

// TestDockerfileCreatesUserDirs pins that the directories below HOME that
// hold user-tier hook files are created, owned by the run-as user and
// traversable, before the COPY that writes into them: BuildKit gives a
// directory COPY creates the file's --chmod mode (0600 would lock the
// workload out of its own ~/.openhands). Claude Code's only user-owned
// artifact sits directly in HOME.
func TestDockerfileCreatesUserDirs(t *testing.T) {
	for _, tc := range []struct {
		spec *harness.Spec
		dirs string
	}{
		{harness.ClaudeCode, ""},
		{harness.OpenCode, ""},
		{harness.Copilot, "/sandbox/.copilot"},
		{harness.Amp, "/sandbox/.config /sandbox/.config/amp /sandbox/.config/amp/plugins"},
		{harness.Hermes, "/sandbox/.hermes"},
		{harness.OpenHands, "/sandbox/.openhands"},
		{harness.Antigravity, "/sandbox/.gemini /sandbox/.gemini/antigravity-cli /sandbox/.gemini/antigravity-cli/cache /sandbox/.gemini/config"},
	} {
		c := mustContext(t, testSpec(tc.spec))
		df := string(c.Dockerfile)
		if strings.Join(c.UserDirs, " ") != tc.dirs {
			t.Fatalf("%s user dirs = %v, want %v", tc.spec.Name, c.UserDirs, tc.dirs)
		}
		if tc.dirs == "" {
			if strings.Contains(df, "RUN install -d -o 1000") {
				t.Fatalf("%s: unexpected user directories:\n%s", tc.spec.Name, df)
			}
			continue
		}
		if at := strings.Index(df, "RUN install -d -o 1000 -g 1000 -m 0755 "+tc.dirs+"\n"); at < 0 || at > strings.Index(df, "\nCOPY ") {
			t.Fatalf("%s user dirs are not created before the first COPY:\n%s", tc.spec.Name, df)
		}
	}
}
