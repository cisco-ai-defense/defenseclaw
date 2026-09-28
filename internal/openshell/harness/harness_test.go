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
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
)

func artifactsFor(t *testing.T, spec *Spec) connector.SandboxArtifacts {
	t.Helper()
	a, err := spec.Provider.SandboxArtifacts(connector.SandboxRenderTarget{IngressPort: 18971, AgentVersion: spec.DefaultVersion})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// shParses reports a script /bin/sh cannot parse.
func shParses(t *testing.T, what, script string) {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		return
	}
	cmd := exec.Command("/bin/sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("%s does not parse: %v\n%s", what, err, out)
	}
}

func TestRegistry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenShell sandbox artifacts are not rendered on Windows hosts")
	}
	if want := []string{"amp", "antigravity", "claudecode", "codex", "copilot", "cursor", "devin", "hermes", "kiro", "omnigent", "opencode", "openhands"}; !slices.Equal(Names(), want) || !sort.StringsAreSorted(Names()) {
		t.Fatalf("Names() = %v, want %v", Names(), want)
	}
	catalog := map[string]bool{}
	for _, id := range profiles.IDs() {
		catalog[id] = true
	}
	// Every registered name has a default pin inside a reviewed hook
	// contract, a root-owned launcher, an install root and its evidence.
	for _, name := range Names() {
		spec, ok := Get(name)
		if !ok || spec.Name != name || spec.Provider == nil {
			t.Fatalf("Get(%s) = %#v, %t", name, spec, ok)
		}
		if err := CheckContract(name, spec.DefaultVersion); strings.TrimSpace(spec.DefaultVersion) == "" || err != nil {
			t.Fatalf("%s default pin %q: %v", name, spec.DefaultVersion, err)
		}
		if l := spec.Launcher(); spec.LauncherPath() != LauncherDir+"/"+name+"-launch" || l.Path != spec.LauncherPath() ||
			l.Owner != connector.SandboxOwnerRoot || l.Mode != 0o755 {
			t.Fatalf("%s launcher %s must be %s, root-owned 0755", name, l.Path, spec.LauncherPath())
		}
		if spec.InstallRoot() != InstallRootBase+"/"+name {
			t.Fatalf("%s install root = %s", name, spec.InstallRoot())
		}
		if len(spec.PreseedRefreshSteps()) == 0 || len(spec.UserCustomization()) == 0 {
			t.Fatalf("%s is missing preseed or customization metadata", name)
		}
		for _, c := range spec.UserCustomization() {
			if filepath.IsAbs(c.Host) || strings.Contains(c.Host, "..") || !strings.HasPrefix(c.Sandbox, connector.SandboxHomeDir+"/") {
				t.Fatalf("%s customization %#v escapes home", name, c)
			}
		}
		if spec.TamperTier != connector.SandboxTamperTierManaged && spec.TamperTier != connector.SandboxTamperTierUser ||
			artifactsFor(t, spec).TamperTier != spec.TamperTier {
			t.Fatalf("%s tamper tier %q does not match its artifacts", name, spec.TamperTier)
		}
		if v := spec.Verification(); v.Status != VerifiedLive && v.Status != Unverified || strings.TrimSpace(v.Note) == "" {
			t.Fatalf("%s verification %#v carries no status, evidence or reason", name, v)
		}
		for _, cp := range spec.CredentialProfiles("eu-west-1") {
			if !catalog[cp.ProfileID] || len(cp.Hosts) == 0 || strings.Contains(strings.Join(cp.Hosts, ","), "{") {
				t.Fatalf("%s profile %#v is not in the catalog or has unresolved hosts", name, cp)
			}
		}
		login, hasLogin := spec.Login()
		if len(spec.CredentialProfiles("")) == 0 && !hasLogin {
			t.Fatalf("%s has neither a credential profile nor an in-sandbox login", name)
		}
		// The login runs through the launcher, the only place the egress
		// proxy is exported (OpenShell refuses a connection around it).
		if hasLogin && (len(login.Argv) < 2 || login.Argv[0] != spec.LauncherPath() || strings.TrimSpace(login.Note) == "") {
			t.Fatalf("%s login %#v does not run through %s", name, login, spec.LauncherPath())
		}
	}
	// OpenClaw and ZeptoClaw use the shims subprocess policy.
	for _, name := range []string{"openclaw", "zeptoclaw"} {
		if _, ok := Get(name); ok {
			t.Fatalf("%s must not be registered as a sandbox harness", name)
		}
	}
	// What each harness was proven with. OpenCode's registration is managed,
	// but other plugins load into the same process; Cursor's enterprise
	// hooks.json is root-owned and its deny wins over user and project hooks.
	for spec, want := range map[*Spec][2]string{
		ClaudeCode: {connector.SandboxTamperTierManaged, VerifiedLive}, Codex: {connector.SandboxTamperTierManaged, VerifiedLive},
		OpenCode: {connector.SandboxTamperTierUser, VerifiedLive}, Copilot: {connector.SandboxTamperTierManaged, VerifiedLive},
		Amp: {connector.SandboxTamperTierUser, Unverified}, Cursor: {connector.SandboxTamperTierManaged, Unverified},
		Devin: {connector.SandboxTamperTierUser, Unverified}, Kiro: {connector.SandboxTamperTierUser, VerifiedLive},
	} {
		if got := [2]string{spec.TamperTier, spec.Verification().Status}; got != want {
			t.Errorf("%s: tier and status %v, want %v", spec.Name, got, want)
		}
	}
	// A caller cannot edit a registered login.
	login, _ := Kiro.Login()
	login.Argv[0] = "/tmp/evil"
	if again, _ := Kiro.Login(); again.Argv[0] != KiroLauncherPath {
		t.Fatalf("Login aliases the registered argv: %v", again.Argv)
	}
}

func TestInstallStepsPinContract(t *testing.T) {
	for _, tc := range []struct {
		name    string
		spec    *Spec
		version string
		want    []string // nil: the steps must not render
		wantErr error
	}{
		{"claude-base-relocate", ClaudeCode, "", []string{"readlink -f /usr/local/bin/claude"}, nil},
		// Inside the contract, but only the base image's release is pinned.
		{"claude-unpinned-digest", ClaudeCode, "2.1.160", nil, nil},
		{"claude-below-contract", ClaudeCode, "2.1.100", nil, ErrUnknownContract},
		{"codex-pin", Codex, "", []string{"@openai/codex@0.146.0"}, nil},
		{"codex-base-0.117", Codex, "0.117.0", nil, ErrUnknownContract},
		{"codex-not-exact", Codex, "latest", nil, nil},
		{"codex-range", Codex, ">=0.146", nil, nil},
		// Inside the contract, but DefenseClaw pinned no digests for it.
		{"codex-unpinned-digest", Codex, "0.150.0", nil, nil},
		{"opencode-pin", OpenCode, "", []string{"'opencode-ai@1.18.31'"}, nil},
		{"opencode-base-1.2.18", OpenCode, "1.2.18", nil, ErrUnknownContract},
		{"opencode-above-range", OpenCode, "1.19.2", nil, ErrUnknownContract},
		{"opencode-unpinned-digest", OpenCode, "1.18.20", nil, nil},
		{"copilot-pin", Copilot, "", []string{"'@github/copilot@1.0.88'"}, nil},
		{"copilot-base-1.0.16", Copilot, "1.0.16", nil, ErrUnknownContract},
		{"copilot-unpinned-digest", Copilot, "1.0.90", nil, nil},
		{"amp-pin", Amp, "", []string{"'@ampcode/cli@0.0.1785334225-g9abe75'"}, nil},
		{"amp-below-floor", Amp, "0.0.1785301270-g4f08a3", nil, ErrUnknownContract},
		{"amp-no-build-suffix", Amp, "0.0.1785334225", nil, nil},
		{"amp-latest", Amp, "latest", nil, nil},
		{"cursor-pin", Cursor, "", []string{"'https://downloads.cursor.com/lab/2026.07.23-e383d2b/linux/arm64/agent-cli-package.tar.gz'"}, nil},
		{"cursor-newer-build", Cursor, "2026.09.26-dd393fe", nil, ErrUnknownContract},
		{"cursor-desktop-version", Cursor, "3.13.0", nil, nil},
		{"kiro-pin", Kiro, "", []string{"'https://prod.download.cli.kiro.dev/stable/2.24.1/kirocli-x86_64-linux.tar.gz'"}, nil},
		{"kiro-older", Kiro, "2.22.0", nil, ErrUnknownContract},
		{"kiro-latest", Kiro, "latest", nil, nil},
		{"devin-pin", Devin, "", []string{"'https://static.devin.ai/cli/3000.4.25/devin-3000.4.25-aarch64-unknown-linux.tar.gz'"}, nil},
		{"devin-newer", Devin, "3000.12.0", nil, ErrUnknownContract},
		{"hermes-pin", Hermes, "", []string{"hermes-agent==0.19.0", "uv python install '3.12.13'", "--exclude-newer '2026-09-27T00:00:00Z'", "UV_NO_CONFIG=1", "is not the pinned"}, nil},
		{"hermes-below-contract", Hermes, "0.18.2", nil, ErrUnknownContract},
		{"hermes-above-contracts", Hermes, "0.22.0", nil, ErrUnknownContract},
		{"hermes-not-exact", Hermes, "latest", nil, nil},
		{"openhands-pin", OpenHands, "", []string{"'openhands==1.16.0'", "is not the pinned"}, nil},
		{"openhands-below-contract", OpenHands, "1.11.0", nil, ErrUnknownContract},
		{"antigravity-pin", Antigravity, "", []string{"sha512sum -c", "1.2.12-5784551402897408", "aarch64)", "x86_64)", "is not the pinned"}, nil},
		{"antigravity-below-contract", Antigravity, "1.1.7", nil, ErrUnknownContract},
		{"antigravity-unpinned-build", Antigravity, "1.2.13", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			steps, err := tc.spec.InstallSteps(tc.version)
			if tc.want == nil {
				if err == nil || tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want a refusal (%v) for an unreviewed or unpinned version", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			joined := ""
			for _, step := range steps {
				joined += step.Run + "\n"
			}
			// Every install verifies the pinned version inside its root.
			for _, want := range append(tc.want, "--version", tc.spec.InstallRoot()) {
				if !strings.Contains(joined, want) {
					t.Errorf("install steps lack %q:\n%s", want, joined)
				}
			}
			shParses(t, "install steps", joined)
		})
	}
}

// TestNpmPinnedInstallChecksDigests pins the checks every npm-installed
// harness runs: the downloaded tarball's SHA-512 against the pinned registry
// integrity before the install from that tarball, the native sha256 for
// both Linux architectures after, and the base image copy removed; Copilot's
// package is also unpacked root-owned at build.
func TestNpmPinnedInstallChecksDigests(t *testing.T) {
	for _, tc := range []struct {
		spec  *Spec
		pin   npmPin
		base  string
		extra []string
	}{
		{Codex, codexPin, "npm uninstall -g '@openai/codex'", nil},
		{OpenCode, openCodePin, "npm uninstall -g 'opencode-ai'", nil},
		{Copilot, copilotPin, "npm uninstall -g '@github/copilot'", []string{
			`COPILOT_PKG_CACHE_HOME="$cache" /usr/local/bin/copilot --version`, "'GitHub Copilot CLI 1.0.88.'",
			"-name .extraction-complete", `chown -R root:root "$cache"; chmod -R go-w "$cache"`,
		}},
		{Amp, ampPin, "", nil},
	} {
		t.Run(tc.spec.Name, func(t *testing.T) {
			steps, err := tc.spec.InstallSteps("")
			if err != nil {
				t.Fatal(err)
			}
			run := steps[0].Run
			sum, err := tc.pin.integritySHA512()
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range append([]string{
				`npm pack "$pkg"`, `sha512sum "$tgz"`, shellQuote(sum),
				`npm install -g --no-fund --no-audit --prefix "$root" "$tgz"`,
				"aarch64) bin=", "x86_64) bin=", shellQuote(tc.pin.Native["aarch64"].SHA256), shellQuote(tc.pin.Native["x86_64"].SHA256),
				`sha256sum "$bin"`, "ln -sfn \"$root/bin/" + tc.spec.Command + "\" /usr/local/bin/" + tc.spec.Command,
			}, tc.extra...) {
				if !strings.Contains(run, want) {
					t.Errorf("install steps lack %q:\n%s", want, run)
				}
			}
			if strings.Contains(run, `"$pkg";`) || strings.Contains(run, "npm view") {
				t.Errorf("the install does not come from the verified tarball: %s", run)
			}
			if (tc.base != "") != strings.Contains(run, "npm uninstall -g") || !strings.Contains(run, tc.base) {
				t.Errorf("base image copy handling: %s", run)
			}
			shParses(t, "install step", run)
		})
	}
	if err := (npmPin{Package: "x", Integrity: "sha512-short", Native: map[string]npmNative{"aarch64": {Path: "bin/x", SHA256: strings.Repeat("a", 64)}}}).validate(); err == nil {
		t.Fatal("malformed integrity accepted")
	}
	if err := (npmPin{Package: "x", Integrity: openCodePin.Integrity, Native: map[string]npmNative{"aarch64": {Path: "../x", SHA256: strings.Repeat("a", 64)}}}).validate(); err == nil {
		t.Fatal("escaping native path accepted")
	}
	if _, err := openCodePin.installRun("/opt/x", "1.18.20", "opencode", ""); err == nil {
		t.Fatal("a release without pinned digests rendered")
	}
}

// TestNpmPinnedInstallVerifiesTheTarball runs a pinned install against a
// fake npm whose registry serves the tarball and platform package the test
// chooses while its metadata names the pinned integrity (a registry can
// answer the two requests differently): the install must come from the
// downloaded tarball, and only when its SHA-512 is the pinned integrity and
// the native executable it installs has the pinned sha256.
func TestNpmPinnedInstallVerifiesTheTarball(t *testing.T) {
	// The install runs with PATH=<fake npm>:/usr/bin:/bin.
	for _, tool := range []string{"/bin/sh", "/usr/bin/sha512sum", "/usr/bin/sha256sum"} {
		if _, err := os.Stat(tool); err != nil {
			t.Skipf("%s is required", tool)
		}
	}
	pinned, native := []byte("the reviewed package tarball\n"), []byte("the reviewed native executable\n")
	tarSum, nativeSum := sha512.Sum512(pinned), sha256.Sum256(native)
	pin := npmPin{
		Package: "@dc-test/tool", Version: "1.0.0",
		Integrity: "sha512-" + base64.StdEncoding.EncodeToString(tarSum[:]),
		Native:    map[string]npmNative{},
	}
	// Every architecture this test may run on (arm64 is macOS's name).
	for _, arch := range []string{"aarch64", "arm64", "x86_64"} {
		pin.Native[arch] = npmNative{Path: "lib/node_modules/@dc-test/tool/bin/native", SHA256: hex.EncodeToString(nativeSum[:])}
	}
	run, err := pin.installRun("/opt/x", "1.0.0", "dctool", "")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		tarball, native []byte
		failure         string
	}{
		"pinned bytes":         {tarball: pinned, native: native},
		"other package bytes":  {tarball: []byte("a tarball the registry swapped in\n"), native: native, failure: "is not the pinned integrity"},
		"other platform bytes": {tarball: pinned, native: []byte("another executable\n"), failure: "is not the pinned"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			served := filepath.Join(dir, "served")
			writeFile(t, served+"/tool.tgz", tc.tarball)
			writeFile(t, served+"/native", tc.native)
			// The registry answers a metadata query with the pinned
			// integrity whatever it serves; npm pack writes the served
			// tarball to the working directory; npm install records its
			// arguments and lays out the package.
			bin := filepath.Join(dir, "bin")
			if err := os.MkdirAll(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			writeExecutable(t, bin+"/npm", "#!/bin/sh\ncase \"$1\" in\n"+
				"  view) echo "+shellQuote(pin.Integrity)+" ;;\n"+
				"  pack) cp "+shellQuote(served+"/tool.tgz")+" dc-test-tool-1.0.0.tgz ;;\n"+
				"  install) printf '%s\\n' \"$@\" >"+shellQuote(dir+"/install-args")+"; root=\"$6\"; mkdir -p \"$root/bin\" \"$root/lib/node_modules/@dc-test/tool/bin\"; "+
				"cp "+shellQuote(served+"/native")+" \"$root/lib/node_modules/@dc-test/tool/bin/native\" ;;\n"+
				"esac\n")
			script := strings.NewReplacer("root='/opt/x'", "root="+shellQuote(filepath.Join(dir, "root")), "install -d -o root -g root -m 0755", "install -d -m 0755",
				"/usr/local/bin/dctool", filepath.Join(dir, "dctool")).Replace(run)
			cmd := exec.Command("/bin/sh", "-c", script)
			cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "TMPDIR=" + dir}
			out, err := cmd.CombinedOutput()
			args, _ := os.ReadFile(filepath.Join(dir, "install-args"))
			if tc.failure != "" {
				if err == nil || !strings.Contains(string(out), tc.failure) {
					t.Fatalf("install passed or failed for another reason: %v\n%s", err, out)
				}
				if tc.failure == "is not the pinned integrity" && len(args) != 0 {
					t.Fatalf("npm install ran with an unverified tarball: %s", args)
				}
				return
			}
			if err != nil {
				t.Fatalf("install: %v\n%s", err, out)
			}
			lines := strings.Split(strings.TrimSpace(string(args)), "\n")
			if tgz := lines[len(lines)-1]; !strings.HasPrefix(tgz, dir+"/") || !strings.HasSuffix(tgz, "/dc-test-tool-1.0.0.tgz") {
				t.Fatalf("npm install got %q, not the downloaded tarball", lines)
			}
		})
	}
}

// TestTarballPinnedInstallChecksDigests pins the checks every archive-installed
// harness runs: an https-only download of the architecture's archive, its
// sha256 before anything is unpacked, a root-owned prefix, and the pinned
// version reported by the installed binary.
func TestTarballPinnedInstallChecksDigests(t *testing.T) {
	for _, tc := range []struct {
		spec    *Spec
		pin     tarballPin
		version string
	}{
		{Cursor, cursorPin, `[ "$got" = '2026.07.23-e383d2b' ]`},
		{Kiro, kiroPin, `[ "$got" = 'kiro-cli-chat 2.24.1' ]`},
		{Devin, devinPin, `[ "$got" = '3000.4.25' ]`},
	} {
		t.Run(tc.spec.Name, func(t *testing.T) {
			steps, err := tc.spec.InstallSteps("")
			if err != nil {
				t.Fatal(err)
			}
			run := steps[0].Run
			wants := []string{
				"curl -fsSL --proto '=https' --tlsv1.2",
				`got="$(sha256sum "$tmp/release.tar.gz" | cut -d' ' -f1)"`,
				`tar -xzf "$tmp/release.tar.gz" -C "$root" --no-same-owner --no-same-permissions`,
				`chown -R root:root "$root"`, "root=" + shellQuote(tc.spec.InstallRoot()), tc.version,
			}
			for _, arch := range []string{"aarch64", "x86_64"} {
				archive := tc.pin.Archives[arch]
				wants = append(wants, arch+") url="+shellQuote(archive.URL)+"; want="+shellQuote(archive.SHA256))
			}
			for _, want := range wants {
				if !strings.Contains(run, want) {
					t.Errorf("install step lacks %q:\n%s", want, run)
				}
			}
			// The digest check comes before the archive is unpacked.
			if check := strings.Index(run, `[ "$got" = "$want" ] || {`); check < 0 || check > strings.Index(run, "tar -xzf") {
				t.Error("the archive is unpacked before its digest is checked")
			}
			shParses(t, "install step", run)
		})
	}
	good := tarballArchive{URL: "https://example.com/tool-1.2.3.tar.gz", SHA256: strings.Repeat("a", 64)}
	for name, pin := range map[string]tarballPin{
		"plain-http":      {Version: "1.2.3", Archives: map[string]tarballArchive{"x86_64": {URL: "http://example.com/tool-1.2.3.tar.gz", SHA256: good.SHA256}}, DigestSource: "x"},
		"short-digest":    {Version: "1.2.3", Archives: map[string]tarballArchive{"x86_64": {URL: good.URL, SHA256: "abc"}}, DigestSource: "x"},
		"other-release":   {Version: "1.2.3", Archives: map[string]tarballArchive{"x86_64": {URL: "https://example.com/tool-9.9.9.tar.gz", SHA256: good.SHA256}}, DigestSource: "x"},
		"no-digest-note":  {Version: "1.2.3", Archives: map[string]tarballArchive{"x86_64": good}},
		"no-archives":     {Version: "1.2.3", DigestSource: "x"},
		"quote-in-url":    {Version: "1.2.3", Archives: map[string]tarballArchive{"x86_64": {URL: "https://example.com/tool-1.2.3'$(x).tar.gz", SHA256: good.SHA256}}, DigestSource: "x"},
		"bad-arch":        {Version: "1.2.3", Archives: map[string]tarballArchive{"x86_64;id": good}, DigestSource: "x"},
		"too-deep-strip":  {Version: "1.2.3", Archives: map[string]tarballArchive{"x86_64": good}, Strip: 9, DigestSource: "x"},
		"version-garbage": {Version: "1.2.3;rm", Archives: map[string]tarballArchive{"x86_64": good}, DigestSource: "x"},
	} {
		if err := pin.validate(); err == nil {
			t.Errorf("%s: invalid archive pin accepted", name)
		}
	}
	if _, err := kiroPin.installRun("/opt/x", "2.23.0"); err == nil {
		t.Fatal("a release without pinned archives rendered")
	}
}

func TestLaunchArgv(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec *Spec
		opts LaunchOptions
		want []string
	}{
		{"claude-interactive-yolo", ClaudeCode, LaunchOptions{Mode: Interactive, Yolo: true},
			[]string{ClaudeCodeLauncherPath, "--dangerously-skip-permissions"}},
		{"claude-interactive-safe", ClaudeCode, LaunchOptions{Mode: Interactive, Args: []string{"--model", "opus"}},
			[]string{ClaudeCodeLauncherPath, "--model", "opus"}},
		{"claude-headless", ClaudeCode, LaunchOptions{Mode: Headless, Yolo: true, Prompt: "fix the tests", Args: []string{"--output-format", "json"}},
			[]string{ClaudeCodeLauncherPath, "--dangerously-skip-permissions", "-p", "fix the tests", "--output-format", "json"}},
		{"codex-interactive-yolo", Codex, LaunchOptions{Mode: Interactive, Yolo: true},
			[]string{CodexLauncherPath, "--dangerously-bypass-approvals-and-sandbox"}},
		// Without Codex's own sandbox, untrusted is the policy that asks
		// before commands and edits (on-request never would).
		{"codex-interactive-safe", Codex, LaunchOptions{Mode: Interactive},
			[]string{CodexLauncherPath, "-c", `sandbox_mode="danger-full-access"`, "-c", `approval_policy="untrusted"`}},
		{"codex-headless-mantle", Codex, LaunchOptions{Mode: Headless, Yolo: true, Prompt: "p", CredentialProfile: profiles.CodexBedrockMantleID, BedrockRegion: "us-west-2", Args: []string{"-m", "openai.gpt-oss-20b"}},
			[]string{CodexLauncherPath, "exec", "--skip-git-repo-check", "--dangerously-bypass-approvals-and-sandbox",
				"-c", `model_provider="mantle"`, "-c", `model_providers.mantle.name="mantle"`,
				"-c", `model_providers.mantle.base_url="https://bedrock-mantle.us-west-2.api.aws/v1"`,
				"-c", `model_providers.mantle.env_key="BEDROCK_MANTLE_API_KEY"`, "-c", `model_providers.mantle.wire_api="responses"`,
				"--disable", "multi_agent", "-c", `web_search="disabled"`, "-m", "openai.gpt-oss-20b", "p"}},
		{"opencode-interactive-yolo", OpenCode, LaunchOptions{Mode: Interactive, Yolo: true}, []string{OpenCodeLauncherPath, "--auto"}},
		{"opencode-interactive-safe", OpenCode, LaunchOptions{Mode: Interactive, Args: []string{"-m", "anthropic/claude-haiku-4-5"}},
			[]string{OpenCodeLauncherPath, "-m", "anthropic/claude-haiku-4-5"}},
		{"opencode-headless-mantle", OpenCode, LaunchOptions{Mode: Headless, Yolo: true, Prompt: "fix it", CredentialProfile: profiles.OpenCodeBedrockMantleID, Args: []string{"--format", "json"}},
			[]string{OpenCodeLauncherPath, "run", "--auto", "--format", "json", "fix it"}},
		{"copilot-interactive-yolo", Copilot, LaunchOptions{Mode: Interactive, Yolo: true}, []string{CopilotLauncherPath, "--yolo"}},
		{"copilot-interactive-safe", Copilot, LaunchOptions{Mode: Interactive}, []string{CopilotLauncherPath}},
		{"copilot-headless-yolo", Copilot, LaunchOptions{Mode: Headless, Yolo: true, Prompt: "fix it", Args: []string{"--no-color"}},
			[]string{CopilotLauncherPath, "-p", "fix it", "--yolo", "--no-color"}},
		{"copilot-headless-safe", Copilot, LaunchOptions{Mode: Headless, Prompt: "fix it"},
			[]string{CopilotLauncherPath, "-p", "fix it", "--allow-all-tools"}},
		{"amp-interactive-yolo", Amp, LaunchOptions{Mode: Interactive, Yolo: true}, []string{AmpLauncherPath, "--dangerously-allow-all"}},
		{"amp-headless-yolo", Amp, LaunchOptions{Mode: Headless, Yolo: true, Prompt: "fix it", Args: []string{"-m", "high"}},
			[]string{AmpLauncherPath, "--dangerously-allow-all", "-m", "high", "--plugin-ready-timeout", "30", "-x", "fix it"}},
		{"amp-headless-safe", Amp, LaunchOptions{Mode: Headless, Prompt: "fix it"},
			[]string{AmpLauncherPath, "--plugin-ready-timeout", "30", "-x", "fix it"}},
		{"cursor-interactive-yolo", Cursor, LaunchOptions{Mode: Interactive, Yolo: true},
			[]string{CursorLauncherPath, "--trust", "--sandbox", "disabled", "--force"}},
		{"cursor-headless-yolo", Cursor, LaunchOptions{Mode: Headless, Yolo: true, Prompt: "fix it", Args: []string{"--model", "sonnet-4"}},
			[]string{CursorLauncherPath, "--trust", "--sandbox", "disabled", "--force", "-p", "--output-format", "text", "--model", "sonnet-4", "fix it"}},
		{"cursor-headless-safe", Cursor, LaunchOptions{Mode: Headless, Prompt: "fix it", CredentialProfile: profiles.CursorID},
			[]string{CursorLauncherPath, "--trust", "--sandbox", "disabled", "-p", "--output-format", "text", "fix it"}},
		{"kiro-interactive-yolo", Kiro, LaunchOptions{Mode: Interactive, Yolo: true}, []string{KiroLauncherPath, "--trust-all-tools"}},
		{"kiro-headless-yolo", Kiro, LaunchOptions{Mode: Headless, Yolo: true, Prompt: "fix it", Args: []string{"--model", "claude-sonnet-4"}},
			[]string{KiroLauncherPath, "--no-interactive", "--trust-all-tools", "--model", "claude-sonnet-4", "fix it"}},
		{"kiro-headless-safe", Kiro, LaunchOptions{Mode: Headless, Prompt: "fix it", CredentialProfile: profiles.KiroID},
			[]string{KiroLauncherPath, "--no-interactive", "fix it"}},
		{"devin-interactive-yolo", Devin, LaunchOptions{Mode: Interactive, Yolo: true}, []string{DevinLauncherPath, "--permission-mode", "dangerous"}},
		{"devin-headless-yolo", Devin, LaunchOptions{Mode: Headless, Yolo: true, Prompt: "fix it", Args: []string{"--model", "opus"}},
			[]string{DevinLauncherPath, "--permission-mode", "dangerous", "--model", "opus", "-p", "fix it"}},
		{"devin-headless-safe", Devin, LaunchOptions{Mode: Headless, Prompt: "fix it"}, []string{DevinLauncherPath, "-p", "fix it"}},
		{"hermes-interactive-yolo", Hermes, LaunchOptions{Mode: Interactive, Yolo: true}, []string{HermesLauncherPath, "--yolo"}},
		{"hermes-headless-mantle", Hermes, LaunchOptions{Mode: Headless, Yolo: true, Prompt: "fix it", CredentialProfile: profiles.BedrockMantleOpenAIID, Args: []string{"-m", "openai.gpt-oss-20b"}},
			[]string{HermesLauncherPath, "chat", "-q", "fix it", "-Q", "--yolo", "--provider", "defenseclaw", "-m", "openai.gpt-oss-20b"}},
		{"hermes-safe-anthropic", Hermes, LaunchOptions{Mode: Interactive, CredentialProfile: profiles.AnthropicID},
			[]string{HermesLauncherPath, "--provider", "anthropic"}},
		{"openhands-headless-yolo", OpenHands, LaunchOptions{Mode: Headless, Yolo: true, Prompt: "p", CredentialProfile: profiles.OpenAIID},
			[]string{OpenHandsLauncherPath, "--headless", "--exit-without-confirmation", "-t", "p", "--always-approve", "--override-with-envs"}},
		{"openhands-interactive-safe", OpenHands, LaunchOptions{Mode: Interactive}, []string{OpenHandsLauncherPath}},
		{"antigravity-headless-yolo", Antigravity, LaunchOptions{Mode: Headless, Yolo: true, Prompt: "p", CredentialProfile: profiles.GeminiID},
			[]string{AntigravityLauncherPath, "-p", "p", "--dangerously-skip-permissions"}},
		{"antigravity-interactive", Antigravity, LaunchOptions{Mode: Interactive, Args: []string{"--model", "gemini-3.1-pro"}},
			[]string{AntigravityLauncherPath, "--model", "gemini-3.1-pro"}},
		// The OmniGent sandbox agent names no model: a credential profile
		// brings its default, or the caller passes one.
		{"omnigent-headless-mantle", OmniGent, LaunchOptions{Mode: Headless, Prompt: "p", CredentialProfile: profiles.BedrockMantleOpenAIID},
			[]string{OmniGentLauncherPath, "run", "-p", "p", "--model", omnigentMantleModel}},
		{"omnigent-mantle-own-model", OmniGent, LaunchOptions{Mode: Interactive, CredentialProfile: profiles.BedrockMantleOpenAIID, Args: []string{"--model=openai.gpt-oss-120b"}},
			[]string{OmniGentLauncherPath, "run", "--model=openai.gpt-oss-120b"}},
		{"omnigent-openai-model", OmniGent, LaunchOptions{Mode: Interactive, CredentialProfile: profiles.OpenAIID, Args: []string{"--model", "gpt-5-mini"}},
			[]string{OmniGentLauncherPath, "run", "--model", "gpt-5-mini"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.spec.LaunchArgv(tc.opts)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("argv =\n%q (%v)\nwant\n%q", got, err, tc.want)
			}
		})
	}
	for name, tc := range map[string]struct {
		spec *Spec
		opts LaunchOptions
	}{
		"headless-no-prompt":       {ClaudeCode, LaunchOptions{Mode: Headless}},
		"unknown-mode":             {ClaudeCode, LaunchOptions{Mode: "detached"}},
		"foreign-profile":          {ClaudeCode, LaunchOptions{Mode: Interactive, CredentialProfile: profiles.OpenAIID}},
		"antigravity-openai":       {Antigravity, LaunchOptions{Mode: Interactive, CredentialProfile: profiles.OpenAIID}},
		"omnigent-openai-no-model": {OmniGent, LaunchOptions{Mode: Interactive, CredentialProfile: profiles.OpenAIID}},
	} {
		if _, err := tc.spec.LaunchArgv(tc.opts); err == nil || name == "omnigent-openai-no-model" && !strings.Contains(err.Error(), "--model") {
			t.Errorf("%s: launch argv rendered or the error does not say what is missing: %v", name, err)
		}
	}
}

// TestEnv pins the create-time environment of each harness and credential
// profile: the provider settings, the proxy exported under the names the
// launchers restore it from (none for a strict sandbox without a proxy URL),
// the hosts that bypass the proxy so OpenShell can inject credentials, and
// no secret-bearing variable (those come from providers, never --env).
func TestEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenShell sandbox artifacts are not rendered on Windows hosts")
	}
	const proxy = "http://b1:secret@host.openshell.internal:18972"
	mantleWest := "bedrock-mantle.us-west-2.api.aws,host.openshell.internal"
	for _, tc := range []struct {
		name string
		spec *Spec
		opts EnvOptions // Artifacts are the spec's own
		want map[string]string
	}{
		{"claudecode mantle", ClaudeCode, EnvOptions{SandboxID: "sb-1", SandboxName: "dc-claudecode-myapp-7f3a", EgressProxyURL: proxy,
			CredentialProfile: profiles.ClaudeBedrockMantleID, BedrockRegion: "us-east-1"}, map[string]string{
			"DISABLE_AUTOUPDATER": "1", "DEFENSECLAW_SANDBOX_ID": "sb-1", "DEFENSECLAW_SANDBOX_NAME": "dc-claudecode-myapp-7f3a",
			"http_proxy": proxy, "NODE_USE_ENV_PROXY": "1", "ANTHROPIC_BASE_URL": "https://bedrock-mantle.us-east-1.api.aws/anthropic",
			"CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS": "1", "NO_PROXY": "bedrock-mantle.us-east-1.api.aws,host.openshell.internal",
		}},
		{"codex strict", Codex, EnvOptions{CredentialProfile: profiles.OpenAIID}, map[string]string{"NO_PROXY": "api.openai.com,host.openshell.internal"}},
		{"opencode mantle", OpenCode, EnvOptions{EgressProxyURL: proxy, CredentialProfile: profiles.OpenCodeBedrockMantleID, BedrockRegion: "us-west-2"}, map[string]string{
			"OPENCODE_DISABLE_AUTOUPDATE": "1", "NO_PROXY": mantleWest,
			"OPENCODE_CONFIG_CONTENT": strings.ReplaceAll(openCodeMantleConfig, bedrockHostToken, "bedrock-mantle.us-west-2.api.aws"),
		}},
		{"opencode anthropic", OpenCode, EnvOptions{EgressProxyURL: proxy, CredentialProfile: profiles.OpenCodeAnthropicID},
			map[string]string{"OPENCODE_DISABLE_AUTOUPDATE": "1", "NO_PROXY": "api.anthropic.com,host.openshell.internal"}},
		// A Copilot BYOK profile must run offline; the GitHub-token one cannot.
		{"copilot mantle", Copilot, EnvOptions{EgressProxyURL: proxy, CredentialProfile: profiles.CopilotBedrockMantleID, BedrockRegion: "us-west-2"}, map[string]string{
			"COPILOT_AUTO_UPDATE": "false", "COPILOT_PKG_CACHE_HOME": CopilotPackageCache, "COPILOT_OFFLINE": "true",
			"COPILOT_PROVIDER_BASE_URL": "https://bedrock-mantle.us-west-2.api.aws/anthropic", "COPILOT_PROVIDER_TYPE": "anthropic",
			"COPILOT_PROVIDER_MODEL_ID": "claude-haiku-4.5", "COPILOT_PROVIDER_WIRE_MODEL": "anthropic.claude-haiku-4-5", "NO_PROXY": mantleWest,
		}},
		{"copilot github", Copilot, EnvOptions{EgressProxyURL: proxy, CredentialProfile: profiles.CopilotGitHubID}, map[string]string{
			"COPILOT_AUTO_UPDATE": "false", "COPILOT_OFFLINE": "",
			"NO_PROXY": "api.business.githubcopilot.com,api.enterprise.githubcopilot.com,api.github.com,api.githubcopilot.com,api.individual.githubcopilot.com,host.openshell.internal",
		}},
		{"amp", Amp, EnvOptions{EgressProxyURL: proxy, CredentialProfile: profiles.AmpID},
			map[string]string{"AMP_SKIP_UPDATE_CHECK": "1", "NO_PROXY": "ampcode.com,host.openshell.internal"}},
		{"cursor", Cursor, EnvOptions{EgressProxyURL: proxy, CredentialProfile: profiles.CursorID},
			map[string]string{"NO_PROXY": "api2.cursor.sh,api3.cursor.sh,host.openshell.internal,repo42.cursor.sh"}},
		{"kiro", Kiro, EnvOptions{EgressProxyURL: proxy, CredentialProfile: profiles.KiroID}, map[string]string{
			connector.KiroSandboxAgentDirEnv: connector.KiroSandboxAgentDir,
			"NO_PROXY":                       "host.openshell.internal,management.us-east-1.kiro.dev,prod.us-east-1.auth.desktop.kiro.dev,q.us-east-1.amazonaws.com,runtime.us-east-1.kiro.dev",
		}},
		{"hermes mantle", Hermes, EnvOptions{CredentialProfile: profiles.BedrockMantleOpenAIID, BedrockRegion: "us-west-2"}, map[string]string{
			connector.HermesSandboxProviderBaseURLEnv: "https://bedrock-mantle.us-west-2.api.aws/v1", "NO_PROXY": mantleWest,
		}},
		{"openhands mantle", OpenHands, EnvOptions{CredentialProfile: profiles.BedrockMantleOpenAIID},
			map[string]string{"LLM_BASE_URL": "https://bedrock-mantle.us-east-1.api.aws/v1", "OPENHANDS_SUPPRESS_BANNER": "1"}},
		{"antigravity gemini", Antigravity, EnvOptions{CredentialProfile: profiles.GeminiID},
			map[string]string{"NO_PROXY": "generativelanguage.googleapis.com,host.openshell.internal"}},
		{"omnigent mantle", OmniGent, EnvOptions{CredentialProfile: profiles.BedrockMantleOpenAIID, BedrockRegion: "eu-west-1"},
			map[string]string{"OPENAI_BASE_URL": "https://bedrock-mantle.eu-west-1.api.aws/v1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			opts.Artifacts = artifactsFor(t, tc.spec)
			env, err := tc.spec.Env(opts)
			if err != nil {
				t.Fatal(err)
			}
			for key, value := range tc.want {
				if env[key] != value {
					t.Errorf("env[%s] = %q, want %q", key, env[key], value)
				}
			}
			if env[openshell.EnvEgressBypass] != env["NO_PROXY"] {
				t.Errorf("%s = %q, NO_PROXY = %q", openshell.EnvEgressBypass, env[openshell.EnvEgressBypass], env["NO_PROXY"])
			}
			for _, key := range []string{"HTTPS_PROXY", openshell.EnvEgressURL} {
				if env[key] != opts.EgressProxyURL {
					t.Errorf("env[%s] = %q, want %q", key, env[key], opts.EgressProxyURL)
				}
			}
			for key := range env {
				if strings.Contains(key, "TOKEN") || strings.Contains(key, "API_KEY") {
					t.Errorf("secret-bearing variable %s must come from a provider, not --env", key)
				}
			}
		})
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(openCodeMantleConfig), &cfg); err != nil || !strings.Contains(openCodeMantleConfig, `"apiKey":"{env:BEDROCK_MANTLE_API_KEY}"`) {
		t.Fatalf("the OpenCode Mantle config must be JSON reading the key placeholder at runtime: %v", err)
	}
	claude := artifactsFor(t, ClaudeCode)
	for _, tc := range []struct {
		name string
		spec *Spec
		opts EnvOptions
	}{
		{"foreign artifacts", Codex, EnvOptions{Artifacts: claude}},
		{"non-http proxy", ClaudeCode, EnvOptions{Artifacts: claude, EgressProxyURL: "socks5://x"}},
		{"foreign profile", ClaudeCode, EnvOptions{Artifacts: claude, CredentialProfile: profiles.OpenAIID}},
	} {
		if _, err := tc.spec.Env(tc.opts); err == nil {
			t.Errorf("%s accepted", tc.name)
		}
	}
}

func TestProbeVersionPatterns(t *testing.T) {
	for _, tc := range []struct {
		spec *Spec
		out  string
		want string
	}{
		{ClaudeCode, "2.1.156 (Claude Code)\n", "2.1.156"},
		{Codex, "codex-cli 0.146.0\n", "0.146.0"},
		{OpenCode, "1.18.31", "1.18.31"},
		// The probe keeps only [A-Za-z0-9 ._()+-] of the first line.
		{Copilot, "GitHub Copilot CLI 1.0.88.", "1.0.88"},
		{Amp, "0.0.1785334225-g9abe75 (released 2026-07-29T141025.000Z 1mo ago)", "0.0.1785334225-g9abe75"},
		{Cursor, "2026.07.23-e383d2b", "2026.07.23-e383d2b"},
		{Kiro, "kiro-cli-chat 2.24.1", "2.24.1"},
		{Devin, "devin 3000.4.25 (7e8e528a)", "3000.4.25"},
		{Hermes, "Hermes Agent v0.19.0 (2026.7.20)\n", "0.19.0"},
		{OpenHands, "OpenHands CLI 1.16.0\n", "1.16.0"},
		{Antigravity, "1.2.12\n", "1.2.12"},
	} {
		if m := tc.spec.Probe().VersionRE.FindStringSubmatch(strings.TrimSpace(tc.out)); len(m) != 2 || m[1] != tc.want {
			t.Errorf("%s version pattern on %q = %v", tc.spec.Name, tc.out, m)
		}
	}
	if !strings.Contains(Hermes.Probe().NetworkBinaries, "/opt/defenseclaw-harness/hermes/tools/hermes-agent/bin/python") {
		t.Fatalf("hermes network binary probe = %s", Hermes.Probe().NetworkBinaries)
	}
}

func TestBypassArgs(t *testing.T) {
	for _, tc := range []struct {
		name          string
		spec          *Spec
		args          []string
		kept, dropped []string
	}{
		{"claude flags", ClaudeCode,
			[]string{"--model", "opus", "--dangerously-skip-permissions", "--allow-dangerously-skip-permissions", "-p", "x"},
			[]string{"--model", "opus", "-p", "x"}, []string{"--dangerously-skip-permissions", "--allow-dangerously-skip-permissions"}},
		{"claude permission mode", ClaudeCode,
			[]string{"--permission-mode", "bypassPermissions", "--permission-mode=bypassPermissions", "--permission-mode", "plan"},
			[]string{"--permission-mode", "plan"}, []string{"--permission-mode", "bypassPermissions", "--permission-mode=bypassPermissions"}},
		{"claude after double dash", ClaudeCode, []string{"--", "--dangerously-skip-permissions"}, []string{"--", "--dangerously-skip-permissions"}, nil},
		{"claude inline value on a bare flag", ClaudeCode, []string{"--dangerously-skip-permissions=true"}, []string{"--dangerously-skip-permissions=true"}, nil},
		{"claude trailing valued flag", ClaudeCode, []string{"--permission-mode"}, []string{"--permission-mode"}, nil},
		{"codex flags", Codex, []string{"--dangerously-bypass-approvals-and-sandbox", "--yolo", "-m", "gpt"},
			[]string{"-m", "gpt"}, []string{"--dangerously-bypass-approvals-and-sandbox", "--yolo"}},
		{"codex approval", Codex,
			[]string{"-a", "never", "--ask-for-approval=never", "-a", "on-request", "-c", `approval_policy="never"`, "--config", "approval_policy = 'never'", "-c", `approval_policy="untrusted"`, "-c", `model="x"`},
			[]string{"-a", "on-request", "-c", `approval_policy="untrusted"`, "-c", `model="x"`},
			[]string{"-a", "never", "--ask-for-approval=never", "-c", `approval_policy="never"`, "--config", "approval_policy = 'never'"}},
		{"codex keeps claude flags", Codex, []string{"--dangerously-skip-permissions"}, []string{"--dangerously-skip-permissions"}, nil},
		{"codex full auto", Codex, []string{"--full-auto"}, []string{}, []string{"--full-auto"}},
		{"opencode auto", OpenCode, []string{"run", "--auto", "hi"}, []string{"run", "hi"}, []string{"--auto"}},
		{"copilot allow all", Copilot, []string{"--yolo", "--allow-all", "--allow-all-tools", "--model", "claude-sonnet-4.5"},
			[]string{"--model", "claude-sonnet-4.5"}, []string{"--yolo", "--allow-all", "--allow-all-tools"}},
		{"amp allow all", Amp, []string{"--dangerously-allow-all", "-x", "hi"}, []string{"-x", "hi"}, []string{"--dangerously-allow-all"}},
		{"cursor force", Cursor, []string{"--force", "-p", "hi"}, []string{"-p", "hi"}, []string{"--force"}},
		{"kiro trust all", Kiro, []string{"--trust-all-tools", "--trust-tools=fs_read"}, []string{"--trust-tools=fs_read"}, []string{"--trust-all-tools"}},
		// clap joins boolean short flags (-r, -l, -v, -h); -f, -d and -w
		// take the rest of the cluster as their value.
		{"kiro trust all short", Kiro,
			[]string{"-a", "-va", "-rva", "-av", "-f", "json", "-fa", "-wa", "-v", "--", "-a"},
			[]string{"-f", "json", "-fa", "-wa", "-v", "--", "-a"}, []string{"-a", "-va", "-rva", "-av"}},
		{"devin permission mode", Devin,
			[]string{"--permission-mode", "dangerous", "--permission-mode=autonomous", "--permission-mode", "auto"},
			[]string{"--permission-mode", "auto"}, []string{"--permission-mode", "dangerous", "--permission-mode=autonomous"}},
		{"hermes yolo prefixes", Hermes, []string{"--y", "--yo", "--yol", "--yolo", "-m", "m"}, []string{"-m", "m"}, []string{"--y", "--yo", "--yol", "--yolo"}},
		{"hermes other options", Hermes, []string{"--yes", "--yolo-extra", "--", "--yolo"}, []string{"--yes", "--yolo-extra", "--", "--yolo"}, nil},
		{"openhands approve prefixes", OpenHands,
			[]string{"--a", "--always", "--always-approve", "--y", "--yolo", "--ll", "--llm-approve", "-t", "x"},
			[]string{"-t", "x"}, []string{"--a", "--always", "--always-approve", "--y", "--yolo", "--ll", "--llm-approve"}},
		{"openhands ambiguous", OpenHands, []string{"--l", "--headless"}, []string{"--l", "--headless"}, nil},
		{"agy go flags", Antigravity,
			[]string{"--dangerously-skip-permissions", "-dangerously-skip-permissions", "--dangerously-skip-permissions=true", "-dangerously-skip-permissions=1", "-p", "x"},
			[]string{"-p", "x"}, []string{"--dangerously-skip-permissions", "-dangerously-skip-permissions", "--dangerously-skip-permissions=true", "-dangerously-skip-permissions=1"}},
		{"agy false and bogus values", Antigravity,
			[]string{"--dangerously-skip-permissions=false", "--dangerously-skip-permissions=yes", "--dangerously-skip"},
			[]string{"--dangerously-skip-permissions=false", "--dangerously-skip-permissions=yes", "--dangerously-skip"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kept, dropped := tc.spec.BypassArgs(tc.args)
			if !reflect.DeepEqual(kept, tc.kept) || !reflect.DeepEqual(dropped, tc.dropped) {
				t.Fatalf("kept %q dropped %q, want %q / %q", kept, dropped, tc.kept, tc.dropped)
			}
		})
	}
	// Every flag a yolo launch adds is one a safe launch drops from the
	// passthrough arguments.
	for _, name := range Names() {
		spec, _ := Get(name)
		safe, err := spec.LaunchArgv(LaunchOptions{Mode: Interactive})
		if err != nil {
			t.Fatal(err)
		}
		yolo, err := spec.LaunchArgv(LaunchOptions{Mode: Interactive, Yolo: true})
		if err != nil {
			t.Fatal(err)
		}
		var added []string
		for _, arg := range yolo {
			if !slices.Contains(safe, arg) {
				added = append(added, arg)
			}
		}
		// OmniGent has no permission prompts of its own to skip: its
		// policies, DefenseClaw's among them, decide in the server.
		if len(added) == 0 && name != "omnigent" {
			t.Errorf("%s: a yolo launch adds no flag", name)
		}
		if kept, _ := spec.BypassArgs(added); len(kept) != 0 {
			t.Errorf("%s: safe launches keep the yolo flags %q", name, kept)
		}
	}
	// Safe launches drop them; yolo launches pass everything through.
	safe, err := ClaudeCode.LaunchArgv(LaunchOptions{Mode: Interactive, Args: []string{"--dangerously-skip-permissions", "--model", "opus"}})
	if err != nil || !reflect.DeepEqual(safe, []string{ClaudeCodeLauncherPath, "--model", "opus"}) {
		t.Fatalf("safe argv = %q, %v", safe, err)
	}
	yolo, err := Codex.LaunchArgv(LaunchOptions{Mode: Interactive, Yolo: true, Args: []string{"-a", "never"}})
	if err != nil || !reflect.DeepEqual(yolo, []string{CodexLauncherPath, "--dangerously-bypass-approvals-and-sandbox", "-a", "never"}) {
		t.Fatalf("yolo argv = %q, %v", yolo, err)
	}
	safeCodex, err := Codex.LaunchArgv(LaunchOptions{Mode: Headless, Prompt: "p", Args: []string{"--dangerously-bypass-approvals-and-sandbox"}})
	if err != nil || strings.Contains(strings.Join(safeCodex, " "), "bypass") {
		t.Fatalf("safe codex argv = %q, %v", safeCodex, err)
	}
}

// TestSpecModel pins the model the launch banner reports, the way Codex
// picks it: -m or --model (the last one, nothing after "--") above
// everything, then the Mantle profile's default, which the run's managed
// config pins above any -c model= override, then a -c model= for a profile
// without one; nothing for a profile or harness that leaves the model to
// the harness.
func TestSpecModel(t *testing.T) {
	mantle := profiles.CodexBedrockMantleID
	for _, tc := range []struct {
		name        string
		spec        *Spec
		profile     string
		args        []string
		want        string
		wantDefault bool
	}{
		{"mantle default", Codex, mantle, nil, CodexMantleDefaultModel, true},
		{"-m", Codex, mantle, []string{"-m", "openai.gpt-oss-120b"}, "openai.gpt-oss-120b", false},
		{"-mMODEL", Codex, mantle, []string{"-mopenai.gpt-oss-120b"}, "openai.gpt-oss-120b", false},
		{"-m=MODEL", Codex, mantle, []string{"-m=openai.gpt-oss-120b"}, "openai.gpt-oss-120b", false},
		{"--model=", Codex, mantle, []string{"--model=a", "--model", "b"}, "b", false},
		{"managed default beats -c model", Codex, mantle, []string{"-c", `model = "c1"`}, CodexMantleDefaultModel, true},
		{"-c model without a default", Codex, profiles.OpenAIID, []string{"-c", `model = "c1"`, "--config", "model='c2'"}, "c2", false},
		{"-m beats -c", Codex, mantle, []string{"-m", "m1", "-c", `model="c1"`}, "m1", false},
		{"other -c keys", Codex, mantle, []string{"-c", `model_reasoning_effort="high"`, "-c", `profiles.x.model="p"`}, CodexMantleDefaultModel, true},
		{"after --", Codex, mantle, []string{"--", "-m", "x"}, CodexMantleDefaultModel, true},
		{"resume subcommand", Codex, mantle, []string{"resume", "--last", "-m", "r"}, "r", false},
		{"openai has no default", Codex, profiles.OpenAIID, nil, "", false},
		{"no profile", Codex, "", nil, "", false},
		{"claude mantle default", ClaudeCode, profiles.ClaudeBedrockMantleID, nil, ClaudeCodeMantleDefaultModel, true},
		{"claude --model", ClaudeCode, profiles.ClaudeBedrockMantleID, []string{"--model", "anthropic.claude-haiku-4-5"}, "anthropic.claude-haiku-4-5", false},
		{"claude --model=", ClaudeCode, profiles.ClaudeBedrockMantleID, []string{"--model=a", "--model=b"}, "b", false},
		{"claude after --", ClaudeCode, profiles.ClaudeBedrockMantleID, []string{"--", "--model", "x"}, ClaudeCodeMantleDefaultModel, true},
		{"claude anthropic has no default", ClaudeCode, profiles.AnthropicID, nil, "", false},
		{"claude anthropic with --model", ClaudeCode, profiles.AnthropicID, []string{"--model", "opus"}, "opus", false},
		{"harness without a model parser", OpenCode, "", []string{"-m", "anthropic/claude-haiku-4-5"}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, isDefault, flag := tc.spec.Model(tc.profile, tc.args)
			if got != tc.want || isDefault != tc.wantDefault {
				t.Fatalf("Model = %q (default %t), want %q (default %t)", got, isDefault, tc.want, tc.wantDefault)
			}
			if tc.spec == Codex && flag != "-m" || tc.spec == ClaudeCode && flag != "--model" {
				t.Fatalf("flag = %q", flag)
			}
		})
	}
}

// TestCredentialProfilesPinTheModelProvider: the Codex profiles name the
// model provider the manager pins in the run's managed config (the session
// flags name the same one, and Mantle's serves only function tools), with a
// default model that survives region resolution; Claude Code on Mantle names
// a Mantle id for the main model and every /model alias.
func TestCredentialProfilesPinTheModelProvider(t *testing.T) {
	openai, err := Codex.CredentialProfile(profiles.OpenAIID, "")
	if err != nil || openai.ModelProvider == nil || openai.ModelProvider.ID != connector.SandboxModelProviderOpenAI ||
		openai.ModelProvider.BaseURL != "https://api.openai.com/v1" || openai.ModelProvider.DefaultModel != "" || openai.ModelProvider.FunctionToolsOnly {
		t.Fatalf("openai profile = %+v, %v", openai.ModelProvider, err)
	}
	mantle, err := Codex.CredentialProfile(profiles.CodexBedrockMantleID, "eu-west-1")
	if err != nil || mantle.ModelProvider == nil || mantle.ModelProvider.BaseURL != "https://bedrock-mantle.eu-west-1.api.aws/v1" ||
		!mantle.ModelProvider.FunctionToolsOnly || mantle.DefaultModel != CodexMantleDefaultModel || mantle.ModelProvider.DefaultModel != CodexMantleDefaultModel {
		t.Fatalf("mantle profile = %+v, %v", mantle.ModelProvider, err)
	}
	joined := strings.Join(mantle.LaunchArgs, " ")
	for _, want := range []string{`model_provider="mantle"`, `model_providers.mantle.base_url="` + mantle.ModelProvider.BaseURL + `"`, `model_providers.mantle.env_key="BEDROCK_MANTLE_API_KEY"`} {
		if !strings.Contains(joined, want) {
			t.Fatalf("mantle launch args %q lack %s", joined, want)
		}
	}
	// The base profile table is not mutated by region resolution.
	if again, _ := Codex.CredentialProfile(profiles.CodexBedrockMantleID, "us-west-2"); again.ModelProvider.BaseURL != "https://bedrock-mantle.us-west-2.api.aws/v1" {
		t.Fatalf("mantle base URL = %s", again.ModelProvider.BaseURL)
	}
	claude, _ := ClaudeCode.CredentialProfile(profiles.ClaudeBedrockMantleID, "eu-west-1")
	for _, name := range connector.ClaudeCodeSandboxModelEnv() {
		if !strings.HasPrefix(claude.Env[name], "anthropic.claude-") {
			t.Fatalf("Claude Code Mantle profile %s = %q", name, claude.Env[name])
		}
	}
	if claude.Env["ANTHROPIC_MODEL"] != ClaudeCodeMantleDefaultModel || claude.DefaultModel != ClaudeCodeMantleDefaultModel {
		t.Fatalf("Claude Code Mantle default = %q / %q", claude.Env["ANTHROPIC_MODEL"], claude.DefaultModel)
	}
	if anthropic, _ := ClaudeCode.CredentialProfile(profiles.AnthropicID, ""); anthropic.Env["ANTHROPIC_MODEL"] != "" {
		t.Fatalf("the Anthropic profile pins a model: %v", anthropic.Env)
	}
	for _, cp := range ClaudeCode.CredentialProfiles("") {
		if cp.ModelProvider != nil {
			t.Fatalf("Claude Code profile %s pins a Codex provider", cp.ProfileID)
		}
	}
}
