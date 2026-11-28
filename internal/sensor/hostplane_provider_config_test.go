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

package sensor

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

// drainHandled runs the consumer until it has handled every scripted event.
func drainHandled(t *testing.T, host *hostPlane, source *fakeSource) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := host.start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	deadline := time.After(5 * time.Second)
	for host.handled.Load() < int64(len(source.script)) {
		select {
		case <-deadline:
			t.Fatalf("consumer handled %d of %d events", host.handled.Load(), len(source.script))
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// credentialAccessWeight is the agent_credential_access weight of the one
// finding harvested from host, 0 when there is none.
func credentialAccessWeight(t *testing.T, host *hostPlane, at time.Time) int {
	t.Helper()
	findings := host.harvest(at, 1)
	if len(findings) > 1 {
		t.Fatalf("got %d findings, want at most one", len(findings))
	}
	weight := 0
	for _, finding := range findings {
		for _, signal := range finding.Signals {
			if signal.ID == "agent_credential_access" {
				weight += signal.Weight
			}
		}
	}
	return weight
}

// Accounts of the provider config fixture.
const (
	uidRoot   = 0
	uidDev    = 1000
	uidVictim = 1001
	uidLinked = 1002
	uidDotty  = 1003
	uidGhost  = 1004
)

// providerConfigFixture is a real file tree under a temporary root: account
// homes with AWS shared configs, a staged copy, a checkout's .aws/config, an
// own-home link to another account's config and a dotfile-manager link. The
// facts resolve paths on it for real; only the account database (uid ->
// home), file ownership and process environments are scripted.
type providerConfigFixture struct {
	root   string
	homes  map[int]string
	owners map[string]int
	env    map[int]map[string]string
}

func newProviderConfigFixture(t *testing.T) *providerConfigFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &providerConfigFixture{root: root, homes: map[int]string{}, owners: map[string]int{}, env: map[int]map[string]string{}}
	for uid, home := range map[int]string{
		uidRoot: "root", uidDev: "home/dev", uidVictim: "home/victim", uidLinked: "home/linked", uidDotty: "home/dotty", uidGhost: "home/ghost",
	} {
		f.homes[uid] = f.path(home)
	}
	for file, uid := range map[string]int{
		"home/dev/.aws/config":                uidDev,
		"home/victim/.aws/config":             uidVictim,
		"root/.aws/config":                    uidRoot,
		"tmp/loot/.aws/config":                uidDev,
		"home/dev/src/app/.aws/config":        uidDev,
		"home/dev/conf/.aws/config":           uidDev,
		"home/dotty/dotfiles/aws/.aws/config": uidDotty,
	} {
		f.write(t, file, uid)
	}
	f.link(t, "home/linked/.aws/config", f.path("home/victim/.aws/config"))
	f.link(t, "home/dotty/.aws/config", f.path("home/dotty/dotfiles/aws/.aws/config"))
	return f
}

func (f *providerConfigFixture) path(rel string) string {
	return filepath.Join(f.root, filepath.FromSlash(rel))
}

func (f *providerConfigFixture) write(t *testing.T, rel string, uid int) {
	t.Helper()
	path := f.path(rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[default]\nregion = us-east-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.owners[path] = uid
}

func (f *providerConfigFixture) link(t *testing.T, rel, target string) {
	t.Helper()
	path := f.path(rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
}

func (f *providerConfigFixture) facts() providerConfigFacts {
	return providerConfigFacts{
		home: func(uid int) string { return f.homes[uid] },
		env: func(pid int, name string) (string, bool) {
			value, ok := f.env[pid][name]
			return value, ok
		},
		realPath: filepath.EvalSymlinks,
		owner: func(path string) (int, bool) {
			uid, ok := f.owners[path]
			return uid, ok
		},
	}
}

func intRef(value int) *int { return &value }

// providerConfigOwnerCheckExists reports whether this platform can name the
// account that owns a file. Where it cannot (Windows, where files are owned
// by a SID: hostplane_provider_config_other.go), no read is the agent's own
// provider config and the GAP-1189 exemption never applies, as at rel.
func providerConfigOwnerCheckExists(t *testing.T) bool {
	t.Helper()
	path := filepath.Join(t.TempDir(), "owner-probe")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, ok := fileOwnerUID(path)
	return ok
}

// claudeExec is a depth-0 claude process of account uid.
func claudeExec(pid, uid int, at time.Time) plane.Event {
	return plane.Event{Kind: plane.KindExec, PID: pid, PPID: 1, Name: "claude", Cmdline: "claude", UID: intRef(uid), At: at}
}

func fileRead(pid, uid int, path string, at time.Time) plane.Event {
	return plane.Event{Kind: plane.KindFileRead, PID: pid, Path: path, UID: intRef(uid), At: at}
}

// providerConfigWeight runs script through a host whose provider config facts
// are fixture's and returns the classified count and credential weight.
func providerConfigWeight(t *testing.T, fixture *providerConfigFixture, base time.Time, script ...plane.Event) (int64, int) {
	t.Helper()
	source := newFake(fullCoverage(), script...)
	host := newHost(source)
	host.providerConfig = fixture.facts()
	drainHandled(t, host, source)
	classified, _, _, _ := host.stats()
	return classified, credentialAccessWeight(t, host, base.Add(time.Hour))
}

// TestGAP1189ClaudeOwnBedrockConfigReadIsNotCredentialAccess: Claude Code on
// Amazon Bedrock reads ~/.aws/config itself at every start, an idle TUI
// session included. That read is the agent starting, not credential access:
// it was agent_credential_access T1552 weight 18 (30 x 0.6) on every idle
// managed Linux session. Its own file is the one below its account's home
// or the one its AWS_CONFIG_FILE names, as a real path, owned by it.
func TestGAP1189ClaudeOwnBedrockConfigReadIsNotCredentialAccess(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	fixture := newProviderConfigFixture(t)
	fixture.env[310] = map[string]string{"AWS_CONFIG_FILE": fixture.path("home/dev/conf/.aws/config")}
	fixture.env[311] = map[string]string{"AWS_CONFIG_FILE": "~/conf/.aws/config"}
	cases := []struct {
		name string
		exec plane.Event
		read plane.Event
	}{
		{"own home", claudeExec(300, uidDev, base), fileRead(300, uidDev, fixture.path("home/dev/.aws/config"), base.Add(time.Second))},
		{"own home, native install", plane.Event{Kind: plane.KindExec, PID: 301, PPID: 1, Name: "2.1.323",
			Exe: "/home/dev/.local/share/claude/versions/2.1.323", Cmdline: "claude", UID: intRef(uidDev), At: base},
			fileRead(301, uidDev, fixture.path("home/dev/.aws/config"), base.Add(time.Second))},
		{"own home, read path with ..", claudeExec(302, uidDev, base),
			fileRead(302, uidDev, fixture.path("home/dev/src/../.aws/config"), base.Add(time.Second))},
		{"account uid only on the exec", claudeExec(303, uidDev, base),
			plane.Event{Kind: plane.KindFileRead, PID: 303, Path: fixture.path("home/dev/.aws/config"), At: base.Add(time.Second)}},
		{"root's own home", claudeExec(304, uidRoot, base), fileRead(304, uidRoot, fixture.path("root/.aws/config"), base.Add(time.Second))},
		{"own-home dotfile link inside the account", claudeExec(305, uidDotty, base),
			fileRead(305, uidDotty, fixture.path("home/dotty/dotfiles/aws/.aws/config"), base.Add(time.Second))},
		{"AWS_CONFIG_FILE absolute", claudeExec(310, uidDev, base),
			fileRead(310, uidDev, fixture.path("home/dev/conf/.aws/config"), base.Add(time.Second))},
		{"AWS_CONFIG_FILE with ~", claudeExec(311, uidDev, base),
			fileRead(311, uidDev, fixture.path("home/dev/conf/.aws/config"), base.Add(time.Second))},
	}
	if !providerConfigOwnerCheckExists(t) {
		// No file owner on this platform: nothing is exempt. The same
		// process reading another account's config (a control) scores 18
		// where the agent is recognised at all, and each own-config read
		// must score exactly what its control does.
		scored := 0
		for _, tc := range cases {
			control := tc.read
			control.Path = fixture.path("home/victim/.aws/config")
			_, want := providerConfigWeight(t, fixture, base, tc.exec, control)
			if want != 0 && want != 18 {
				t.Errorf("%s: control weight %d, want 0 or 18", tc.name, want)
			}
			if _, weight := providerConfigWeight(t, fixture, base, tc.exec, tc.read); weight != want {
				t.Errorf("%s: agent_credential_access weight %d, want %d: no platform file owner, so the own-config exemption must not apply",
					tc.name, weight, want)
			}
			if want == 18 {
				scored++
			}
		}
		if scored == 0 {
			t.Error("no own-config read scored 18 without a platform file owner, want the exemption absent")
		}
		return
	}
	for _, tc := range cases {
		classified, weight := providerConfigWeight(t, fixture, base, tc.exec, tc.read)
		if classified != 0 || weight != 0 {
			t.Errorf("%s: classified %d, agent_credential_access %d for the agent reading its own provider config, want none",
				tc.name, classified, weight)
		}
	}
}

// TestGAP1592ProviderConfigOfAnotherAccountOrPlaceStays: the GAP-1189
// exemption is the agent account's own file only. The depth-0 claude
// process reading any other .aws/config scores as before the exemption
// (18): another account's home, /root, a staged copy, a checkout's
// .aws/config, an own-home link to another account's file, and an
// AWS_CONFIG_FILE naming another account's file. Before GAP-1592 each of
// these matched the /.aws/config suffix and scored 0.
func TestGAP1592ProviderConfigOfAnotherAccountOrPlaceStays(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	fixture := newProviderConfigFixture(t)
	fixture.env[420] = map[string]string{"AWS_CONFIG_FILE": fixture.path("home/victim/.aws/config")}
	fixture.env[421] = map[string]string{"AWS_CONFIG_FILE": "conf/.aws/config"}
	cases := []struct {
		name     string
		pid, uid int
		path     string
	}{
		{"another account's home", 400, uidDev, fixture.path("home/victim/.aws/config")},
		{"root's home", 401, uidDev, fixture.path("root/.aws/config")},
		{"staged loot dir", 402, uidDev, fixture.path("tmp/loot/.aws/config")},
		{"repo checkout", 403, uidDev, fixture.path("home/dev/src/app/.aws/config")},
		{"own-home link to another account's config, link path", 404, uidLinked, fixture.path("home/linked/.aws/config")},
		{"own-home link to another account's config, resolved path", 405, uidLinked, fixture.path("home/victim/.aws/config")},
		{"own home ../ into another account", 406, uidDev, fixture.path("home/dev/../victim/.aws/config")},
		{"root agent reads a user's config", 407, uidRoot, fixture.path("home/dev/.aws/config")},
		{"AWS_CONFIG_FILE names another account's config", 420, uidDev, fixture.path("home/victim/.aws/config")},
		{"relative AWS_CONFIG_FILE", 421, uidDev, fixture.path("home/dev/conf/.aws/config")},
		{"own home, but the account's home is not known", 430, 4242, fixture.path("home/dev/.aws/config")},
		{"own home config that does not resolve", 431, uidGhost, fixture.path("home/ghost/.aws/config")},
	}
	for _, tc := range cases {
		_, weight := providerConfigWeight(t, fixture, base, claudeExec(tc.pid, tc.uid, base),
			fileRead(tc.pid, tc.uid, tc.path, base.Add(time.Second)))
		if weight != 18 {
			t.Errorf("%s: agent_credential_access weight %d, want 18 (as before the exemption)", tc.name, weight)
		}
	}

	// No account on the exec or the read (a Windows source, which names a
	// SID): nothing is exempt.
	_, weight := providerConfigWeight(t, fixture, base,
		plane.Event{Kind: plane.KindExec, PID: 440, PPID: 1, Name: "claude", Cmdline: "claude", At: base},
		plane.Event{Kind: plane.KindFileRead, PID: 440, Path: fixture.path("home/dev/.aws/config"), At: base.Add(time.Second)})
	if weight != 18 {
		t.Errorf("read with no account: agent_credential_access weight %d, want 18", weight)
	}
}

// TestGAP1189CredentialReadsOutsideOwnProviderConfigStay is the negative
// side: every read that is not the identified agent itself reading its own
// provider config is graded as before.
func TestGAP1189CredentialReadsOutsideOwnProviderConfigStay(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	fixture := newProviderConfigFixture(t)
	own := fixture.path("home/dev/.aws/config")
	claude := claudeExec(400, uidDev, base)
	cases := []struct {
		name   string
		script []plane.Event
		want   int
	}{
		{"child of the agent reads ~/.aws/config", []plane.Event{claude,
			{Kind: plane.KindExec, PID: 401, PPID: 400, Name: "sh", Cmdline: "sh -c true", UID: intRef(uidDev), At: base.Add(time.Second)},
			fileRead(401, uidDev, own, base.Add(2*time.Second)),
		}, 18},
		{"agent reads ~/.aws/credentials", []plane.Event{claude,
			fileRead(400, uidDev, fixture.path("home/dev/.aws/credentials"), base.Add(time.Second)),
		}, 30},
		{"agent reads another credential-adjacent file", []plane.Event{claude,
			fileRead(400, uidDev, fixture.path("home/dev/.npmrc"), base.Add(time.Second)),
		}, 18},
		{"agent reads a file only named like the config", []plane.Event{claude,
			fileRead(400, uidDev, own+".bak", base.Add(time.Second)),
		}, 18},
		{"pattern-recognised agent with no connector reads ~/.aws/config", []plane.Event{
			{Kind: plane.KindExec, PID: 500, PPID: 1, Name: "aider", Cmdline: "aider", UID: intRef(uidDev), At: base},
			fileRead(500, uidDev, own, base.Add(time.Second)),
		}, 18},
		{"connector agent without a provider config reads ~/.aws/config", []plane.Event{
			{Kind: plane.KindExec, PID: 600, PPID: 1, Name: "codex", Cmdline: "codex", UID: intRef(uidDev), At: base},
			fileRead(600, uidDev, own, base.Add(time.Second)),
		}, 18},
	}
	for _, tc := range cases {
		if _, weight := providerConfigWeight(t, fixture, base, tc.script...); weight != tc.want {
			t.Errorf("%s: agent_credential_access weight %d, want %d", tc.name, weight, tc.want)
		}
	}

	// A process with no agent above it stays behind the lineage gate.
	source := newFake(fullCoverage(),
		plane.Event{Kind: plane.KindExec, PID: 700, PPID: 1, Name: "python3", Cmdline: "python3 app.py", UID: intRef(uidDev), At: base},
		fileRead(700, uidDev, own, base.Add(time.Second)),
	)
	host := newHost(source)
	host.providerConfig = fixture.facts()
	drainHandled(t, host, source)
	if classified, gated, _, _ := host.stats(); classified != 0 || gated == 0 {
		t.Fatalf("unattributed ~/.aws/config read: classified %d gated %d, want gated", classified, gated)
	}
}

// TestGAP1592ProcessStartEnv reads a variable from a process's start
// environment, which is where AWS_CONFIG_FILE comes from on Linux.
func TestGAP1592ProcessStartEnv(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		// No start environment is read here: only the account's home counts.
		for _, pid := range []int{os.Getpid(), -1} {
			if value, ok := processStartEnv(pid, "PATH"); ok {
				t.Fatalf("pid %d: got %q, want no start environment off Linux", pid, value)
			}
		}
		return
	}
	for _, name := range []string{"PATH", "HOME"} {
		if want := os.Getenv(name); want != "" {
			if got, ok := processStartEnv(os.Getpid(), name); !ok || got == "" {
				t.Fatalf("%s: got %q %v, want the start value", name, got, ok)
			}
			break
		}
	}
	if value, ok := processStartEnv(os.Getpid(), "DC_GAP1592_NEVER_SET"); ok {
		t.Fatalf("unset variable: got %q", value)
	}
	if _, ok := processStartEnv(-1, "PATH"); ok {
		t.Fatal("no such process: got a value")
	}
}

// TestGAP1189OwnProviderConfigReadWindowsFoldsCase checks the suffix match
// folds case only where the indicator set does.
func TestGAP1189OwnProviderConfigReadWindowsFoldsCase(t *testing.T) {
	t.Parallel()
	if !hasPathSuffix(`C:/Users/Dev/.AWS/Config`, "/.aws/config", tactics.IndicatorsFor("windows").CaseInsensitivePaths) {
		t.Fatal("windows suffix match does not fold case")
	}
	if hasPathSuffix("/home/dev/.AWS/config", "/.aws/config", tactics.IndicatorsFor("linux").CaseInsensitivePaths) {
		t.Fatal("linux suffix match folds case")
	}
}
