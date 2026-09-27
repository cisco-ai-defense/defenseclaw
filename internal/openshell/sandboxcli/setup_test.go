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

package sandboxcli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/wrapper"
)

// hostReport is a doctor report of a ready Linux host; edit adjusts it.
func hostReport(edit func(*openshell.DoctorReport)) func(context.Context, *openshell.Doctor) *openshell.DoctorReport {
	return func(context.Context, *openshell.Doctor) *openshell.DoctorReport {
		rep := &openshell.DoctorReport{CLIVersion: "0.1.1", DockerVersion: "29.4.0", GatewayVersion: "0.1.1"}
		for _, c := range []openshell.Check{
			{ID: openshell.CheckIDPlatform, Title: "Platform", Status: openshell.StatusPass, Detail: "linux/arm64"},
			{ID: openshell.CheckIDUser, Title: "User", Status: openshell.StatusPass},
			{ID: openshell.CheckIDLandlock, Title: "Landlock", Status: openshell.StatusPass, Detail: "ABI 6"},
			{ID: openshell.CheckIDDocker, Title: "Docker", Status: openshell.StatusPass},
			{ID: openshell.CheckIDGatewayService, Title: "Gateway service", Status: openshell.StatusPass},
			{ID: openshell.CheckIDCLI, Title: "OpenShell CLI", Status: openshell.StatusPass},
			{ID: openshell.CheckIDRegistration, Title: "Gateway registration", Status: openshell.StatusPass},
			{ID: openshell.CheckIDMTLS, Title: "mTLS files", Status: openshell.StatusPass},
			{ID: openshell.CheckIDGatewayVersion, Title: "Gateway version", Status: openshell.StatusPass},
			{ID: openshell.CheckIDBindMounts, Title: "Bind mounts", Status: openshell.StatusWarn, Detail: "off"},
		} {
			rep.Checks = append(rep.Checks, c)
		}
		if edit != nil {
			edit(rep)
		}
		return rep
	}
}

type fakeInstaller struct {
	consent func(*openshell.InstallPlan) (bool, error)
	ran     bool
}

func (f *fakeInstaller) Install(context.Context) (*openshell.InstallResult, error) {
	ok, err := f.consent(&openshell.InstallPlan{Release: "v0.1.1"})
	if err != nil || !ok {
		return nil, errors.New("declined")
	}
	f.ran = true
	v, _ := openshell.ParseVersion("0.1.1")
	return &openshell.InstallResult{Installed: true, CLIVersion: v}, nil
}

func TestSetupNonInteractive(t *testing.T) {
	ta := newTestApp(t, "")
	ta.IO.TTY = false
	writeConfig(t, ta, "")
	ta.Cfg.OpenShell.Enabled = false
	ta.HostDoctor = hostReport(nil)
	toml := filepath.Join(t.TempDir(), "gateway.toml")
	if err := os.WriteFile(toml, []byte("[openshell.drivers.docker]\nenable_bind_mounts = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ta.gateway.applyRes = &openshell.GatewayApplyResult{Files: []openshell.AppliedFile{{Path: toml, Backup: toml + ".defenseclaw.bak"}}, Restarted: true}
	err := ta.Setup(context.Background(), SetupOptions{NonInteractive: true, Yes: true, Wrappers: true})
	if err != nil {
		t.Fatalf("Setup: %v\n%s", err, ta.output())
	}
	if len(ta.gateway.planned) != 1 || !ta.gateway.planned[0].EnableBindMounts || ta.gateway.planned[0].Env[openshell.EnvTelemetryEnabled] != "false" || ta.gateway.applied != 1 {
		t.Fatalf("gateway plans = %+v, applied %d", ta.gateway.planned, ta.gateway.applied)
	}
	r, err := ta.loadReceipt()
	if err != nil || len(r.GatewayFiles) != 1 || r.GatewayFiles[0].Backup != toml+".defenseclaw.bak" || r.GatewayFiles[0].SHA256 == "" {
		t.Fatalf("receipt = %+v, %v", r, err)
	}
	c := loadConfig(t, ta)
	if !c.OpenShell.Enabled || !slices.Equal(c.OpenShell.Harnesses, []string{"claudecode", "codex"}) || c.OpenShell.UpstreamTelemetry {
		t.Fatalf("config openshell = %+v", c.OpenShell)
	}
	if !slices.Equal(ta.images.built, []string{"claudecode", "codex"}) {
		t.Fatalf("images built = %v", ta.images.built)
	}
	b, err := wrapper.Read(filepath.Join(ta.home, ".bashrc"))
	if err != nil || !b.Has("claude") || !b.Has("codex") {
		t.Fatalf("wrappers = %+v, %v", b, err)
	}
	out := ta.output()
	for _, want := range []string{"Checking this machine…  ✓ linux/arm64  ✓ Landlock  ✓ Docker 29.4.0  ✓ OpenShell 0.1.1",
		"gateway configured and restarted", "Done →  cd <project> && defenseclaw sandbox run claude"} {
		if !strings.Contains(out, want) {
			t.Errorf("setup output lacks %q:\n%s", want, out)
		}
	}
}

func TestSetupNeedsConsentToInstall(t *testing.T) {
	ta := newTestApp(t, "")
	ta.IO.TTY = false
	writeConfig(t, ta, "")
	missing := hostReport(func(r *openshell.DoctorReport) {
		r.CLIVersion = ""
		r.Get(openshell.CheckIDCLI).Status = openshell.StatusFail
	})
	ta.HostDoctor = missing
	err := ta.Setup(context.Background(), SetupOptions{NonInteractive: true})
	if err == nil || !strings.Contains(err.Error(), "--install-openshell") {
		t.Fatalf("Setup without consent = %v", err)
	}
	if !strings.Contains(ta.output(), "✗ OpenShell not installed") {
		t.Fatalf("output:\n%s", ta.output())
	}
	inst := &fakeInstaller{}
	ta.Installer = func(consent func(*openshell.InstallPlan) (bool, error)) Installer {
		inst.consent = consent
		return inst
	}
	calls := 0
	ta.HostDoctor = func(ctx context.Context, d *openshell.Doctor) *openshell.DoctorReport {
		calls++
		if calls == 1 {
			return missing(ctx, d)
		}
		return hostReport(nil)(ctx, d)
	}
	if err := ta.Setup(context.Background(), SetupOptions{NonInteractive: true, InstallOpenShell: true, SkipImages: true}); err != nil {
		t.Fatalf("Setup with --install-openshell: %v\n%s", err, ta.output())
	}
	if !inst.ran {
		t.Fatal("the installer did not run")
	}
}

func TestSetupStopsOnHostFailure(t *testing.T) {
	ta := newTestApp(t, "")
	writeConfig(t, ta, "")
	before, _ := os.ReadFile(ta.ConfigPath)
	ta.HostDoctor = hostReport(func(r *openshell.DoctorReport) {
		c := r.Get(openshell.CheckIDLandlock)
		c.Status, c.Detail = openshell.StatusFail, "ABI 1 is older than 3"
	})
	err := ta.Setup(context.Background(), SetupOptions{NonInteractive: true})
	if err == nil || !strings.Contains(err.Error(), "Landlock") {
		t.Fatalf("Setup = %v", err)
	}
	if after, _ := os.ReadFile(ta.ConfigPath); string(after) != string(before) {
		t.Fatal("a failed setup changed config.yaml")
	}
}

func TestSetupCopyOnlyWithoutMounts(t *testing.T) {
	ta := newTestApp(t, "")
	writeConfig(t, ta, "")
	ta.HostDoctor = hostReport(nil)
	ta.gateway.state.Env = map[string]string{openshell.EnvTelemetryEnabled: "false"}
	if err := ta.Setup(context.Background(), SetupOptions{NonInteractive: true, NoMounts: true, SkipImages: true, Harnesses: []string{"codex"}}); err != nil {
		t.Fatalf("Setup: %v\n%s", err, ta.output())
	}
	if len(ta.gateway.planned) != 0 {
		t.Fatalf("gateway changed without need: %+v", ta.gateway.planned)
	}
	c := loadConfig(t, ta)
	if c.OpenShell.Workdir.Mode != "copy" || !slices.Equal(c.OpenShell.Harnesses, []string{"codex"}) {
		t.Fatalf("config = %+v", c.OpenShell)
	}
}

func TestDoctorReportsDefenseClawChecks(t *testing.T) {
	ta := newTestApp(t, "")
	ta.HostDoctor = hostReport(nil)
	ta.images.recs = []image.Record{{Connector: "claudecode", HookFireVerified: true, UID: os.Getuid(), DefenseClawVersion: manager.ImageVersion(),
		IngressPort: ta.Cfg.OpenShellIngressPort(), HarnessVersion: "2.1.156"}}
	if _, err := wrapper.Enable(wrapper.Bash, filepath.Join(ta.home, ".bashrc"), "/nonexistent/defenseclaw-gateway", wrapper.Wrap{Command: "claude", Harness: "claude"}); err != nil {
		t.Fatal(err)
	}
	err := ta.RunDoctor(context.Background(), DoctorOptions{})
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 1 {
		t.Fatalf("doctor = %v, want exit 1 for the broken wrapper", err)
	}
	out := ta.output()
	for _, want := range []string{"DefenseClaw daemon", "connected to OpenShell 0.1.1 gateway openshell", "Harness images",
		"not built yet: codex", "calls /nonexistent/defenseclaw-gateway, which is missing", "Organization policy"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor lacks %q:\n%s", want, out)
		}
	}
	ta.out.Reset()
	if err := ta.RunDoctor(context.Background(), DoctorOptions{Output: OutputJSON}); err != nil {
		t.Fatalf("doctor --output json = %v", err)
	}
	var rep struct {
		OK     bool
		Checks []openshell.Check
	}
	if err := json.Unmarshal(ta.out.Bytes(), &rep); err != nil || rep.OK || len(rep.Checks) < 10 {
		t.Fatalf("doctor json = %+v, %v", rep, err)
	}
}

func TestTeardownRemovesEverythingDefenseClawCreated(t *testing.T) {
	ta := newTestApp(t, "")
	writeConfig(t, ta, "  wrappers: [claudecode]\n")
	ctx := context.Background()
	owner, err := image.NewStore(ta.Cfg.DataDir).Owner()
	if err != nil {
		t.Fatal(err)
	}
	fake := openshelltest.New()
	client := fake.Client(openshell.ClientOptions{})
	ours := map[string]string{manager.LabelManaged: "true", manager.LabelOwner: owner}
	theirs := map[string]string{manager.LabelManaged: "true", manager.LabelOwner: "someone-else"}
	for name, labels := range map[string]map[string]string{"dc-claude-orphan": ours, "dc-claude-theirs": theirs} {
		if _, err := client.CreateSandbox(ctx, name, &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{Labels: labels}); err != nil {
			t.Fatal(err)
		}
	}
	// Ingress profiles: this config's listener's, an earlier port's (our
	// orphan's provider uses it), another daemon's unused one (it is not
	// ours to remove) and the legacy gateway-wide one of earlier releases.
	ownPort := ta.Cfg.OpenShellIngressPort()
	oldPort, otherPort := ownPort+1000, ownPort+2000
	imports := []struct {
		id string
		in profiles.Input
	}{
		{profiles.IngressID, profiles.Input{IngressPort: ownPort}},
		{profiles.IngressID, profiles.Input{IngressPort: oldPort}},
		{profiles.IngressID, profiles.Input{IngressPort: otherPort}},
		{profiles.LegacyIngressID, profiles.Input{IngressPort: 18000}},
		{profiles.AnthropicID, profiles.Input{Binaries: []string{"/opt/defenseclaw-harness/claudecode/bin/claude"}}},
	}
	for i, im := range imports {
		p, err := profiles.Render(im.id, im.in)
		if err != nil {
			t.Fatal(err)
		}
		if i == 3 {
			p.Spec.ID = profiles.LegacyIngressID
		}
		if _, err := client.ImportProfiles(ctx, []openshell.ProfileImportItem{{Profile: p.Spec, Source: "test"}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []*openshell.Provider{
		{Name: "dc-claude-orphan-ingress", Type: profiles.IngressProfileID(oldPort), Labels: ours, Spec: openshell.ProviderSpec{Credentials: map[string]string{"DEFENSECLAW_SANDBOX_TOKEN": "t"}}},
		{Name: "dc-claude-theirs-llm", Type: profiles.AnthropicID, Labels: theirs, Spec: openshell.ProviderSpec{Credentials: map[string]string{"ANTHROPIC_API_KEY": "k"}}},
	} {
		if _, err := client.CreateProvider(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	ta.OpenShell = func(context.Context) (openshell.Client, *openshell.Registration, error) {
		return noCloseClient{client}, &openshell.Registration{Name: "openshell"}, nil
	}
	ta.daemon.add(sampleSandbox("dc-claude-live"))
	ta.images.recs = []image.Record{{Tag: "defenseclaw/sandbox:claudecode-1"}}
	// Setup changed two gateway files; the user edited one since.
	dir := t.TempDir()
	kept, edited := filepath.Join(dir, "gateway.toml"), filepath.Join(dir, "gateway.env")
	for _, p := range []string{kept, edited} {
		if err := os.WriteFile(p, []byte("dc\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := ta.recordGatewayApply(&openshell.GatewayApplyResult{Files: []openshell.AppliedFile{{Path: kept, Backup: kept + ".bak"}, {Path: edited}}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(edited, []byte("user edit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rc := filepath.Join(ta.home, ".bashrc")
	if _, err := wrapper.Enable(wrapper.Bash, rc, "/usr/local/bin/defenseclaw-gateway", wrapper.Wrap{Command: "claude", Harness: "claude"}); err != nil {
		t.Fatal(err)
	}
	// A staged copy an interrupted create left, which no record names.
	leftover := filepath.Join(ta.Cfg.DataDir, "sandboxes", "dc-claude-stale", "copy", "stage", "proj", "README.md")
	if err := os.MkdirAll(filepath.Dir(leftover), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leftover, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ta.Teardown(ctx, TeardownOptions{DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ta.output(), "leftover data     dc-claude-stale") {
		t.Fatalf("dry run plan does not list the leftover data:\n%s", ta.output())
	}
	if !strings.Contains(ta.output(), "dc-claude-live, dc-claude-orphan") || strings.Contains(ta.output(), "dc-claude-theirs") {
		t.Fatalf("dry run plan:\n%s", ta.output())
	}
	wantProfiles := strings.Join([]string{profiles.LegacyIngressID, profiles.IngressProfileID(ownPort), profiles.IngressProfileID(oldPort)}, ", ")
	if !strings.Contains(ta.output(), "provider profiles "+wantProfiles+"\n") {
		t.Fatalf("dry run plan does not remove exactly %s:\n%s", wantProfiles, ta.output())
	}
	if len(ta.daemon.callsTo("DELETE", "/api/v1/sandbox/sandboxes/dc-claude-live")) != 0 || len(ta.gateway.rollbacks) != 0 {
		t.Fatal("the dry run changed something")
	}

	if err := ta.Teardown(ctx, TeardownOptions{Yes: true}); err != nil {
		t.Fatalf("Teardown: %v\n%s", err, ta.output())
	}
	if n := len(ta.daemon.callsTo("DELETE", "/api/v1/sandbox/sandboxes/dc-claude-live")); n != 1 {
		t.Fatalf("daemon deletes = %d", n)
	}
	if _, err := os.Stat(filepath.Join(ta.Cfg.DataDir, "sandboxes", "dc-claude-stale")); !os.IsNotExist(err) {
		t.Fatalf("the leftover data is still there: %v", err)
	}
	if _, err := client.GetSandbox(ctx, "dc-claude-orphan"); !openshell.IsNotFound(err) {
		t.Fatalf("orphan sandbox left: %v", err)
	}
	if _, err := client.GetSandbox(ctx, "dc-claude-theirs"); err != nil {
		t.Fatalf("another data dir's sandbox was deleted: %v", err)
	}
	if _, err := client.GetProvider(ctx, "dc-claude-orphan-ingress"); !openshell.IsNotFound(err) {
		t.Fatalf("our provider left: %v", err)
	}
	for _, id := range []string{profiles.IngressProfileID(ownPort), profiles.IngressProfileID(oldPort), profiles.LegacyIngressID} {
		if _, err := client.GetProfile(ctx, id); !openshell.IsNotFound(err) {
			t.Fatalf("the unused ingress profile %s is left: %v", id, err)
		}
	}
	if _, err := client.GetProfile(ctx, profiles.IngressProfileID(otherPort)); err != nil {
		t.Fatalf("another daemon's ingress profile was deleted: %v", err)
	}
	if _, err := client.GetProfile(ctx, profiles.AnthropicID); err != nil {
		t.Fatalf("a profile another provider uses was deleted: %v", err)
	}
	if !slices.Equal(ta.images.removed, []string{"defenseclaw/sandbox:claudecode-1"}) {
		t.Fatalf("images removed = %v", ta.images.removed)
	}
	if len(ta.gateway.rollbacks) != 1 || len(ta.gateway.rollbacks[0].Files) != 1 || ta.gateway.rollbacks[0].Files[0].Path != kept {
		t.Fatalf("rollbacks = %+v", ta.gateway.rollbacks)
	}
	if !strings.Contains(ta.output(), edited+" changed after DefenseClaw edited it") {
		t.Fatalf("no notice for the edited gateway file:\n%s", ta.output())
	}
	if b, _ := wrapper.Read(rc); len(b.Wraps) != 0 {
		t.Fatalf("wrappers left: %+v", b)
	}
	if c := loadConfig(t, ta); c.OpenShell.Enabled || len(c.OpenShell.Wrappers) != 0 {
		t.Fatalf("config after teardown = %+v", c.OpenShell)
	}
}

func TestTeardownWithoutDaemonOrGateway(t *testing.T) {
	ta := newTestApp(t, "")
	ta.API = sandboxapi.NewClient("http://127.0.0.1:1", "x")
	ta.Cfg = nil
	// Without a config the data dir is the default one, the fixture's
	// here: a teardown that reads (and rewrites) the setup receipt must
	// not reach the developer's.
	if got, want := ta.dataDir(), filepath.Dir(ta.ConfigPath); got != want {
		t.Fatalf("data dir without a config = %s, want the fixture's %s", got, want)
	}
	if err := ta.Teardown(context.Background(), TeardownOptions{Yes: true}); err != nil {
		t.Fatalf("Teardown: %v\n%s", err, ta.output())
	}
	if !strings.Contains(ta.output(), "nothing to tear down") {
		t.Fatalf("output:\n%s", ta.output())
	}
}

// noCloseClient keeps the shared fake gateway open when a command closes
// its client.
type noCloseClient struct{ openshell.Client }

func (noCloseClient) Close() error { return nil }
