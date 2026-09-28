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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
)

// mountsOn is a gateway that already allows bind mounts, so setup asks
// nothing about them.
var mountsOn = openshell.BindMounts{AllowDriverConfig: true, EnableBindMounts: true}

// gatewayWithRunning is a fake OpenShell gateway running n sandboxes of
// someone else.
func gatewayWithRunning(t *testing.T, n int) func(context.Context) (openshell.Client, *openshell.Registration, error) {
	t.Helper()
	ctx := context.Background()
	fake := openshelltest.New()
	client := fake.Client(openshell.ClientOptions{})
	for i := range n {
		name := "dc-claude-theirs-" + string(rune('a'+i))
		if _, err := client.CreateSandbox(ctx, name, &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{
			Labels: map[string]string{manager.LabelManaged: "true", manager.LabelOwner: "someone-else"}}); err != nil {
			t.Fatal(err)
		}
		if err := fake.SetPhase(openshell.DefaultWorkspace, name, openshell.PhaseReady); err != nil {
			t.Fatal(err)
		}
	}
	return func(context.Context) (openshell.Client, *openshell.Registration, error) {
		return noCloseClient{client}, &openshell.Registration{Name: "openshell"}, nil
	}
}

// TestSetupTelemetryQuestionSaysItRestartsTheGateway pins that the
// telemetry question says, before it is answered, that a yes edits
// gateway.env and restarts the shared gateway, with what runs on it (manual
// test R2-31).
func TestSetupTelemetryQuestionSaysItRestartsTheGateway(t *testing.T) {
	for _, tc := range []struct {
		name    string
		running int
		want    string
		applied int
	}{
		{"idle", 0, "; no sandbox runs on it now) [Y/n]", 1},
		// The restart question that follows answers no by default.
		{"running", 2, ", which drops the connections of the 2 sandboxes running on it) [Y/n]", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The telemetry question (yes), then, with sandboxes running,
			// the restart (no).
			ta := newTestApp(t, "\n\n")
			writeConfig(t, ta, "")
			ta.HostDoctor = hostReport(nil)
			ta.gateway.state.BindMounts = mountsOn
			ta.gateway.state.EnvPath = filepath.Join(ta.home, ".config", "openshell", "gateway.env")
			ta.OpenShell = gatewayWithRunning(t, tc.running)
			if err := ta.Setup(context.Background(), SetupOptions{SkipImages: true, NoWrappers: true}); err != nil {
				t.Fatalf("Setup: %v\n%s", err, ta.output())
			}
			out := ta.output()
			want := "Disable OpenShell's anonymous usage telemetry? (edits ~/.config/openshell/gateway.env and restarts the OpenShell gateway" + tc.want
			if !strings.Contains(out, want) {
				t.Fatalf("the telemetry question does not say what a yes does:\nwant %q\n%s", want, out)
			}
			if len(ta.gateway.planned) != 1 || ta.gateway.planned[0].Env[openshell.EnvTelemetryEnabled] != "false" {
				t.Fatalf("gateway plans = %+v", ta.gateway.planned)
			}
			if ta.gateway.applied != tc.applied {
				t.Fatalf("applied %d, want %d\n%s", ta.gateway.applied, tc.applied, out)
			}
		})
	}
}

// TestSetupKeepsASavedTelemetryAnswer pins that a saved
// openshell.upstream_telemetry: true (an earlier "keep it") is not asked
// again, and not overwritten, by a later setup (manual tests R2-31, R2-67).
func TestSetupKeepsASavedTelemetryAnswer(t *testing.T) {
	ta := newTestApp(t, "")
	writeConfig(t, ta, "  upstream_telemetry: true\n")
	ta.Cfg.OpenShell.UpstreamTelemetry = true
	ta.HostDoctor = hostReport(nil)
	ta.gateway.state.BindMounts = mountsOn
	if err := ta.Setup(context.Background(), SetupOptions{SkipImages: true, NoWrappers: true}); err != nil {
		t.Fatalf("Setup: %v\n%s", err, ta.output())
	}
	out := ta.output()
	if strings.Contains(out, "Disable OpenShell's anonymous usage telemetry?") {
		t.Fatalf("setup asked about telemetry again:\n%s", out)
	}
	if !strings.Contains(out, "OpenShell's anonymous usage telemetry stays on (openshell.upstream_telemetry is true in") {
		t.Fatalf("setup does not say why it keeps the telemetry:\n%s", out)
	}
	if len(ta.gateway.planned) != 0 {
		t.Fatalf("gateway changed: %+v", ta.gateway.planned)
	}
	if c := loadConfig(t, ta); !c.OpenShell.UpstreamTelemetry {
		t.Fatal("setup overwrote openshell.upstream_telemetry")
	}
}

// TestSetupHarnessLines pins the harness part of setup: one line per
// harness it sets up with the model credential or the next step, the
// --harness hint, the others by the names the command line takes, and an
// image question for a harness nobody named (manual test R2-34).
func TestSetupHarnessLines(t *testing.T) {
	ta := newTestApp(t, "y\nn\n")
	writeConfig(t, ta, "")
	ta.HostDoctor = hostReport(nil)
	ta.gateway.state.BindMounts = mountsOn
	ta.gateway.state.Env = map[string]string{openshell.EnvTelemetryEnabled: "false"}
	ta.env["ANTHROPIC_API_KEY"] = "sk-test"
	ta.images.missing = map[string]bool{"claudecode": true, "codex": true}
	if err := ta.Setup(context.Background(), SetupOptions{NoWrappers: true}); err != nil {
		t.Fatalf("Setup: %v\n%s", err, ta.output())
	}
	out := ta.output()
	for _, want := range []string{
		"  Harnesses (add another with `defenseclaw sandbox setup --harness NAME`):\n" +
			"    Claude Code (claude)  model credential ANTHROPIC_API_KEY ✓\n" +
			"    Codex (codex)         model credential none found: before the first run, set OPENAI_API_KEY or log in with `codex login --with-api-key`; or log in inside the sandbox\n" +
			"  Other harnesses: agy, amp (not verified yet), copilot, cursor-agent (not verified yet), devin (not verified yet), hermes, kiro, omnigent, opencode, openhands\n",
		"Build the Claude Code image now? (the first build downloads about 3 GB; otherwise the first `defenseclaw sandbox run claude` builds it) [Y/n]",
		"Build the Codex image now?",
		"skipped: the Codex image (the first `defenseclaw sandbox run codex` builds it, or `defenseclaw sandbox image build codex`)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("setup output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "[x]") || strings.Contains(out, "Credentials:") {
		t.Errorf("setup still prints the checklist line:\n%s", out)
	}
	if !slices.Equal(ta.images.built, []string{"claudecode"}) {
		t.Fatalf("images built = %v, want only the one agreed to", ta.images.built)
	}

	// A harness named with --harness is asked for: its image is built
	// without a question, and an image already built is only checked.
	ta = newTestApp(t, "")
	writeConfig(t, ta, "")
	ta.HostDoctor = hostReport(nil)
	ta.gateway.state.BindMounts = mountsOn
	ta.gateway.state.Env = map[string]string{openshell.EnvTelemetryEnabled: "false"}
	ta.images.missing = map[string]bool{"codex": true}
	if err := ta.Setup(context.Background(), SetupOptions{NoWrappers: true, Harnesses: []string{"codex"}}); err != nil {
		t.Fatalf("Setup --harness codex: %v\n%s", err, ta.output())
	}
	if strings.Contains(ta.output(), "image now?") || !slices.Equal(ta.images.built, []string{"codex"}) {
		t.Fatalf("images built = %v:\n%s", ta.images.built, ta.output())
	}
	ta.out.Reset()
	ta.images.built, ta.images.missing = nil, nil
	if err := ta.Setup(context.Background(), SetupOptions{NoWrappers: true}); err != nil {
		t.Fatalf("Setup: %v\n%s", err, ta.output())
	}
	if strings.Contains(ta.output(), "image now?") || !slices.Equal(ta.images.built, []string{"codex"}) {
		t.Fatalf("a current image was asked about: built = %v:\n%s", ta.images.built, ta.output())
	}
}

// TestSetupHarnessAddsToTheConfiguredOnes pins that --harness adds to
// openshell.harnesses instead of replacing it (manual test R2-72).
func TestSetupHarnessAddsToTheConfiguredOnes(t *testing.T) {
	ta := newTestApp(t, "")
	ta.IO.TTY = false
	writeConfig(t, ta, "  harnesses: [opencode, copilot, kiro]\n")
	ta.Cfg.OpenShell.Harnesses = []string{"opencode", "copilot", "kiro"}
	ta.HostDoctor = hostReport(nil)
	ta.gateway.state.BindMounts = mountsOn
	ta.gateway.state.Env = map[string]string{openshell.EnvTelemetryEnabled: "false"}
	for _, step := range []struct {
		harness string
		want    []string
	}{
		{"opencode", []string{"opencode", "copilot", "kiro"}},
		{"claude", []string{"opencode", "copilot", "kiro", "claudecode"}},
	} {
		ta.out.Reset()
		if err := ta.Setup(context.Background(), SetupOptions{NonInteractive: true, SkipImages: true, NoWrappers: true, Harnesses: []string{step.harness}}); err != nil {
			t.Fatalf("Setup --harness %s: %v\n%s", step.harness, err, ta.output())
		}
		if c := loadConfig(t, ta); !slices.Equal(c.OpenShell.Harnesses, step.want) {
			t.Fatalf("after setup --harness %s, openshell.harnesses = %v, want %v", step.harness, c.OpenShell.Harnesses, step.want)
		}
	}
	if !strings.Contains(ta.output(), "  Set up before: copilot, kiro, opencode\n") {
		t.Fatalf("setup does not list the harnesses set up before:\n%s", ta.output())
	}
}

// TestSetupNamesKiroAsTyped pins that setup names a harness the way the
// command line takes it, not by an internal command, and offers no shell
// wrapper that would never run (manual test R2-73).
func TestSetupNamesKiroAsTyped(t *testing.T) {
	ta := newTestApp(t, "")
	writeConfig(t, ta, "")
	ta.HostDoctor = hostReport(nil)
	ta.gateway.state.BindMounts = mountsOn
	ta.gateway.state.Env = map[string]string{openshell.EnvTelemetryEnabled: "false"}
	if err := ta.Setup(context.Background(), SetupOptions{SkipImages: true, Wrappers: true, Harnesses: []string{"kiro"}}); err != nil {
		t.Fatalf("Setup: %v\n%s", err, ta.output())
	}
	out := ta.output()
	for _, want := range []string{"    Kiro CLI (kiro)  model credential none found: you log in inside the sandbox on the first run\n",
		"Kiro CLI gets no shell wrapper: `kiro-cli` starts kiro-cli-chat itself, which a wrapper cannot catch; start it with `defenseclaw sandbox run kiro`",
		"Done →  cd <project> && defenseclaw sandbox run kiro\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("setup output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "run kiro-cli-chat") || strings.Contains(out, "`kiro-cli-chat` run sandboxed") {
		t.Errorf("setup names kiro by its internal command:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(ta.home, ".bashrc")); !os.IsNotExist(err) {
		t.Fatalf("setup installed a kiro-cli-chat wrapper: %v", err)
	}
	// Every harness's name resolves back to it.
	for _, h := range harness.Names() {
		spec, _ := harness.Get(h)
		if got, err := ResolveHarness(HarnessArg(spec)); err != nil || got != spec {
			t.Errorf("HarnessArg(%s) = %q resolves to %v, %v", h, HarnessArg(spec), got, err)
		}
	}
}

// TestDoctorWrapperHintNamesAConfiguredHarness pins that the doctor's
// wrapper hint names a harness this install set up (manual test R2-44).
func TestDoctorWrapperHintNamesAConfiguredHarness(t *testing.T) {
	for _, tc := range []struct {
		harnesses []string
		want      string
	}{
		{nil, "none (`defenseclaw sandbox enable claude` makes `claude` run sandboxed)"},
		{[]string{"kiro", "hermes", "openhands"}, "none (`defenseclaw sandbox enable hermes` makes `hermes` run sandboxed)"},
		{[]string{"kiro"}, "none"},
	} {
		ta := newTestApp(t, "")
		ta.Cfg.OpenShell.Harnesses = tc.harnesses
		if c := ta.wrappersCheck(); c.Detail != tc.want {
			t.Errorf("harnesses %v: wrappers check = %q, want %q", tc.harnesses, c.Detail, tc.want)
		}
	}
}

// TestTeardownDryRunListsEveryStep pins the dry run a newcomer reads: every
// step, "none" and "nothing to restore" included, the provider profiles
// labeled by whose they are, and a closing "nothing was changed" (manual
// test R2-40). A teardown with only openshell.enabled left turns it off.
func TestTeardownDryRunListsEveryStep(t *testing.T) {
	ctx := context.Background()
	ta := newTestApp(t, "")
	writeConfig(t, ta, "")
	fake := openshelltest.New()
	client := fake.Client(openshell.ClientOptions{})
	ownPort := ta.Cfg.OpenShellIngressPort()
	imports := []struct {
		id string
		in profiles.Input
	}{
		{profiles.IngressID, profiles.Input{IngressPort: ownPort}},
		{profiles.IngressID, profiles.Input{IngressPort: ownPort + 1000}},
		{profiles.AnthropicID, profiles.Input{Binaries: []string{"/opt/defenseclaw-harness/claudecode/bin/claude"}}},
	}
	for _, im := range imports {
		p, err := profiles.Render(im.id, im.in)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.ImportProfiles(ctx, []openshell.ProfileImportItem{{Profile: p.Spec, Source: "test"}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"dc-cred-0001", "dc-cred-0002", "dc-cred-0003", "dc-cred-0004"} {
		p, err := profiles.Render(profiles.AnthropicID, profiles.Input{Binaries: []string{"/opt/defenseclaw-harness/claudecode/bin/claude"}})
		if err != nil {
			t.Fatal(err)
		}
		p.Spec.ID = id
		if _, err := client.ImportProfiles(ctx, []openshell.ProfileImportItem{{Profile: p.Spec, Source: "test"}}); err != nil {
			t.Fatal(err)
		}
	}
	ta.OpenShell = func(context.Context) (openshell.Client, *openshell.Registration, error) {
		return noCloseClient{client}, &openshell.Registration{Name: "openshell"}, nil
	}
	ta.daemon.add(sampleSandbox("dc-claude-live"))
	ta.images.recs = []image.Record{{Tag: "defenseclaw/sandbox:claudecode-1"}}

	if err := ta.Teardown(ctx, TeardownOptions{DryRun: true}); err != nil {
		t.Fatal(err)
	}
	out := ta.output()
	for _, want := range []string{
		"  sandboxes         dc-claude-live\n",
		"  providers         none\n",
		"  provider profiles " + profiles.IngressProfileID(ownPort) + " (this install's hook ingress)\n" +
			"                    " + profiles.AnthropicID + ", 4 --credential profiles (dc-cred-…) (shared by every DefenseClaw install on this gateway and unused now; an install that needs one imports it again)\n",
		"  images            defenseclaw/sandbox:claudecode-1\n",
		"  gateway config    nothing to restore (setup recorded no change to it)\n",
		"  shell wrappers    none\n",
		"  config            turn openshell.enabled off in " + ta.ConfigPath + "\n",
		"dry run: nothing was changed\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, profiles.IngressProfileID(ownPort+1000)) {
		t.Errorf("the dry run removes another install's ingress profile:\n%s", out)
	}
	if !loadConfig(t, ta).OpenShell.Enabled {
		t.Fatal("the dry run changed the config")
	}

	// Only openshell.enabled is left: teardown still turns it off.
	ta = newTestApp(t, "")
	writeConfig(t, ta, "")
	if err := ta.Teardown(ctx, TeardownOptions{Yes: true}); err != nil {
		t.Fatalf("Teardown: %v\n%s", err, ta.output())
	}
	if strings.Contains(ta.output(), "nothing to tear down") || loadConfig(t, ta).OpenShell.Enabled {
		t.Fatalf("teardown left openshell.enabled on:\n%s", ta.output())
	}
}
