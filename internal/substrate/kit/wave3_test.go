// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The actor kit runs in Linux actor images only (kit.Config refuses other systems); its tests render and
// resolve paths for Linux.
//go:build linux

package kit

import (
	"bytes"
	"path"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Every wave-3 connector renders for Substrate with no reference to an
// OpenShell shell hook, transport or binding token, and has both argv forms.
func TestWave3OverlaysCarryNoOpenShellReferences(t *testing.T) {
	for _, name := range Wave3Connectors {
		ov := wave2Overlay(t, name)
		for _, f := range ov.Files {
			if bytes.Contains(f.Data, []byte("-hook.sh")) || bytes.Contains(f.Data, []byte(connector.SandboxIngressHost)) ||
				bytes.Contains(f.Data, []byte(connector.SandboxTokenEnv)) {
				t.Errorf("%s: %s keeps an OpenShell reference", name, f.Path)
			}
		}
		if len(InteractiveArgv[name]) == 0 || len(HeadlessArgv[name]) == 0 {
			t.Errorf("%s: no interactive or headless argv", name)
		}
		hasPrompt := false
		for _, a := range HeadlessArgv[name] {
			hasPrompt = hasPrompt || a == "{prompt}"
		}
		if !hasPrompt {
			t.Errorf("%s: the headless argv has no {prompt}", name)
		}
	}
}

// Cursor's and Devin's registrations ran the OpenShell shell hook, which an
// actor image does not carry (so every tool call was refused): they run the
// actor hook, with the event in the payload.
func TestWave3HookCommandsRunTheActorHook(t *testing.T) {
	want := map[string][2]string{
		"cursor": {"/etc/cursor/hooks.json", `"command": "'` + HookBinary + `' --connector cursor"`},
		"devin":  {XDGConfigHome + "/devin/config.json", `"command": "` + HookBinary + ` --connector devin"`},
	}
	for name, w := range want {
		ov := wave2Overlay(t, name)
		got := string(file(ov, w[0]))
		if !strings.Contains(got, w[1]) {
			t.Errorf("%s: %s lacks %q:\n%.600s", name, w[0], w[1], got)
		}
		if strings.Contains(got, "--event") {
			t.Errorf("%s: the hook command names an event, but the event is in the payload", name)
		}
	}
}

// Amp's plugin posts through the actor hook (hook-post): no token, no
// connection of its own, fail closed. Its headless run reads the root-owned
// allow-all settings; an interactive run does not.
func TestAmpSubstratePluginAndHeadlessSettings(t *testing.T) {
	ov := wave2Overlay(t, "amp")
	plugin := file(ov, "/sandbox/.config/amp/plugins/defenseclaw.ts")
	if len(plugin) == 0 {
		t.Fatal("amp: no plugin in the overlay")
	}
	for _, must := range []string{HookBinary, `"hook-post"`, "/api/v1/amp/hook", "sandbox hooks always fail closed"} {
		if !bytes.Contains(plugin, []byte(must)) {
			t.Errorf("amp plugin lacks %q", must)
		}
	}
	for _, mustNot := range []string{connector.SandboxTokenEnv, connector.SandboxIngressHost, "DC_TOKEN_FILE"} {
		if bytes.Contains(plugin, []byte(mustNot)) {
			t.Errorf("amp plugin still has %q", mustNot)
		}
	}
	settings := file(ov, AmpHeadlessSettings)
	if !strings.Contains(string(settings), `"amp.dangerouslyAllowAll": true`) {
		t.Errorf("amp: headless settings %q", settings)
	}
	head := strings.Join(HeadlessArgv["amp"], " ")
	if !strings.Contains(head, "--settings-file "+AmpHeadlessSettings+" -x {prompt}") {
		t.Errorf("amp headless argv %q does not read the settings file", head)
	}
	if strings.Contains(strings.Join(InteractiveArgv["amp"], " "), "settings-file") {
		t.Error("amp interactive argv reads the allow-all settings")
	}
}

func TestSigninRefusalFromTheGateway(t *testing.T) {
	body := []byte(`{"error":"Forbidden","reason":"subscription_signin_refused","message":"Devin CLI signs in with a vendor account."}`)
	if msg, ok := signinRefusal(403, body); !ok || !strings.Contains(msg, "Devin CLI") {
		t.Fatalf("signinRefusal = %q, %v", msg, ok)
	}
	if _, ok := signinRefusal(403, []byte(`{"reason":"actor_not_registered"}`)); ok {
		t.Error("another 403 reason is not an E9 refusal")
	}
	if _, ok := signinRefusal(200, body); ok {
		t.Error("a 200 is not a refusal")
	}
	if msg, ok := signinRefusal(403, []byte(`{"reason":"subscription_signin_refused"}`)); !ok || msg == "" {
		t.Errorf("a refusal without a message needs a default: %q, %v", msg, ok)
	}
}

// GAP-0136: the hook registration of Devin lives under the root-owned
// XDGConfigHome (both agents run with XDG_CONFIG_HOME there), not in the
// agent-owned HOME: the file, its folder and the tree above it are root-owned,
// so the agent cannot rewrite, rename or delete them.
func TestWave3HookRegistrationsAreRootOwned(t *testing.T) {
	cases := map[string]string{
		"devin": XDGConfigHome + "/devin/config.json",
	}
	for name, p := range cases {
		ov := wave2Overlay(t, name)
		var found bool
		for _, f := range ov.Files {
			if f.Path == p {
				found = true
				if f.User || f.Mode != 0o644 {
					t.Errorf("%s: %s is user-owned or writable (user=%v mode=%o)", name, p, f.User, f.Mode)
				}
			}
			if strings.HasPrefix(f.Path, "/sandbox/.config/"+name+"/") && name == "devin" {
				t.Errorf("%s: %s is still a copy under HOME", name, f.Path)
			}
		}
		if !found {
			t.Errorf("%s: %s not in the overlay", name, p)
		}
		rootDirs := map[string]bool{}
		for _, d := range ov.RootDirs {
			rootDirs[d] = true
		}
		for _, d := range []string{XDGConfigHome, path.Dir(p)} {
			if !rootDirs[d] {
				t.Errorf("%s: %s is not made root-owned and readable (RootDirs %v)", name, d, ov.RootDirs)
			}
		}
		if got := wave2RelayEnv[name]["XDG_CONFIG_HOME"]; got != XDGConfigHome {
			t.Errorf("%s: the agent does not run with XDG_CONFIG_HOME=%s (%q)", name, XDGConfigHome, got)
		}
		for _, f := range ov.Files {
			if strings.HasPrefix(f.Path, XDGConfigHome) && f.User {
				t.Errorf("%s: %s under the root-owned config home is the agent's", name, f.Path)
			}
		}
	}
	dv := wave2Overlay(t, "devin")
	if !strings.Contains(string(file(dv, XDGConfigHome+"/devin/config.json")), `"version": 1`) {
		t.Error("devin: the config does not carry the schema version Devin would otherwise write at its first start")
	}
	userDirs := strings.Join(dv.UserDirs, " ")
	if !strings.Contains(userDirs, XDGConfigHome+"/devin/cli") {
		t.Errorf("devin: no agent-owned state folder (UserDirs %v)", dv.UserDirs)
	}
}

// Amp's plugin stays in the agent's HOME (it chmods its config folder at every
// start, so the folder cannot be root-owned): the connector is refused in
// managed instead (package signin), and the plugin is the agent's file.
func TestAmpPluginStaysInHome(t *testing.T) {
	ov := wave2Overlay(t, "amp")
	var found bool
	for _, f := range ov.Files {
		if f.Path == "/sandbox/.config/amp/plugins/defenseclaw.ts" {
			found = true
			if !f.User {
				t.Error("amp: the plugin is not the agent's file, but Amp cannot run with its folder root-owned")
			}
		}
	}
	if !found {
		t.Error("amp: no plugin in the overlay")
	}
	if len(wave2RelayEnv["amp"]) != 0 {
		t.Errorf("amp runs with a moved config home: %v", wave2RelayEnv["amp"])
	}
}
