// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"bytes"
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
		"devin":  {"/usr/local/lib/defenseclaw/devin/config.json", `"command": "` + HookBinary + ` --connector devin"`},
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
	// Devin has a baked copy under HOME as well; both must agree.
	ov := wave2Overlay(t, "devin")
	if !bytes.Equal(file(ov, "/sandbox/.config/devin/config.json"), file(ov, "/usr/local/lib/defenseclaw/devin/config.json")) {
		t.Error("devin: the baked and canonical config differ")
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

// GAP-0136: the hook registration files of Amp and Devin, their folders and
// ~/.config are root-owned, so the agent cannot rewrite, rename or delete them.
func TestWave3HookRegistrationsAreRootOwned(t *testing.T) {
	cases := map[string][]string{
		"amp":   {"/sandbox/.config/amp/plugins/defenseclaw.ts"},
		"devin": {"/sandbox/.config/devin/config.json", "/usr/local/lib/defenseclaw/devin/config.json"},
	}
	for name, files := range cases {
		ov := wave2Overlay(t, name)
		for _, p := range files {
			var found bool
			for _, f := range ov.Files {
				if f.Path != p {
					continue
				}
				found = true
				if f.User || f.Mode != 0o644 {
					t.Errorf("%s: %s is user-owned or writable (user=%v mode=%o)", name, p, f.User, f.Mode)
				}
			}
			if !found {
				t.Errorf("%s: %s not in the overlay", name, p)
			}
		}
		roots := strings.Join(ov.RootDirs, " ")
		for _, d := range []string{"/sandbox/.config"} {
			if !strings.Contains(roots, d) {
				t.Errorf("%s: %s is not root-owned (RootDirs %v)", name, d, ov.RootDirs)
			}
		}
	}
	amp := wave2Overlay(t, "amp")
	rootSet := map[string]bool{}
	for _, d := range amp.RootDirs {
		rootSet[d] = true
	}
	for _, d := range []string{"/sandbox/.config/amp/plugins", "/sandbox/.config/amp", "/sandbox/.config"} {
		if !rootSet[d] {
			t.Errorf("amp: %s is not root-owned (RootDirs %v)", d, amp.RootDirs)
		}
	}
	dv := wave2Overlay(t, "devin")
	if !strings.Contains(string(file(dv, "/sandbox/.config/devin/config.json")), `"version": 1`) {
		t.Error("devin: the config does not carry the schema version Devin would otherwise write at its first start")
	}
	if !bytes.Equal(file(dv, "/sandbox/.config/devin/config.json"), file(dv, "/usr/local/lib/defenseclaw/devin/config.json")) {
		t.Error("devin: the live and canonical config differ")
	}
}
