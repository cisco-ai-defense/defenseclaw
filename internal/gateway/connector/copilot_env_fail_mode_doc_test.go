// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// 1.0.4 lead directive with the train's per-user Copilot native deny
// (w3-g3-hooks): the per-user GitHub Copilot CLI hook takes its fail mode
// from the installed render alone. DEFENSECLAW_FAIL_MODE in the agent's
// environment neither closes an open hook nor opens a closed one; strict
// availability closes it. A closed hook answers a gateway outage with
// Copilot's native deny. T5 integration: the g-hooks-upg branch asserted the
// pre-w3-g3-hooks behaviour (an outage always allowed); the train keeps the
// deny and the docs say what runs.
func TestPerUserCopilotHookFailModeIsTheInstalledOne(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX hooks")
	}
	outage := ConnectorHookOutage(NewCopilotConnector())
	if outage.PerUserClosed != OutageBlocks || outage.StrictAvailability != StrictAvailabilityRead {
		t.Fatalf("HookOutage does not say what the per-user Copilot hook does (closed denies, strict availability read): %+v", outage)
	}
	for _, tc := range []struct {
		installed, env, strict string
		deny                   bool
	}{
		{installed: "closed", env: "open", deny: true},
		{installed: "closed", env: "", deny: true},
		{installed: "open", env: "closed", deny: false}, // the outage-open tier: the environment cannot close it
		{installed: "open", env: "", strict: "1", deny: true},
	} {
		t.Run("installed="+tc.installed+"/env="+tc.env+"/strict="+tc.strict, func(t *testing.T) {
			home := t.TempDir()
			hookDir := filepath.Join(home, "hooks")
			opts := SetupOpts{DataDir: home, APIAddr: "127.0.0.1:1", APIToken: "scoped-test-token", HookFailMode: tc.installed}
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewCopilotConnector()); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", filepath.Join(hookDir, "copilot-hook.sh"), "--event", "preToolUse")
			cmd.Stdin = strings.NewReader(`{"cwd":"/tmp","toolName":"bash","toolArgs":"{\"command\":\"ls\"}"}`)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "DEFENSECLAW_HOME=" + home,
				"DEFENSECLAW_GATEWAY_AUTOSTART=0", "DEFENSECLAW_FAIL_MODE=" + tc.env, "DEFENSECLAW_STRICT_AVAILABILITY=" + tc.strict}
			out, _ := cmd.CombinedOutput()
			if denied := strings.Contains(string(out), `"permissionDecision":"deny"`); denied != tc.deny {
				t.Fatalf("per-user Copilot hook denied an outage = %v, want %v\n%s", denied, tc.deny, out)
			}
		})
	}
	for _, doc := range []struct {
		path string
		want []string
	}{
		{filepath.Join("..", "..", "..", "docs-site", "content", "docs", "reference", "configuration", "fail-modes.mdx"), []string{
			"`DEFENSECLAW_FAIL_MODE` is not read",
		}},
		{filepath.Join("..", "..", "envvars", "registry.json"), []string{
			"Not read by 1.0.4 hooks",
		}},
	} {
		data, err := os.ReadFile(doc.path)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(strings.Fields(string(data)), " ")
		for _, want := range doc.want {
			if !strings.Contains(text, want) {
				t.Errorf("%s does not say what the per-user hooks do: missing %q", doc.path, want)
			}
		}
	}
}

// A Copilot confirm is Copilot's own "ask": in Autopilot and in `copilot -p`
// Copilot cannot ask and denies the call, and the audit keeps confirm because
// Copilot's hook input names no mode. The connector page says so (GAP-0664).
func TestCopilotConfirmIsCopilotsAskAndThePageSaysWhereItDenies(t *testing.T) {
	out := copilotHookOutputForProfile("preToolUse", "confirm", "confirm", "needs approval", "")
	if out["permissionDecision"] != "ask" {
		t.Fatalf("preToolUse confirm = %v, want Copilot's ask", out)
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs-site", "content", "docs", "connectors", "copilot.mdx"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(strings.Fields(string(data)), " ")
	// Outside Secure Client the gateway maps a Copilot CLI confirm to a block
	// (s2-copilot, copilotCLIProfileMapVerdict): its hook does not say whether
	// it can show the prompt. The rendered ask above stays Secure Client's.
	for _, want := range []string{"`preToolUse` blocks an action-mode call that needs confirmation",
		"DefenseClaw records the delivered denial as a block"} {
		if !strings.Contains(text, want) {
			t.Errorf("connectors/copilot.mdx does not say %q", want)
		}
	}
}
