// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/effects"
)

func TestAliasMemoNotWrittenByABlockedLink(t *testing.T) {
	useEffectsRulesMode(t, "on")
	installToolCallCorpusProfileConnector(t, "claudecode", "strict")
	cfg := &config.Config{}
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.BlockAt = "CRITICAL"
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
	const command = "ln -sf ~/.ssh/id_rsa /home/u/work/blocked-alias; cat /home/u/work/blocked-alias"
	args, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	first := shadowLiveRequest(command)
	first.Input.Tool = "Bash"
	first.Input.Args = args
	first.LegacyText = string(args)
	first.sessionID = "gap2075-blocked-session"
	verdict := (&APIServer{scannerCfg: cfg}).inspectTrustedToolPolicyCtx(t.Context(),
		&ToolInspectRequest{Tool: "Bash", Args: args, Direction: "tool_call", Connector: "claudecode"}, first)
	if verdict == nil || verdict.Action != guardrailActionBlock {
		t.Fatalf("first call action %v, want block", verdict)
	}
	use := shadowLiveRequest("cat /home/u/work/blocked-alias")
	use.sessionID = first.sessionID
	if got := effectShadowRun(use, effectRulesOn, tierRestricted)[0]; len(got.ReadProofs) != 0 {
		t.Fatalf("blocked link was remembered: %+v", got.ReadProofs)
	}
}

func TestAliasMemoClearedByOverwrite(t *testing.T) {
	var memo effectAliasMemo
	request := shadowLiveRequest("")
	request.sessionID = "gap2075-overwrite"
	const alias = "/home/u/work/replace-alias"
	link, facts := aliasMemoFixture(alias)
	read := effects.Result{Effects: []effects.Effect{{Kind: effects.KindRead,
		TargetState: effects.TargetStateKnown, RoleState: effects.RoleStateKnown,
		Target: effects.Target{Path: alias}}}}
	memo.remember(request, link, facts, effects.FlavorPOSIX)
	// A normal copy follows the existing destination link; the alias stays.
	memo.remember(request, effects.Result{Effects: []effects.Effect{{Kind: effects.KindWrite,
		Target: effects.Target{Path: alias}, Origin: effects.Origin{Program: "cp"}}}}, nil, effects.FlavorPOSIX)
	if got := memo.uses(request, read); len(got) != 1 {
		t.Fatalf("copy through link lost alias proof: %+v", got)
	}
	// Rename replaces the directory entry, so the old link is gone.
	memo.remember(request, effects.Result{Effects: []effects.Effect{{Kind: effects.KindWrite,
		Target: effects.Target{Path: alias}, Origin: effects.Origin{Program: "mv"}}}}, nil, effects.FlavorPOSIX)
	if got := memo.uses(request, read); len(got) != 0 {
		t.Fatalf("replaced alias retained credential proof: %+v", got)
	}
}

func TestAliasMemoNotWrittenWhenSecondShellReadingBlocks(t *testing.T) {
	useEffectsRulesMode(t, "on")
	installToolCallCorpusProfileConnector(t, "hermes", "strict")
	cfg := &config.Config{}
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "hermes"
	cfg.Guardrail.BlockAt = "CRITICAL"
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
	const link = "ln -sf ~/.ssh/id_rsa /home/u/work/second-reading-alias"
	args, err := json.Marshal(map[string]any{"command": link, "background": true})
	if err != nil {
		t.Fatal(err)
	}
	action := shadowLiveRequest(link)
	action.Connector = "hermes"
	action.Input.Tool = "terminal"
	action.Input.Command = ""
	action.Input.Args = args
	action.LegacyText = string(args)
	action.sessionID = "gap2075-second-reading"
	secondary, err := json.Marshal(map[string]string{"command": "cat ~/.ssh/id_rsa"})
	if err != nil {
		t.Fatal(err)
	}
	req := &ToolInspectRequest{Tool: "terminal", Args: args, Direction: "tool_call", Connector: "hermes"}
	verdict := (&APIServer{scannerCfg: cfg}).inspectSandboxShellToolPolicyCtx(t.Context(), req, action, secondary, "Bash")
	if verdict == nil || verdict.Action != guardrailActionBlock {
		t.Fatalf("merged call action %v, want block", verdict)
	}
	use := shadowLiveRequest("cat /home/u/work/second-reading-alias")
	use.Connector = "hermes"
	use.sessionID = action.sessionID
	if got := effectShadowRun(use, effectRulesOn, tierRestricted)[0]; len(got.ReadProofs) != 0 {
		t.Fatalf("blocked call's link was remembered: %+v", got.ReadProofs)
	}
}

// An HTTP call may be refused after the scanner has read its link effect.
// The alias must stay absent when the route's final bounded-review policy
// blocks that call.
func TestAliasMemoNotWrittenAfterFinalInspectBlock(t *testing.T) {
	useEffectsRulesMode(t, "on")
	installToolCallCorpusProfileConnector(t, "claudecode", "strict")
	previousHome := sameHostHomeForTest
	sameHostHomeForTest = "/home/u"
	t.Cleanup(func() { sameHostHomeForTest = previousHome })
	cfg := &config.Config{}
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.BlockAt = "CRITICAL"
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
	api := &APIServer{scannerCfg: cfg}
	const link = "ln -sf ~/.ssh/id_rsa /home/u/work/final-block-alias"
	body, err := json.Marshal(map[string]any{
		"tool": "Bash", "connector": "claudecode", "session_id": "gap2075-final-block",
		"args": map[string]string{"command": link}, "args_partial": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	api.handleInspectTool(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", bytes.NewReader(body)))
	var verdict ToolInspectVerdict
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &verdict) != nil ||
		verdict.Action != guardrailActionBlock {
		t.Fatalf("final inspect: status %d body %s", recorder.Code, recorder.Body.String())
	}
	use := shadowLiveRequest("cat /home/u/work/final-block-alias")
	use.sessionID = "gap2075-final-block"
	if got := effectShadowRun(use, effectRulesOn, tierRestricted)[0]; len(got.ReadProofs) != 0 {
		t.Fatalf("final-blocked link was remembered: %+v", got.ReadProofs)
	}
}
