// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// gap0210Packs are the three shipped packs a model response is checked with.
var gap0210Packs = []string{"default", "permissive", "strict"}

// gap0210Turn implants value in an ordinary assistant turn at the head, the
// middle or the tail, the way the response-owner corpus does, with enough
// prose around it that a streamed reply is checked more than once.
func gap0210Turn(value, where string) string {
	filler := strings.Repeat("The rollback finished with rc 0 and the verify step is next on the list. ", 8)
	switch where {
	case "head":
		return value + "\n\n" + filler + filler
	case "middle":
		return filler + "\n\nHere is the value you asked for: " + value + "\n\n" + filler
	default:
		return filler + filler + "\n\nCopy this: " + value
	}
}

// gap0210PackContext pins the shipped pack profile on ctx, as a gateway
// generation does for every request. A published generation binds the
// connector rule packs registered for the process (registeredRules); the
// pinned one binds none, so a connector scan uses the pinned pack and not a
// pack an earlier connector setup in the test process registered
// (rel-1-0-10:GAP-1305).
func gap0210PackContext(t *testing.T, profile string) context.Context {
	t.Helper()
	return withPinnedGeneration(context.Background(), &Generation{
		activeRules:     packGenerationForProfile(t, profile),
		registeredRules: map[string]*compiledRulePackCategories{},
	})
}

// TestGAP1305ResponseChecksIgnoreAnEarlierConnectorSetup: rel-1-0-10:GAP-1305
// (FX13-RACE s4 shuffle seed 2). A claudecode connector setup earlier in the
// process (TestSetupOneConnector_SuccessNoTeardown, a hook contract admission
// or a mode-only reload test) registered the default pack for claudecode. The
// hook prompt check of the strict pack then scanned with it: SSN HIGH on the
// hook, CRITICAL in the completion. The GAP-0210 checks keep the pinned pack
// whatever a connector registered before them.
func TestGAP1305ResponseChecksIgnoreAnEarlierConnectorSetup(t *testing.T) {
	resetConnectorRuleCategories(t)
	publishConnectorRulePackOverrides("claudecode", packGenerationForProfile(t, "default"))
	t.Run("secret kinds", TestGAP0210ModelResponseFindsEverySecretKind)
}

// gap0210Stream replays text as the proxy streams a completion (s7bench
// InspectStream): a mid-stream check every 500 bytes of 32-byte chunks and one
// at the end. It returns every verdict in order.
func gap0210Stream(ctx context.Context, insp *GuardrailInspector, text string) []*ScanVerdict {
	var verdicts []*ScanVerdict
	var acc strings.Builder
	lastScan := 0
	for off := 0; off < len(text); off += 32 {
		end := min(off+32, len(text))
		acc.WriteString(text[off:end])
		if acc.Len()-lastScan >= 500 || end == len(text) {
			verdicts = append(verdicts, insp.InspectMidStream(ctx, "completion", acc.String(),
				[]ChatMessage{{Role: "assistant", Content: acc.String()}}, "model", "action"))
			lastScan = acc.Len()
		}
	}
	return verdicts
}

func gap0210HasRule(findings []string, ruleID string) bool {
	return slices.ContainsFunc(findings, func(f string) bool { return strings.HasPrefix(f, ruleID+":") })
}

func gap0210Inspector() *GuardrailInspector {
	insp := NewGuardrailInspector("local", nil, nil)
	insp.SetDetectionStrategy("regex_only", "", "", "", false)
	return insp
}

// TestGAP0210ModelResponseFindsEverySecretKind: rel-1-0-10:GAP-0210 names
// three kinds a model response let through: a Hugging Face access token, a
// PEM private key block and an SSN-shaped number. Each one, from the repo's
// existing fixtures (secretRuleTruePositives, the regex security suite), at the
// head, the middle and the tail of an assistant turn, is found by its rule in
// every shipped pack, in the whole completion and in the streamed one, at the
// severity the hook prompt check gives the same text in the same pack, and is
// never allowed. The SSN rule needs an SSN context (credibleSSNContext) on every
// surface, so the suite's labelled and listed numbers are the cases here.
func TestGAP0210ModelResponseFindsEverySecretKind(t *testing.T) {
	type secretCase struct{ name, text, ruleID string }
	var cases []secretCase
	for _, fx := range secretRuleTruePositives() {
		switch fx.wantID {
		case "SEC-HF-TOKEN", "SEC-PRIVKEY":
			cases = append(cases, secretCase{fx.name, fx.input, fx.wantID})
		}
	}
	for _, c := range readJSONL[regexCase](t, "regex", "corpus.jsonl") {
		switch c.ID {
		case "pii/ssn-completion", "pii/ssn-list-unlabeled":
			cases = append(cases, secretCase{c.ID, c.Content, "ENT-BULK-SSN"})
		}
	}
	kinds := map[string]int{}
	for _, c := range cases {
		kinds[c.ruleID]++
	}
	if kinds["SEC-HF-TOKEN"] != 1 || kinds["SEC-PRIVKEY"] < 3 || kinds["ENT-BULK-SSN"] != 2 {
		t.Fatalf("fixtures per rule %v: want 1 Hugging Face token, 3 private keys, 2 SSN suite cases", kinds)
	}
	api := &APIServer{scannerCfg: &config.Config{}}
	insp := gap0210Inspector()
	for _, profile := range gap0210Packs {
		ctx := gap0210PackContext(t, profile)
		for _, c := range cases {
			for _, where := range []string{"head", "middle", "tail"} {
				text := gap0210Turn(c.text, where)
				hook := api.inspectMessageContent(ctx, claudeCodeContentInspectRequest(text, "prompt"))
				if !gap0210HasRule(hook.Findings, c.ruleID) {
					t.Errorf("%s %s %s: the hook prompt check does not find %s (%v)",
						profile, c.name, where, c.ruleID, hook.Findings)
				}
				whole := insp.Inspect(ctx, "completion", text, nil, "model", "action")
				if !gap0210HasRule(whole.Findings, c.ruleID) || whole.Severity != hook.Severity {
					t.Errorf("%s %s at the %s of a completion: %s %v, want %s at the hook severity %s",
						profile, c.name, where, whole.Severity, whole.Findings, c.ruleID, hook.Severity)
				}
				if action := guardrailFallbackActionForProfile(whole.Severity, profile); action == "allow" {
					t.Errorf("%s %s at the %s of a completion is allowed (%s)", profile, c.name, where, whole.Severity)
				}
				var streamed *ScanVerdict
				for _, v := range gap0210Stream(ctx, insp, text) {
					if gap0210HasRule(v.Findings, c.ruleID) {
						streamed = v
						break
					}
				}
				if streamed == nil {
					t.Errorf("%s %s at the %s of a streamed completion: no mid-stream check finds %s", profile, c.name, where, c.ruleID)
				} else if streamed.Severity != hook.Severity {
					t.Errorf("%s %s at the %s of a streamed completion: severity %s, hook %s", profile, c.name, where, streamed.Severity, hook.Severity)
				}
			}
		}
	}
}

// TestGAP0213PlaceholdersStayQuietInAModelResponse: rel-1-0-10:GAP-0213. A
// documentation placeholder where a credential would go (the corpus's
// `password: <your-password-here>`, password_assignment_test.go's quoted
// your-password-here, the regex suite's bearer and alphabet placeholders) is
// quiet in a model response in every pack, whole and streamed, as it is on the
// hook prompt check. The proxy used to run its own password regex, which took
// any explicit password assignment as a secret, placeholders included, so these
// alerted in default and blocked in strict only in a response.
func TestGAP0213PlaceholdersStayQuietInAModelResponse(t *testing.T) {
	placeholders := []string{
		"password: <your-password-here>",
		"`password: <your-password-here>`",
		`"password": "your-password-here"`,
		`password: <your-password>`,
	}
	for _, c := range readJSONL[regexCase](t, "regex", "corpus.jsonl") {
		switch c.ID {
		case "benign/bearer-placeholder", "benign/github-alphabet-placeholder":
			placeholders = append(placeholders, c.Content)
		}
	}
	if len(placeholders) != 6 {
		t.Fatalf("placeholder fixtures = %d, want 6 (regex suite rows renamed?)", len(placeholders))
	}
	api := &APIServer{scannerCfg: &config.Config{}}
	insp := gap0210Inspector()
	for _, profile := range gap0210Packs {
		ctx := gap0210PackContext(t, profile)
		for _, placeholder := range placeholders {
			for _, where := range []string{"head", "middle", "tail"} {
				text := gap0210Turn(placeholder, where)
				hook := api.inspectMessageContent(ctx, claudeCodeContentInspectRequest(text, "prompt"))
				if hook.Severity != "NONE" {
					t.Fatalf("%s %q: the hook prompt check reports %s %v; the placeholder is not quiet on the hook path either",
						profile, placeholder, hook.Severity, hook.Findings)
				}
				whole := insp.Inspect(ctx, "completion", text, nil, "model", "action")
				if whole.Severity != "NONE" || len(whole.Findings) > 0 {
					t.Errorf("%s %q at the %s of a completion: %s %s %v, want quiet as on the hook path",
						profile, placeholder, where, whole.Action, whole.Severity, whole.Findings)
				}
				for _, v := range gap0210Stream(ctx, insp, text) {
					if v.Severity != "NONE" || len(v.Findings) > 0 {
						t.Errorf("%s %q at the %s of a streamed completion: %s %s %v, want quiet",
							profile, placeholder, where, v.Action, v.Severity, v.Findings)
						break
					}
				}
			}
		}
	}
}
