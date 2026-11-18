// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// gap0210WeakPasswordTier is one policy context of the review table: a
// shipped pack, maybe under a managed (standalone) install.
type gap0210WeakPasswordTier struct {
	name, pack string
	managed    bool
}

var gap0210WeakPasswordTiers = []gap0210WeakPasswordTier{
	{"default", "default", false},
	{"permissive", "permissive", false},
	{"strict", "strict", false},
	{"managed", "default", true},
	{"managed-strict", "strict", true},
}

func (tier gap0210WeakPasswordTier) context(t *testing.T) context.Context {
	t.Helper()
	cfg := &config.Config{}
	if tier.managed {
		cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
		cfg.Enterprise.Profile = managed.ProfileStandalone
	}
	return withPinnedGeneration(context.Background(), &Generation{Config: cfg, activeRules: packGenerationForProfile(t, tier.pack)})
}

// gap0210WeakPasswordRows are the weak explicit password assignments of
// TestAlertFatigueWeakButRealPasswordsRemainVisible: rows A01-A04 of the
// GAP-0210 Codex review r1 (s7-cxrv0210).
var gap0210WeakPasswordRows = []struct{ id, text string }{
	{"A01", "password=password123"},
	{"A02", "password=changeme123"},
	{"A03", "password=dummysecret"},
	{"A04", "password=examplepass"},
}

// TestGAP0210WeakExplicitPasswordsStillAlertInAModelResponse: rel-1-0-10
// GAP-0210 review r1 (rows A01-A04). rel alerted on a weak explicit password
// assignment in a model response, whole and streamed, through the proxy's own
// password regex; GAP-0210 removed that regex, and SEC-PASSWORD-ASSIGN reads
// these values as weak, so the response was allowed (40 weaker cells). The
// proxy content check reports them again as SEC-PASSWORD-ASSIGN
// (weakPasswordAssignmentFindings) in every tier, bare, at the head, the
// middle and the tail of an assistant turn, and with a zero-width space after
// the key; the finding carries no value. The hook prompt check stays quiet on
// them, as on rel (GAP-0522).
func TestGAP0210WeakExplicitPasswordsStillAlertInAModelResponse(t *testing.T) {
	api := &APIServer{scannerCfg: &config.Config{}}
	insp := gap0210Inspector()
	for _, tier := range gap0210WeakPasswordTiers {
		ctx := tier.context(t)
		for _, row := range gap0210WeakPasswordRows {
			value := strings.TrimPrefix(row.text, "password=")
			variants := map[string]string{
				"bare":       row.text,
				"head":       gap0210Turn(row.text, "head"),
				"middle":     gap0210Turn(row.text, "middle"),
				"tail":       gap0210Turn(row.text, "tail"),
				"zero-width": gap0210Turn(strings.Replace(row.text, "=", "\u200b=", 1), "middle"),
			}
			for where, text := range variants {
				label := tier.name + " " + row.id + " " + where
				if hook := api.inspectMessageContent(ctx, claudeCodeContentInspectRequest(text, "prompt")); hook.Severity != "NONE" {
					t.Errorf("%s: the hook prompt check reports %s %v; rel is quiet there (GAP-0522)", label, hook.Severity, hook.Findings)
				}
				whole := insp.Inspect(ctx, "completion", text, nil, "model", "action")
				if whole.Action != "alert" || whole.Severity != "MEDIUM" || !gap0210HasRule(whole.Findings, passwordAssignRuleID) {
					t.Errorf("%s: completion %s %s %v, want alert MEDIUM %s as on rel", label, whole.Action, whole.Severity, whole.Findings, passwordAssignRuleID)
				}
				for _, f := range whole.Findings {
					if strings.Contains(f, value) {
						t.Errorf("%s: completion finding carries the value: %q", label, f)
					}
				}
				streamed := gap0210Stream(ctx, insp, text)
				found := false
				for _, v := range streamed {
					found = found || gap0210HasRule(v.Findings, passwordAssignRuleID)
				}
				last := streamed[len(streamed)-1]
				if !found || last.Action != "alert" || last.Severity != "MEDIUM" {
					t.Errorf("%s: streamed completion found=%v, final check %s %s %v, want alert MEDIUM %s",
						label, found, last.Action, last.Severity, last.Findings, passwordAssignRuleID)
				}
			}
		}
	}
}

// TestGAP0210PlaceholderPasswordsStayQuietOnTheProxy: the rows the restored
// weak-password reading must leave quiet in a model response, as the hook
// path does (rel-1-0-10:GAP-0213): a well-known documentation placeholder,
// masks, slots and fill-ins that name their key (TestPasswordAssignmentRule's
// ignore list and benignPasswordRows), in every tier, whole and streamed.
func TestGAP0210PlaceholderPasswordsStayQuietOnTheProxy(t *testing.T) {
	quiet := []string{
		"password: changeme",
		"password: xxxxxxxxxx",
		`password = "********"`,
		"password: <your-password-here>",
		`"password": "your-password-here"`,
		"DB_PASSWORD=your_db_password_here",
		"password = ${DB_PASSWORD}",
		"password: required|min:8",
		`password="{db_password}"`,
		"password=**redacted**",
	}
	insp := gap0210Inspector()
	for _, tier := range gap0210WeakPasswordTiers {
		ctx := tier.context(t)
		for _, in := range quiet {
			text := gap0210Turn(in, "middle")
			whole := insp.Inspect(ctx, "completion", text, nil, "model", "action")
			if gap0210HasRule(whole.Findings, passwordAssignRuleID) || whole.Action != "allow" {
				t.Errorf("%s %q: completion %s %s %v, want quiet", tier.name, in, whole.Action, whole.Severity, whole.Findings)
			}
			for _, v := range gap0210Stream(ctx, insp, text) {
				if gap0210HasRule(v.Findings, passwordAssignRuleID) || v.Action != "allow" {
					t.Errorf("%s %q: streamed completion %s %s %v, want quiet", tier.name, in, v.Action, v.Severity, v.Findings)
					break
				}
			}
		}
	}
}
