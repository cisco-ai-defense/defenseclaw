// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingeval

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// Final is the alias the gateway would forward to after the R1 pipeline:
// classifier candidate -> fallback on error -> guardrail narrowing (a
// sensitive finding keeps only local aliases) -> profile filter (alias not
// in allowed_aliases -> default_alias). Each step narrows; none widens.
type Final struct {
	Alias      string `json:"alias"`
	FilteredBy string `json:"filtered_by,omitempty"` // fallback|guardrail|profile|deny
}

// Route applies the pipeline to one prediction.
func Route(p Prediction, sensitiveSignal bool, prof Profile, profs Profiles) Final {
	local := map[string]bool{}
	for _, a := range profs.LocalAliases {
		local[a] = true
	}
	allowed := map[string]bool{}
	for _, a := range prof.AllowedAliases {
		allowed[a] = true
	}
	f := Final{Alias: p.Alias}
	if p.Err != "" || f.Alias == "" {
		f.Alias, f.FilteredBy = profs.RequestAlias, "fallback"
	}
	if sensitiveSignal && !local[f.Alias] {
		f.Alias, f.FilteredBy = "", "guardrail"
		if allowed[prof.DefaultAlias] && local[prof.DefaultAlias] {
			f.Alias = prof.DefaultAlias
		} else {
			for _, a := range prof.AllowedAliases {
				if local[a] {
					f.Alias = a
					break
				}
			}
		}
		if f.Alias == "" {
			return Final{Alias: "deny", FilteredBy: "deny"}
		}
	}
	if !allowed[f.Alias] {
		f.FilteredBy = "profile"
		cand := prof.DefaultAlias
		if !allowed[cand] || (sensitiveSignal && !local[cand]) {
			cand = ""
			for _, a := range prof.AllowedAliases {
				if !sensitiveSignal || local[a] {
					cand = a
					break
				}
			}
		}
		if cand == "" {
			return Final{Alias: "deny", FilteredBy: "deny"}
		}
		f.Alias = cand
	}
	return f
}

// Guardrail runs the shipped local guardrail (embedded rule pack,
// regex_only, default posture) on the prompt for the one signal that may
// narrow a route: personal data or a secret. The pack's injection and
// exfiltration local patterns are emptied for this inspector, so every
// local-pattern finding left is a PII or secret pattern; rule-pack findings
// count only when their rule ID starts with one of NarrowPrefixes (SEC-
// secrets, ENT- personal data). Matched text is never kept: findings are
// reduced to a rule ID or a class (pii-data, pii-request, local-secret).
type Guardrail struct {
	NarrowPrefixes []string

	once sync.Once
	err  error
	insp *gateway.GuardrailInspector
}

// DefaultNarrowPrefixes are the rule-ID prefixes of the embedded pack's
// secret (SEC-) and personal-data (ENT-) rules.
var DefaultNarrowPrefixes = []string{"SEC-", "ENT-"}

func (g *Guardrail) init() {
	pack, err := guardrail.LoadRulePack("")
	if err != nil {
		g.err = err
		return
	}
	if err := gateway.ApplyRulePackOverrides(pack); err != nil {
		g.err = err
		return
	}
	lp := guardrail.LocalPatterns{Version: 1}
	if pack.LocalPatterns != nil {
		lp = *pack.LocalPatterns
	}
	lp.Injection, lp.InjectionRegexes, lp.Exfiltration = []string{}, []string{}, []string{}
	if err := gateway.ApplyLocalPatternsOverride(&lp); err != nil {
		g.err = err
		return
	}
	g.insp = gateway.NewGuardrailInspector("local", nil, nil)
	g.insp.SetDetectionStrategy("regex_only", "", "", "", false)
	g.insp.SetPosture("default")
}

var ruleIDShape = regexp.MustCompile(`^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$`)

// Sensitive reports the narrowing signal and the finding classes.
func (g *Guardrail) Sensitive(ctx context.Context, it Item) (bool, []string, error) {
	g.once.Do(g.init)
	if g.err != nil {
		return false, nil, g.err
	}
	msgs := make([]gateway.ChatMessage, 0, len(it.Messages))
	for _, m := range it.Messages {
		msgs = append(msgs, gateway.ChatMessage{Role: m.Role, Content: m.Content})
	}
	v := g.insp.Inspect(ctx, "prompt", it.AllText(), msgs, "", "observe")
	if v == nil {
		return false, nil, nil
	}
	narrow := false
	classes := make([]string, 0, len(v.Findings))
	for _, f := range v.Findings {
		c, sensitive := g.classify(f)
		classes = append(classes, c)
		narrow = narrow || sensitive
	}
	return narrow, classes, nil
}

// classify reduces a finding to a class without its matched text.
func (g *Guardrail) classify(f string) (string, bool) {
	f = strings.TrimSpace(f)
	head := f
	if i := strings.Index(f, ":"); i > 0 {
		head = f[:i]
	}
	switch {
	case ruleIDShape.MatchString(head):
		for _, p := range g.NarrowPrefixes {
			if strings.HasPrefix(head, p) {
				return head, true
			}
		}
		return head, false
	case head == "pii-data" || head == "pii-request":
		return head, true
	case head == "bulk-access" || head == "exfil-context":
		return head, false
	default: // a secret local pattern or detector match (text dropped)
		return "local-secret", true
	}
}
