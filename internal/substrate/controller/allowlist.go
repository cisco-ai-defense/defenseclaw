// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
)

// AllowlistTemplate is a template the 1.0.10 actor allowlist refuses
// (GAP-0354, GAP-0355), with the reason.
type AllowlistTemplate struct {
	Template string
	Reason   string
}

// TemplatesFailingAllowlist attests every template of the cluster and lists,
// sorted, those that pass every rule but the 1.0.10 allowlist: the templates
// whose new actors the upgrade refuses (doctor, substrate.template_allowlist).
func TemplatesFailingAllowlist(ctx context.Context, c ateapi.Client, a Attestor) ([]AllowlistTemplate, error) {
	ts, err := ateapi.AllActorTemplates(ctx, c, "", DefaultPageSize)
	if err != nil {
		return nil, err
	}
	var out []AllowlistTemplate
	for _, t := range ts {
		att, err := a.Attest(ctx, t)
		if err != nil || att.Attested || !att.Allowlist {
			continue
		}
		out = append(out, AllowlistTemplate{Template: ateapi.Key(ateapi.RefOf(t.GetMetadata())), Reason: att.Reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Template < out[j].Template })
	return out, nil
}

// AllowlistCheckID is the doctor row of TemplatesFailingAllowlist.
const AllowlistCheckID = "substrate.template_allowlist"

// maxAllowlistShown bounds the templates a doctor row names.
const maxAllowlistShown = 20

// AllowlistCheck is the doctor row: pass, warn naming every template (up to
// maxAllowlistShown) with its reason, or warn when the templates could not
// be read.
func AllowlistCheck(ts []AllowlistTemplate, err error) (status, detail, fix string) {
	switch {
	case err != nil:
		return "warn", "the templates could not be listed to check them against the 1.0.10 actor allowlist: " + err.Error(), ""
	case len(ts) == 0:
		return "pass", "every template passes the actor environment, entrypoint and mount allowlist", ""
	}
	parts := make([]string, 0, len(ts))
	for i, t := range ts {
		if i == maxAllowlistShown {
			parts = append(parts, fmt.Sprintf("and %d more", len(ts)-i))
			break
		}
		parts = append(parts, t.Template+" ("+t.Reason+")")
	}
	return "warn", fmt.Sprintf("%d template(s) fail the actor allowlist of DefenseClaw 1.0.10: %s", len(ts), strings.Join(parts, "; ")),
		AllowlistImpact
}
