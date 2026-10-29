// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// codeNativeOTLPProductCredential names an account's own Codex or Claude
// Code configuration whose native OTLP exporter carries the managed gateway
// token (GAP-1360).
const codeNativeOTLPProductCredential = "native_otlp_product_credential"

// codeNativeOTLPConfigUnchecked names an account's own configuration the
// native OTLP check could not read.
const codeNativeOTLPConfigUnchecked = "native_otlp_config_unchecked"

// warnUserNativeOTLPExporters runs the same check managed Windows verify
// runs: it asks the gateway (`enterprise hooks native-otlp-check`, which
// reads each account's own Codex config.toml and Claude Code settings.json
// as that user) for native OTLP exporters that carry the managed gateway
// token. Such an exporter sends the token and the agent's prompt telemetry
// to whoever holds its port, which no DefenseClaw process serves. The
// guardian removes a removable one on its next pass; between passes, and
// for one it cannot edit, this is the only report. It is a warning, never a
// verify failure (GAP-1360).
func (l *lifecycle) warnUserNativeOTLPExporters(ctx context.Context) {
	r := l.result
	out, err := l.env.runGatewayCLI(ctx, "enterprise", "hooks", "native-otlp-check", "--manifest", l.env.Layout.ManifestPath, "--json")
	var report struct {
		OK       bool `json:"ok"`
		Findings []struct {
			User      string   `json:"user"`
			Connector string   `json:"connector"`
			Path      string   `json:"path"`
			Entries   []string `json:"entries"`
			Error     string   `json:"error"`
		} `json:"findings"`
		Unchecked []string `json:"unchecked"`
		Error     string   `json:"error"`
	}
	if parseErr := json.Unmarshal(out.Stdout, &report); parseErr != nil || !report.OK {
		reason := report.Error
		switch {
		case reason != "":
		case err != nil:
			reason = err.Error()
		case parseErr != nil:
			reason = "invalid report: " + parseErr.Error()
		default:
			reason = "the check did not confirm success"
		}
		r.AddWarning(codeNativeOTLPConfigUnchecked, "could not check the accounts' own Codex and Claude Code configuration for a native OTLP exporter that carries the DefenseClaw gateway token: "+
			bounded(reason, 512)+"; rerun `"+l.env.lifecycleCommand(ActionVerify)+"`")
		return
	}
	repair := l.env.lifecycleCommand(ActionRepair)
	for _, finding := range report.Findings {
		label := connectorLabel(finding.Connector)
		if finding.Error != "" {
			r.AddWarning(codeNativeOTLPConfigUnchecked, fmt.Sprintf(
				"could not check %s's own %s configuration %s for a native OTLP exporter that carries the DefenseClaw gateway token: %s",
				finding.User, label, finding.Path, bounded(finding.Error, 512)))
			continue
		}
		r.MarkSecurityIncomplete(codeNativeOTLPProductCredential)
		r.AddWarning(codeNativeOTLPProductCredential, fmt.Sprintf(
			"%s's own %s configuration %s has a native OTLP exporter that sends the DefenseClaw gateway token to a port the managed gateway does not serve (%s); the guardian removes it on its next pass; or run `%s`",
			finding.User, label, finding.Path, strings.Join(finding.Entries, ", "), repair))
	}
}

// connectorLabel is the product name of a native OTLP connector.
func connectorLabel(name string) string {
	switch name {
	case "codex":
		return "Codex"
	case "claudecode":
		return "Claude Code"
	}
	return name
}

// bounded cuts s to at most n bytes.
func bounded(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
