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

package guardrail

import "strings"

// DataAxis labels a finding with one of three lethal-trifecta ingredients.
// A finding can carry multiple axes (e.g. a tool-exfil finding hits both
// sensitive_access and egress_external). The correlator intersects axes
// across a session's recent findings to detect attack flows.
type DataAxis string

const (
	AxisIngressUntrusted DataAxis = "ingress_untrusted"
	AxisSensitiveAccess  DataAxis = "sensitive_access"
	AxisEgressExternal   DataAxis = "egress_external"
)

// AxesForRuleID returns the data-axis labels for a regex rule by ID.
// Unknown rule IDs return nil — callers should fall back to category-
// based heuristics. The mapping is conservative: when a rule could
// plausibly hit multiple axes (e.g. "exec via network fetch"), we
// list all of them so patterns see the full signal.
func AxesForRuleID(ruleID string) []DataAxis {
	if axes, ok := ruleAxes[ruleID]; ok {
		return axes
	}
	// Prefix-based fallback so a newly added rule inherits sensible
	// axes from its family without requiring a code change. Covers
	// the regex families shipped in policies/guardrail/*/rules/*.yaml
	// and the plugin-scanner rule families (GW-*, META-*, STRUCT-*).
	switch {
	case strings.HasPrefix(ruleID, "SEC-"),
		strings.HasPrefix(ruleID, "PATH-"),
		strings.HasPrefix(ruleID, "ENT-"),
		strings.HasPrefix(ruleID, "CRED-"),
		strings.HasPrefix(ruleID, "PII-"):
		return []DataAxis{AxisSensitiveAccess}
	case strings.HasPrefix(ruleID, "C2-"),
		strings.HasPrefix(ruleID, "DNS-TUNNEL"):
		return []DataAxis{AxisEgressExternal}
	case strings.HasPrefix(ruleID, "INJ-"),
		strings.HasPrefix(ruleID, "TRUST-"),
		strings.HasPrefix(ruleID, "JAIL-"):
		return []DataAxis{AxisIngressUntrusted}
	case strings.HasPrefix(ruleID, "SSRF-"):
		// SSRF probes read internal metadata endpoints AND make an
		// outbound network call — both axes.
		return []DataAxis{AxisSensitiveAccess, AxisEgressExternal}
	case strings.HasPrefix(ruleID, "META-REMOTE"),
		strings.HasPrefix(ruleID, "META-EXEC"):
		// META-REMOTE-CODE-EXEC and friends are plugin-scanner
		// meta-findings for remote execution attempts.
		return []DataAxis{AxisIngressUntrusted}
	case strings.HasPrefix(ruleID, "META-ENV-EXFIL"),
		strings.HasPrefix(ruleID, "META-EXFIL"):
		return []DataAxis{AxisSensitiveAccess, AxisEgressExternal}
	case strings.HasPrefix(ruleID, "GW-ENV-WRITE"),
		strings.HasPrefix(ruleID, "GW-ENV-READ"):
		return []DataAxis{AxisSensitiveAccess}
	case strings.HasPrefix(ruleID, "GW-"):
		// Generic GW-* (gateway rule family) indicates the rule fired
		// on proxied content — we treat that as an ingress signal
		// unless a more specific mapping above caught it.
		return []DataAxis{AxisIngressUntrusted}
	case strings.HasPrefix(ruleID, "CMD-DESTRUCTIVE"),
		strings.HasPrefix(ruleID, "SHELL-DESTRUCTIVE"):
		// Destructive commands aren't one of the three trifecta
		// axes; the DESTRUCTIVE-FLOW correlator pattern matches on
		// tool_capability_class + rule_id instead.
		return nil
	}
	return nil
}

// AxesForJudgeCategory returns the data-axis labels for an LLM judge's
// named category. The mapping lives in code rather than YAML so the
// judge categories (which are the stable interface) drive the axis
// taxonomy rather than being driven by it.
func AxesForJudgeCategory(judge, category string) []DataAxis {
	key := strings.ToLower(judge) + "." + strings.ToLower(category)
	return judgeAxes[key]
}

// ruleAxes is the canonical mapping from regex rule ID to data-axis
// labels. Kept as a plain map (not YAML) so the compiler catches
// typos and a reviewer can audit the full list in one place.
var ruleAxes = map[string][]DataAxis{
	// Sensitive data access (credentials, PII, system secrets)
	"CRED-AWS-FILE":       {AxisSensitiveAccess},
	"CRED-AWS-KEY":        {AxisSensitiveAccess},
	"SEC-GOOGLE":          {AxisSensitiveAccess},
	"SEC-SLACK-TOKEN":     {AxisSensitiveAccess},
	"SEC-SLACK-WEBHOOK":   {AxisSensitiveAccess, AxisEgressExternal},
	"SEC-DISCORD-WEBHOOK": {AxisSensitiveAccess, AxisEgressExternal},
	"SEC-CONNSTR":         {AxisSensitiveAccess},
	"SEC-SENDGRID":        {AxisSensitiveAccess},
	"SEC-GITHUB":          {AxisSensitiveAccess},
	"SEC-PRIVKEY":         {AxisSensitiveAccess},
	"PATH-SSH-KEY":        {AxisSensitiveAccess},
	"PATH-GIT-CREDS":      {AxisSensitiveAccess},
	"PATH-NETRC":          {AxisSensitiveAccess},
	"PATH-PROC-ENVIRON":   {AxisSensitiveAccess},
	"PATH-ETC-PASSWD":     {AxisSensitiveAccess},
	"PATH-ETC-SHADOW":     {AxisSensitiveAccess},
	"ENT-BULK-SSN":        {AxisSensitiveAccess},
	"PII-SSN":             {AxisSensitiveAccess},
	"PII-PASSPORT":        {AxisSensitiveAccess},
	"PII-PASSWORD":        {AxisSensitiveAccess},

	// External egress (exfil channels, C2 infrastructure)
	"C2-WEBHOOK-SITE":    {AxisEgressExternal},
	"C2-NGROK":           {AxisEgressExternal},
	"C2-PIPEDREAM":       {AxisEgressExternal},
	"C2-REQUESTBIN":      {AxisEgressExternal},
	"C2-OAST":            {AxisEgressExternal},
	"C2-INTERACT-SH":     {AxisEgressExternal},
	"DNS-TUNNEL":         {AxisEgressExternal},
	"SSRF-AWS-META":      {AxisSensitiveAccess, AxisEgressExternal},
	"SSRF-GCP-META":      {AxisSensitiveAccess, AxisEgressExternal},
	"SSRF-AZURE-META":    {AxisSensitiveAccess, AxisEgressExternal},
	"SSRF-INTERNAL-HOST": {AxisEgressExternal},
	"SSRF-PRIVATE-IP":    {AxisEgressExternal},

	// Ingress untrusted (injection attempts in user/tool-response content)
	"INJ-IGNORE-ALL":        {AxisIngressUntrusted},
	"INJ-IGNORE-PREVIOUS":   {AxisIngressUntrusted},
	"INJ-DISREGARD":         {AxisIngressUntrusted},
	"INJ-JAILBREAK":         {AxisIngressUntrusted},
	"INJ-DAN-MODE":          {AxisIngressUntrusted},
	"INJ-OVERRIDE":          {AxisIngressUntrusted},
	"INJ-DELIMITER-HIJACK":  {AxisIngressUntrusted},
	"TRUST-AUTHORITY-CLAIM": {AxisIngressUntrusted},
	"TRUST-NEW-INSTRUCTION": {AxisIngressUntrusted},
	"TRUST-SAFETY-OVERRIDE": {AxisIngressUntrusted},
}

// judgeAxes maps "judge.category" (both lowercased) to axes. The keys
// mirror the Categories maps in each judge's YAML — see
// internal/guardrail/defaults/judge/*.yaml.
var judgeAxes = map[string][]DataAxis{
	// Injection judge — all five categories indicate the prompt
	// itself is adversarial content (ingress).
	"injection.instruction manipulation": {AxisIngressUntrusted},
	"injection.context manipulation":     {AxisIngressUntrusted},
	"injection.obfuscation":              {AxisIngressUntrusted},
	"injection.semantic manipulation":    {AxisIngressUntrusted},
	"injection.token exploitation":       {AxisIngressUntrusted},

	// PII judge — detected entities are sensitive-access findings.
	"pii.email address":           {AxisSensitiveAccess},
	"pii.ip address":              {AxisSensitiveAccess},
	"pii.phone number":            {AxisSensitiveAccess},
	"pii.driver's license number": {AxisSensitiveAccess},
	"pii.passport number":         {AxisSensitiveAccess},
	"pii.social security number":  {AxisSensitiveAccess},
	"pii.username":                {AxisSensitiveAccess},
	"pii.password":                {AxisSensitiveAccess},

	// Exfil judge — one category per axis.
	"exfil.sensitive file access": {AxisSensitiveAccess},
	"exfil.exfiltration channel":  {AxisEgressExternal},

	// Tool-injection judge.
	"tool-injection.instruction manipulation": {AxisIngressUntrusted},
	"tool-injection.context manipulation":     {AxisIngressUntrusted},
	"tool-injection.obfuscation":              {AxisIngressUntrusted},
	"tool-injection.data exfiltration":        {AxisSensitiveAccess, AxisEgressExternal},
	"tool-injection.destructive commands":     {}, // destructive = separate flow, not trifecta
}

// AxesToStrings converts a []DataAxis to []string for JSON/DB storage.
func AxesToStrings(axes []DataAxis) []string {
	out := make([]string, len(axes))
	for i, a := range axes {
		out[i] = string(a)
	}
	return out
}
