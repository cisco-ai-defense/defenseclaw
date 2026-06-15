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
	// the regex families in policies/guardrail/*/rules/*.yaml, the
	// plugin-scanner families (GW-*, META-*, JSON-SEC-*, SRC-*), the
	// ClawShield PII detector (CS-PII-*), the cognitive-tamper pack
	// (COG-*), and the LLM judges (JUDGE-*). Family members whose axis
	// differs from the group default are pinned via exact ruleAxes
	// entries above, which are consulted first.
	switch {
	case strings.HasPrefix(ruleID, "SEC-"),
		strings.HasPrefix(ruleID, "PATH-"),
		strings.HasPrefix(ruleID, "ENT-"),
		strings.HasPrefix(ruleID, "CRED-"),
		strings.HasPrefix(ruleID, "PII-"),
		strings.HasPrefix(ruleID, "CS-PII-"),
		strings.HasPrefix(ruleID, "JSON-SEC-"),
		strings.HasPrefix(ruleID, "COG-"),
		strings.HasPrefix(ruleID, "JUDGE-PII-"),
		strings.HasPrefix(ruleID, "JUDGE-EXFIL-"):
		return []DataAxis{AxisSensitiveAccess}
	case strings.HasPrefix(ruleID, "C2-"),
		strings.HasPrefix(ruleID, "DNS-TUNNEL"):
		return []DataAxis{AxisEgressExternal}
	case strings.HasPrefix(ruleID, "INJ-"),
		strings.HasPrefix(ruleID, "TRUST-"),
		strings.HasPrefix(ruleID, "JAIL-"),
		strings.HasPrefix(ruleID, "JUDGE-INJ-"),
		strings.HasPrefix(ruleID, "JUDGE-TOOL-INJ-"):
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

// AxesForFinding is the single labeling entrypoint the finding
// enricher should call. It resolves data-axis labels from every
// signal a persisted finding carries, in priority order:
//
//  1. AxesForRuleID(ruleID) — regex / plugin / clawshield / judge
//     rule families (covers JUDGE-* via the prefix fallbacks).
//  2. AxesForJudgeCategory(category) — when a finding stamped its
//     judge category instead of a stable JUDGE-* rule id. The
//     category is treated as "<judge>.<category>" or matched against
//     every judge namespace.
//  3. literal axis labels carried in Tags — honours the documented
//     InspectFinding.Tags contract so a producer can self-declare
//     "ingress_untrusted" / "sensitive_access" / "egress_external".
//
// Returns nil when nothing matches; callers treat nil as "unlabeled".
func AxesForFinding(ruleID, category string, tags []string) []DataAxis {
	if axes := AxesForRuleID(ruleID); len(axes) > 0 {
		return axes
	}
	if axes := axesFromCategory(category); len(axes) > 0 {
		return axes
	}
	if axes := axesFromTags(tags); len(axes) > 0 {
		return axes
	}
	return nil
}

// axesFromCategory tries to resolve a finding's free-form Category
// against the judge axis table. It accepts either a fully-qualified
// "<judge>.<category>" key or a bare category, in which case it
// probes every judge namespace for a match. This keeps
// AxesForJudgeCategory live for findings that carry a category but
// no stable JUDGE-* rule id.
func axesFromCategory(category string) []DataAxis {
	c := strings.ToLower(strings.TrimSpace(category))
	if c == "" {
		return nil
	}
	if axes, ok := judgeAxes[c]; ok && len(axes) > 0 {
		return axes
	}
	for _, judge := range []string{"injection", "pii", "exfil", "tool-injection"} {
		if axes := AxesForJudgeCategory(judge, c); len(axes) > 0 {
			return axes
		}
	}
	return nil
}

// axesFromTags scans a finding's tags for literal axis labels. A
// producer that already knows its trifecta role can emit
// "ingress_untrusted" / "sensitive_access" / "egress_external" as a
// tag and have it honoured without a code change here.
func axesFromTags(tags []string) []DataAxis {
	var out []DataAxis
	seen := map[DataAxis]bool{}
	for _, t := range tags {
		switch DataAxis(strings.ToLower(strings.TrimSpace(t))) {
		case AxisIngressUntrusted:
			if !seen[AxisIngressUntrusted] {
				seen[AxisIngressUntrusted] = true
				out = append(out, AxisIngressUntrusted)
			}
		case AxisSensitiveAccess:
			if !seen[AxisSensitiveAccess] {
				seen[AxisSensitiveAccess] = true
				out = append(out, AxisSensitiveAccess)
			}
		case AxisEgressExternal:
			if !seen[AxisEgressExternal] {
				seen[AxisEgressExternal] = true
				out = append(out, AxisEgressExternal)
			}
		}
	}
	return out
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

	// Judge findings whose axis differs from their family default.
	// These exact entries are consulted before the JUDGE-* prefix
	// fallbacks in AxesForRuleID, so they override them.
	"JUDGE-EXFIL-CHANNEL":     {AxisEgressExternal},
	"JUDGE-TOOL-INJ-EXFIL":    {AxisSensitiveAccess, AxisEgressExternal},
	"JUDGE-TOOL-INJ-DESTRUCT": {}, // destructive = separate flow, not trifecta

	// Command rules that open an outbound channel (curl/wget upload,
	// pipe-to-shell from the network). These read no secret on their
	// own but provide the egress leg of an exfil flow.
	"CMD-CURL-UPLOAD": {AxisEgressExternal},
	"CMD-WGET-POST":   {AxisEgressExternal},
	"CMD-PIPE-CURL":   {AxisEgressExternal},
	"CMD-PIPE-WGET":   {AxisEgressExternal},
	"CMD-ENV-DUMP":    {AxisSensitiveAccess},

	// Cloud metadata C2 endpoints read instance credentials (sensitive)
	// over an outbound call (egress) — both axes. The C2- prefix
	// fallback only sets egress, so these exact entries add the
	// sensitive-access leg.
	"C2-METADATA-AWS":   {AxisSensitiveAccess, AxisEgressExternal},
	"C2-METADATA-GCP":   {AxisSensitiveAccess, AxisEgressExternal},
	"C2-METADATA-AZURE": {AxisSensitiveAccess, AxisEgressExternal},

	// SRC-* is a mixed family (some read secrets, some open the
	// network, some exec). Only the data-axis-bearing members are
	// listed; SRC-EXEC / SRC-CHILD-PROC carry a capability instead
	// (see CapabilityForRuleID) and intentionally have no axis.
	"SRC-ENV-READ":    {AxisSensitiveAccess},
	"SRC-FETCH":       {AxisEgressExternal},
	"SRC-NET-SERVER":  {AxisEgressExternal},
	"SRC-HTTP-SERVER": {AxisEgressExternal},
	"SRC-WS":          {AxisEgressExternal},
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

// PrefixAxisRule describes a single entry in the prefix-based axis
// fallback table consumed by AxesForRuleID. Exposed so external tools
// (docs-site policy creator build, regression tests, audits) can
// derive a deterministic listing of every classification rule without
// re-parsing axes.go by hand.
type PrefixAxisRule struct {
	// Prefixes is the set of rule-ID prefixes that share an axis label.
	// Order is preserved from the source switch so deterministic JSON
	// output round-trips byte-for-byte through this and back.
	Prefixes []string `json:"prefixes"`
	// Axes is the canonical label assigned to rule IDs matching any
	// of the prefixes. nil means "explicitly no trifecta axis"
	// (e.g. destructive commands, which the correlator tracks via
	// tool_capability_class instead).
	Axes []DataAxis `json:"axes"`
}

// PrefixCapabilityRule mirrors PrefixAxisRule for the tool-capability
// classification of regex rules. Today only destructive command rules
// carry a capability class; the structure exists so future additions
// flow through the same generator path used by docs-site builds.
type PrefixCapabilityRule struct {
	Prefixes   []string            `json:"prefixes"`
	Capability ToolCapabilityClass `json:"capability"`
}

// RuleAxesSnapshot captures every input that AxesForRuleID consults,
// in a form that docs-site's build-policy-assets.ts can read at
// build time. The intent is to keep ONE authoritative copy of the
// rule-id → axis mapping (this file) and have downstream tooling
// derive its labels from this snapshot rather than maintaining a
// hand-edited duplicate.
type RuleAxesSnapshot struct {
	// Exact is the canonical rule-id → axes map (ruleAxes in this
	// file). Keys are sorted alphabetically so the JSON is
	// deterministic across builds.
	Exact map[string][]DataAxis `json:"exact_rule_axes"`
	// PrefixAxes is the ordered prefix-based fallback used when a
	// rule isn't in Exact. The TS side scans this list in order and
	// returns the first match, mirroring the switch in
	// AxesForRuleID.
	PrefixAxes []PrefixAxisRule `json:"prefix_axes"`
	// PrefixCapabilities is the ordered prefix-based capability
	// classification (today: destructive command families). Same
	// "first match wins" semantics as PrefixAxes.
	PrefixCapabilities []PrefixCapabilityRule `json:"prefix_capabilities"`
}

// DumpRuleAxesSnapshot returns a fully-populated snapshot suitable
// for JSON encoding. The data is a copy so callers can mutate the
// returned slices without affecting the package globals.
//
// Reviewers: every time you add an entry to ruleAxes or extend the
// switch in AxesForRuleID, mirror it here so docs-site stays in
// sync via the generator test in
// internal/guardrail/axes_export_test.go.
func DumpRuleAxesSnapshot() RuleAxesSnapshot {
	exactCopy := make(map[string][]DataAxis, len(ruleAxes))
	for k, v := range ruleAxes {
		// Defensive copy so external mutation can't poison the global.
		buf := make([]DataAxis, len(v))
		copy(buf, v)
		exactCopy[k] = buf
	}
	return RuleAxesSnapshot{
		Exact: exactCopy,
		PrefixAxes: []PrefixAxisRule{
			{Prefixes: []string{"SEC-", "PATH-", "ENT-", "CRED-", "PII-", "CS-PII-", "JSON-SEC-", "COG-", "JUDGE-PII-", "JUDGE-EXFIL-"}, Axes: []DataAxis{AxisSensitiveAccess}},
			{Prefixes: []string{"C2-", "DNS-TUNNEL"}, Axes: []DataAxis{AxisEgressExternal}},
			{Prefixes: []string{"INJ-", "TRUST-", "JAIL-", "JUDGE-INJ-", "JUDGE-TOOL-INJ-"}, Axes: []DataAxis{AxisIngressUntrusted}},
			{Prefixes: []string{"SSRF-"}, Axes: []DataAxis{AxisSensitiveAccess, AxisEgressExternal}},
			{Prefixes: []string{"META-REMOTE", "META-EXEC"}, Axes: []DataAxis{AxisIngressUntrusted}},
			{Prefixes: []string{"META-ENV-EXFIL", "META-EXFIL"}, Axes: []DataAxis{AxisSensitiveAccess, AxisEgressExternal}},
			{Prefixes: []string{"GW-ENV-WRITE", "GW-ENV-READ"}, Axes: []DataAxis{AxisSensitiveAccess}},
			{Prefixes: []string{"GW-"}, Axes: []DataAxis{AxisIngressUntrusted}},
			// nil axes — captured explicitly so the TS side knows to
			// emit "no axis" rather than falling through to a default.
			{Prefixes: []string{"CMD-DESTRUCTIVE", "SHELL-DESTRUCTIVE"}, Axes: nil},
		},
		PrefixCapabilities: []PrefixCapabilityRule{
			{Prefixes: []string{"CMD-DESTRUCTIVE", "SHELL-DESTRUCTIVE"}, Capability: CapExecShell},
		},
	}
}
