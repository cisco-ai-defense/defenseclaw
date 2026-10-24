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

package sandboxapi

import (
	"path"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The messages a managed host shows when its organization's sandbox policy
// refuses something. They name only the caller's own profile, never another
// account's, and print every value through refusalValue or refusalPath, so
// a project directory or a host name can't carry terminal escapes or extra
// lines into them. The policy refusals (HostRunRefused, HostRunRefusedOn,
// HostRunUnavailable, AccessRefused) start with AdminMessage and end with
// the request-access contact. The notices (ForeignStopped, SettingsDrift,
// PolicyUnloadable, ProfileStop, AccountBusy) are one-line texts. ProfileStop
// names the request-access contact when the policy prevents another run;
// a policy that can't be loaded has none to give (spec change log 4).
// testdata/refusals.golden pins every one.

// refusalHarness is a sandbox harness as a message names it: its display
// name and the name `defenseclaw sandbox run` takes for it. The table
// mirrors harness.Spec.DisplayName and sandboxcli.HarnessArg, which import
// this package; a test pins them together.
type refusalHarness struct{ display, command string }

var refusalHarnesses = map[string]refusalHarness{
	"amp":         {"Amp", "amp"},
	"antigravity": {"Antigravity", "antigravity"},
	"claudecode":  {"Claude Code", "claude"},
	"codex":       {"Codex", "codex"},
	"copilot":     {"GitHub Copilot CLI", "copilot"},
	"cursor":      {"Cursor Agent", "cursor-agent"},
	"devin":       {"Devin CLI", "devin"},
	"hermes":      {"Hermes Agent", "hermes"},
	"kiro":        {"Kiro CLI", "kiro"},
	"opencode":    {"OpenCode", "opencode"},
}

// harnessFor names conn (a connector, or a harness command) for a message.
// A connector without a sandbox harness reads as its own name.
func harnessFor(conn string) refusalHarness {
	conn = strings.ToLower(strings.TrimSpace(conn))
	if h, ok := refusalHarnesses[conn]; ok {
		return h
	}
	for _, h := range refusalHarnesses {
		if h.command == conn {
			return h
		}
	}
	name := refusalValue(conn)
	return refusalHarness{display: name, command: name}
}

// Bounds of the values a message prints.
const (
	refusalValueMax = 128
	refusalPathMax  = 1024
	// sandboxCommand is the launcher every managed host has on PATH.
	sandboxCommand = "defenseclaw sandbox"
)

// refusalValue makes a name, host or phrase printable in a message: one
// line of safe text (DisplayText), trimmed, at most refusalValueMax bytes.
func refusalValue(s string) string { return refusalClip(s, refusalValueMax) }

// refusalReasonMax bounds the reason a refusal quotes in its own words (why a
// sandbox can't run here). It is longer than a name or a host: the Docker
// prerequisite of a MicroVM run says why Docker is needed and then why the
// account lacks it, about 140 bytes, which refusalValueMax cut inside the
// sentence ("...in the docker group that ca…", GAP-0555).
const refusalReasonMax = 320

// refusalReason makes the reason a refusal gives in its own words printable:
// one line of safe text, trimmed, at most refusalReasonMax bytes.
func refusalReason(s string) string { return refusalClip(s, refusalReasonMax) }

// refusalClip is s as one line of safe text (DisplayText), trimmed, cut to
// limit bytes (on a character boundary, with an ellipsis) when it is longer.
func refusalClip(s string, limit int) string {
	s = strings.Join(strings.Fields(DisplayText(s)), " ")
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// refusalPath is dir as a shell word for a paste-ready command, or "" when
// dir is not a clean absolute path a person could paste safely (relative,
// too long, or with control, bidirectional or invalid characters).
func refusalPath(dir string) string {
	if dir == "" || len(dir) > refusalPathMax || !strings.HasPrefix(dir, "/") || DisplayText(dir) != dir {
		return ""
	}
	if strings.ContainsAny(dir, "\t\n\r") {
		return ""
	}
	return "'" + strings.ReplaceAll(path.Clean(dir), "'", `'\''`) + "'"
}

// adminSentence is AdminMessage as the first words of a message.
func adminSentence() string {
	return strings.ToUpper(AdminMessage[:1]) + AdminMessage[1:] + ": "
}

// contact is the request-access contact a refusal ends with, or the
// fallback ("your IT help desk") when the organization configured none.
func contact(requestAccess string) string {
	if v := refusalValue(requestAccess); v != "" {
		if len(v) >= len("contact ") && strings.EqualFold(v[:len("contact ")], "contact ") {
			v = strings.TrimSpace(v[len("contact "):])
		}
		if v == "" {
			return strings.TrimPrefix(config.OpenShellRequestAccessFallback, "contact ")
		}
		return v
	}
	return strings.TrimPrefix(config.OpenShellRequestAccessFallback, "contact ")
}

// profileNote is " (profile NAME)" for the caller's own profile, "" when
// only the organization's floor applies.
func profileNote(profile string) string {
	if p := refusalValue(profile); p != "" {
		return " (profile " + p + ")"
	}
	return ""
}

// HostRunRefused is the hook refusal of a host run of conn, which the
// caller's floor requires to run in a sandbox (required_for), with a
// paste-ready command that starts it sandboxed from projectDir.
func HostRunRefused(conn, profile, projectDir, requestAccess string) string {
	h := harnessFor(conn)
	run := sandboxCommand + " run " + h.command
	var b strings.Builder
	b.WriteString(adminSentence() + h.display + " must run in a sandbox on this computer" + profileNote(profile) + ".\n")
	if dir := refusalPath(projectDir); dir != "" {
		b.WriteString("Start it sandboxed from this project:\n  cd " + dir + " && " + run + "\n")
	} else {
		b.WriteString("Start it sandboxed from your project folder:\n  " + run + "\n")
	}
	b.WriteString("To always start it sandboxed: " + sandboxCommand + " enable " + h.command + "\n")
	b.WriteString("Need an exception? Contact " + contact(requestAccess))
	return b.String()
}

// Host surfaces HostRunRefusedOn words differently from the CLI: an app or
// IDE extension embeds its agent, so it can't run in a sandbox itself
// (connector.HostSurfaceDesktop and HostSurfaceExtension).
var refusalSurfaces = map[string]string{
	"desktop":   "desktop app",
	"extension": "IDE extension",
}

// refusalProducts name the product whose app or extension a hook came from.
// A connector without one reads as its harness.
var refusalProducts = map[string]string{
	"claudecode": "Claude Code",
	"codex":      "Codex",
	"copilot":    "GitHub Copilot",
	"cursor":     "Cursor",
}

// HostRunRefusedOn is HostRunRefused for a hook from surface. A CLI (or an
// unclassified) surface gets HostRunRefused. An app or IDE extension can't
// be started in a sandbox, so its refusal says so and points to the CLI
// harness the command starts, without the "always start it sandboxed"
// line, which only the CLI honours.
func HostRunRefusedOn(conn, surface, profile, projectDir, requestAccess string) string {
	where, ok := refusalSurfaces[strings.ToLower(strings.TrimSpace(surface))]
	if !ok {
		return HostRunRefused(conn, profile, projectDir, requestAccess)
	}
	h := harnessFor(conn)
	product, ok := refusalProducts[strings.ToLower(strings.TrimSpace(conn))]
	if !ok {
		product = h.display
	}
	run := sandboxCommand + " run " + h.command
	var b strings.Builder
	b.WriteString(adminSentence() + product + " must run in a sandbox on this computer" + profileNote(profile) +
		", and its " + where + " can't run in one.\n")
	if dir := refusalPath(projectDir); dir != "" {
		b.WriteString("Use " + h.display + " in a sandbox instead, from this project:\n  cd " + dir + " && " + run + "\n")
	} else {
		b.WriteString("Use " + h.display + " in a sandbox instead, from your project folder:\n  " + run + "\n")
	}
	b.WriteString("Need an exception? Contact " + contact(requestAccess))
	return b.String()
}

// HostRunUnavailable is the hook refusal of a host run of conn that must
// run in a sandbox where sandboxes can't run for the caller (Q1); why says
// what is missing ("OpenShell is not installed"), "" when unknown, and code
// is its registered reason code ("no_kvm_group"), which the contact line
// asks the person to quote so IT knows the cause (GAP-0257).
func HostRunUnavailable(conn, why, code, requestAccess string) string {
	reason := ""
	if w := strings.TrimRight(refusalReason(why), ". "); w != "" {
		reason = " (" + w + ")"
	}
	quote := ""
	if c := refusalCode(code); c != "" {
		quote = " (quote reason " + c + ")"
	}
	return adminSentence() + harnessFor(conn).display + " must run in a sandbox, and sandboxes aren't available on this computer" +
		reason + ".\nNeed an exception? Contact " + contact(requestAccess) + quote
}

// provisionalLine is the line ProvisionalRefusal adds.
const provisionalLine = "Your organization's directory couldn't be reached, so its default policy applies for now. Try again in a moment."

// ProvisionalRefusal is message, a host-run refusal (HostRunRefusedOn,
// HostRunUnavailable), for a caller whose profile is the organization's
// default only because the directory lookup failed or was slow
// (default_lookup_failed): its second line says so and that a retry will
// likely get the person's own policy (GAP-0293, GAP-0384).
func ProvisionalRefusal(message string) string {
	first, rest, ok := strings.Cut(message, "\n")
	if !ok {
		return message + "\n" + provisionalLine
	}
	return first + "\n" + provisionalLine + "\n" + rest
}

// refusalCode is a reason code as a message quotes it: a snake_case token
// of at most 64 bytes, "" for anything else.
func refusalCode(code string) string {
	if code == "" || len(code) > 64 || code[0] < 'a' || code[0] > 'z' {
		return ""
	}
	for _, r := range code {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return ""
		}
	}
	return code
}

// DockerUnavailable is the refusal of a sandbox start on a managed Mac
// whose Docker does not answer for the caller: the MicroVM driver boots the
// agent's image, which DefenseClaw builds in the account's Docker
// (GAP-0443). why is Docker's own answer, kept in the caller's log; the
// refusal maps it to a plain explanation without runtime addresses.
func DockerUnavailable(why, requestAccess string) string {
	reason := "Cannot connect to the Docker daemon"
	lower := strings.ToLower(why)
	if strings.Contains(lower, "permission denied") || strings.Contains(lower, "access is denied") {
		reason = "your account does not have permission to access Docker"
	}
	return "sandboxes on this Mac build your agent's image in Docker, and Docker does not answer for your account (" + reason +
		").\nStart Docker Desktop and run this again.\nNeed an exception? Contact " + contact(requestAccess)
}

// DriverUnavailable is the refusal of a sandbox start on Linux where the
// organization requires the MicroVM driver (driver_fallback: none, on the
// host or in the caller's profile) and it can't run for the caller: why is
// the KVM probe's reason in the caller's words
// (openshell.DriverReasonText).
func DriverUnavailable(why, requestAccess string) string {
	reason := ""
	if w := refusalReason(why); w != "" {
		reason = ": " + w
	}
	return adminSentence() + "your organization requires MicroVM sandboxes on this computer, and they can't run here" +
		reason + ".\nNeed an exception? Contact " + contact(requestAccess)
}

// accessRuleTexts say why the caller's floor refuses host, by the rule
// that refuses it (the openshell.admin key).
var accessRuleTexts = map[string]string{
	"egress_allow_only": "is not on your profile's allowed hosts",
	"egress_block":      "is blocked by your organization",
	"allow_unblock":     "can't be unblocked under your profile",
	"user_approvals":    "needs an approval your profile doesn't let you give",
	"allow_host_ports":  "is a port on this computer your profile doesn't open to sandboxes",
	"min_profile":       "can't be kept for future sandboxes under the strict profile your organization requires",
	"required_pack":     "is not allowed by the sandbox pack your organization requires",
}

// AccessRefused is the refusal of an ask or unblock for host that the
// caller's floor does not allow (rule is the refusing openshell.admin
// key), with the facts to quote in an access request.
func AccessRefused(rule, host, profile, sandbox, requestAccess string) string {
	return AccessRefusedWhy("", rule, host, profile, sandbox, requestAccess)
}

// AccessRefusedWhy is AccessRefused with why, the refusing check's own
// words ("your profile lets you approve access for this session only"), as
// its reason; "" says it by the rule. Every managed refusal of an ask, an
// approval or an unblock has this one shape: reason, "You can't approve
// this.", the request-access contact and the Quote line (GAP-0508).
func AccessRefusedWhy(why, rule, host, profile, sandbox, requestAccess string) string {
	rule, host, sandbox = refusalValue(rule), refusalValue(host), refusalValue(sandbox)
	// Egress list refusals use the same sentence for activity and unblock;
	// a check's alternate list wording adds no facts to the access request.
	if rule == "egress_allow_only" || rule == "egress_block" {
		why = ""
	}
	// The check's words may say it already, or end a sentence.
	why = strings.TrimRight(refusalLine(strings.TrimPrefix(why, AdminMessage+": ")), ". ")
	for _, said := range []string{"; you can't approve this", "; ask your administrator if you need it", "; ask your administrator"} {
		why = strings.TrimSuffix(why, said)
	}
	if why == "" {
		text, ok := accessRuleTexts[rule]
		if !ok {
			text = "is not allowed by your profile"
		}
		why = firstNonEmpty(host, "this destination") + " " + text
	}
	var facts []string
	if host != "" {
		facts = append(facts, "host "+host)
	}
	if sandbox != "" {
		facts = append(facts, "sandbox "+sandbox)
	}
	return policyRefusal(why, rule, profile, requestAccess, facts...)
}

// policyRefusal gives access and pack refusals the same complete sentence,
// approval limit, contact and facts to quote in an access request.
func policyRefusal(why, rule, profile, requestAccess string, facts ...string) string {
	var note, quote []string
	if p := refusalValue(profile); p != "" {
		if !strings.Contains(why, "your profile "+p+" ") {
			note = append(note, "profile "+p)
		}
		quote = append(quote, "profile "+p)
	}
	if rule != "" {
		note = append(note, "rule "+rule)
		quote = append(quote, "rule "+rule)
	}
	quote = append(quote, facts...)
	first := adminSentence() + why
	if len(note) > 0 {
		first += " (" + strings.Join(note, ", ") + ")"
	}
	first += ". You can't approve this.\nRequest access: " + contact(requestAccess) + "."
	if len(quote) > 0 {
		first += " Quote: " + strings.Join(quote, ", ") + "."
	}
	return first
}

// IsPolicyRefusal reports a message one of the policy refusals above built
// (it starts with AdminMessage as a sentence): it is complete as it is, so
// a surface prints it verbatim instead of framing it again.
func IsPolicyRefusal(message string) bool {
	return strings.HasPrefix(message, adminSentence())
}

// QuoteLine is the request-access line of a policy refusal, "Request
// access: CONTACT. Quote: ...", or "" when message has none.
func QuoteLine(message string) string {
	if i := strings.LastIndex(message, "\nRequest access: "); i >= 0 {
		return message[i+1:]
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// ForeignStopped is the notice for a sandbox the daemon stopped because
// DefenseClaw did not start it (foreign_sandboxes: stop).
func ForeignStopped(name string) string {
	return "Sandbox " + refusalValue(name) + " was stopped: it wasn't started with " + sandboxCommand +
		" run, which your organization requires."
}

// ForeignRemoved is the notice for a foreign sandbox the daemon deleted
// because OpenShell would not stop it in its phase.
func ForeignRemoved(name string) string {
	return "Sandbox " + refusalValue(name) + " was removed: it wasn't started with " + sandboxCommand +
		" run, which your organization requires."
}

// ForeignRemoving is the notice for a foreign sandbox still there after
// OpenShell took its delete (a MicroVM still provisioning): the daemon
// deletes it again at every reconcile.
func ForeignRemoving(name string) string {
	return "Sandbox " + refusalValue(name) + " is being removed: it wasn't started with " + sandboxCommand +
		" run, which your organization requires."
}

// ForeignNotRemoved is the notice for a foreign sandbox that outlived
// several deletes, still in phase: the person removes it.
func ForeignNotRemoved(name, phase string) string {
	return "DefenseClaw couldn't remove sandbox " + refusalValue(name) + " (still " + refusalValue(phase) +
		"): remove it with `openshell sandbox delete " + refusalValue(name) + "`; your organization requires sandboxes started with " +
		sandboxCommand + " run."
}

// ForeignAlerted is the notice for a foreign sandbox left running and
// reported (foreign_sandboxes: alert).
func ForeignAlerted(name string) string {
	return "Sandbox " + refusalValue(name) + " wasn't started with " + sandboxCommand +
		" run, which your organization requires; your organization was told."
}

// SettingsDrift is the notice while sandboxes are paused because the
// user's OpenShell settings differ from the organization's in field (a
// phrase such as "compute driver").
func SettingsDrift(field string) string {
	return "Sandboxes are paused: your OpenShell settings differ from your organization's (" + refusalValue(field) +
		"). Ask IT to repair them."
}

// PolicyUnloadable is the generic text of a sandbox policy the managed
// gateway can't load; the details are only in the admin views.
func PolicyUnloadable() string {
	return "Your organization's sandbox policy can't be loaded on this computer."
}

// ProfileStop is the notice for a sandbox stopped because the caller's
// profile no longer allows field (a phrase such as "mounts"); harness is
// the connector or harness command to start again. When no new run of that
// harness is allowed, the next step is to request access instead; for host
// ports, to start it again without them (GAP-0078).
func ProfileStop(field, harness, requestAccess string) string {
	field = refusalValue(field)
	text := "This sandbox was stopped: your profile no longer allows " + field + ". "
	switch field {
	case "sandboxes", "this agent in a sandbox":
		return text + "Request access: " + contact(requestAccess) + "."
	case "host ports":
		return text + "Start it again without --host-port: " + sandboxCommand + " run " + harnessFor(harness).command
	}
	return text + "Start it again: " + sandboxCommand + " run " + harnessFor(harness).command
}

// AccountBusy is the neutral text for a second account on a host whose
// sandboxes another account runs (Q2): it names nobody.
func AccountBusy() string {
	return "Sandboxes aren't available for your account on this computer."
}

// HarnessNotAllowed is the refusal of a sandbox run of conn, which the
// caller's profile does not let run in a sandbox (allowed_harnesses).
func HarnessNotAllowed(conn, profile, requestAccess string) string {
	return adminSentence() + harnessFor(conn).display + " isn't allowed in a sandbox under your profile" + profileNote(profile) +
		".\nNeed an exception? Contact " + contact(requestAccess)
}

// HarnessNotEnabled is the refusal of a sandbox run of conn, which the
// caller's profile allows, where the organization has not set conn's
// connector up for the caller on this computer (the managed gateway does
// not know the account for it): only IT can, so the contact line names the
// connector to quote.
func HarnessNotEnabled(conn, profile, requestAccess string) string {
	h := harnessFor(conn)
	quote := ""
	if c := refusalCode(strings.ToLower(strings.TrimSpace(conn))); c != "" {
		quote = " (quote connector " + c + ")"
	}
	return adminSentence() + h.display + " isn't set up for your account on this computer" + profileNote(profile) +
		", so it can't run in a sandbox here.\nTo use it, contact " + contact(requestAccess) + quote
}

// refusalLineMax bounds one line of a refusal sentence another component
// worded (the managed gateway's, the daemon's).
const refusalLineMax = 512

// refusalLine is one line of safe text (DisplayText), trimmed, at most
// refusalLineMax bytes.
func refusalLine(s string) string { return refusalClip(s, refusalLineMax) }

// ManagedRefusal is a refusal of the caller's organization in the shape of
// plan §7.1 where no builder above fits: AdminMessage, the refusing
// sentence (the managed gateway's or the daemon's own words, which name no
// other account) with the caller's own profile, and the request-access
// contact. quote, when set, is what IT needs quoted ("reason
// sandbox_unavailable"); a bare reason code never stands in the sentence
// (GAP-0486, GAP-0493). A sentence that carries its own contact line
// (HostRunUnavailable, DriverUnavailable, AccessRefused) is returned as it
// is, line by line made safe to print.
func ManagedRefusal(sentence, profile, quote, requestAccess string) string {
	if strings.Contains(sentence, "\nNeed an exception? ") || strings.Contains(sentence, "\nRequest access: ") {
		lines := strings.Split(sentence, "\n")
		for i, l := range lines {
			lines[i] = refusalLine(l)
		}
		return strings.Join(lines, "\n")
	}
	s := refusalLine(sentence)
	if len(s) >= len(AdminMessage) && strings.EqualFold(s[:len(AdminMessage)], AdminMessage) {
		s = strings.TrimSpace(strings.TrimPrefix(s[len(AdminMessage):], ":"))
	}
	s = strings.TrimRight(s, ". ")
	// The gateway sends a fatal pack violation as "pack (DETAIL)";
	// local violations carry DETAIL and the required_pack rule separately.
	packReason, wrapped := strings.CutPrefix(s, "pack (")
	if wrapped && strings.HasSuffix(packReason, ")") {
		packReason = strings.TrimSuffix(packReason, ")")
	} else {
		packReason, wrapped = s, false
	}
	if (wrapped || quote == "rule required_pack") && strings.Contains(packReason, " sandbox pack") {
		var facts []string
		if _, tail, ok := strings.Cut(packReason, "; the "); ok {
			if pack, _, ok := strings.Cut(tail, " pack is looser in "); ok {
				facts = append(facts, "pack "+refusalValue(pack))
			}
		}
		return policyRefusal(packReason, "required_pack", profile, requestAccess, facts...)
	}
	if s == "" {
		s = "your organization's sandbox policy refused this"
	}
	if !strings.Contains(s, "(profile ") {
		s += profileNote(profile)
	}
	out := adminSentence() + s + ".\nNeed an exception? Contact " + contact(requestAccess)
	if q := refusalValue(quote); q != "" {
		out += " (quote " + q + ")"
	}
	return out
}
