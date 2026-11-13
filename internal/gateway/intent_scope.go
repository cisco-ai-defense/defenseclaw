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

package gateway

import (
	"encoding/json"
	"sort"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// The user's task is a scope for the tool judge to check a call against, not a
// permission. Two deterministic parts keep it that way (GAP-0262):
//
//   - namedScopeTargets lists the hosts, addresses and paths the task names;
//     the judge sample carries the list, so "the task names no destination" is
//     a fact in the sample and not something the model has to infer.
//   - intentScopeExceeded finds a call that sends data (a post, upload, mail,
//     a copy to another host) to a destination the task does not name. The
//     tool judge's verdict cannot fall below an alert for such a call, whatever
//     the model made of the task.
//
// Rules never read the task, so a rule finding stands whatever it says.

const (
	intentScopeFinding    = "INTENT-SCOPE-SEND"
	maxNamedScopeTargets  = 20
	maxScopeDestinations  = 16
	pendingScopeFloorsCap = 256
)

var (
	scopeURLHostRe = lazyregexp.New(`(?i)\b(?:https?|ftp|ftps|sftp|s3|gs|wss?)://(?:[^\s/@'"` + "`" + `]*@)?(\[[0-9a-f:]+\]|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)`)
	scopeEmailRe   = lazyregexp.New(`(?i)\b[a-z0-9._%+-]+@([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,})\b`)
	scopeDomainRe  = lazyregexp.New(`(?i)\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,})\b`)
	scopePathRe    = lazyregexp.New(`(?:^|[\s"'(])((?:~|\.{1,2})?/[A-Za-z0-9._@%+=,~/-]{2,})`)
	// A shell command that sends: curl or wget with a body or an upload, or a
	// transfer or mail program. The destination is read from the same text.
	scopeShellSendRe = lazyregexp.New(`(?i)\b(?:curl|wget|http|https|xh)\b[^\n]*?(?:\s-X\s*(?:POST|PUT|PATCH)\b|\s--request\s*(?:POST|PUT|PATCH)\b|\s-d\b|\s--data\b|\s--data-[a-z]+\b|\s-F\b|\s--form\b|\s-T\b|\s--upload-file\b|\s--json\b)|\b(?:scp|rsync|sftp|ncat|netcat|nc|mail|mailx|sendmail|swaks|aws\s+s3\s+(?:cp|sync|mv)|gsutil\s+(?:cp|rsync)|az\s+storage\s+blob\s+upload)\b`)
)

// scopeSendSegments and scopeReadSegments classify a tool name by its words
// (camel case and . _ - : / split it).
var scopeSendSegments = map[string]bool{
	"post": true, "upload": true, "send": true, "email": true, "mail": true, "publish": true, "webhook": true,
	"notify": true, "submit": true, "export": true, "forward": true, "share": true, "put": true, "push": true,
	"dispatch": true, "transmit": true, "sync": true, "bcc": true,
}
var scopeReadSegments = map[string]bool{
	"get": true, "fetch": true, "read": true, "list": true, "query": true, "search": true, "download": true,
	"head": true, "find": true, "check": true, "status": true, "view": true, "describe": true, "open": true,
	"navigate": true, "resolve": true, "lookup": true,
}

// scopeDestinationKeys are argument names whose string value is a place the
// call sends to.
var scopeDestinationKeys = map[string]bool{
	"url": true, "uri": true, "endpoint": true, "destination": true, "dest": true, "recipient": true, "recipients": true,
	"to": true, "cc": true, "bcc": true, "bcc_override": true, "webhook": true, "webhook_url": true,
	"log_destination": true, "upload_url": true, "target_url": true, "sink": true, "host": true, "bucket": true,
	"remote": true, "address": true, "email": true, "emails": true, "recipient_email": true, "send_to": true,
	"callback": true, "callback_url": true, "forward_to": true,
}

// namedScopeTargets returns the hosts, e-mail addresses and absolute paths the
// task names, lower case, sorted and deduplicated.
func namedScopeTargets(intent string) []string {
	set := map[string]bool{}
	add := func(v string) {
		v = strings.ToLower(strings.TrimRight(strings.TrimSpace(v), ".,;:)"))
		if v != "" {
			set[v] = true
		}
	}
	for _, m := range scopeURLHostRe.FindAllStringSubmatch(intent, -1) {
		add(m[1])
	}
	for _, m := range scopeEmailRe.FindAllString(intent, -1) {
		add(m)
	}
	for _, m := range scopeDomainRe.FindAllStringSubmatch(intent, -1) {
		add(m[1])
	}
	for _, m := range scopePathRe.FindAllStringSubmatch(intent, -1) {
		add(m[1])
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	if len(out) > maxNamedScopeTargets {
		out = out[:maxNamedScopeTargets]
	}
	return out
}

func toolNameSegments(name string) []string {
	var segs []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			segs = append(segs, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	var prev rune
	for _, r := range name {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r) && unicode.IsLower(prev):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
		prev = r
	}
	flush()
	return segs
}

type scopeString struct{ key, value string }

// scopeStrings returns every string value of the call's JSON arguments with
// the name of the key it sits under; arguments that are not JSON come back as
// one value with no key.
func scopeStrings(args string) []scopeString {
	var root any
	if err := json.Unmarshal([]byte(args), &root); err != nil {
		return []scopeString{{"", args}}
	}
	var out []scopeString
	var walk func(key string, v any, depth int)
	walk = func(key string, v any, depth int) {
		if depth > 6 || len(out) > 256 {
			return
		}
		switch t := v.(type) {
		case string:
			out = append(out, scopeString{strings.ToLower(key), t})
		case []any:
			for _, e := range t {
				walk(key, e, depth+1)
			}
		case map[string]any:
			for k, e := range t {
				walk(k, e, depth+1)
			}
		}
	}
	walk("", root, 0)
	return out
}

// scopeLoopback reports a destination that never leaves the host.
func scopeLoopback(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	return host == "localhost" || host == "::1" || strings.HasPrefix(host, "127.") || strings.HasSuffix(host, ".localhost")
}

// scopeNamed reports whether host is one of the task's named targets or inside
// one (api.example.com for a task that names example.com, and the reverse).
func scopeNamed(host string, named []string) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	for _, n := range named {
		if strings.HasPrefix(n, "/") || strings.HasPrefix(n, "~") || strings.HasPrefix(n, ".") {
			continue
		}
		if at := strings.LastIndex(n, "@"); at >= 0 {
			n = n[at+1:]
		}
		if host == n || strings.HasSuffix(host, "."+n) || strings.HasSuffix(n, "."+host) {
			return true
		}
	}
	return false
}

// callSendDestinations returns the hosts and mail domains a sending call goes
// to; nil for a call that does not send.
func callSendDestinations(toolName, args string) []string {
	segs := toolNameSegments(toolName)
	toolSends, toolReads := false, false
	for _, s := range segs {
		toolSends = toolSends || scopeSendSegments[s]
		toolReads = toolReads || scopeReadSegments[s]
	}
	values := scopeStrings(args)
	var texts []string
	shell := false
	for _, v := range values {
		switch {
		case v.key == "command" || v.key == "cmd" || v.key == "script" || v.key == "code" || v.key == "":
			if scopeShellSendRe.MatchString(v.value) {
				shell = true
				texts = append(texts, v.value)
			}
		case scopeDestinationKeys[v.key]:
			if !toolReads || toolSends {
				texts = append(texts, v.value)
			}
		}
	}
	if !shell && !toolSends && len(texts) == 0 {
		return nil
	}
	if !shell && toolReads && !toolSends {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" && !seen[h] && len(out) < maxScopeDestinations {
			seen[h] = true
			out = append(out, h)
		}
	}
	for _, t := range texts {
		for _, m := range scopeURLHostRe.FindAllStringSubmatch(t, -1) {
			add(m[1])
		}
		for _, m := range scopeEmailRe.FindAllStringSubmatch(t, -1) {
			add(m[1])
		}
		if !strings.Contains(t, "://") && !strings.Contains(t, "@") && !strings.ContainsAny(t, " \t\n/\\") {
			// a bare host or domain in a destination key
			if m := scopeDomainRe.FindStringSubmatch(t); m != nil && m[1] == strings.ToLower(strings.TrimSpace(t)) {
				add(m[1])
			}
		}
	}
	return out
}

// intentScopeExceeded returns a reason when the call sends data to a
// destination the task does not name, or "" (also when there is no task: with
// nothing to check against, the judge decides alone).
func intentScopeExceeded(intent, toolName, args string) string {
	if strings.TrimSpace(intent) == "" {
		return ""
	}
	dests := callSendDestinations(toolName, args)
	if len(dests) == 0 {
		return ""
	}
	named := namedScopeTargets(intent)
	for _, d := range dests {
		if scopeLoopback(d) || scopeNamed(d, named) {
			continue
		}
		return "the call sends data to a destination the user's task does not name"
	}
	return ""
}

// keepScopeFloor remembers the scope finding of a prepared sample until it is
// judged, as keepDecisionState does for the decision model.
func (j *LLMJudge) keepScopeFloor(sample, reason string) {
	j.scopeFloorsMu.Lock()
	defer j.scopeFloorsMu.Unlock()
	if j.scopeFloors == nil || len(j.scopeFloors) >= pendingScopeFloorsCap {
		j.scopeFloors = make(map[string]string)
	}
	j.scopeFloors[sample] = reason
}

func (j *LLMJudge) takeScopeFloor(sample string) string {
	j.scopeFloorsMu.Lock()
	defer j.scopeFloorsMu.Unlock()
	reason := j.scopeFloors[sample]
	delete(j.scopeFloors, sample)
	return reason
}

// applyIntentScopeFloor keeps the judge's verdict from falling below an alert
// for a call that exceeds the task's scope. A judge verdict at or above the
// floor is returned unchanged; a lower one, no verdict, or a failed judge gets
// the scope finding; a lone review-only finding stops being audit-only.
func applyIntentScopeFloor(judged *ScanVerdict, reason string) *ScanVerdict {
	if reason == "" {
		return judged
	}
	floor := &ScanVerdict{
		Action:   "alert",
		Severity: "MEDIUM",
		Reason:   reason,
		Findings: []string{intentScopeFinding},
		Scanner:  "intent-scope",
	}
	if judged == nil || judged.JudgeFailed {
		return floor
	}
	if guardrailSeverityRank(judged.Severity) > guardrailSeverityRank(floor.Severity) ||
		(guardrailSeverityRank(judged.Severity) == guardrailSeverityRank(floor.Severity) && !judged.reviewOnly &&
			normalizedGuardrailAction(judged.Action) != guardrailActionAllow) {
		return judged
	}
	out := *judged
	out.reviewOnly = false
	out.Severity = floor.Severity
	out.Action = strongerGuardrailAction(judged.Action, floor.Action)
	out.Findings = append(append([]string(nil), judged.Findings...), floor.Findings...)
	if out.Reason == "" || out.Reason == "no findings" {
		out.Reason = floor.Reason
	} else {
		out.Reason += "; " + floor.Reason
	}
	out.ScannerSources = appendUniqueStrings(out.ScannerSources, judged.Scanner, floor.Scanner)
	return &out
}
