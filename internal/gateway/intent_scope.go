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
	"crypto/sha256"
	"encoding/json"
	"sort"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
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
//     tool judge's verdict carries at least a MEDIUM finding for such a call,
//     whatever the model made of the task; whether that shows as an alert is
//     the connector's alert_at level.
//
// Rules never read the task, so a rule finding stands whatever it says.

const (
	intentScopeFinding    = "INTENT-SCOPE-SEND"
	maxNamedScopeTargets  = 20
	maxScopeDestinations  = 16
	maxScopeDepth         = 10
	maxScopeValues        = 1024
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

// scopeReadSegments are tool-name words of a call that does not send data
// anywhere: it reads, checks, fetches, drafts or renders.
var scopeReadSegments = map[string]bool{
	"get": true, "fetch": true, "read": true, "list": true, "query": true, "search": true, "download": true,
	"head": true, "find": true, "check": true, "status": true, "view": true, "describe": true, "open": true,
	"navigate": true, "resolve": true, "lookup": true, "browse": true, "visit": true, "crawl": true, "scrape": true,
	"exists": true, "validate": true, "verify": true, "ping": true, "show": true, "info": true, "test": true,
	"probe": true, "inspect": true, "count": true, "preview": true, "draft": true, "compose": true, "render": true,
	"format": true, "lint": true, "parse": true,
}

// scopeSinkKeys are argument names whose string value is a place the call
// sends to, whatever the tool is called.
var scopeSinkKeys = map[string]bool{
	"destination": true, "dest": true, "recipient": true, "recipients": true, "to": true, "cc": true, "bcc": true,
	"bcc_override": true, "webhook": true, "webhook_url": true, "log_destination": true, "upload_url": true,
	"target_url": true, "sink": true, "recipient_email": true, "send_to": true, "callback": true, "callback_url": true,
	"forward_to": true,
}

// scopeAmbiguousKeys name a place that is a source as often as a sink (a fetch
// tool's url, an exists tool's email, a database host). They count only when
// the tool's own name says it sends.
var scopeAmbiguousKeys = map[string]bool{
	"url": true, "uri": true, "endpoint": true, "host": true, "bucket": true, "remote": true, "address": true,
	"email": true, "emails": true,
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
	var mailSpans [][2]int
	for _, loc := range scopeEmailRe.FindAllStringIndex(intent, -1) {
		add(intent[loc[0]:loc[1]])
		mailSpans = append(mailSpans, [2]int{loc[0], loc[1]})
	}
	for _, loc := range scopeDomainRe.FindAllStringSubmatchIndex(intent, -1) {
		inMailbox := false
		for _, sp := range mailSpans {
			inMailbox = inMailbox || (loc[2] >= sp[0] && loc[3] <= sp[1])
		}
		if !inMailbox {
			add(intent[loc[2]:loc[3]])
		}
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
// one value with no key. A walk that reaches the depth or value cap records it
// in trunc: the call is then out of scope (the bound rule,
// internal/guardrail/bounded), never silently clean.
func scopeStrings(args string, trunc *bounded.Truncated) []scopeString {
	var root any
	if err := json.Unmarshal([]byte(args), &root); err != nil {
		return []scopeString{{"", args}}
	}
	var out []scopeString
	values := bounded.NewCounter(trunc, bounded.Nodes, maxScopeValues)
	var walk func(key string, v any, depth int)
	walk = func(key string, v any, depth int) {
		if !trunc.Within(bounded.Depth, depth, maxScopeDepth) {
			return
		}
		switch t := v.(type) {
		case string:
			if values.Take() {
				out = append(out, scopeString{strings.ToLower(key), t})
			}
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

// scopeDest is one place a call sends to: a host (a URL, a bare host, the host
// of user@host in scp or rsync) or a mailbox (a recipient of a mail call).
type scopeDest struct {
	host    string
	mailbox string
}

// scopeNamedHost reports whether host is a host the task names or a sub-domain
// of one. A named host does not name its parent domain: a task that names
// bucket.s3.amazonaws.com does not name s3.amazonaws.com.
func scopeNamedHost(host string, named []string) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	for _, n := range named {
		if strings.ContainsAny(n, "@/~") || strings.HasPrefix(n, ".") {
			continue
		}
		if host == n || strings.HasSuffix(host, "."+n) {
			return true
		}
	}
	return false
}

// scopeNamedMailbox reports whether the exact address is one the task names. A
// named mailbox does not name the other mailboxes of its domain.
func scopeNamedMailbox(mailbox string, named []string) bool {
	mailbox = strings.ToLower(mailbox)
	for _, n := range named {
		if n == mailbox {
			return true
		}
	}
	return false
}

// scopeMailProgramRe finds a mail program in a shell command: an address there
// is a mailbox; user@host in scp, rsync or curl is a host.
var scopeMailProgramRe = lazyregexp.New(`(?i)\b(?:mail|mailx|sendmail|swaks|msmtp|mutt)\b`)

// scopeToolVerb reads what a tool does from its name: the verb is the last word
// of a namespaced name (email.exists, http.post) or the first of a verb_noun
// name (browse_website, send_email); a name whose ends are neither falls back
// to any word in it. "email" is a noun in email.exists and a verb in
// email.send, so a send word anywhere is not enough.
func scopeToolVerb(toolName string) (sends, reads bool) {
	segs := toolNameSegments(toolName)
	if len(segs) == 0 {
		return false, false
	}
	for _, s := range []string{segs[len(segs)-1], segs[0]} {
		if scopeReadSegments[s] {
			return false, true
		}
		if scopeSendSegments[s] {
			return true, false
		}
	}
	for _, s := range segs {
		if scopeSendSegments[s] {
			return true, false
		}
	}
	for _, s := range segs {
		if scopeReadSegments[s] {
			return false, true
		}
	}
	return false, false
}

// callSendDestinations returns the places a sending call goes to, and the caps
// its reading hit; nil for a call that does not send.
func callSendDestinations(toolName, args string, trunc *bounded.Truncated) []scopeDest {
	toolSends, toolReads := scopeToolVerb(toolName)
	values := scopeStrings(args, trunc)
	var texts []string
	shell := false
	for _, v := range values {
		switch {
		case v.key == "command" || v.key == "cmd" || v.key == "script" || v.key == "code" || v.key == "":
			if scopeShellSendRe.MatchString(v.value) {
				shell = true
				texts = append(texts, v.value)
			}
		case scopeSinkKeys[v.key]:
			if !toolReads || toolSends {
				texts = append(texts, v.value)
			}
		case scopeAmbiguousKeys[v.key]:
			if toolSends {
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
	var out []scopeDest
	destinations := bounded.NewCounter(trunc, bounded.Items, maxScopeDestinations)
	add := func(d scopeDest) {
		key := d.host + "|" + d.mailbox
		if (d.host == "" && d.mailbox == "") || seen[key] {
			return
		}
		if destinations.Take() {
			seen[key] = true
			out = append(out, d)
		}
	}
	for _, t := range texts {
		shellText := scopeShellSendRe.MatchString(t)
		mailCommand := shellText && scopeMailProgramRe.MatchString(t)
		// One match past the cap is enough to know the cap is hit.
		for _, m := range scopeURLHostRe.FindAllStringSubmatch(t, maxScopeDestinations+1) {
			add(scopeDest{host: strings.ToLower(m[1])})
		}
		for _, m := range scopeEmailRe.FindAllStringSubmatch(t, maxScopeDestinations+1) {
			if shellText && !mailCommand {
				add(scopeDest{host: strings.ToLower(m[1])})
			} else {
				add(scopeDest{mailbox: strings.ToLower(m[0])})
			}
		}
		if !strings.Contains(t, "://") && !strings.Contains(t, "@") && !strings.ContainsAny(t, " \t\n/\\") {
			// a bare host or domain in a destination key
			if m := scopeDomainRe.FindStringSubmatch(t); m != nil && m[1] == strings.ToLower(strings.TrimSpace(t)) {
				add(scopeDest{host: m[1]})
			}
		}
	}
	return out
}

const maxSessionScopeTargets = 64

// mergeScopeTargets adds the targets a new prompt names to the session's set,
// keeping the newest maxSessionScopeTargets.
func mergeScopeTargets(session []string, prompt string) []string {
	seen := make(map[string]bool, len(session))
	for _, t := range session {
		seen[t] = true
	}
	out := append([]string(nil), session...)
	for _, t := range namedScopeTargets(prompt) {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	if len(out) > maxSessionScopeTargets {
		out = out[len(out)-maxSessionScopeTargets:]
	}
	return out
}

// intentScopeExceeded returns a reason when the call sends data to a
// destination neither the task nor an earlier prompt of the session names, or
// "" (also when there is no task: with nothing to check against, the judge
// decides alone). sessionTargets are the targets the session's user prompts
// named; they never come from tool output.
func intentScopeExceeded(intent string, sessionTargets []string, toolName, args string) string {
	if strings.TrimSpace(intent) == "" {
		return ""
	}
	var trunc bounded.Truncated
	dests := callSendDestinations(toolName, args, &trunc)
	named := append(namedScopeTargets(intent), sessionTargets...)
	// What was read before a cap is still judged, and a call cut short at a cap
	// is judged as unknown at least: the stricter of the two stands.
	exceeded := false
	for _, d := range dests {
		if d.mailbox != "" {
			if scopeNamedMailbox(d.mailbox, named) {
				continue
			}
		} else if scopeLoopback(d.host) || scopeNamedHost(d.host, named) {
			continue
		}
		exceeded = true
		break
	}
	if trunc.Any() {
		reason := "the call is too large to read in full, so it is judged as outside the user's task (" + trunc.Set().Reason() + ")"
		if exceeded {
			reason = "the call sends data to a destination the user's task does not name, and it is too large to read in full (" + trunc.Set().Reason() + ")"
		}
		return reason
	}
	if exceeded {
		return "the call sends data to a destination the user's task does not name"
	}
	return ""
}

// keepScopeFloor remembers the scope finding of a prepared sample until it is
// judged, as keepDecisionState does for the decision model. A sample is unique
// (it carries the call's nonce), so the key is its digest; when the cap is
// reached the oldest pending floor goes, one at a time.
func (j *LLMJudge) keepScopeFloor(sample, reason string) {
	j.scopeFloorsMu.Lock()
	defer j.scopeFloorsMu.Unlock()
	if j.scopeFloors == nil {
		j.scopeFloors = make(map[[sha256.Size]byte]scopeFloorEntry)
	}
	for len(j.scopeFloors) >= pendingScopeFloorsCap {
		var oldest [sha256.Size]byte
		oldestSeq := uint64(1<<63 - 1)
		for key, e := range j.scopeFloors {
			if e.seq < oldestSeq {
				oldest, oldestSeq = key, e.seq
			}
		}
		delete(j.scopeFloors, oldest)
	}
	j.scopeFloorSeq++
	j.scopeFloors[sha256.Sum256([]byte(sample))] = scopeFloorEntry{reason: reason, seq: j.scopeFloorSeq}
}

func (j *LLMJudge) takeScopeFloor(sample string) string {
	j.scopeFloorsMu.Lock()
	defer j.scopeFloorsMu.Unlock()
	key := sha256.Sum256([]byte(sample))
	e := j.scopeFloors[key]
	delete(j.scopeFloors, key)
	return e.reason
}

type scopeFloorEntry struct {
	reason string
	seq    uint64
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
	if i := strings.Index(reason, bounded.ReasonCode); i >= 0 {
		// A walk cut short at a cap also carries the shared evaluation-limit finding
		// naming the cap, and the severity of the unknown tier: an alert in the
		// default and permissive packs (their alert_at), a block in the strict pack.
		floor.Severity = "HIGH"
		floor.Findings = append(floor.Findings, evaluationLimitRuleID+":"+boundedTruncatedTitle+" ("+strings.TrimSuffix(reason[i:], ")")+")")
	}
	if judged == nil {
		return floor
	}
	if judged.JudgeFailed {
		// Never replace a judge failure: the hook has to see it (fallback
		// metric, loud log, the escalated fail-closed refusal). The alert
		// rides next to it.
		floor.JudgeFailed = true
		floor.judgeFailedUnderFloor = true
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
