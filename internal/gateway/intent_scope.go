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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
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

// scopeUnreadableReason is the floor's reason for a command that may send and
// whose destination could not be read (a host the shell builds, a syntax error,
// a command past the parser's limits). It gets the unknown tier, like a call cut
// short at a cap.
const scopeUnreadableReason = "the call may send data and its destination cannot be read, so it is judged as outside the user's task (unreadable_send)"

const (
	intentScopeFinding     = "INTENT-SCOPE-SEND"
	maxNamedScopeTargets   = 20
	maxScopeDestinations   = 16
	maxScopeDepth          = 10
	maxScopeValues         = 1024
	maxScopeScanMatches    = 4096
	maxScopeGitConfigBytes = 64 << 10
	maxScopeGitDepth       = 12
)

var (
	scopeURLHostRe = lazyregexp.New(`(?i)\b(?:https?|ftp|ftps|sftp|s3|gs|wss?)://(?:[^\s/@'"` + "`" + `]*@)?(\[[0-9a-f:]+\]|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)`)
	scopeEmailRe   = lazyregexp.New(`(?i)\b[a-z0-9._%+-]+@([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,})\b`)
	scopeDomainRe  = lazyregexp.New(`(?i)\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,})\b`)
	scopePathRe    = lazyregexp.New(`(?:^|[\s"'(])((?:~|\.{1,2})?/[A-Za-z0-9._@%+=,~/-]{2,})`)
)

// scopeSendSegments and scopeReadSegments classify a tool name by its words
// (camel case and . _ - : / split it).
var scopeSendSegments = map[string]bool{
	"post": true, "upload": true, "send": true, "email": true, "mail": true, "publish": true, "webhook": true,
	"notify": true, "submit": true, "export": true, "forward": true, "share": true, "put": true, "push": true,
	"dispatch": true, "transmit": true, "sync": true, "bcc": true, "backup": true, "archive": true,
	"snapshot": true, "replicate": true, "mirror": true,
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

// scopeShellKeys are argument names whose string value is shell text.
var scopeShellKeys = map[string]bool{"command": true, "cmd": true, "script": true, "code": true}

// scopeSinkKeys are argument names whose string value is a place the call
// sends to, whatever the tool is called.
var scopeSinkKeys = map[string]bool{
	"destination": true, "dest": true, "recipient": true, "recipients": true, "to": true, "cc": true, "bcc": true,
	"bcc_override": true, "webhook": true, "webhook_url": true, "log_destination": true, "upload_url": true,
	"target_url": true, "sink": true, "recipient_email": true, "send_to": true, "callback": true, "callback_url": true,
	"forward_to": true, "output_url": true, "output_uri": true, "output_destination": true, "export_url": true,
	"export_destination": true, "backup_url": true, "backup_destination": true, "backup_location": true,
	"archive_url": true, "archive_destination": true, "archive_location": true, "snapshot_destination": true,
	"destination_url": true, "destination_uri": true, "dest_url": true, "dest_bucket": true, "target_bucket": true,
	"upload_destination": true, "replica_url": true, "mirror_url": true,
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
	// Every node below the root counts, strings or not: a call of a million
	// numbers, nulls or empty arrays is as unread as one of a million strings.
	nodes := bounded.NewCounter(trunc, bounded.Nodes, maxScopeValues)
	var walk func(key string, v any, depth int)
	walk = func(key string, v any, depth int) {
		if !trunc.Within(bounded.Depth, depth, maxScopeDepth) {
			return
		}
		switch t := v.(type) {
		case string:
			out = append(out, scopeString{strings.ToLower(key), t})
		case []any:
			for _, e := range t {
				if !nodes.Take() {
					return
				}
				walk(key, e, depth+1)
			}
		case map[string]any:
			for k, e := range t {
				if !nodes.Take() {
					return
				}
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

// scanScopeMatches returns the matches of re in t, at most maxScopeScanMatches
// of them; more is a cap hit (the bound rule), and the scan stops there.
func scanScopeMatches(re *lazyregexp.Regexp, t string, trunc *bounded.Truncated) [][]string {
	ms := re.FindAllStringSubmatch(t, maxScopeScanMatches+1)
	if len(ms) > maxScopeScanMatches {
		trunc.Hit(bounded.Items)
		ms = ms[:maxScopeScanMatches]
	}
	return ms
}

// scopeKeyPrecheckBytes is the size above which a call is first checked for any
// key a destination or a command could sit under (the walk of a megabyte of
// nested arrays cost 58 ms).
const scopeKeyPrecheckBytes = 32 << 10

// scopeMayHaveDestination reports whether a JSON object argument text names, as an
// object key, one of the keys callSendDestinations reads (a shell key, a sink key
// or an ambiguous key); arguments that are not an object are always read.
func scopeMayHaveDestination(args string) bool {
	trimmed := strings.TrimLeft(args, " \t\r\n")
	if !strings.HasPrefix(trimmed, "{") {
		return true
	}
	lower := strings.ToLower(args)
	for _, set := range []map[string]bool{scopeShellKeys, scopeSinkKeys, scopeAmbiguousKeys} {
		for k := range set {
			if strings.Contains(lower, `"`+k+`"`) {
				return true
			}
		}
	}
	return false
}

// scanScopeStrings is scanScopeMatches for the whole match text.
func scanScopeStrings(re *lazyregexp.Regexp, t string, trunc *bounded.Truncated) []string {
	ms := re.FindAllString(t, maxScopeScanMatches+1)
	if len(ms) > maxScopeScanMatches {
		trunc.Hit(bounded.Items)
		ms = ms[:maxScopeScanMatches]
	}
	return ms
}

// callSendDestinations returns the distinct places a sending call goes to, and
// the caps its reading hit; nil for a call that does not send. A repeat of a
// destination already read costs nothing; the seventeenth distinct one is a cap
// hit. unreadable reports a command that may send and could not be read (the
// unknown tier applies to the send; there is no text scan).
func callSendDestinations(toolName, args string, trunc *bounded.Truncated) (dests []scopeDest, unreadable bool) {
	toolSends, toolReads := scopeToolVerb(toolName)
	if len(args) > scopeKeyPrecheckBytes && !scopeMayHaveDestination(args) {
		return nil, false
	}
	values := scopeStrings(args, trunc)
	var texts, shellTexts []string
	for _, v := range values {
		switch {
		case scopeShellKeys[v.key] || v.key == "":
			shellTexts = append(shellTexts, v.value)
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
	// A shell command is read by its parsed effects: a send is a command that sends.
	shell := false
	if len(shellTexts) > 0 {
		shell, unreadable = shellSendDestinations(toolName, args, shellTexts, trunc, add)
	}
	if !shell && !toolSends && len(texts) == 0 {
		return nil, false
	}
	if !shell && toolReads && !toolSends {
		return nil, false
	}
	for _, t := range texts {
		for _, m := range scanScopeMatches(scopeURLHostRe, t, trunc) {
			add(scopeDest{host: strings.ToLower(m[1])})
		}
		for _, m := range scanScopeMatches(scopeEmailRe, t, trunc) {
			add(scopeDest{mailbox: strings.ToLower(m[0])})
		}
		if !strings.Contains(t, "://") && !strings.Contains(t, "@") && !strings.ContainsAny(t, " \t\n/\\") {
			// a bare host or domain in a destination key
			if m := scopeDomainRe.FindStringSubmatch(t); m != nil && m[1] == strings.ToLower(strings.TrimSpace(t)) {
				add(scopeDest{host: m[1]})
			}
		}
	}
	return out, unreadable
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
// destination neither the task nor an earlier prompt of the session names (nor
// a host the working folder's git remotes name), or "" (also when there is no
// task: with nothing to check against, the judge decides alone).
// sessionTargets are the targets the session's user prompts named, never from
// tool output; gitHosts are the hosts of the git remotes of the call's folder.
func intentScopeExceeded(intent string, sessionTargets []string, toolName, args string, gitHosts ...string) string {
	if strings.TrimSpace(intent) == "" {
		return ""
	}
	var trunc bounded.Truncated
	dests, unreadable := callSendDestinations(toolName, args, &trunc)
	named := append(append(namedScopeTargets(intent), sessionTargets...), gitHosts...)
	// What was read before a cap is still judged, and a call cut short at a cap
	// is judged as unknown at least: the stricter of the two stands.
	exceeded := false
	for _, d := range dests {
		if d.mailbox != "" {
			if scopeNamedMailbox(d.mailbox, named) || scopePartyNamed(d.mailbox, intent, named) {
				continue
			}
		} else if scopeLoopback(d.host) || scopeNamedHost(d.host, named) {
			continue
		}
		exceeded = true
		break
	}
	if unreadable {
		return scopeUnreadableReason
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

// scopePartyNamed reports a mailbox of a party the task names without its
// address: a word of the task is a whole word of the mailbox's local part (at
// least three letters), and the task names the mailbox's domain. A word alone
// is not enough: a look-alike local part at another domain is not the party.
func scopePartyNamed(mailbox, intent string, named []string) bool {
	at := strings.LastIndexByte(mailbox, '@')
	if at <= 0 || !scopeNamedHost(mailbox[at+1:], named) {
		return false
	}
	words := map[string]bool{}
	for _, w := range strings.FieldsFunc(strings.ToLower(intent), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		if len(w) >= 3 {
			words[w] = true
		}
	}
	for _, p := range strings.FieldsFunc(mailbox[:at], func(r rune) bool { return r == '.' || r == '_' || r == '-' || r == '+' }) {
		if len(p) >= 3 && words[p] {
			return true
		}
	}
	return false
}

// scopeGitReadTimeout bounds the one read of a session's git remotes: a network
// home or a stalled mount must not hold the hook.
const scopeGitReadTimeout = 250 * time.Millisecond

// scopeGitRemoteHostsWithin is scopeGitRemoteHosts with a deadline; on a timeout
// the session has no git hosts.
func scopeGitRemoteHostsWithin(dir string, limit time.Duration) []string {
	if dir == "" || !filepath.IsAbs(dir) {
		return nil
	}
	done := make(chan []string, 1)
	go func() { done <- scopeGitRemoteHosts(dir) }()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case hosts := <-done:
		return hosts
	case <-timer.C:
		return nil
	}
}

// SnapshotSessionGitRemotes reads the git remotes of cwd once for the session, at
// its first event (a prompt or, failing that, the first tool call). Later calls
// keep that read: a remote added during the session is not the user's.
func (j *LLMJudge) SnapshotSessionGitRemotes(ctx context.Context, cwd string) {
	if j == nil || cwd == "" {
		return
	}
	sessionID := sandboxSessionStateKey(ctx, SessionIDFromContext(ctx))
	if sessionID == "" {
		return
	}
	j.toolContextMu.Lock()
	entry, ok := j.toolContext[sessionID]
	j.toolContextMu.Unlock()
	if !ok || entry.gitRead {
		return
	}
	hosts := scopeGitRemoteHostsWithin(cwd, scopeGitReadTimeout)
	j.toolContextMu.Lock()
	defer j.toolContextMu.Unlock()
	if entry, ok := j.toolContext[sessionID]; ok && !entry.gitRead {
		entry.gitHosts, entry.gitRead = hosts, true
		j.toolContext[sessionID] = entry
	}
}

// scopeGitRemoteHosts returns the hosts of the git remotes of the repository
// that holds dir: the forge the user's work is on, which a task about that work
// names without spelling it (a push, a pull request, a CI call). It reads the
// repository's own config file, never a tool result.
func scopeGitRemoteHosts(dir string) []string {
	if dir == "" || !filepath.IsAbs(dir) {
		return nil
	}
	dir = filepath.Clean(dir)
	for depth := 0; depth < maxScopeGitDepth; depth++ {
		if hosts, ok := readGitRemoteHosts(filepath.Join(dir, ".git", "config")); ok {
			return hosts
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return nil
}

func readGitRemoteHosts(path string) ([]string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	var hosts []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(&limitedScopeReader{r: f, left: maxScopeGitConfigBytes})
	inRemote := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			inRemote = strings.HasPrefix(line, "[remote ")
			continue
		}
		if !inRemote || !strings.HasPrefix(line, "url") {
			continue
		}
		_, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		host := gitRemoteHost(strings.TrimSpace(value))
		if host != "" && !seen[host] && len(hosts) < 8 {
			seen[host] = true
			hosts = append(hosts, host)
		}
	}
	return hosts, true
}

type limitedScopeReader struct {
	r    *os.File
	left int
}

func (l *limitedScopeReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, os.ErrClosed
	}
	if len(p) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= n
	return n, err
}

// gitRemoteHost is the host of a git remote url: https://host/x, ssh://git@host/x
// or the scp form git@host:x.
func gitRemoteHost(url string) string {
	if loc := scopeShellURLRe.FindStringSubmatch(url); loc != nil {
		return strings.ToLower(loc[1])
	}
	if m := scopeRemoteOperand.FindStringSubmatch(url); m != nil {
		return strings.ToLower(m[1])
	}
	return ""
}

// scopeShadowObserver, when set (the benchmark harness), is told of every call
// the scope floor recorded in shadow.
var scopeShadowObserver atomic.Pointer[func(sessionID, tool, reason string)]

// hookScopeFloorState is the scope finding of one hook tool call, read before the
// judge ran.
type hookScopeFloorState struct {
	reason string
	mode   string
}

// hookScopeFloor reads the scope finding of a tool call from the session's task
// and the call's arguments. It is deterministic, takes no model's answer and is
// read before the judge runs, so a judge that is late, busy, skipped or failed
// cannot drop it (GAP-0372). The task is kept by the hook session judges.
func (a *APIServer) hookScopeFloor(ctx context.Context, toolName, args, cwd string) hookScopeFloorState {
	cfg := a.decisionConfig(ctx)
	if cfg == nil {
		return hookScopeFloorState{}
	}
	mode := cfg.Guardrail.Judge.IntentScopeMode()
	if mode == config.IntentScopeOff {
		return hookScopeFloorState{}
	}
	for _, j := range a.hookSessionJudges(ctx) {
		if reason := j.scopeFloorReason(ctx, toolName, args, cwd); reason != "" {
			return hookScopeFloorState{reason: reason, mode: mode}
		}
	}
	return hookScopeFloorState{}
}

// scopeFloorReason is the scope finding of a call in this judge's session, or "".
func (j *LLMJudge) scopeFloorReason(ctx context.Context, toolName, args, cwd string) string {
	if j == nil {
		return ""
	}
	sessionID := sandboxSessionStateKey(ctx, SessionIDFromContext(ctx))
	if sessionID == "" {
		return ""
	}
	j.toolContextMu.Lock()
	entry, ok := j.toolContext[sessionID]
	j.toolContextMu.Unlock()
	if !ok || entry.userIntent == "" {
		return ""
	}
	if !entry.gitRead && cwd != "" {
		// A session whose first event was this call: the read happens now, once.
		j.SnapshotSessionGitRemotes(ctx, cwd)
		j.toolContextMu.Lock()
		entry = j.toolContext[sessionID]
		j.toolContextMu.Unlock()
	}
	return intentScopeExceeded(entry.userIntent, entry.scopeTargets, toolName, args, entry.gitHosts...)
}

// applyHookScopeFloor folds the scope finding into the hook verdict: in shadow
// mode only a judge event and a log line are recorded and the verdict is
// returned as it is; otherwise the finding goes through the connector's
// block_at / alert_at like a judge finding, and never lowers the verdict.
func (a *APIServer) applyHookScopeFloor(ctx context.Context, connector string, scope hookScopeFloorState, toolName, args string, verdict *ToolInspectVerdict) *ToolInspectVerdict {
	if scope.reason == "" {
		return verdict
	}
	if scope.mode != config.IntentScopeAlert {
		recordIntentScopeShadow(ctx, toolName, args, scope.reason)
		return verdict
	}
	cfg := a.decisionConfig(ctx)
	if cfg == nil {
		return verdict
	}
	floor := hookJudgeLaneVerdict(cfg, connector, "tool_call", applyIntentScopeFloor(nil, scope.reason))
	return mergeWithJudgeVerdict(verdict, floor)
}

// applyIntentScopeFloor is the verdict of a scope finding: at least a MEDIUM
// alert, HIGH (the unknown tier) for a call read only up to a cap or not at
// all, merged under a judge verdict without lowering it. A nil judged verdict
// gives the floor alone.
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
	if reason == scopeUnreadableReason {
		floor.Severity = "HIGH"
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

// recordIntentScopeShadow records a call the scope floor would have raised: a
// judge event of kind tool_intent_scope_shadow (action allow, the finding, the
// tool name, the reason as evidence) and one log line. The verdict is untouched.
func recordIntentScopeShadow(ctx context.Context, toolName, args, reason string) {
	shadow := applyIntentScopeFloor(nil, reason)
	findings := judgeFindingsPayload(shadow)
	for i := range findings {
		findings[i].Source = "intent-scope-shadow"
		findings[i].Evidence = reason
	}
	fmt.Fprintf(os.Stderr, "[guardrail] intent-scope shadow: tool=%s reason=%q (record only, verdict unchanged)\n", sanitizeToolName(toolName), reason)
	if obs := scopeShadowObserver.Load(); obs != nil {
		(*obs)(SessionIDFromContext(ctx), sanitizeToolName(toolName), reason)
	}
	emitJudge(ctx, "tool_intent_scope_shadow", "", gatewaylog.DirectionToolCall,
		len(args), 0, "allow", deriveSeverity(shadow.Severity), "", "",
		JudgeEmitOpts{Findings: findings, ToolName: sanitizeToolName(toolName)})
}
