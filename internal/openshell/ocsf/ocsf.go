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

// Package ocsf parses the single-line OCSF "shorthand" that the OpenShell
// 0.1.x supervisor pushes through WatchSandbox log lines.
//
// OpenShell 0.1.1 sends those lines with level "OCSF", target "ocsf" and an
// empty structured-fields map, so the shorthand text is the only carrier of
// the event. Its grammar comes from the upstream display formatter
// (crates/openshell-ocsf/src/format/shorthand.rs):
//
//	<CLASS>[:<ACTIVITY>] [<SEV>] <class-specific detail> [<k:v> ...]...
//
// The formatter is a display projection, not a wire contract: fields are
// optional, reason text is not escaped, and a release can reorder context.
// The parser is therefore tolerant. It never panics, keeps every bracketed
// key:value pair it finds in Record.Context, and reports only lines that do
// not start with a recognizable class and severity as ErrNotShorthand.
package ocsf

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// ErrNotShorthand reports a message that is not an OCSF shorthand line.
var ErrNotShorthand = errors.New("ocsf: not a shorthand event line")

// LogLevel and LogTarget identify OCSF shorthand lines in the sandbox log
// stream.
const (
	LogLevel  = "OCSF"
	LogTarget = "ocsf"
)

// Class is the OCSF event class prefix of a shorthand line.
type Class string

// Classes emitted by OpenShell 0.1.x.
const (
	ClassNetwork   Class = "NET"
	ClassHTTP      Class = "HTTP"
	ClassSSH       Class = "SSH"
	ClassProcess   Class = "PROC"
	ClassFinding   Class = "FINDING"
	ClassLifecycle Class = "LIFECYCLE"
	ClassConfig    Class = "CONFIG"
	ClassAPI       Class = "API"
	ClassEvent     Class = "EVENT"
)

// UID returns the OCSF class_uid the shorthand prefix was rendered from, or
// 0 for the base event and unknown prefixes.
func (c Class) UID() int {
	switch c {
	case ClassNetwork:
		return 4001
	case ClassHTTP:
		return 4002
	case ClassSSH:
		return 4007
	case ClassProcess:
		return 1007
	case ClassFinding:
		return 2004
	case ClassLifecycle:
		return 6002
	case ClassConfig:
		return 5019
	case ClassAPI:
		return 6003
	default:
		return 0
	}
}

// Severity is the OCSF severity of a shorthand line.
type Severity string

// Severities, in OCSF severity_id order.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
	SeverityFatal    Severity = "fatal"
)

// ID returns the OCSF severity_id (1 informational … 6 fatal).
func (s Severity) ID() int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	case SeverityCritical:
		return 5
	case SeverityFatal:
		return 6
	default:
		return 0
	}
}

var severityTags = map[string]Severity{
	"INFO":  SeverityInfo,
	"LOW":   SeverityLow,
	"MED":   SeverityMedium,
	"HIGH":  SeverityHigh,
	"CRIT":  SeverityCritical,
	"FATAL": SeverityFatal,
}

// Actions the upstream ActionId labels render as (upper-cased).
const (
	ActionAllowed  = "ALLOWED"
	ActionDenied   = "DENIED"
	ActionObserved = "OBSERVED"
	ActionModified = "MODIFIED"
	ActionUnknown  = "UNKNOWN"
	ActionOther    = "OTHER"
)

var actions = map[string]bool{
	ActionAllowed: true, ActionDenied: true, ActionObserved: true,
	ActionModified: true, ActionUnknown: true, ActionOther: true,
}

// Record is one parsed shorthand line. Fields the line does not carry stay
// at their zero value; PID and ExitCode use HasPID and a pointer so that a
// literal 0 stays distinguishable from "absent".
type Record struct {
	Class    Class    `json:"class"`
	Activity string   `json:"activity,omitempty"`
	Severity Severity `json:"severity"`
	Action   string   `json:"action,omitempty"`

	// Actor process (NET, HTTP, PROC).
	Binary string `json:"binary,omitempty"`
	PID    int    `json:"pid,omitempty"`
	HasPID bool   `json:"has_pid,omitempty"`

	// Destination (NET, HTTP) or peer (SSH).
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`

	// HTTP request.
	Method string `json:"method,omitempty"`
	URL    string `json:"url,omitempty"`
	Path   string `json:"path,omitempty"`

	// Policy decision context.
	Policy string `json:"policy,omitempty"`
	Engine string `json:"engine,omitempty"`
	Reason string `json:"reason,omitempty"`

	// Message is the free text of CONFIG and EVENT lines and the [msg:…]
	// context of NET/HTTP lines.
	Message string `json:"message,omitempty"`

	// FINDING.
	Title       string `json:"title,omitempty"`
	FindingType string `json:"finding_type,omitempty"`
	Confidence  string `json:"confidence,omitempty"`

	// LIFECYCLE and API status.
	App    string `json:"app,omitempty"`
	Status string `json:"status,omitempty"`

	// PROC.
	CmdLine  string `json:"cmd_line,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`

	// SSH.
	Auth string `json:"auth,omitempty"`

	// API:INFERENCE.
	Model     string `json:"model,omitempty"`
	Provider  string `json:"provider,omitempty"`
	LatencyMS int    `json:"latency_ms,omitempty"`
	Operation string `json:"operation,omitempty"`

	// Context holds every bracketed key:value pair, unescaped. Reserved
	// keys that populate typed fields above (policy, engine, reason, msg,
	// type, confidence, auth, exit, cmd) are kept here as well.
	Context map[string]string `json:"context,omitempty"`

	// Raw is the original message.
	Raw string `json:"raw"`
}

// Denied reports whether the line records a denied action (or a blocked
// finding).
func (r Record) Denied() bool {
	if r.Action == ActionDenied {
		return true
	}
	return r.Class == ClassFinding && r.Activity == "BLOCKED"
}

// Allowed reports whether the line records an allowed action.
func (r Record) Allowed() bool { return r.Action == ActionAllowed }

// IsShorthand reports whether a sandbox log line carries an OCSF shorthand
// message, going by the level and target OpenShell 0.1.x stamps on them.
func IsShorthand(level, target string) bool {
	return strings.EqualFold(level, LogLevel) || target == LogTarget
}

// head matches "<CLASS>[:<ACTIVITY>] [<SEV>]" with an optional leading
// "HH:MM:SS.mmm " timestamp. Activities may contain spaces ("NO ACTION").
var head = regexp.MustCompile(`^(?:\d{2}:\d{2}:\d{2}\.\d{3} )?([A-Z]+)(?::([^\[\]]*?))? \[(INFO|LOW|MED|HIGH|CRIT|FATAL)\]`)

// Parse parses one shorthand message. It returns ErrNotShorthand, together
// with a Record that has only Raw set, when msg does not begin with a class
// and a severity tag. Any other malformation is tolerated: the fields that
// could be recognized are filled in.
func Parse(msg string) (Record, error) {
	rec := Record{Raw: msg}
	line := strings.TrimRight(msg, "\r\n")
	m := head.FindStringSubmatchIndex(line)
	if m == nil {
		return rec, ErrNotShorthand
	}
	rec.Class = Class(line[m[2]:m[3]])
	if m[4] >= 0 {
		rec.Activity = strings.TrimSpace(line[m[4]:m[5]])
	}
	rec.Severity = severityTags[line[m[6]:m[7]]]
	body := line[m[1]:]

	switch rec.Class {
	case ClassNetwork:
		parseNetwork(&rec, body)
	case ClassHTTP:
		parseHTTP(&rec, body)
	case ClassSSH:
		parseSSH(&rec, body)
	case ClassProcess:
		parseProcess(&rec, body)
	case ClassFinding:
		parseFinding(&rec, body)
	case ClassLifecycle:
		parseLifecycle(&rec, body)
	case ClassConfig:
		parseConfig(&rec, body)
	case ClassAPI:
		parseAPI(&rec, body)
	default:
		// EVENT and any class a newer release adds: free text plus
		// trailing context.
		parseFreeText(&rec, body)
	}
	return rec, nil
}

func parseNetwork(rec *Record, body string) {
	text := rec.consumeContext(body)
	text = strings.TrimSpace(text)
	text = rec.takeAction(text)
	if text == "" {
		return
	}
	actor, dst, ok := strings.Cut(text, " -> ")
	if ok {
		rec.setActor(actor)
		rec.setDestination(dst)
		return
	}
	if rec.setActor(text) {
		return
	}
	rec.setDestination(text)
}

func parseHTTP(rec *Record, body string) {
	text := strings.TrimSpace(rec.consumeContext(body))
	text = rec.takeAction(text)
	if actor, req, ok := strings.Cut(text, " -> "); ok {
		rec.setActor(actor)
		text = req
	}
	method, target, _ := strings.Cut(strings.TrimSpace(text), " ")
	rec.Method = method
	if rec.Method == "" {
		rec.Method = rec.Activity
	}
	rec.setURL(strings.TrimSpace(target))
}

func parseSSH(rec *Record, body string) {
	text := strings.TrimSpace(rec.consumeContext(body))
	text = rec.takeAction(text)
	if text != "" {
		rec.setDestination(text)
	}
	rec.Auth = rec.Context["auth"]
}

func parseProcess(rec *Record, body string) {
	text := strings.TrimSpace(rec.consumeContext(body))
	rec.setActor(text)
	rec.CmdLine = rec.Context["cmd"]
	if v, ok := rec.Context["exit"]; ok {
		if code, err := strconv.Atoi(v); err == nil {
			rec.ExitCode = &code
		}
	}
}

func parseFinding(rec *Record, body string) {
	text := strings.TrimSpace(rec.consumeContext(body))
	if title, ok := unquote(text); ok {
		rec.Title = title
	} else {
		rec.Title = text
	}
	rec.FindingType = rec.Context["type"]
	rec.Confidence = rec.Context["confidence"]
}

func parseLifecycle(rec *Record, body string) {
	text := strings.TrimSpace(rec.consumeContext(body))
	if i := strings.LastIndexByte(text, ' '); i >= 0 {
		rec.App, rec.Status = text[:i], text[i+1:]
	} else {
		rec.App = text
	}
}

func parseConfig(rec *Record, body string) {
	rec.Message = strings.TrimSpace(rec.consumeContext(body))
}

func parseFreeText(rec *Record, body string) {
	rec.Message = strings.TrimSpace(rec.consumeContext(body))
}

// parseAPI handles "API:INFERENCE [SEV] [status] [model] [via provider]
// [<n>ms] [<operation>]". The formatter always closes the line with the
// operation group, which has no key, so it is taken before the generic
// context scan.
func parseAPI(rec *Record, body string) {
	text := strings.TrimRight(body, " ")
	if start, inner, ok := lastGroup(text); ok {
		rec.Operation = unescapeContext(inner)
		text = text[:start]
	}
	text = strings.TrimSpace(rec.consumeContext(text))
	fields := strings.Fields(text)
	if n := len(fields); n > 0 && strings.HasSuffix(fields[n-1], "ms") {
		if ms, err := strconv.Atoi(strings.TrimSuffix(fields[n-1], "ms")); err == nil {
			rec.LatencyMS = ms
			fields = fields[:n-1]
		}
	}
	for i := 0; i < len(fields); i++ {
		if fields[i] == "via" && i+1 < len(fields) {
			rec.Provider = unescapeContext(fields[i+1])
			fields = append(fields[:i], fields[i+2:]...)
			break
		}
	}
	switch len(fields) {
	case 0:
	case 1:
		rec.Model = unescapeContext(fields[0])
	default:
		rec.Status = fields[0]
		rec.Model = unescapeContext(strings.Join(fields[1:], " "))
	}
}

// consumeContext strips every trailing " [...]" group whose content is
// key:value shaped, records the pairs, and returns the remaining text.
// Groups are peeled from the end so that free text containing brackets
// (CONFIG messages quote their own provenance) keeps its prefix.
func (r *Record) consumeContext(body string) string {
	text := strings.TrimRight(body, " ")
	var groups []string
	for {
		start, inner, ok := lastGroup(text)
		if !ok || !looksLikeContext(inner) {
			break
		}
		groups = append(groups, inner)
		text = strings.TrimRight(text[:start], " ")
	}
	// Apply outermost-last so that the right-most group wins on duplicate
	// keys, matching how the formatter appends its own suffix last.
	for i := len(groups) - 1; i >= 0; i-- {
		r.applyGroup(groups[i])
	}
	return text
}

// applyGroup records the key:value pairs of one bracket group. Keys whose
// values are free text (reason, msg, cmd) swallow the rest of the group,
// because the formatter does not escape them.
func (r *Record) applyGroup(inner string) {
	rest := strings.TrimSpace(inner)
	for rest != "" {
		key, value, ok := strings.Cut(rest, ":")
		if !ok || key == "" || strings.ContainsAny(key, " ") {
			return
		}
		key = unescapeContext(key)
		if freeTextKeys[key] {
			r.setContext(key, value)
			return
		}
		value, rest, _ = strings.Cut(value, " ")
		rest = strings.TrimLeft(rest, " ")
		r.setContext(key, unescapeContext(value))
	}
}

var freeTextKeys = map[string]bool{"reason": true, "msg": true, "cmd": true}

func (r *Record) setContext(key, value string) {
	if r.Context == nil {
		r.Context = make(map[string]string)
	}
	r.Context[key] = value
	switch key {
	case "policy":
		r.Policy = value
	case "engine":
		r.Engine = value
	case "reason":
		r.Reason = value
	case "msg":
		r.Message = value
	}
}

// takeAction consumes a leading action label.
func (r *Record) takeAction(text string) string {
	word, rest, _ := strings.Cut(text, " ")
	if actions[word] {
		r.Action = word
		return strings.TrimSpace(rest)
	}
	return text
}

var actorPattern = regexp.MustCompile(`^(.+)\((-?\d+)\)$`)

// setActor parses "name(pid)"; it reports false when s is not an actor.
func (r *Record) setActor(s string) bool {
	m := actorPattern.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return false
	}
	r.Binary = m[1]
	if pid, err := strconv.Atoi(m[2]); err == nil {
		r.PID, r.HasPID = pid, true
	}
	return true
}

// setDestination parses "host[:port][/proto]". Bare IPv6 addresses are
// ambiguous with a port suffix; the last colon is taken as the port
// separator only when what precedes it is itself a valid IP.
func (r *Record) setDestination(s string) {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '/'); i > 0 && !strings.Contains(s[i:], ":") {
		r.Protocol = s[i+1:]
		s = s[:i]
	}
	host, port := s, ""
	switch {
	case strings.HasPrefix(s, "["):
		if h, p, err := net.SplitHostPort(s); err == nil {
			host, port = h, p
		}
	case strings.Count(s, ":") == 1:
		host, port, _ = strings.Cut(s, ":")
	case strings.Count(s, ":") > 1:
		if i := strings.LastIndexByte(s, ':'); i > 0 && net.ParseIP(s[:i]) != nil && isDigits(s[i+1:]) {
			host, port = s[:i], s[i+1:]
		}
	}
	r.Host = host
	if n, err := strconv.Atoi(port); err == nil && n >= 0 && n <= 65535 {
		r.Port = n
	}
}

func (r *Record) setURL(raw string) {
	if raw == "" {
		return
	}
	r.URL = raw
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		r.Path = raw
		return
	}
	r.Host = u.Hostname()
	r.Path = u.EscapedPath()
	if u.RawQuery != "" {
		r.Path += "?" + u.RawQuery
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			r.Port = n
		}
	} else {
		switch strings.ToLower(u.Scheme) {
		case "http", "ws":
			r.Port = 80
		case "https", "wss":
			r.Port = 443
		}
	}
}

// lastGroup finds the bracket group that closes text. It returns the index
// of its opening bracket and its inner text. Escaped brackets (\[ \]) do
// not count, and nested unescaped brackets (reason text is not escaped) are
// balanced.
func lastGroup(text string) (int, string, bool) {
	if !strings.HasSuffix(text, "]") || escaped(text, len(text)-1) {
		return 0, "", false
	}
	depth := 0
	for i := len(text) - 1; i >= 0; i-- {
		switch text[i] {
		case ']':
			if !escaped(text, i) {
				depth++
			}
		case '[':
			if escaped(text, i) {
				continue
			}
			depth--
			if depth == 0 {
				if i > 0 && text[i-1] != ' ' {
					return 0, "", false
				}
				return i, text[i+1 : len(text)-1], true
			}
		}
	}
	return 0, "", false
}

func escaped(s string, i int) bool {
	n := 0
	for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
		n++
	}
	return n%2 == 1
}

// looksLikeContext reports whether a group's first token is key:value.
func looksLikeContext(inner string) bool {
	first, _, _ := strings.Cut(strings.TrimSpace(inner), " ")
	key, _, ok := strings.Cut(first, ":")
	return ok && key != ""
}

// unescapeContext reverses the formatter's context escaping: \\ \[ \] and
// \u{hex}.
func unescapeContext(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		next := s[i+1]
		switch next {
		case '\\', '[', ']', '"':
			b.WriteByte(next)
			i++
		case 'n':
			b.WriteByte('\n')
			i++
		case 'r':
			b.WriteByte('\r')
			i++
		case 't':
			b.WriteByte('\t')
			i++
		case 'u':
			if end := strings.IndexByte(s[i:], '}'); strings.HasPrefix(s[i:], `\u{`) && end > 3 {
				if cp, err := strconv.ParseUint(s[i+3:i+end], 16, 32); err == nil {
					b.WriteRune(rune(cp))
					i += end
					continue
				}
			}
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// unquote reads a formatter-quoted title ("…" with \" \\ \n escapes).
func unquote(s string) (string, bool) {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' || escaped(s, len(s)-1) {
		return "", false
	}
	return unescapeContext(s[1 : len(s)-1]), true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
