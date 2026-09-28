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

package hookexec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// Cursor has no managed-hooks-only setting: it runs every matching hook from
// the enterprise, user, project and Claude-format sources and merges their
// responses, and preToolUse responses may replace the tool input. To keep the
// input DefenseClaw inspects identical to the input that runs, the managed
// hook allows tool calls only while every user- and project-level preToolUse
// handler is DefenseClaw's own managed registration or approved by the
// administrator.

const (
	// foreignHookFileLimit bounds every user or project hook file the guard
	// reads. Larger files cannot be verified and deny.
	foreignHookFileLimit int64 = 1 << 20
	// foreignHookMaxRoots bounds the distinct workspace roots taken from the
	// payload. A payload that reports more cannot be verified and denies.
	foreignHookMaxRoots = 32
	// foreignHookCacheLimit bounds the in-process parse cache.
	foreignHookCacheLimit = 64
	// foreignHookDescribeLimit bounds the handler text shown in a denial.
	foreignHookDescribeLimit = 200

	foreignHookScopeUser    = "user"
	foreignHookScopeProject = "project"

	foreignHookFormatCursor = "cursor"      // {"hooks":{event:[handler]}}
	foreignHookFormatClaude = "claude-code" // {"hooks":{event:[{matcher,hooks:[handler]}]}}

	foreignHookBlockedReason = "enterprise_foreign_hook_blocked"
)

// foreignHookGatedEvents are the events whose foreign handlers can change what
// runs: preToolUse may return updated_input (updatedInput in the Claude
// format). Permission-only and observational events cannot change what runs.
var foreignHookGatedEvents = [...]string{"preToolUse"}

// foreignHookFinding is one input-rewriting handler (or an unverifiable file)
// found outside the administrator-managed hook source.
type foreignHookFinding struct {
	Scope string
	// Path is the hook file. It is empty for a problem with the workspace
	// roots in the payload.
	Path   string
	Event  string
	Digest string
	// Handler describes what the handler runs, for the user-facing denial.
	Handler string
	Problem string
}

type foreignHookSource struct {
	scope  string
	path   string
	format string
}

type foreignHookParsedHandler struct {
	event string
	// entry is the registration the approval digest covers: the Cursor
	// handler object, or the Claude-format matcher group reduced to this one
	// handler so the matcher is covered too.
	entry   map[string]interface{}
	handler map[string]interface{}
}

type foreignHookParseResult struct {
	handlers []foreignHookParsedHandler
	problem  string
}

// foreignHookParseCache memoizes parse results by source format and content
// sha256 so repeated sources (for example the same file reached through two
// workspace roots, or a long-lived caller) are parsed once. It never caches a
// verdict for a path: every call re-reads and re-hashes the current bytes, and
// the allowlist and ownership checks run on every lookup.
var foreignHookParseCache = struct {
	sync.Mutex
	entries map[string]foreignHookParseResult
}{entries: map[string]foreignHookParseResult{}}

// cursorForeignHookGuardApplies reports whether this invocation is the managed
// Cursor preToolUse gate.
func cursorForeignHookGuardApplies(opts Options) bool {
	return opts.ManagedEnterprise &&
		strings.EqualFold(strings.TrimSpace(opts.Connector), "cursor") &&
		strings.EqualFold(strings.TrimSpace(opts.Event), "preToolUse")
}

// evaluateCursorForeignHooks returns the unapproved findings for this
// invocation. The payload supplies Cursor's workspace roots.
func evaluateCursorForeignHooks(opts Options, payload []byte) []foreignHookFinding {
	approved := make(map[string]struct{}, len(opts.ApprovedForeignHooks))
	for _, digest := range opts.ApprovedForeignHooks {
		value := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(digest)), "sha256:")
		if value != "" {
			approved[value] = struct{}{}
		}
	}
	var blocking []foreignHookFinding
	for _, finding := range scanCursorForeignHooks(opts, payload) {
		if finding.Problem == "" {
			if _, ok := approved[finding.Digest]; ok {
				continue
			}
		}
		blocking = append(blocking, finding)
	}
	return blocking
}

func scanCursorForeignHooks(opts Options, payload []byte) []foreignHookFinding {
	sources, findings := cursorForeignHookSources(opts, payload)
	for _, source := range sources {
		result := readForeignHookSource(source)
		if result.problem != "" {
			findings = append(findings, foreignHookFinding{
				Scope:   source.scope,
				Path:    source.path,
				Problem: result.problem,
			})
			continue
		}
		for _, handler := range result.handlers {
			if foreignHookHandlerOwned(handler.handler, opts.ForeignHookTrustedExecutable) {
				continue
			}
			digest, err := foreignHookApprovalDigest(source.scope, handler.event, handler.entry)
			if err != nil {
				findings = append(findings, foreignHookFinding{
					Scope:   source.scope,
					Path:    source.path,
					Problem: "cannot fingerprint a hook handler: " + err.Error(),
				})
				continue
			}
			findings = append(findings, foreignHookFinding{
				Scope:   source.scope,
				Path:    source.path,
				Event:   handler.event,
				Digest:  digest,
				Handler: describeForeignHookHandler(handler.handler),
			})
		}
	}
	return findings
}

// cursorForeignHookSources lists the hook sources to scan and the problems
// that already make this invocation unverifiable.
func cursorForeignHookSources(opts Options, payload []byte) ([]foreignHookSource, []foreignHookFinding) {
	var sources []foreignHookSource
	var problems []foreignHookFinding
	seen := map[string]struct{}{}
	add := func(scope, format string, parts ...string) {
		path := filepath.Clean(filepath.Join(parts...))
		key := foreignHookPathKey(path)
		if _, duplicate := seen[key]; duplicate {
			return
		}
		seen[key] = struct{}{}
		sources = append(sources, foreignHookSource{scope: scope, path: path, format: format})
	}
	homes := append([]string(nil), opts.ForeignHookHomes...)
	if len(homes) == 0 {
		if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
			homes = []string{home}
		}
	}
	if profile := strings.TrimSpace(opts.ForeignHookProfileHome); profile != "" {
		homes = append(homes, profile)
	}
	for _, home := range homes {
		if !filepath.IsAbs(home) {
			continue
		}
		add(foreignHookScopeUser, foreignHookFormatCursor, home, ".cursor", "hooks.json")
		add(foreignHookScopeUser, foreignHookFormatClaude, home, ".claude", "settings.json")
		add(foreignHookScopeUser, foreignHookFormatClaude, home, ".claude", "settings.local.json")
	}
	if dir := strings.TrimSpace(opts.getenv("CLAUDE_CONFIG_DIR")); dir != "" && filepath.IsAbs(dir) {
		add(foreignHookScopeUser, foreignHookFormatClaude, dir, "settings.json")
		add(foreignHookScopeUser, foreignHookFormatClaude, dir, "settings.local.json")
	}
	roots, rootProblem := cursorPayloadWorkspaceRoots(payload)
	if rootProblem != "" {
		problems = append(problems, foreignHookFinding{Scope: foreignHookScopeProject, Problem: rootProblem})
	}
	for _, root := range roots {
		add(foreignHookScopeProject, foreignHookFormatCursor, root, ".cursor", "hooks.json")
		add(foreignHookScopeProject, foreignHookFormatClaude, root, ".claude", "settings.json")
		add(foreignHookScopeProject, foreignHookFormatClaude, root, ".claude", "settings.local.json")
	}
	return sources, problems
}

func (o Options) getenv(key string) string {
	if o.Getenv != nil {
		return o.Getenv(key)
	}
	return os.Getenv(key)
}

// cursorPayloadWorkspaceRoots returns the distinct absolute workspace roots
// Cursor reports for this invocation (workspace_roots plus cwd when
// present). A payload whose roots cannot all be resolved to local absolute
// paths, or that reports more than foreignHookMaxRoots distinct roots,
// returns a problem so the guard denies instead of scanning a subset.
func cursorPayloadWorkspaceRoots(payload []byte) ([]string, string) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, "the hook payload is not a JSON object"
	}
	var raw []json.RawMessage
	if value, ok := envelope["workspace_roots"]; ok && !isJSONNull(value) {
		if err := json.Unmarshal(value, &raw); err != nil {
			return nil, "workspace_roots is not an array"
		}
	}
	if value, ok := envelope["cwd"]; ok && !isJSONNull(value) {
		raw = append(raw, value)
	}
	var roots []string
	seen := map[string]struct{}{}
	for _, item := range raw {
		var value string
		if err := json.Unmarshal(item, &value); err != nil {
			return nil, "a workspace root is not a string"
		}
		if strings.TrimSpace(value) == "" {
			continue
		}
		root, ok := normalizeCursorWorkspaceRoot(value)
		if !ok {
			return nil, fmt.Sprintf("the workspace folder %s is not a local absolute path", quoteForeignHookText(value))
		}
		key := foreignHookPathKey(root)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		if len(roots) == foreignHookMaxRoots {
			return nil, fmt.Sprintf("the workspace has more than %d folders", foreignHookMaxRoots)
		}
		seen[key] = struct{}{}
		roots = append(roots, root)
	}
	return roots, ""
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func normalizeCursorWorkspaceRoot(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsRune(value, 0) {
		return "", false
	}
	if strings.HasPrefix(strings.ToLower(value), "file://") {
		parsed, err := url.Parse(value)
		if err != nil {
			return "", false
		}
		value = parsed.Path
		if parsed.Host != "" && !strings.EqualFold(parsed.Host, "localhost") {
			// file://server/share/path names a UNC path, which only Windows
			// opens directly.
			if runtime.GOOS != "windows" || parsed.Port() != "" || strings.Trim(parsed.Path, `/\`) == "" {
				return "", false
			}
			value = `\\` + parsed.Host + filepath.FromSlash(parsed.Path)
		}
	}
	// Cursor on Windows can report URI-style paths such as /c:/Users/x.
	if len(value) >= 3 && (value[0] == '/' || value[0] == '\\') && isDriveLetter(value[1]) && value[2] == ':' {
		value = value[1:]
	}
	value = filepath.Clean(filepath.FromSlash(value))
	if !filepath.IsAbs(value) {
		return "", false
	}
	return value, true
}

func isDriveLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func readForeignHookSource(source foreignHookSource) foreignHookParseResult {
	data, exists, err := readForeignHookFile(source.path)
	if err != nil {
		return foreignHookParseResult{problem: err.Error()}
	}
	if !exists || len(bytes.TrimSpace(data)) == 0 {
		return foreignHookParseResult{}
	}
	sum := sha256.Sum256(data)
	key := source.format + ":" + hex.EncodeToString(sum[:])
	foreignHookParseCache.Lock()
	cached, ok := foreignHookParseCache.entries[key]
	foreignHookParseCache.Unlock()
	if ok {
		return cached
	}
	result := parseForeignHookDocument(source.format, data)
	foreignHookParseCache.Lock()
	if len(foreignHookParseCache.entries) >= foreignHookCacheLimit {
		foreignHookParseCache.entries = map[string]foreignHookParseResult{}
	}
	foreignHookParseCache.entries[key] = result
	foreignHookParseCache.Unlock()
	return result
}

// readForeignHookFile reads a user- or project-owned hook file without
// following a final symbolic link or reparse point and without reading more
// than foreignHookFileLimit bytes. Anything that cannot be read as a bounded
// regular file is reported as an error so the caller fails closed.
func readForeignHookFile(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, fmt.Errorf("cannot inspect the file: %v", err)
	}
	if info.IsDir() {
		// A directory is not a loadable hook file.
		return nil, false, nil
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, true, errors.New("the file is a link or not a regular file")
	}
	if info.Size() > foreignHookFileLimit {
		return nil, true, fmt.Errorf("the file exceeds %d bytes", foreignHookFileLimit)
	}
	file, err := openForeignHookFileNoFollow(path)
	if err != nil {
		return nil, true, fmt.Errorf("cannot open the file: %v", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, true, errors.New("the file changed while it was inspected")
	}
	data, err := io.ReadAll(io.LimitReader(file, foreignHookFileLimit+1))
	if err != nil {
		return nil, true, fmt.Errorf("cannot read the file: %v", err)
	}
	if int64(len(data)) > foreignHookFileLimit {
		return nil, true, fmt.Errorf("the file exceeds %d bytes", foreignHookFileLimit)
	}
	return data, true, nil
}

// decodeForeignHookJSONObject decodes one JSON document, rejecting trailing
// data. A JSON null yields an empty (nil) object.
func decodeForeignHookJSONObject(data []byte) (map[string]interface{}, string) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var document map[string]interface{}
	if err := decoder.Decode(&document); err != nil {
		return nil, "the file is not valid JSON: " + err.Error()
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, "the file contains data after the JSON document"
	}
	return document, ""
}

// parseForeignHookDocument extracts the gated (preToolUse) handlers from a
// Cursor or Claude-format hook document.
func parseForeignHookDocument(format string, data []byte) foreignHookParseResult {
	document, problem := decodeForeignHookJSONObject(data)
	if problem != "" {
		return foreignHookParseResult{problem: problem}
	}
	return parseForeignHookContainer(format, document)
}

// parseForeignHookContainer reads the event map under container's hooks key.
func parseForeignHookContainer(format string, container map[string]interface{}) foreignHookParseResult {
	var result foreignHookParseResult
	rawHooks, exists := container["hooks"]
	if !exists || rawHooks == nil {
		return result
	}
	hooks, ok := rawHooks.(map[string]interface{})
	if !ok {
		return foreignHookParseResult{problem: "the hooks value is not an object"}
	}
	if problem := collectForeignHookEvents(format, hooks, &result); problem != "" {
		return foreignHookParseResult{problem: problem}
	}
	return result
}

func collectForeignHookEvents(format string, events map[string]interface{}, result *foreignHookParseResult) string {
	names := make([]string, 0, len(events))
	for event := range events {
		if _, gated := foreignHookGatedEvent(event); gated {
			names = append(names, event)
		}
	}
	sort.Strings(names)
	for _, event := range names {
		canonical, _ := foreignHookGatedEvent(event)
		entries, ok := events[event].([]interface{})
		if !ok {
			if events[event] == nil {
				continue
			}
			return fmt.Sprintf("the %s value is not an array", event)
		}
		for _, entry := range entries {
			handlers, problem := foreignHookEntryHandlers(format, entry)
			if problem != "" {
				return fmt.Sprintf("the %s entry %s", event, problem)
			}
			for _, handler := range handlers {
				handler.event = canonical
				result.handlers = append(result.handlers, handler)
			}
		}
	}
	return ""
}

// foreignHookGatedEvent returns the canonical name of a gated event. Event
// names are compared case-insensitively because Cursor maps the Claude-format
// PreToolUse name onto preToolUse.
func foreignHookGatedEvent(event string) (string, bool) {
	event = strings.TrimSpace(event)
	for _, gated := range foreignHookGatedEvents {
		if strings.EqualFold(event, gated) {
			return gated, true
		}
	}
	return "", false
}

func foreignHookEntryHandlers(format string, entry interface{}) ([]foreignHookParsedHandler, string) {
	object, ok := entry.(map[string]interface{})
	if !ok {
		return nil, "is not an object"
	}
	rawHandlers, grouped := object["hooks"]
	if format == foreignHookFormatCursor {
		return []foreignHookParsedHandler{{entry: object, handler: object}}, ""
	}
	if !grouped {
		// A matcher group without handlers runs nothing. Treat an object that
		// carries handler fields as a bare handler rather than assuming the
		// consumer ignores it.
		for _, key := range []string{"type", "command", "url", "prompt"} {
			if _, ok := object[key]; ok {
				return []foreignHookParsedHandler{{entry: object, handler: object}}, ""
			}
		}
		return nil, ""
	}
	list, ok := rawHandlers.([]interface{})
	if !ok {
		return nil, "has a hooks value that is not an array"
	}
	handlers := make([]foreignHookParsedHandler, 0, len(list))
	for _, raw := range list {
		handler, ok := raw.(map[string]interface{})
		if !ok {
			return nil, "has a handler that is not an object"
		}
		group := make(map[string]interface{}, len(object))
		for key, value := range object {
			if key != "hooks" {
				group[key] = value
			}
		}
		group["hooks"] = []interface{}{handler}
		handlers = append(handlers, foreignHookParsedHandler{entry: group, handler: handler})
	}
	return handlers, ""
}

// foreignHookApprovalDigest is the sha256 of the canonical JSON (sorted keys,
// original number literals, no HTML escaping) of the handler's registration
// together with its event and scope. Binding the event, scope and (for the
// Claude format) matcher means approving a handler in a user file does not
// approve the same text in a cloned project, and approving it for one event
// or matcher does not approve it for another. Administrators approve
// a handler by adding the digest the denial prints to the allowlist.
func foreignHookApprovalDigest(scope, event string, entry map[string]interface{}) (string, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(map[string]interface{}{"entry": entry, "event": event, "scope": scope}); err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes.TrimSuffix(buffer.Bytes(), []byte("\n")))
	return hex.EncodeToString(sum[:]), nil
}

// describeForeignHookHandler names what a handler runs (its command and
// arguments, URL or prompt), quoted and bounded, so whoever reviews the
// approval sees what it covers.
func describeForeignHookHandler(handler map[string]interface{}) string {
	for _, key := range []string{"command", "url", "prompt"} {
		value, ok := handler[key].(string)
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		if key == "command" {
			if args, ok := handler["args"].([]interface{}); ok {
				for _, arg := range args {
					if text, ok := arg.(string); ok {
						value += " " + text
					}
				}
			}
		}
		return key + " " + quoteForeignHookText(value)
	}
	return ""
}

func quoteForeignHookText(value string) string {
	if len(value) <= foreignHookDescribeLimit {
		return strconv.Quote(value)
	}
	cut := foreignHookDescribeLimit
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return strconv.Quote(value[:cut]) + "..."
}

// foreignHookHandlerOwned accepts only an exact managed DefenseClaw
// registration (--enterprise-managed) of the administrator-owned hook
// executable that runs this guard. The managed path takes its gateway and
// credentials from protected machine state and verifies the gateway before
// sending a request. Without --enterprise-managed the same executable follows
// per-user configuration, so its output is treated like any other user hook.
// Registrations that point at per-user scripts are user-owned code and remain
// foreign.
func foreignHookHandlerOwned(handler map[string]interface{}, trustedExecutable string) bool {
	trustedExecutable = strings.TrimSpace(trustedExecutable)
	if trustedExecutable == "" || !filepath.IsAbs(trustedExecutable) {
		return false
	}
	if kind, exists := handler["type"]; exists {
		if value, ok := kind.(string); !ok || value != "command" {
			return false
		}
	}
	command, ok := handler["command"].(string)
	if !ok {
		return false
	}
	if rawArgs, exists := handler["args"]; exists {
		list, ok := rawArgs.([]interface{})
		if !ok {
			return false
		}
		args := make([]string, 0, len(list))
		for _, raw := range list {
			value, ok := raw.(string)
			if !ok {
				return false
			}
			args = append(args, value)
		}
		return sameForeignHookExecutable(command, trustedExecutable) && ownedForeignHookArgs(args)
	}
	prefixes := []string{`"` + trustedExecutable + `" `}
	if !strings.ContainsAny(trustedExecutable, " \t") {
		// An unquoted path is unambiguous only when it has no whitespace.
		prefixes = append(prefixes, trustedExecutable+" ")
	}
	for _, prefix := range prefixes {
		if len(command) <= len(prefix) || foreignHookPathKey(command[:len(prefix)]) != foreignHookPathKey(prefix) {
			continue
		}
		return ownedForeignHookArgs(strings.Split(command[len(prefix):], " "))
	}
	return false
}

func sameForeignHookExecutable(command, trustedExecutable string) bool {
	command = strings.TrimSpace(command)
	if !filepath.IsAbs(command) {
		return false
	}
	return foreignHookPathKey(filepath.Clean(command)) == foreignHookPathKey(filepath.Clean(trustedExecutable))
}

// foreignHookPathKey folds case only where the platform's paths are
// case-insensitive.
func foreignHookPathKey(path string) string {
	if runtime.GOOS == "windows" {
		return strings.ToLower(path)
	}
	return path
}

func ownedForeignHookArgs(args []string) bool {
	if len(args) != 4 {
		return false
	}
	return args[0] == "hook" &&
		args[1] == "--connector" &&
		foreignHookConnectorToken(args[2]) &&
		args[3] == "--enterprise-managed"
}

func foreignHookConnectorToken(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func (f foreignHookFinding) subject() string {
	if f.Path == "" {
		return "the workspace folders Cursor reported"
	}
	return fmt.Sprintf("the %s-level hook file %s", f.Scope, f.Path)
}

// cursorForeignHookDenyMessage names the first blocking file so the user or
// administrator can act on it without reading logs. describeHandler adds what
// the unapproved handler runs.
func cursorForeignHookDenyMessage(findings []foreignHookFinding, describeHandler bool) string {
	first := findings[0]
	more := ""
	if len(findings) > 1 {
		more = fmt.Sprintf(" (%d more unapproved hook entries found)", len(findings)-1)
	}
	if first.Problem != "" {
		action := "Fix or remove the file so DefenseClaw can check the hooks it registers."
		if first.Path == "" {
			action = fmt.Sprintf(
				"Open local folders, at most %d in one workspace, so DefenseClaw can check their hooks.",
				foreignHookMaxRoots,
			)
		}
		return fmt.Sprintf(
			"DefenseClaw blocked this tool call: %s cannot be verified (%s)%s. %s",
			first.subject(), first.Problem, more, action,
		)
	}
	runs := ""
	if describeHandler && first.Handler != "" {
		runs = " that runs " + first.Handler
	}
	return fmt.Sprintf(
		"DefenseClaw blocked this tool call: %s registers a %s hook%s "+
			"(sha256:%s) that the administrator has not approved%s. Remove it, or ask "+
			"your administrator to approve it in connector_hooks.cursor.approved_foreign_hooks.",
		first.subject(), first.Event, runs, first.Digest, more,
	)
}

// denyCursorForeignHooks emits Cursor's preToolUse deny response. The user
// message shows what the unapproved handler runs; the agent message leaves it
// out so a command line from the user's files is not sent to the model.
func denyCursorForeignHooks(opts Options, sp spec, findings []foreignHookFinding) int {
	userMessage := cursorForeignHookDenyMessage(findings, true)
	agentMessage := cursorForeignHookDenyMessage(findings, false)
	logHookFailure(opts, sp, foreignHookBlockedReason+": "+userMessage, "policy", "closed")
	fmt.Fprintf(opts.Stderr, "defenseclaw: %s\n", userMessage)
	fmt.Fprintln(opts.Stdout,
		`{"permission":"deny","user_message":`+mustJSONString(userMessage)+
			`,"agent_message":`+mustJSONString(agentMessage)+`}`)
	return 0
}
