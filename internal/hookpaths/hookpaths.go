// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package hookpaths resolves tool write targets in the invoking user's process.
package hookpaths

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"mvdan.cc/sh/v3/syntax"
)

const Header = "X-DefenseClaw-Resolved-Writes"

// CWDKey carries the hook process's cwd for a gateway whose ProtectHome
// prevents it from validating that directory locally.
const CWDKey = "\x00cwd"

// TruncatedKey means at least one static write target could not fit in the
// bounded evidence. The gateway must not treat the remaining map as complete.
const TruncatedKey = "\x00truncated"

// maxWriteTargetLinkDepth matches the Linux kernel limit (MAXSYMLINKS) for
// one path resolution. Every followed link counts, also in parent components,
// so a link loop ends here and reports an unresolvable target.
const maxWriteTargetLinkDepth = 40

// MaxWriteTargets bounds the distinct write operands one request carries,
// far above any realistic command. Resolve and Decode share it, so the native
// hook runner and the shell hooks (hook resolve-writes) send, and the gateway
// accepts, the same bound for every connector.
const MaxWriteTargets = 512

// MaxWriteTargetPathBytes bounds one operand. A longer operand is omitted and
// the map is marked truncated.
const MaxWriteTargetPathBytes = 1024

// maxEncodedTargets bounds the JSON map. MaxHeaderValueBytes is its unpadded
// base64 size plus slack; it stays well inside one argv string for curl -H in
// the shell hooks (128 KiB on Linux).
const (
	maxEncodedTargets   = 64 << 10
	MaxHeaderValueBytes = 88 << 10
)

// maxShellOperandCommandBytes is the bound for walking the shell syntax of a
// command, the same on the hook client and in the gateway.
const maxShellOperandCommandBytes = 64 << 10

// ShellWriteOperands lists the literal file operands of the output
// redirects in a POSIX command as absolute, cleaned paths. The hook client
// and the gateway both use it, so a client-resolved operand has the key the
// gateway looks up. ok is false when the command is too long or does not
// parse; its operands are then unknown.
func ShellWriteOperands(command, cwd, home string) (operands []string, ok bool) {
	if len(command) > maxShellOperandCommandBytes {
		return nil, false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(command), "")
	if err != nil {
		return nil, false
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		redirect, isRedirect := node.(*syntax.Redirect)
		if !isRedirect || redirect.Word == nil {
			return true
		}
		switch redirect.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
		default:
			return true
		}
		start, end := int(redirect.Word.Pos().Offset()), int(redirect.Word.End().Offset())
		if start < 0 || end > len(command) || end <= start {
			return true
		}
		name := strings.Trim(command[start:end], "\"\x27")
		if name == "" || strings.ContainsAny(name, "*?[]`") ||
			strings.Contains(name, "$") && !strings.HasPrefix(name, "$HOME/") {
			return true
		}
		if strings.HasPrefix(name, "~/") || strings.HasPrefix(name, "$HOME/") {
			name = strings.TrimRight(home, "/") + name[strings.IndexByte(name, '/'):]
		}
		if !filepath.IsAbs(name) && filepath.IsAbs(cwd) {
			name = filepath.Join(cwd, name)
		}
		operands = append(operands, filepath.Clean(name))
		return true
	})
	return operands, true
}

// resolveWritePath follows existing links, including a link whose final file
// does not exist yet. A shell redirect can create that final file. Resolve
// the parent separately so links in directory components are covered too.
func resolveWritePath(path string, linkDepth int) (string, bool) {
	if linkDepth > maxWriteTargetLinkDepth || !filepath.IsAbs(path) {
		return "", false
	}
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	if err != nil && !os.IsNotExist(err) {
		return "", false
	}
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		link, err := os.Readlink(path)
		if err != nil {
			return "", false
		}
		if !filepath.IsAbs(link) {
			link = filepath.Join(filepath.Dir(path), link)
		}
		return resolveWritePath(link, linkDepth+1)
	}
	parent := filepath.Dir(path)
	if parent == path {
		return path, true
	}
	resolvedParent, ok := resolveWritePath(parent, linkDepth)
	if !ok {
		return "", false
	}
	return filepath.Join(resolvedParent, filepath.Base(path)), true
}

// protectedFile is the identity of the user's authorized_keys file. A hard
// link elsewhere names the same file under another path, so a target is
// compared by file identity (device and inode on Unix, volume serial and file
// index on Windows) and not by pathname alone.
type protectedFile struct {
	path    string
	info    os.FileInfo
	unknown bool
}

func newProtectedFile(home string) protectedFile {
	protected := protectedFile{path: filepath.Join(home, ".ssh", "authorized_keys")}
	info, err := os.Stat(protected.path)
	switch {
	case err == nil:
		protected.info = info
	case !os.IsNotExist(err):
		protected.unknown = true
	}
	return protected
}

// target maps a resolved write target to the protected path when both name
// the same file. When the protected file cannot be identified, a multiply
// linked target may be an alias of it and is reported as unresolvable.
func (p protectedFile) target(resolved string) (string, bool) {
	if p.info == nil && !p.unknown {
		return resolved, true
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return resolved, true
	}
	if p.info != nil {
		if os.SameFile(info, p.info) {
			return p.path, true
		}
		return resolved, true
	}
	if linkCount(resolved, info) > 1 {
		return "", false
	}
	return resolved, true
}

// Resolve returns a bounded, header-safe map from absolute write operands to
// their filesystem targets. An empty value means resolution was attempted but
// could not be trusted. A regular file maps to itself, unless it is a hard
// link to the user's authorized_keys file. An operand is never dropped
// silently: when one cannot be listed (over a bound, or the command exceeds
// the shell analysis limits) the map carries TruncatedKey.
func Resolve(payload []byte) string {
	var envelope map[string]json.RawMessage
	if len(payload) > 1<<20 || json.Unmarshal(payload, &envelope) != nil {
		return ""
	}
	field := func(names ...string) json.RawMessage {
		for _, name := range names {
			if value := envelope[name]; len(value) != 0 {
				return value
			}
		}
		return nil
	}
	var tool string
	_ = json.Unmarshal(field("tool_name", "toolName"), &tool)
	args := field("tool_input", "toolInput", "tool_args", "toolArgs", "args", "arguments")
	if len(args) == 0 {
		return ""
	}
	// The gateway names relative operands from the event cwd; use the same
	// directory so both sides build the same keys.
	var cwd string
	_ = json.Unmarshal(field("cwd"), &cwd)
	if !filepath.IsAbs(cwd) {
		var err error
		if cwd, err = os.Getwd(); err != nil {
			return incompleteEvidence("")
		}
	}
	cwd = filepath.Clean(cwd)
	home, err := os.UserHomeDir()
	if err != nil {
		return incompleteEvidence(cwd)
	}
	input := actionfacts.Input{Tool: tool, Args: args, CWD: cwd, ActiveHome: home}
	facts := actionfacts.Analyze(input)
	// A connector can name the shell text "cmd" while ActionFacts requires
	// its canonical command field. Resolve that exact string as a shell too.
	truncated := facts.Parse.Status == actionfacts.StatusLimitExceeded
	var operands []string
	var toolArgs map[string]json.RawMessage
	if json.Unmarshal(args, &toolArgs) == nil {
		for _, key := range []string{"command", "cmd"} {
			var command string
			if json.Unmarshal(toolArgs[key], &command) == nil && command != "" {
				fallback := input
				fallback.Tool, fallback.Args, fallback.Command = "Bash", nil, command
				fallbackFacts := actionfacts.Analyze(fallback)
				facts.Paths = append(facts.Paths, fallbackFacts.Paths...)
				truncated = truncated || fallbackFacts.Parse.Status == actionfacts.StatusLimitExceeded
				// A command over the analysis limits has no path facts, but
				// the gateway still checks each literal redirect operand.
				var parsed bool
				operands, parsed = ShellWriteOperands(command, cwd, home)
				truncated = truncated || !parsed
				break
			}
		}
	}
	targets := map[string]string{CWDKey: cwd}
	// The fixed part counts the truncation marker, so setting it never
	// exceeds the budget.
	protected := newProtectedFile(home)
	size := 2 + len(jsonString(CWDKey)) + 1 + len(jsonString(cwd)) + 1 + len(jsonString(TruncatedKey)) + 1 + 3
	add := func(path string) {
		if path == "" || strings.ContainsAny(path, "*?[]$`") || strings.HasPrefix(path, "~") {
			return
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(cwd, path)
		}
		path = filepath.Clean(path)
		if _, present := targets[path]; present {
			return
		}
		if len(path) > MaxWriteTargetPathBytes || len(targets)-1 >= MaxWriteTargets {
			truncated = true
			return
		}
		resolved, ok := resolveWritePath(path, 0)
		if ok {
			resolved, ok = protected.target(resolved)
		}
		if !ok {
			resolved = ""
		}
		entry := len(jsonString(path)) + 1 + len(jsonString(resolved)) + 1
		if size+entry > maxEncodedTargets {
			truncated = true
			return
		}
		size += entry
		targets[path] = resolved
	}
	for _, candidate := range facts.Paths {
		if candidate.Access != actionfacts.PathAccessWrite && candidate.Access != actionfacts.PathAccessAppend {
			continue
		}
		path := candidate.Resolved
		if path == "" {
			path = candidate.Normalized
		}
		add(path)
	}
	for _, operand := range operands {
		add(operand)
	}
	if truncated {
		targets[TruncatedKey] = "1"
	}
	encoded, err := json.Marshal(targets)
	if err != nil || len(encoded) > maxEncodedTargets {
		return incompleteEvidence(cwd)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

// incompleteEvidence is the header for a tool call whose write operands
// could not be listed. The gateway must not treat it as complete.
func incompleteEvidence(cwd string) string {
	targets := map[string]string{TruncatedKey: "1"}
	if cwd != "" && len(cwd) <= MaxWriteTargetPathBytes {
		targets[CWDKey] = cwd
	}
	encoded, err := json.Marshal(targets)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func jsonString(value string) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

// Decode accepts only the bounded client evidence format.
func Decode(value string) (map[string]string, bool) {
	if value == "" || len(value) > MaxHeaderValueBytes {
		return nil, false
	}
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, false
	}
	var targets map[string]string
	if json.Unmarshal(data, &targets) != nil || len(targets) > MaxWriteTargets+2 ||
		(targets[TruncatedKey] != "" && targets[TruncatedKey] != "1") {
		return nil, false
	}
	return targets, true
}
