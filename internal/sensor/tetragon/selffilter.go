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

package tetragon

import (
	"path"
	"regexp"
	"strings"
	"time"

	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"
)

// The self-filter reduces hook noise without creating a blind spot.
//
// A DefenseClaw hook runs for every tool call an agent makes, and the shell
// hooks of a per-user install start 15-16 processes each: left alone they
// are most of the exec volume under an agent. So a hook the helper can
// verify is forwarded once (its exec and exit, the join anchor for the
// gateway) and its own tool processes are summarized as a count on its
// exit. A process is a verified hook only when all of these hold:
//
//   - its exec is the exact rendered hook command: the root-owned native
//     hook (BinDir/defenseclaw-hook hook --connector C --enterprise-managed
//     [--event E] [--hook-contract N]) or a hook script under an enrolled
//     home's .defenseclaw/hooks/;
//   - it was launched by the agent root directly, or by the root's one
//     `sh -c '<that exact command>'` launcher, and the root is not itself a
//     shell nor running under a command shell (`sh -c ...` started by a
//     program, which is what a tool call is);
//   - its uid is the root's uid.
//
// Nothing is dropped by script path or name alone. Everything that fails a
// condition is forwarded as a normal event, and anything under a verified
// hook that is not one of the hook's own tools is forwarded marked
// hook_subtree_unexpected. The native hook starts no processes, so under it
// every child is unexpected. Missing ancestry fails the check: the bias is
// toward forwarding (noise), never toward hiding.

type role int

const (
	roleNone role = iota
	roleVerifiedHook
	roleHookTool
	roleUnexpected
)

// procInfo is what the mapper remembers about a process.
type procInfo struct {
	execID       string
	parentExecID string
	pid          int
	binary       string
	// args are Tetragon's raw rendered arguments; never forwarded.
	args     string
	uid      int
	uidKnown bool
	role     role
	// script marks a verified hook script (whose own tools are summarized).
	script bool
	// argv is a verified hook's validated argument vector.
	argv []string
	// hook is the verified hook a tool or unexpected process is under.
	hook *procInfo
	// tools counts a verified hook's summarized tool processes.
	tools    int
	seenAt   time.Time
	exitedAt time.Time
}

func infoOf(process *pb.Process, at time.Time) *procInfo {
	info := &procInfo{
		execID:       process.GetExecId(),
		parentExecID: process.GetParentExecId(),
		pid:          int(process.GetPid().GetValue()),
		binary:       process.GetBinary(),
		args:         process.GetArguments(),
		seenAt:       at,
	}
	if uid := process.GetUid(); uid != nil {
		info.uid, info.uidKnown = int(uid.GetValue()), true
	}
	return info
}

func sameUID(a, b *procInfo) bool { return a.uidKnown && b.uidKnown && a.uid == b.uid }

// processTable is a bounded exec-id index.
type processTable struct {
	entries map[string]*procInfo
	puts    int
}

// tableLimit bounds the table; exited entries are kept briefly so a late
// child or exit still finds its parent.
const (
	tableLimit    = 32768
	exitRetention = time.Minute
)

func (t *processTable) get(execID string) *procInfo {
	if execID == "" {
		return nil
	}
	return t.entries[execID]
}

// put records a process and returns the entry the table keeps: a process
// reported again keeps what the filter already decided about it.
func (t *processTable) put(info *procInfo) *procInfo {
	if info.execID == "" {
		return info
	}
	if previous := t.entries[info.execID]; previous != nil && previous.role != roleNone {
		return previous
	}
	t.entries[info.execID] = info
	t.puts++
	if len(t.entries) > tableLimit || t.puts%4096 == 0 {
		t.sweep(info.seenAt)
	}
	return info
}

// sweep drops exited processes past their retention, then the oldest
// entries if the table is still over its bound.
func (t *processTable) sweep(now time.Time) {
	for id, info := range t.entries {
		if !info.exitedAt.IsZero() && now.Sub(info.exitedAt) > exitRetention {
			delete(t.entries, id)
		}
	}
	for len(t.entries) > tableLimit {
		var oldestID string
		var oldest time.Time
		for id, info := range t.entries {
			if oldestID == "" || info.seenAt.Before(oldest) {
				oldestID, oldest = id, info.seenAt
			}
		}
		delete(t.entries, oldestID)
	}
}

// hookTools are the programs the rendered hook scripts run themselves
// (internal/gateway/connector/hooks), only from the system directories.
var hookTools = map[string]bool{
	"jq": true, "curl": true, "python3": true, "mktemp": true, "id": true, "uname": true,
	"sed": true, "tail": true, "head": true, "cat": true, "rm": true, "date": true,
	"find": true, "chmod": true, "mkdir": true, "env": true, "realpath": true, "awk": true,
	"tr": true, "dirname": true, "cut": true, "openssl": true, "kill": true,
}

var systemBinDirs = map[string]bool{"/usr/bin": true, "/bin": true, "/usr/local/bin": true, "/usr/sbin": true, "/sbin": true}

func isHookTool(binary string) bool {
	return hookTools[path.Base(binary)] && systemBinDirs[path.Dir(binary)]
}

var shells = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "mksh": true, "ash": true, "fish": true}

func isShell(binary string) bool { return shells[path.Base(binary)] }

// hookToken is a connector, event or contract token of the native hook's
// command line (the shape internal/enterprisepolicy validates).
var hookToken = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)

// classify decides a newly exec'd process's role.
func (m *Mapper) classify(info *procInfo) {
	parent := m.table.get(info.parentExecID)
	if parent != nil {
		var hook *procInfo
		switch parent.role {
		case roleVerifiedHook:
			hook = parent
		case roleHookTool, roleUnexpected:
			hook = parent.hook
		}
		if hook != nil {
			info.hook = hook
			if parent.role != roleUnexpected && hook.script && isHookTool(info.binary) && sameUID(info, hook) {
				info.role = roleHookTool
				hook.tools++
			} else {
				info.role = roleUnexpected
			}
			return
		}
	}
	if argv, script, ok := m.verifiedHook(info, parent); ok {
		info.role, info.argv, info.script = roleVerifiedHook, argv, script
	}
}

// verifiedHook applies the three conditions.
func (m *Mapper) verifiedHook(info, parent *procInfo) ([]string, bool, bool) {
	argv, script, ok := m.hookShape(info)
	if !ok || parent == nil {
		return nil, false, false
	}
	root := parent
	if isShell(parent.binary) {
		command, ok := launcherCommand(parent.args)
		if !ok {
			return nil, false, false
		}
		words, ok := simpleWords(command)
		if !ok || !equalWords(words, argv) || !sameUID(parent, info) {
			return nil, false, false
		}
		root = m.table.get(parent.parentExecID)
		if root == nil {
			return nil, false, false
		}
	}
	if isShell(root.binary) || !sameUID(root, info) || m.underCommandShell(root) {
		return nil, false, false
	}
	return argv, script, true
}

// hookShape returns the argument vector of a rendered hook command, and
// whether it is a hook script.
func (m *Mapper) hookShape(info *procInfo) ([]string, bool, bool) {
	fields := strings.Fields(info.args)
	if info.binary == m.hookBinary {
		argv := append([]string{info.binary}, fields...)
		if !nativeHookArgs(fields) {
			return nil, false, false
		}
		return argv, false, true
	}
	for _, home := range m.config.Homes {
		dir := home + "/.defenseclaw/hooks/"
		name, ok := strings.CutPrefix(info.binary, dir)
		if !ok || name == "" || strings.Contains(name, "/") || !strings.HasSuffix(name, ".sh") {
			continue
		}
		// Tetragon reports a script exec as the script path, with the
		// interpreter's arguments (the script path first).
		if len(fields) > 0 && fields[0] == info.binary {
			fields = fields[1:]
		}
		for _, field := range fields {
			if !hookToken.MatchString(field) {
				return nil, false, false
			}
		}
		return append([]string{info.binary}, fields...), true, true
	}
	return nil, false, false
}

// nativeHookArgs accepts only `hook --connector C --enterprise-managed`,
// optionally followed by --event E and --hook-contract N, each once.
func nativeHookArgs(fields []string) bool {
	if len(fields) < 4 || fields[0] != "hook" || fields[1] != "--connector" || !hookToken.MatchString(fields[2]) ||
		fields[3] != "--enterprise-managed" {
		return false
	}
	seen := map[string]bool{}
	rest := fields[4:]
	for len(rest) > 0 {
		if len(rest) < 2 || seen[rest[0]] || !hookToken.MatchString(rest[1]) {
			return false
		}
		switch rest[0] {
		case "--event":
		case "--hook-contract":
			if strings.Trim(rest[1], "0123456789") != "" {
				return false
			}
		default:
			return false
		}
		seen[rest[0]] = true
		rest = rest[2:]
	}
	return true
}

// launcherCommand is the command of a `sh -c CMD` launcher from Tetragon's
// rendered arguments: option words containing c (-c, -lc, -cl, or -l
// before -c), then the command as the last argument. Tetragon wraps an
// argument that contains a space in double quotes and escapes nothing, so
// the command is everything after the options, unwrapped.
func launcherCommand(args string) (string, bool) {
	rest := strings.TrimLeft(args, " ")
	sawC := false
	for {
		word, tail, _ := strings.Cut(rest, " ")
		if !strings.HasPrefix(word, "-") || word == "-" || strings.HasPrefix(word, "--") {
			break
		}
		if strings.Trim(word[1:], "lc") != "" {
			return "", false
		}
		sawC = sawC || strings.Contains(word, "c")
		rest = tail
	}
	if !sawC || rest == "" {
		return "", false
	}
	if strings.HasPrefix(rest, `"`) {
		if len(rest) < 2 || !strings.HasSuffix(rest, `"`) {
			return "", false
		}
		return rest[1 : len(rest)-1], true
	}
	if strings.ContainsAny(rest, " \t") {
		// More than one argument after the command: not a launcher.
		return "", false
	}
	return rest, true
}

// simpleWords splits a shell command that is one simple command of literal
// words: single and double quotes, no expansion, redirection, operator,
// escape or assignment. Anything else is refused.
func simpleWords(command string) ([]string, bool) {
	var words []string
	var word strings.Builder
	inWord := false
	for i := 0; i < len(command); i++ {
		c := command[i]
		switch {
		case c == ' ' || c == '\t':
			if inWord {
				words = append(words, word.String())
				word.Reset()
				inWord = false
			}
		case c == '\'':
			end := strings.IndexByte(command[i+1:], '\'')
			if end < 0 {
				return nil, false
			}
			word.WriteString(command[i+1 : i+1+end])
			i += end + 1
			inWord = true
		case c == '"':
			end := strings.IndexByte(command[i+1:], '"')
			if end < 0 {
				return nil, false
			}
			quoted := command[i+1 : i+1+end]
			if strings.ContainsAny(quoted, "$`\\") {
				return nil, false
			}
			word.WriteString(quoted)
			i += end + 1
			inWord = true
		case strings.IndexByte(";&|<>()$`\\*?[]{}~#!\n\r", c) >= 0:
			return nil, false
		default:
			word.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, word.String())
	}
	if len(words) == 0 || strings.Contains(words[0], "=") {
		return nil, false
	}
	return words, true
}

func equalWords(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// underCommandShell reports whether root runs under a command shell that a
// program started (`sh -c ...` whose parent is not a shell): the shape of an
// agent's tool call. An ancestor that is a command shell with an unknown
// parent counts too.
func (m *Mapper) underCommandShell(root *procInfo) bool {
	current := m.table.get(root.parentExecID)
	for depth := 0; current != nil && depth < 16; depth++ {
		if isShell(current.binary) && hasCommandOption(current.args) {
			parent := m.table.get(current.parentExecID)
			if parent == nil || !isShell(parent.binary) {
				return true
			}
		}
		current = m.table.get(current.parentExecID)
	}
	return false
}

// hasCommandOption reports a shell run with -c (alone or combined).
func hasCommandOption(args string) bool {
	for _, word := range strings.Fields(args) {
		if !strings.HasPrefix(word, "-") || strings.HasPrefix(word, "--") {
			return false
		}
		if strings.Contains(word, "c") {
			return true
		}
	}
	return false
}
