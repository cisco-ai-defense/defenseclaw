// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package hookpaths resolves tool write targets in the invoking user's process.
package hookpaths

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/copilotargs"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

const Header = "X-DefenseClaw-Resolved-Writes"

// CWDKey carries the hook process's cwd for a gateway whose ProtectHome
// prevents it from validating that directory locally.
const CWDKey = "\x00cwd"

// TruncatedKey means at least one static write target could not fit in the
// bounded evidence. The gateway must not treat the remaining map as complete.
const TruncatedKey = "\x00truncated"

// PatchCompleteKey is positive hook-side proof that every apply_patch
// directive was parsed and each target was resolved in the user's filesystem
// view. The gateway may be unable to repeat that walk under ProtectHome.
const PatchCompleteKey = "\x00patch-complete"

// SourceLinkFactPrefix identifies a copy source inspected by the user-side hook.
const SourceLinkFactPrefix = "\x00source-link:"

// OpaqueScopeFactPrefix keys the hook client's check of one write operand
// against the scopes of a command that may create links it cannot read (an
// extraction, a sync or a copy that keeps links). The client walks the operand
// on the user's view of the filesystem. "0" means no traversed name or link
// hop is inside a scope; "c" means only the operand's own copy scope covers
// it. A gateway that cannot walk the user's home (ProtectHome) uses the fact
// in place of its incomplete walk. A name lexically inside a scope stays
// opaque, and a missing fact leaves the operand unknown.
const OpaqueScopeFactPrefix = "\x00opaque-scope:"

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

// MaxPayloadBytes is the hook payload cap, the same for the hook client and
// the gateway request body. The shell walk below covers a whole command up to
// this size, past the smaller ActionFacts analysis limits.
const MaxPayloadBytes = 1 << 20

// ShellWriteOperands lists the file operands of the output redirects in a
// shell command as absolute, cleaned paths, spelled the way the shell opens
// them (backslash escapes, single, double and ANSI-C quotes resolved). The
// hook client and the gateway both use it, so a client-resolved operand has
// the key the gateway looks up. ok is false when the command is over
// MaxPayloadBytes or does not parse; its operands are then unknown. dynamic
// reports a redirect target that is not a static word (a parameter other
// than HOME, a substitution or a glob), which is not listed.
func ShellWriteOperands(command, cwd, home string) (operands []string, ok, dynamic bool) {
	file, parsed := parseShell(command)
	if !parsed {
		return nil, false, false
	}
	env := expand.ListEnviron("HOME=" + strings.TrimRight(home, "/"))
	// A definition runs nothing. A body is read once, where it is defined,
	// when the command may call it (GAP-1430). Expanding each call instead
	// costs time exponential in the call nesting.
	called := calledFunctions(file, home)
	syntax.Walk(file, func(node syntax.Node) bool {
		if declaration, isFunction := node.(*syntax.FuncDecl); isFunction {
			return declaration.Name != nil && called[declaration.Name.Value]
		}
		redirect, isRedirect := node.(*syntax.Redirect)
		if !isRedirect || redirect.Word == nil {
			return true
		}
		switch redirect.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
		default:
			return true
		}
		name, static := staticShellWord(redirect.Word, env, home != "")
		if !static {
			dynamic = true
			return true
		}
		if name == "" {
			return true
		}
		operands = append(operands, OperandPath(name, cwd))
		return true
	})
	return operands, true, dynamic
}

// calledFunctions walks executable top-level calls, then reachable bodies.
// A body's call sites do not make it reachable on their own. Each definition
// is visited once, including duplicate definitions of the same name.
func calledFunctions(file *syntax.File, home string) map[string]bool {
	definitions := map[string][]*syntax.Stmt{}
	syntax.Walk(file, func(node syntax.Node) bool {
		if declaration, ok := node.(*syntax.FuncDecl); ok && declaration.Name != nil {
			definitions[declaration.Name.Value] = append(definitions[declaration.Name.Value], declaration.Body)
		}
		return true
	})
	called := make(map[string]bool, len(definitions))
	if len(definitions) == 0 {
		return called
	}
	queue := make([]string, 0, len(definitions))
	allMarked := false
	mark := func(name string) {
		if len(definitions[name]) > 0 && !called[name] {
			called[name] = true
			queue = append(queue, name)
		}
	}
	markAll := func() {
		for defined := range definitions {
			mark(defined)
		}
	}
	// Trap handlers are shell programs, not just one word. Walk their call
	// sites so `trap 'f argument' EXIT` reaches f without treating `echo f`
	// as a call. A dynamic handler can name any function in this command.
	markTrapHandler := func(value string, static bool) {
		if !static {
			markAll()
			return
		}
		handler, ok := parseShell(value)
		if !ok {
			mark(strings.TrimSpace(value))
			return
		}
		syntax.Walk(handler, func(node syntax.Node) bool {
			call, ok := node.(*syntax.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			if name, fixed := StaticWord(call.Args[0], home); fixed {
				mark(name)
				if name == "eval" || name == "source" || name == "." || name == "trap" {
					markAll()
				}
			} else {
				markAll()
			}
			return true
		})
	}
	boundName, boundValue := boundedProgramAssignment(file, home)
	scan := func(node syntax.Node) bool {
		if _, definition := node.(*syntax.FuncDecl); definition {
			return false
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		name, static := StaticWord(call.Args[0], home)
		if !static && simpleShellParameter(call.Args[0]) == boundName && boundName != "" {
			name, static = boundValue, true
		}
		if !static {
			// A dynamic command word can name any of the defined functions.
			if !allMarked {
				markAll()
				allMarked = true
			}
			return true
		}
		mark(name)
		if name == "trap" {
			// EXIT, ERR, DEBUG and RETURN can all execute a handler.
			handler := 1
			if len(call.Args) > handler {
				if value, ok := StaticWord(call.Args[handler], home); ok && value == "--" {
					handler++
				}
			}
			if len(call.Args) > handler {
				value, static := StaticWord(call.Args[handler], home)
				markTrapHandler(value, static)
			}
		}
		if name == "eval" {
			for _, arg := range call.Args[1:] {
				value, static := StaticWord(arg, home)
				markTrapHandler(value, static)
			}
		}
		if name == "source" || name == "." {
			// The sourced file can invoke a definition in this shell.
			markAll()
		}
		return true
	}
	syntax.Walk(file, scan)
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		for _, body := range definitions[name] {
			syntax.Walk(body, scan)
		}
	}
	return called
}

// OperandPath preserves dot-dot in the command operand until link resolution.
// filepath.Join would erase a directory link before the following dot-dot.
func OperandPath(name, cwd string) string {
	// Keep the old canonical spelling for ordinary operands. Only dot-dot
	// needs a raw spelling until the component walk has followed links.
	if !strings.Contains(filepath.ToSlash(name), "/../") &&
		!strings.HasSuffix(filepath.ToSlash(name), "/..") {
		if !filepath.IsAbs(name) && filepath.IsAbs(cwd) {
			return filepath.Join(cwd, name)
		}
		return filepath.Clean(name)
	}
	if filepath.IsAbs(name) || !filepath.IsAbs(cwd) {
		return name
	}
	return cwd + string(filepath.Separator) + name
}

// parseShell parses a command of at most MaxPayloadBytes as bash, or else as
// POSIX sh.
func parseShell(command string) (*syntax.File, bool) {
	if len(command) > MaxPayloadBytes {
		return nil, false
	}
	return shellparse.Parse(command)
}

// staticShellWord expands a redirect word that names one fixed path: quotes,
// escapes, a leading ~/ and $HOME. Anything whose value depends on the
// runtime (another parameter, a substitution, a glob, ~user) is not static.
func staticShellWord(word *syntax.Word, env expand.Environ, haveHome bool) (string, bool) {
	for i, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			if strings.ContainsAny(part.Value, "*?[") {
				return "", false
			}
			if i == 0 && strings.HasPrefix(part.Value, "~") &&
				(!haveHome || part.Value != "~" && !strings.HasPrefix(part.Value, "~/")) {
				return "", false
			}
		case *syntax.SglQuoted:
		case *syntax.DblQuoted:
			for _, inner := range part.Parts {
				switch inner := inner.(type) {
				case *syntax.Lit:
				case *syntax.ParamExp:
					if !homeParam(inner, haveHome) {
						return "", false
					}
				default:
					return "", false
				}
			}
		case *syntax.ParamExp:
			if !homeParam(part, haveHome) {
				return "", false
			}
		default:
			return "", false
		}
	}
	// Fields removes quotes and backslash escapes like the shell; a target
	// that splits into several fields is an ambiguous redirect, not a write.
	fields, err := expand.Fields(&expand.Config{Env: env}, word)
	if err != nil || len(fields) != 1 {
		return "", false
	}
	return fields[0], true
}

// StaticWord expands one shell word using only the known home directory.
func StaticWord(word *syntax.Word, home string) (string, bool) {
	if word == nil {
		return "", false
	}
	return staticShellWord(word, expand.ListEnviron("HOME="+strings.TrimRight(home, "/")), home != "")
}

func homeParam(param *syntax.ParamExp, haveHome bool) bool {
	return haveHome && param.Param != nil && param.Param.Value == "HOME" && !param.Excl && !param.Length &&
		!param.Width && !param.IsSet && param.Index == nil && param.Slice == nil && param.Repl == nil &&
		param.Names == 0 && param.Exp == nil && param.Flags == nil && param.NestedParam == nil &&
		len(param.Modifiers) == 0
}

// resolveWritePath follows existing links, including a link whose final file
// does not exist yet. The shared walk preserves components of link targets
// until each has been checked, so a linked directory before ".." is not
// removed lexically.
func resolveWritePath(path string, linkDepth int) (string, bool) {
	resolved, _, _, ok := walkWritePath("", path, linkDepth, false, false)
	return resolved, ok
}

// walkWritePath resolves both ordinary operands and raw symlink targets. base
// is the already-resolved directory containing a relative target. When collect
// is true, forms includes every traversed name and link hop for opaque-scope
// checks. A missing component is permitted at the end (redirects create
// files), but it cannot be crossed by "..": its link status is unknown.
func walkWritePath(base, path string, linkDepth int, collect, patchTarget bool) (string, []string, int, bool) {
	if linkDepth > maxWriteTargetLinkDepth {
		return "", nil, linkDepth, false
	}
	current := base
	absolute := filepath.IsAbs(path)
	if absolute {
		current = filepath.VolumeName(path) + string(filepath.Separator)
		path = strings.TrimPrefix(path, filepath.VolumeName(path))
	} else if !filepath.IsAbs(base) {
		return "", nil, linkDepth, false
	}
	var forms []string
	if collect && absolute {
		forms = append(forms, current)
	}
	add := func(form string) bool {
		if collect {
			forms = append(forms, form)
			return len(forms) <= maxOpaquePathForms
		}
		return true
	}
	// The stack records whether a component added after base is missing.
	// A resolved link is a physical directory, so ".." ascends from its
	// target. A missing component cannot be crossed: it may become a link
	// before the command executes.
	var crossed []bool
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		switch part {
		case "", ".":
			continue
		case "..":
			if len(crossed) > 0 {
				if crossed[len(crossed)-1] {
					return "", nil, linkDepth, false
				}
				crossed = crossed[:len(crossed)-1]
			}
			current = filepath.Dir(current)
			if !add(current) {
				return "", nil, linkDepth, false
			}
		default:
			candidate := filepath.Join(current, part)
			if !add(candidate) {
				return "", nil, linkDepth, false
			}
			info, err := os.Lstat(candidate)
			if err != nil && !os.IsNotExist(err) {
				return "", nil, linkDepth, false
			}
			unknown := os.IsNotExist(err)
			if err == nil && info.Mode()&os.ModeSymlink != 0 {
				// The cwd proc link is interpreted by the process opening the
				// operand. Resolving it in the hook would prove a different path.
				if ProcCWDWriteOperand(candidate) {
					return "", nil, linkDepth, false
				}
				link, err := os.Readlink(candidate)
				if err != nil {
					return "", nil, linkDepth, false
				}
				// A patch tool may reinterpret a link target with line breaks
				// as multiple file directives. Ordinary file opens use the
				// literal kernel path and retain their normal proof.
				if patchTarget && strings.ContainsAny(link, "\r\n") {
					return "", nil, linkDepth, false
				}
				var extra []string
				var nextDepth int
				var ok bool
				current, extra, nextDepth, ok = walkWritePath(current, link, linkDepth+1, collect, patchTarget)
				if !ok || collect && len(forms)+len(extra) > maxOpaquePathForms {
					return "", nil, linkDepth, false
				}
				linkDepth = nextDepth
				forms = append(forms, extra...)
				_, err = os.Lstat(current)
				if err != nil && !os.IsNotExist(err) {
					return "", nil, linkDepth, false
				}
				crossed = append(crossed, os.IsNotExist(err))
			} else {
				current = candidate
				crossed = append(crossed, unknown)
			}
		}
	}
	return filepath.Clean(current), forms, linkDepth, true
}

// AuthorizedKeysFiles names the user's authorized-keys files under ~/.ssh:
// the sshd default AuthorizedKeysFile (.ssh/authorized_keys and
// .ssh/authorized_keys2), the same set the direct-write rule
// persistence.ssh_authorized_keys_command protects. A symlink, a hard link
// and a direct write are judged against this one list.
var AuthorizedKeysFiles = [...]string{"authorized_keys", "authorized_keys2"}

// AuthorizedKeysPaths returns the AuthorizedKeysFiles paths under home.
func AuthorizedKeysPaths(home string) []string {
	paths := make([]string, 0, len(AuthorizedKeysFiles))
	for _, name := range AuthorizedKeysFiles {
		paths = append(paths, filepath.Join(home, ".ssh", name))
	}
	return paths
}

// ProtectedAuthorizedKeysPaths also includes sshd's Windows administrator
// key file, which may live outside the invoking user's home.
func ProtectedAuthorizedKeysPaths(home string) []string {
	paths := AuthorizedKeysPaths(home)
	if runtime.GOOS == "windows" {
		if programData := os.Getenv("ProgramData"); filepath.IsAbs(programData) {
			paths = append(paths, filepath.Join(programData, "ssh", "administrators_authorized_keys"))
		}
	}
	return paths
}

// ResolveWriteTarget resolves an absolute write operand the way the hook
// client does: links are followed, including one whose final file does not
// exist yet. ok is false when the target cannot be resolved.
func ResolveWriteTarget(path string) (string, bool) {
	return resolveWritePath(path, 0)
}

// ResolvePatchWriteTarget rejects a link whose target contains a line break:
// a patch parser can interpret the resolved name as another directive.
func ResolvePatchWriteTarget(path string) (string, bool) {
	resolved, _, _, ok := walkWritePath("", path, 0, false, true)
	return resolved, ok
}

// ResolveProcSelfCWDTarget interprets the cwd alias using the event cwd, not
// the hook or gateway process cwd. The suffix is walked before dot-dot is
// removed so directory links keep their physical meaning.
func ResolveProcSelfCWDTarget(path, cwd string) (string, bool) {
	const prefix = "/proc/self/cwd/"
	if !strings.HasPrefix(path, prefix) || !filepath.IsAbs(cwd) {
		return "", false
	}
	physicalCWD, ok := ResolveWriteTarget(cwd)
	if !ok {
		return "", false
	}
	return ResolveWriteTarget(physicalCWD + "/" + strings.TrimPrefix(path, prefix))
}

// protectedFile is the identity of one of the user's authorized-keys files. A
// hard link elsewhere names the same file under another path, so a target is
// compared by file identity (device and inode on Unix, volume serial and file
// index on Windows) and not by pathname alone.
type protectedFile struct {
	path    string
	info    os.FileInfo
	unknown bool
	// renamed is an unreadable protected path that is a symlink: the file
	// it names may have another name, so its link names cannot prove it.
	renamed bool
}

// protectedLinkNames lists every name of a file (fileLinkNames). It is a
// variable so a test can list the names a POSIX volume cannot.
var protectedLinkNames = fileLinkNames

type protectedFiles []protectedFile

func newProtectedFiles(home string) protectedFiles {
	files := make(protectedFiles, 0, len(AuthorizedKeysFiles))
	for _, path := range ProtectedAuthorizedKeysPaths(home) {
		protected := protectedFile{path: path}
		info, err := os.Stat(path)
		switch {
		case err == nil:
			protected.info = info
		case !os.IsNotExist(err):
			protected.unknown = true
			if link, err := os.Lstat(path); err == nil && link.Mode()&os.ModeSymlink != 0 {
				protected.renamed = true
			}
		}
		files = append(files, protected)
	}
	return files
}

// has reports a resolved target that is one of the protected paths.
func (files protectedFiles) has(resolved string) bool {
	for _, p := range files {
		if samePathName(resolved, p.path) {
			return true
		}
	}
	return false
}

// target maps a resolved write target to the protected path when both name
// the same file. A protected file the caller cannot read (sshd's Windows
// administrators key file under its folder's ACL) is matched by the names
// of a multiply linked target instead: the protected file's own entry is one
// of its names, so a full list of names (Windows) without that file name
// proves an ordinary file, like a pnpm or uv store file. A link count proves
// nothing. Where the names cannot all be listed (POSIX, a network share) the
// target may be an alias and is reported as unresolvable.
func (files protectedFiles) target(resolved string) (string, bool) {
	var info os.FileInfo
	var names []string
	listed, complete := false, false
	for _, p := range files {
		if p.info == nil && !p.unknown {
			continue
		}
		if info == nil {
			var err error
			if info, err = os.Stat(resolved); err != nil || !info.Mode().IsRegular() {
				return resolved, true
			}
		}
		if p.info != nil {
			if os.SameFile(info, p.info) {
				return p.path, true
			}
			continue
		}
		if linkCount(resolved, info) <= 1 {
			continue
		}
		if !listed {
			listed = true
			var listable bool
			names, complete, listable = protectedLinkNames(resolved)
			complete = complete && listable
		}
		if !complete || p.renamed {
			return "", false
		}
		for _, name := range names {
			if strings.EqualFold(filepath.Base(name), filepath.Base(p.path)) {
				return p.path, true
			}
		}
	}
	return resolved, true
}

// Resolve returns a bounded, header-safe map from absolute write operands to
// their filesystem targets. An empty value means resolution was attempted but
// could not be trusted. A regular file maps to itself, unless it is a hard
// link to one of the user's authorized-keys files. An operand
// is never dropped silently: when one cannot be listed (over a bound, or the command exceeds
// the shell analysis limits) the map carries TruncatedKey. The body is read
// as the Claude Code and Codex command hooks send it.
func Resolve(payload []byte) string {
	return ResolveConnector("", "", "", payload)
}

// ResolveConnector is Resolve for a hook body of connector, read as the
// gateway's profile for that connector reads it. surface and event are the
// hook command's --hook-surface value and bound event, the values the hook
// sends the gateway; only Copilot reads them. A Copilot body is read in the
// dialect the gateway selects from them (copilotargs.LocalDialect): the
// CLI's toolName/toolArgs (or native PermissionRequest toolInput), or the VS
// Code Local harness's tool_name/tool_input, through the copilotargs
// projection the gateway's Copilot profiles use. A body
// that spells the tool name, or the tool arguments, twice with different
// values is marked incomplete: no client sends one, and an operand this map
// does not list fails closed where the gateway cannot place it.
//
// A structured write call over the ActionFacts analysis limits is judged by
// the gateway on its reduced call (actionfacts.OverLimitWriteTargetReduction),
// so the map lists that call's targets and the limit alone does not make it
// incomplete. Any other reason still does.
func ResolveConnector(connector, surface, event string, payload []byte) string {
	if len(payload) > MaxPayloadBytes {
		return incompleteEvidence("")
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(payload, &envelope) != nil {
		return ""
	}
	copilot := strings.EqualFold(strings.TrimSpace(connector), "copilot")
	var toolRaw, args json.RawMessage
	var toolConflict, argsConflict bool
	if copilot {
		toolRaw, args, toolConflict, argsConflict = copilotCall(envelope, surface, event)
	} else {
		toolRaw, _, toolConflict = firstAlias(envelope, []string{"tool_name", "toolName"})
		args, _, argsConflict = firstAlias(envelope,
			[]string{"tool_input", "toolInput", "tool_args", "toolArgs", "args", "arguments"})
	}
	var tool string
	_ = json.Unmarshal(toolRaw, &tool)
	tool = strings.TrimSpace(tool)
	if copilot {
		tool = copilotargs.LocalActionTool(tool)
	}
	if len(args) == 0 && !toolConflict && !argsConflict {
		return ""
	}
	// The gateway names relative operands from the event cwd; use the same
	// directory so both sides build the same keys.
	var cwd string
	_ = json.Unmarshal(envelope["cwd"], &cwd)
	if !filepath.IsAbs(cwd) {
		var err error
		if cwd, err = os.Getwd(); err != nil {
			return incompleteEvidence("")
		}
	}
	cwd = filepath.Clean(cwd)
	var toolArgs map[string]json.RawMessage
	_ = json.Unmarshal(args, &toolArgs)
	// Codex exec_command runs in tool_input.workdir, which can differ from
	// the session cwd carried by the hook event. Resolve relative operands
	// there so client evidence and the gateway proof name the same files.
	if tool == "exec_command" {
		if raw, present := toolArgs["workdir"]; present {
			var workdir string
			if json.Unmarshal(raw, &workdir) != nil || workdir == "" ||
				strings.HasPrefix(workdir, "~") || strings.IndexByte(workdir, 0) >= 0 {
				return incompleteEvidence(cwd)
			}
			if filepath.IsAbs(workdir) {
				cwd = filepath.Clean(workdir)
			} else {
				cwd = filepath.Join(cwd, workdir)
			}
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return incompleteEvidence(cwd)
	}
	if len(args) == 0 {
		return incompleteEvidence(cwd)
	}
	if copilot {
		// The gateway judges a Copilot edit or create without its metadata
		// field (copilotargs.WriteArgsWithoutMetadata): describe that call.
		if clean, ok := copilotargs.WriteArgsWithoutMetadata(tool, args); ok {
			args = clean
		}
	}
	input := actionfacts.Input{Tool: tool, Args: args, CWD: cwd, ActiveHome: home}
	facts := actionfacts.Analyze(input)
	if view, _, ok := actionfacts.OverLimitWriteTargetReduction(input, facts); ok {
		// The gateway judges the reduced call: list its targets.
		facts = view
	}
	// A native write call with a key outside its reviewed schema stays
	// partial, but the harness writes the file its target key names, and
	// the gateway judges that target (actionfacts.UnknownKeyWriteTargetViews):
	// list it.
	for _, view := range actionfacts.UnknownKeyWriteTargetViews(input, facts) {
		facts.Paths = append(facts.Paths, view.Paths...)
	}
	// A connector can name the shell text "cmd" while ActionFacts requires
	// its canonical command field. Resolve that exact string as a shell too.
	truncated := facts.Parse.Status == actionfacts.StatusLimitExceeded || toolConflict || argsConflict
	var operands, literalOperands []string
	var directoryOperands []RedirectOccurrence
	var directoryUnknown bool
	links := shellLinks{known: true}
	sourceFacts := map[string]string{}
	if physicalCWD, ok := ResolveWriteTarget(cwd); ok {
		sourceFacts[DirectoryFactPrefix+cwd] = physicalCWD
	} else {
		sourceFacts[DirectoryFactPrefix+cwd] = "?"
	}
	var safeRedirects []RedirectOccurrence
	opaqueFacts := map[string]string{}
	var unprovenReason string
	// identity is the file-identity evidence for InstructionIdentityKey: a
	// known instruction file wins over an unknown multiply linked one.
	var identity string
	// A bare instruction name from the command text needs no client walk:
	// the gateway reads the same text.
	noteIdentity := func(instruction string, unknown bool) {
		if filepath.IsAbs(instruction) && len(instruction) <= MaxWriteTargetPathBytes {
			if identity == "" || identity == InstructionIdentityUnknown {
				identity = instruction
			}
			return
		}
		if (unknown || filepath.IsAbs(instruction)) && identity == "" {
			identity = InstructionIdentityUnknown
		}
	}
	if toolArgs != nil {
		for _, key := range []string{"command", "cmd"} {
			var command string
			if json.Unmarshal(toolArgs[key], &command) == nil && command != "" {
				if !isApplyPatchToolName(tool) && unprovenReason == "" {
					unprovenReason = ActionCommandDecision(command, cwd, home)
				}
				// A hard link the command creates is another name for its
				// source; one to an instruction file is refused (GAP-0869).
				noteIdentity(InstructionLinkCreation(tool, command, cwd, home, nil))
				fallback := input
				fallback.Tool, fallback.Args, fallback.Command = "Bash", nil, command
				fallbackFacts := actionfacts.Analyze(fallback)
				facts.Paths = append(facts.Paths, fallbackFacts.Paths...)
				truncated = truncated || fallbackFacts.Parse.Status == actionfacts.StatusLimitExceeded
				// A command over the analysis limits has no path facts, but
				// the gateway still checks each literal redirect operand.
				var parsed bool
				operands, parsed, _ = ShellWriteOperands(command, cwd, home)
				literalOperands = LiteralWriteOperands(command, cwd, home)
				// A bound pathname pattern has no fixed operand to list; the
				// gateway reads the same result and fails closed on it.
				boundedOperands, _ := BoundedShellWriteOperands(command, cwd, home)
				literalOperands = append(literalOperands, boundedOperands...)
				literalOperands = append(literalOperands, QuotedDynamicCopyDestinations(command, cwd, home)...)
				directoryOperands, directoryUnknown = ShellDirectoryWriteOperands(command, cwd, home, sourceFacts, true, false)
				truncated = truncated || directoryUnknown
				truncated = truncated || !parsed
				// A link the command creates can make a later write a write
				// to a protected file (GAP-1505). The command of an
				// apply_patch tool is a patch envelope, not shell.
				if !isApplyPatchToolName(tool) {
					links = commandLinksWithFacts(command, cwd, home, sourceFacts, true)
					safeRedirects = SafeShellRedirectOccurrencesWithFacts(command, cwd, home, sourceFacts)
					truncated = truncated || !links.known
				}
				break
			}
		}
	}
	targets := map[string]string{CWDKey: cwd}
	// The fixed part counts the truncation marker, so setting it never
	// exceeds the budget.
	protected := newProtectedFiles(home)
	size := 2 + len(jsonString(CWDKey)) + 1 + len(jsonString(cwd)) + 1 + len(jsonString(TruncatedKey)) + 1 + 3
	// A shell operand is already the literal path the shell opens; only a
	// path fact can still carry unexpanded syntax.
	add := func(path string, literal, safeRedirect bool) {
		if path == "" || !literal && (strings.ContainsAny(path, "*?[]$`") || strings.HasPrefix(path, "~")) {
			return
		}
		path = OperandPath(path, cwd)
		if old, present := targets[path]; present {
			if safeRedirect {
				return
			}
			size -= len(jsonString(path)) + 1 + len(jsonString(old)) + 1
			delete(targets, path)
		}
		if len(path) > MaxWriteTargetPathBytes || len(targets)-1 >= MaxWriteTargets {
			truncated = true
			return
		}
		resolved, ok := "", false
		resolutionPath := path
		aliasKnown := true
		if strings.HasPrefix(path, "/proc/self/cwd/") {
			resolutionPath, aliasKnown = ResolveProcSelfCWDTarget(path, cwd)
		}
		if aliasKnown && links.known {
			resolved, ok = links.resolve(resolutionPath, protected)
		} else if aliasKnown && safeRedirect {
			if direct, directOK := resolveWritePath(resolutionPath, 0); directOK {
				resolved, ok = protected.target(direct)
			}
		} else if aliasKnown && links.opaque && (!links.opaqueTarget(resolutionPath) || !links.opaqueTargetExceptCopy(resolutionPath, resolutionPath) && slices.Contains(links.copyDestinations, resolutionPath)) {
			resolved, ok = links.resolve(resolutionPath, protected)
		}
		if aliasKnown && links.opaque {
			if fact := links.opaqueScopeFact(resolutionPath); fact != "" {
				opaqueFacts[OpaqueScopeFactPrefix+resolutionPath] = fact
			}
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
		if resolved != "" {
			// Protection follows the file: a hard link, case or short-name
			// variant of an instruction file writes it (GAP-0869).
			noteIdentity(InstructionAlias(resolved, cwd, home, nil), false)
		}
	}
	// Exact shell operands take precedence over a duplicate PathFact. Their
	// early-redirect exemption must not cover a later command writer.
	for i, operand := range operands {
		add(operand, true, i < len(safeRedirects) && safeRedirects[i].Safe)
	}
	for _, operand := range literalOperands {
		add(operand, true, false)
	}
	for _, operand := range directoryOperands {
		add(operand.Path, true, operand.Safe)
	}
	for _, candidate := range facts.Paths {
		if candidate.Access != actionfacts.PathAccessWrite && candidate.Access != actionfacts.PathAccessAppend {
			continue
		}
		path := candidate.Resolved
		if path == "" {
			path = candidate.Normalized
		}
		if raw, ok := RawDotDotOperand(candidate.Value, cwd); ok {
			path = raw
		}
		if slices.Contains(operands, path) && pathFactIsRedirect(candidate, facts.Commands) {
			continue
		}
		add(path, false, false)
	}
	// An apply_patch edit names its files in the patch envelope, not in a
	// redirect. Unknown targets make the map incomplete.
	patchTargets, patchKnown := ApplyPatchWriteTargets(tool, args, "", cwd, home)
	truncated = truncated || !patchKnown
	patchListed := patchKnown && len(patchTargets) > 0
	for _, target := range patchTargets {
		add(target, true, false)
		if targets[OperandPath(target, cwd)] == "" {
			patchListed = false
		}
	}
	if isApplyPatchToolName(tool) && patchListed {
		entry := len(jsonString(PatchCompleteKey)) + 1 + len(jsonString("1")) + 1
		if size+entry > maxEncodedTargets || len(targets) >= MaxWriteTargets+2 {
			return incompleteEvidence(cwd)
		}
		targets[PatchCompleteKey] = "1"
		size += entry
	}
	for key, value := range sourceFacts {
		entry := len(jsonString(key)) + 1 + len(jsonString(value)) + 1
		if len(targets)-1 >= MaxWriteTargets || size+entry > maxEncodedTargets {
			truncated = true
			break
		}
		targets[key] = value
		size += entry
	}
	// A fact that does not fit is omitted; the gateway reads a missing fact
	// as unknown, so the map need not be marked truncated for it.
	for _, key := range slices.Sorted(maps.Keys(opaqueFacts)) {
		entry := len(jsonString(key)) + 1 + len(jsonString(opaqueFacts[key])) + 1
		if len(targets)-1 >= MaxWriteTargets || size+entry > maxEncodedTargets {
			break
		}
		targets[key] = opaqueFacts[key]
		size += entry
	}
	if unprovenReason != "" {
		entry := len(jsonString(UnprovenReasonKey)) + 1 + len(jsonString(unprovenReason)) + 1
		if size+entry > maxEncodedTargets || len(targets) >= MaxWriteTargets+2 {
			return unprovenEvidence(cwd, unprovenReason, identity)
		}
		targets[UnprovenReasonKey] = unprovenReason
		size += entry
	}
	if identity != "" {
		entry := len(jsonString(InstructionIdentityKey)) + 1 + len(jsonString(identity)) + 1
		if size+entry > maxEncodedTargets || len(targets) >= MaxWriteTargets+3 {
			return unprovenEvidence(cwd, unprovenReason, identity)
		}
		targets[InstructionIdentityKey] = identity
		size += entry
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

// copilotCall returns the tool name and the projected arguments of a Copilot
// hook body as the gateway's profile for its dialect reads them
// (copilotargs.LocalDialect), and whether another spelling of the tool name
// or of the arguments carries a different value. A native PermissionRequest
// reads toolInput only when toolArgs is absent, through the projection the
// gateway's profile uses (copilotargs.PermissionToolArgs): an edit whose
// diff does not prove the declared target is incomplete. The other
// dialect's fields and generic aliases are spellings the gateway ignores.
func copilotCall(envelope map[string]json.RawMessage, surface, event string) (json.RawMessage, json.RawMessage, bool, bool) {
	var hookEvent string
	_ = json.Unmarshal(envelope["hook_event_name"], &hookEvent)
	_, local := copilotargs.LocalDialect(surface, event)
	toolNames := []string{"toolName", "tool_name"}
	argNames := []string{"toolArgs", "tool_input", "toolInput", "tool_args", "args", "arguments"}
	var nativeHook string
	_ = json.Unmarshal(envelope["hookName"], &nativeHook)
	_, hasToolArgs := envelope["toolArgs"]
	nativePermission := !local && event == "permissionRequest" && nativeHook == "permissionRequest" &&
		!hasToolArgs && aliasSet(envelope["toolInput"])
	if local {
		toolNames[0], toolNames[1] = toolNames[1], toolNames[0]
		argNames[0], argNames[1] = argNames[1], argNames[0]
	} else if nativePermission {
		argNames[0], argNames[2] = argNames[2], argNames[0]
	}
	toolRaw, toolConflict := dialectAlias(envelope, toolNames)
	rawArgs, argsConflict := dialectAlias(envelope, argNames)
	if !local && (hookEvent != "" || aliasSet(envelope["tool_name"]) || aliasSet(envelope["tool_input"])) {
		toolConflict = true
	}
	if local && (aliasSet(envelope["toolName"]) || aliasSet(envelope["toolArgs"])) {
		toolConflict = true
	}
	var tool string
	_ = json.Unmarshal(toolRaw, &tool)
	tool = strings.TrimSpace(tool)
	// Both profiles project an arguments field that is present, null
	// included, and read none when it is absent.
	if _, present := envelope[argNames[0]]; !present {
		return toolRaw, nil, toolConflict, argsConflict
	}
	var value any
	if json.Unmarshal(rawArgs, &value) != nil {
		value = nil
	}
	if local {
		return toolRaw, copilotargs.LocalToolArgs(tool, value), toolConflict, argsConflict
	}
	if nativePermission {
		projected := copilotargs.PermissionToolArgs(tool, value)
		return toolRaw, projected, toolConflict, argsConflict || (tool == "edit" && len(projected) == 0)
	}
	return toolRaw, copilotargs.CLIToolArgs(tool, value), toolConflict, argsConflict
}

// dialectAlias returns the value of names[0], the one spelling a Copilot
// profile reads, and whether another of names carries a value other than
// null that differs from it (or is set while names[0] is not).
func dialectAlias(envelope map[string]json.RawMessage, names []string) (json.RawMessage, bool) {
	value := bytes.TrimSpace(envelope[names[0]])
	conflict := false
	for _, name := range names[1:] {
		other := envelope[name]
		if aliasSet(other) {
			conflict = conflict || !aliasSet(value) || !sameAliasValue(value, bytes.TrimSpace(other))
		}
	}
	return value, conflict
}

// aliasSet reports a field present with a value other than null.
func aliasSet(value json.RawMessage) bool {
	value = bytes.TrimSpace(value)
	return len(value) != 0 && !bytes.Equal(value, []byte("null"))
}

// firstAlias returns the first of names that envelope carries with a value
// other than null, its name, and whether another of names carries a different
// value: a string, compared with surrounding space trimmed as the gateway
// reads a tool name, or any other JSON value, compared compacted.
func firstAlias(envelope map[string]json.RawMessage, names []string) (json.RawMessage, string, bool) {
	var first json.RawMessage
	var firstName string
	conflict := false
	for _, name := range names {
		value := bytes.TrimSpace(envelope[name])
		if !aliasSet(value) {
			continue
		}
		if first == nil {
			first, firstName = value, name
			continue
		}
		conflict = conflict || !sameAliasValue(first, value)
	}
	return first, firstName, conflict
}

func sameAliasValue(a, b json.RawMessage) bool {
	var textA, textB string
	if json.Unmarshal(a, &textA) == nil && json.Unmarshal(b, &textB) == nil {
		return strings.TrimSpace(textA) == strings.TrimSpace(textB)
	}
	var compactA, compactB bytes.Buffer
	if json.Compact(&compactA, a) != nil || json.Compact(&compactB, b) != nil {
		return false
	}
	return bytes.Equal(compactA.Bytes(), compactB.Bytes())
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

func unprovenEvidence(cwd, reason, identity string) string {
	// The full target map overflowed while adding the class reason or the
	// file-identity evidence. Keep the incomplete-map marker and both facts
	// in the small header.
	targets := map[string]string{CWDKey: cwd, TruncatedKey: "1"}
	if reason != "" {
		targets[UnprovenReasonKey] = reason
	}
	if identity != "" {
		targets[InstructionIdentityKey] = identity
	}
	encoded, _ := json.Marshal(targets)
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
	if json.Unmarshal(data, &targets) != nil || len(targets) > MaxWriteTargets+5 ||
		(targets[TruncatedKey] != "" && targets[TruncatedKey] != "1") ||
		(targets[PatchCompleteKey] != "" && targets[PatchCompleteKey] != "1") ||
		(targets[UnprovenReasonKey] != "" && UnprovenWriteTitle(targets[UnprovenReasonKey]) == "") {
		return nil, false
	}
	if identity, present := targets[InstructionIdentityKey]; present && identity != InstructionIdentityUnknown &&
		(!filepath.IsAbs(identity) || len(identity) > MaxWriteTargetPathBytes) {
		return nil, false
	}
	for key, value := range targets {
		if strings.HasPrefix(key, DirectoryFactPrefix) && value != "?" && !filepath.IsAbs(value) {
			return nil, false
		}
		if strings.HasPrefix(key, SourceLinkFactPrefix) && (value != "0" && value != "1" && value != "?") {
			return nil, false
		}
		if strings.HasPrefix(key, OpaqueScopeFactPrefix) && (value != "0" && value != "c" ||
			!filepath.IsAbs(strings.TrimPrefix(key, OpaqueScopeFactPrefix))) {
			return nil, false
		}
	}
	return targets, true
}

// rawDotDotOperand keeps the shell spelling when a link can precede "..".
func RawDotDotOperand(value, cwd string) (string, bool) {
	if !strings.Contains(filepath.ToSlash(value), "/../") || strings.ContainsAny(value, "*?[]$`~") || !filepath.IsAbs(cwd) {
		return "", false
	}
	return OperandPath(value, cwd), true
}

func pathFactIsRedirect(candidate actionfacts.PathFact, commands []actionfacts.CommandFact) bool {
	for _, command := range commands {
		if command.ID != candidate.CommandID {
			continue
		}
		for _, redirect := range command.Redirects {
			if redirect.Access == candidate.Access && !redirect.Expands &&
				(redirect.Target == candidate.Value || redirect.Target == candidate.Normalized) {
				return true
			}
		}
	}
	return false
}

// Programs that create a link from their operands: ln and link always, cp
// with --link or --symbolic-link. mv and rename move a link to another name;
// cd changes what a relative link operand denotes. A multicall binary runs
// its first operand as the program. Archive, copy, and sync tools can
// preserve or extract links whose names this package cannot list.
var (
	linkPrograms      = []string{"ln", "gln", "link", "glink"}
	copyPrograms      = []string{"cp", "gcp"}
	renamePrograms    = []string{"mv", "gmv", "rename"}
	cdPrograms        = []string{"cd", "pushd", "popd"}
	multicallPrograms = []string{"busybox", "toybox"}
	archivePrograms   = []string{"rsync", "cpio", "bsdcpio", "pax", "tar", "gtar", "bsdtar", "unzip", "7z", "7za", "7zr", "jar", "ditto"}
	copyLinkOption    = regexp.MustCompile(`(?:^|\s)(?:-[A-Za-z]*[ls][A-Za-z]*|--(?:link|symbolic-link))(?:[\s=]|$)`)
	// opaqueLink is a link that an interpreter, PowerShell or a Windows tool
	// creates from text this package does not evaluate.
	opaqueLink = regexp.MustCompile(`(?i)\bos\.(?:sym)?link\s*\(|\.(?:hardlink_to|symlink_to|link_to)\s*\(|` +
		`\bfs(?:\.promises)?\.(?:sym)?link(?:sync)?\s*\(|\bmklink\b|\bfsutil(?:\.exe)?\s+hardlink\b|` +
		`-itemtype\s+['"]?(?:hardlink|symboliclink|junction)\b|\bcreate(?:symbolic|hard)link\b`)
)

// linkAlias is a name that a link created by the command gives to target.
type linkAlias struct{ name, target string }

// shellLinks are the links one shell command creates. known is false when
// link names or operands are dynamic or an archive can extract links. opaque
// identifies a possible unreadable link; a dynamic program word alone keeps
// the older per-user behavior (GAP-1523).
type shellLinks struct {
	aliases          []linkAlias
	known            bool
	opaque           bool
	relative         bool // a link operand is relative to the working directory
	globalOpaque     bool
	opaqueScopes     []opaqueScope
	copyDestinations []string
}

// unknown marks the links unknown, and opaque when a link may be created.
func (l *shellLinks) unknown(opaque bool) {
	l.known = false
	l.opaque = l.opaque || opaque
	l.globalOpaque = l.globalOpaque || opaque
}

type opaqueScope struct {
	path string
	copy bool
}

// unknownIn confines an archive to its destination directory.
func (l *shellLinks) unknownIn(scope string) {
	l.addOpaqueScope(scope, false)
}

func (l *shellLinks) unknownCopyIn(scope string) {
	l.addOpaqueScope(scope, true)
}

func (l *shellLinks) addOpaqueScope(scope string, copyScope bool) {
	l.known = false
	l.opaque = true
	if scope == "" {
		l.globalOpaque = true
		return
	}
	l.opaqueScopes = append(l.opaqueScopes, opaqueScope{filepath.Clean(scope), copyScope})
}

func (l shellLinks) opaqueTarget(path string) bool {
	return l.opaqueTargetExceptCopy(path, "")
}

// opaqueTargetExceptCopy excludes only the copy operation's own destination
// scope. An archive or another operation covering that path still wins.
func (l shellLinks) opaqueTargetExceptCopy(path, ownCopy string) bool {
	return l.opaqueTargetWithFacts(path, ownCopy, nil)
}

// opaqueScopeFact is the OpaqueScopeFactPrefix value for path, or "" when a
// scope covers it or its walk is incomplete.
func (l shellLinks) opaqueScopeFact(path string) string {
	switch {
	case !l.opaqueTarget(path):
		return "0"
	case !l.opaqueTargetExceptCopy(path, path):
		return "c"
	}
	return ""
}

// opaqueTargetWithFacts is opaqueTargetExceptCopy for a caller that may not
// see every component of path. facts is the hook client's evidence map; its
// opaque-scope fact replaces only an incomplete walk.
func (l shellLinks) opaqueTargetWithFacts(path, ownCopy string, facts map[string]string) bool {
	// A second copy to the same name may follow a link created by the first.
	// Only one copy statement can claim the own-destination exemption.
	if ownCopy != "" {
		count := 0
		for _, destination := range l.copyDestinations {
			if destination == ownCopy {
				count++
			}
		}
		if count != 1 {
			ownCopy = ""
		}
	}
	if !l.opaque {
		return false
	}
	if l.globalOpaque || len(l.opaqueScopes) == 0 {
		return true
	}
	forms, complete := writePathForms(path, 0)
	if !complete {
		// The user's walk of the same operand stands in for one this process
		// cannot finish; the scope check below still sees the name itself.
		fact := facts[OpaqueScopeFactPrefix+path]
		if fact != "0" && (fact != "c" || ownCopy == "" || ownCopy != path) {
			return true
		}
		forms = []string{filepath.Clean(path)}
	}
	for _, scope := range l.opaqueScopes {
		if scope.copy && scope.path == ownCopy {
			continue
		}
		for _, form := range forms {
			if form == scope.path || strings.HasPrefix(form, scope.path+string(filepath.Separator)) {
				return true
			}
		}
	}
	return false
}

// writePathForms includes every traversed name and link hop. An extractor
// may replace a link inside its scope after this check, so the intermediate
// forms matter even when the final target is outside that scope.
const maxOpaquePathForms = 256

func writePathForms(path string, linkDepth int) ([]string, bool) {
	_, forms, _, ok := walkWritePath("", path, linkDepth, true, false)
	return forms, ok
}

func commandLinksWithFacts(command, cwd, home string, facts map[string]string, record bool) shellLinks {
	links := shellLinks{known: true}
	file, parsed := parseShell(command)
	if !parsed {
		// Resolve already marks a command that does not parse incomplete.
		if opaqueLink.MatchString(command) {
			links.unknown(true)
		}
		return links
	}
	if opaqueLinkText(file, command, home) {
		links.unknown(true)
		return links
	}
	linkCall, linkCWD := staticChangedDirectoryLink(file, cwd, home)
	env := expand.ListEnviron("HOME=" + strings.TrimRight(home, "/"))
	renames, cds := false, false
	var copyScopes []string
	boundPrograms := actionBoundProgramWords(file, home)
	syntax.Walk(file, func(node syntax.Node) bool {
		call, isCall := node.(*syntax.CallExpr)
		if !isCall || len(call.Args) == 0 {
			return true
		}
		args := call.Args
		words := make([]string, len(args))
		static := make([]bool, len(args))
		for i, arg := range args {
			words[i], static[i] = staticShellWord(arg, env, home != "")
		}
		if !static[0] {
			words[0], static[0] = staticProgramWord(args[0], home)
		}
		if !static[0] {
			words[0], static[0] = boundPrograms[call]
			static[0] = words[0] != ""
		}
		program, start := "", call.Pos()
		if static[0] {
			program = programBase(words[0])
		}
		// busybox ln and toybox ln are ln (GAP-1521).
		for slices.Contains(multicallPrograms, program) && len(args) > 1 {
			args, words, static, start = args[1:], words[1:], static[1:], args[1].Pos()
			program = ""
			if static[0] {
				program = programBase(words[0])
			}
		}
		if opaqueProgram(program) {
			links.unknown(true)
			return true
		}
		switch {
		case program == "":
			// A program named by a parameter or a substitution may be ln.
			links.unknown(false)
		case slices.Contains(linkPrograms, program):
			workingDirectory := cwd
			if call == linkCall {
				workingDirectory = linkCWD
			}
			if slices.Contains(static, false) || !links.add(program, words[1:], workingDirectory) {
				links.unknown(true)
			}
		case slices.Contains(copyPrograms, program):
			if len(args) == 3 && !static[1] && static[2] &&
				quotedDynamicCopySource(args[1]) && words[2] != "" && !strings.HasPrefix(words[2], "-") {
				// A quoted source is one argv word. If it expands to an option,
				// cp has no source and cannot write its fixed destination.
				links.copyDestinations = append(links.copyDestinations, OperandPath(words[2], cwd))
				return true
			}
			destination := cpDestination(words[1:], static[1:], cwd)
			if destination != "" {
				links.copyDestinations = append(links.copyDestinations, destination)
			}
			option, dynamic := copyLinkOptions(args[1:], words[1:], static[1:])
			if copyPreservesLinks(words[1:], static[1:]) {
				copyScopes = append(copyScopes, destination)
				if cpDiskSymlink(words[1:], static[1:], cwd, home, facts, record) {
					links.unknownCopyIn(destination)
				}
			}
			switch {
			case option:
				if slices.Contains(static, false) || !links.add(program, words[1:], cwd) {
					links.unknown(true)
				}
			case dynamic:
				// A word that is not static may expand to a link option.
				links.unknown(false)
				copyScopes = append(copyScopes, cpDestination(words[1:], static[1:], cwd))
			}
		case slices.Contains(archivePrograms, program):
			if slices.Contains(static[1:], false) {
				// An option supplied at runtime may select extraction.
				links.unknownIn(archiveDestination(program, words[1:], static[1:], cwd))
			}
			if archiveMayLink(program, words[1:], static[1:]) {
				links.unknownIn(archiveDestination(program, words[1:], static[1:], cwd))
			}
			if archiveCopiesLinks(program, words[1:], static[1:]) {
				destination := archiveDestination(program, words[1:], static[1:], cwd)
				copyScopes = append(copyScopes, destination)
				if archiveCopiesDiskSymlink(program, words[1:], static[1:], cwd, home, facts, record) {
					links.unknownIn(destination)
				}
			}
		case program == "git":
			if destination, materializes := gitMaterializationScope(words[1:], static[1:], cwd); materializes {
				for _, assignment := range call.Assigns {
					if assignment.Name == nil {
						continue
					}
					switch assignment.Name.Value {
					case "GIT_WORK_TREE", "GIT_DIR", "GIT_COMMON_DIR":
						destination = ""
					}
				}
				links.unknownIn(destination)
			}
		case slices.Contains(renamePrograms, program):
			renames = true
		case slices.Contains(cdPrograms, program):
			cds = true
		default:
			// A wrapper (sudo, env, xargs, find -exec, sh -c) may run one.
			text := command[start.Offset():call.End().Offset()]
			switch {
			case tactics.RunsProgram(text, linkPrograms...):
				links.unknown(true)
			case tactics.RunsProgram(text, copyPrograms...) && copyLinkOption.MatchString(text):
				// The option may be the wrapper's own, as in bash -lc.
				mayLink, copyWord := wrappedMayLink(text)
				links.unknown(mayLink || !copyWord)
			case tactics.RunsProgram(text, multicallPrograms...) || tactics.RunsProgram(text, archivePrograms...):
				if mayLink, _ := wrappedMayLink(text); mayLink {
					links.unknown(true)
				}
			}
			renames = renames || tactics.RunsProgram(text, renamePrograms...)
			cds = cds || tactics.RunsProgram(text, cdPrograms...)
		}
		return true
	})
	if len(links.aliases) > 0 {
		for _, scope := range copyScopes {
			links.unknownCopyIn(scope)
		}
	}
	if len(links.aliases) > 0 && (renames || cds && links.relative && linkCall == nil) {
		links.unknown(true)
	}
	// Scopes are read against the starting directory; after a directory
	// change a relative write may land in a scope under another name.
	if cds && len(links.opaqueScopes) > 0 {
		links.globalOpaque = true
	}
	return links
}

// staticChangedDirectoryLink handles one ordered cd/link/write chain. The
// physical cd target fixes the link's name without guessing about other shell
// control flow. The hook cannot see the CDPATH of the agent's shell, which
// startup files may set without exporting it, so only an absolute or ./
// operand without dot-dot names a proven directory. After any other cd the
// shell may stand in a directory the hook cannot name, where the new link or a
// link already there may lead the write to a protected file, so the chain is
// not accepted and the link scope stays opaque.
func staticChangedDirectoryLink(file *syntax.File, cwd, home string) (*syntax.CallExpr, string) {
	if len(file.Stmts) != 1 {
		return nil, ""
	}
	var statements []*syntax.Stmt
	var flatten func(*syntax.Stmt) bool
	flatten = func(stmt *syntax.Stmt) bool {
		if stmt == nil || stmt.Background || stmt.Negated {
			return false
		}
		if pair, ok := stmt.Cmd.(*syntax.BinaryCmd); ok {
			return len(stmt.Redirs) == 0 && pair.Op == syntax.AndStmt && flatten(pair.X) && flatten(pair.Y)
		}
		statements = append(statements, stmt)
		return len(statements) <= 3
	}
	if !flatten(file.Stmts[0]) || len(statements) != 3 {
		return nil, ""
	}
	first, firstOK := statements[0].Cmd.(*syntax.CallExpr)
	second, secondOK := statements[1].Cmd.(*syntax.CallExpr)
	third, thirdOK := statements[2].Cmd.(*syntax.CallExpr)
	if !firstOK || !secondOK || !thirdOK || len(statements[0].Redirs) != 0 || len(statements[1].Redirs) != 0 ||
		len(first.Assigns) != 0 || len(first.Args) != 2 ||
		len(second.Assigns) != 0 || len(second.Args) != 4 || len(third.Assigns) != 0 || len(third.Args) == 0 {
		return nil, ""
	}
	cd, cdOK := StaticWord(first.Args[0], home)
	path, pathOK := StaticWord(first.Args[1], home)
	link, linkOK := StaticWord(second.Args[0], home)
	option, optionOK := StaticWord(second.Args[1], home)
	writer, writerOK := StaticWord(third.Args[0], home)
	if !cdOK || cd != "cd" || !pathOK || path == "" || strings.HasPrefix(path, "-") || !cdBypassesSearchPath(path) ||
		!linkOK || !slices.Contains(linkPrograms, programBase(link)) || !optionOK || option != "-s" ||
		!writerOK || writer != "echo" || len(statements[2].Redirs) != 1 {
		return nil, ""
	}
	for _, word := range second.Args[2:] {
		if _, static := StaticWord(word, home); !static {
			return nil, ""
		}
	}
	changed, ok := ResolveWriteTarget(OperandPath(path, cwd))
	if !ok {
		return nil, ""
	}
	info, err := os.Stat(changed)
	if err != nil || !info.IsDir() {
		return nil, ""
	}
	return second, changed
}

// cdBypassesSearchPath reports a cd operand that Bash resolves without CDPATH
// and without logical dot-dot processing against the event cwd.
func cdBypassesSearchPath(path string) bool {
	if !filepath.IsAbs(path) && path != "." && !strings.HasPrefix(path, "./") {
		return false
	}
	for _, component := range strings.Split(filepath.ToSlash(path), "/") {
		if component == ".." {
			return false
		}
	}
	return true
}

// dataPrograms only print, search or count text, so link API text in their
// arguments or here-documents is data, not code (GAP-1536).
var dataPrograms = []string{"echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "ack", "cat", "head", "tail",
	"wc", "sort", "uniq", "cut", "tr", "nl", "less", "more"}

// opaqueLinkText reports link API text that the command may run. Only a
// command made of data programs alone, without substitutions, is exempt: an
// interpreter may read the text from an argument, a here-document, a pipe or
// a file the command writes, under any name or wrapper.
func opaqueLinkText(file *syntax.File, command, home string) bool {
	if !opaqueLink.MatchString(command) {
		return false
	}
	for _, stmt := range file.Stmts {
		if !dataStatement(stmt, home) {
			return true
		}
	}
	return false
}

func dataStatement(stmt *syntax.Stmt, home string) bool {
	if stmt == nil || stmt.Background || stmt.Cmd == nil {
		return false
	}
	switch cmd := stmt.Cmd.(type) {
	case *syntax.BinaryCmd:
		if !dataStatement(cmd.X, home) || !dataStatement(cmd.Y, home) {
			return false
		}
	case *syntax.CallExpr:
		if len(cmd.Assigns) > 0 || len(cmd.Args) == 0 {
			return false
		}
		program, static := StaticWord(cmd.Args[0], home)
		if !static || !slices.Contains(dataPrograms, programBase(program)) {
			return false
		}
	default:
		return false
	}
	plain := true
	syntax.Walk(stmt, func(node syntax.Node) bool {
		switch node.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			plain = false
		}
		return plain
	})
	return plain
}

// linearShellStatements excludes loops, subshells, and command substitutions:
// their execution order can differ from source order.
func linearShellStatements(file *syntax.File) ([]*syntax.Stmt, bool) {
	var statements []*syntax.Stmt
	var collect func(*syntax.Stmt) bool
	collect = func(stmt *syntax.Stmt) bool {
		if stmt == nil || stmt.Background || stmt.Negated {
			return false
		}
		switch cmd := stmt.Cmd.(type) {
		case *syntax.BinaryCmd:
			if cmd.Op != syntax.AndStmt && cmd.Op != syntax.OrStmt {
				return false
			}
			return collect(cmd.X) && collect(cmd.Y)
		case *syntax.CallExpr:
			plain := true
			syntax.Walk(cmd, func(node syntax.Node) bool {
				switch node.(type) {
				case *syntax.CmdSubst, *syntax.ProcSubst:
					plain = false
					return false
				}
				return true
			})
			if !plain {
				return false
			}
			statements = append(statements, stmt)
			return true
		}
		return false
	}
	for _, stmt := range file.Stmts {
		if !collect(stmt) {
			return nil, false
		}
	}
	slices.SortFunc(statements, func(a, b *syntax.Stmt) int {
		return int(a.Pos().Offset()) - int(b.Pos().Offset())
	})
	return statements, true
}

// RedirectOccurrence is one shell redirect in source order. The safety bit
// belongs to that occurrence, even when a later writer names the same path.
type RedirectOccurrence struct {
	Path string
	Safe bool
}

// SafeShellRedirectOccurrences reports redirects opened before any command
// in the line can create a link. An extracting command's own redirect opens
// before extraction begins.
func SafeShellRedirectOccurrences(command, cwd, home string) []RedirectOccurrence {
	return SafeShellRedirectOccurrencesWithFacts(command, cwd, home, nil)
}

// SafeShellRedirectOccurrencesWithFacts uses client source facts when the
// gateway cannot inspect a copy source in the user home.
func SafeShellRedirectOccurrencesWithFacts(command, cwd, home string, facts map[string]string) []RedirectOccurrence {
	operands, parsed, _ := ShellWriteOperands(command, cwd, home)
	if !parsed {
		return nil
	}
	result := make([]RedirectOccurrence, len(operands))
	for i, path := range operands {
		result[i].Path = path
	}
	file, ok := parseShell(command)
	if !ok {
		return result
	}
	statements, linear := linearShellStatements(file)
	if !linear {
		return result
	}
	seenLink, index := false, 0
	for _, stmt := range statements {
		for _, redirect := range stmt.Redirs {
			switch redirect.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
			default:
				continue
			}
			path, static := StaticWord(redirect.Word, home)
			if !static || path == "" {
				continue
			}
			path = OperandPath(path, cwd)
			if index < len(result) && result[index].Path == path {
				result[index].Safe = !seenLink
			}
			index++
		}
		start, end := int(stmt.Pos().Offset()), int(stmt.End().Offset())
		if start < 0 || end > len(command) || start >= end {
			seenLink = true
			continue
		}
		site := commandLinksWithFacts(command[start:end], cwd, home, facts, false)
		seenLink = seenLink || !site.known || len(site.aliases) > 0
	}
	return result
}

// ArchiveBeforeWrite reports an extraction followed by a shell redirect.
// The redirect on the extracting statement itself opens before extraction.
func ArchiveBeforeWrite(command, home string) bool {
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	statements, linear := linearShellStatements(file)
	if !linear {
		return false
	}
	extracted := false
	for _, stmt := range statements {
		if extracted {
			for _, redirect := range stmt.Redirs {
				switch redirect.Op {
				case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
					return true
				}
			}
		}
		call := stmt.Cmd.(*syntax.CallExpr)
		if len(call.Args) == 0 {
			continue
		}
		words := make([]string, len(call.Args))
		static := make([]bool, len(call.Args))
		for i, arg := range call.Args {
			words[i], static[i] = StaticWord(arg, home)
		}
		program := programBase(words[0])
		if slices.Contains(multicallPrograms, program) && len(words) > 1 {
			words, static = words[1:], static[1:]
			program = programBase(words[0])
		}
		if slices.Contains(archivePrograms, program) && program != "rsync" &&
			!archiveCopiesLinks(program, words[1:], static[1:]) &&
			(slices.Contains(static[1:], false) || archiveMayLink(program, words[1:], static[1:])) {
			extracted = true
		}
	}
	return false
}

// Links are the links one shell command creates, read as Resolve reads them.
type Links struct {
	links     shellLinks
	protected protectedFiles
}

// CommandLinks reads the links that the shell command of a tool call
// creates. The command of an apply_patch tool is a patch envelope, not shell.
func CommandLinks(tool, command, cwd, home string) Links {
	return CommandLinksWithFacts(tool, command, cwd, home, nil)
}

// CommandLinksWithFacts uses copy-source link evidence from the user-side hook.
func CommandLinksWithFacts(tool, command, cwd, home string, facts map[string]string) Links {
	if command == "" || isApplyPatchToolName(tool) {
		return Links{links: shellLinks{known: true}}
	}
	links := Links{links: commandLinksWithFacts(command, cwd, home, facts, false)}
	if len(links.links.aliases) > 0 {
		links.protected = newProtectedFiles(home)
	}
	return links
}

// OpaqueTargetWithFacts reports whether an unreadable link operation can
// affect path. Such operations include a wrapper or multicall binary running
// ln, an interpreter or Windows link call, an archive or sync link option, or
// an mv or relative cd with a link. Archive and copy scopes narrow the
// affected paths; ownCopy excludes the scope of the copy statement that writes
// path as its own destination. A program word that is not static alone does
// not count (GAP-1523). facts carries the managed hook client's
// OpaqueScopeFactPrefix entries for a gateway that cannot walk the user's
// home; nil keeps the local walk as the only evidence.
func (l Links) OpaqueTargetWithFacts(path string, ownCopy bool, facts map[string]string) bool {
	if ownCopy {
		return l.links.opaqueTargetWithFacts(path, path, facts)
	}
	return l.links.opaqueTargetWithFacts(path, "", facts)
}

// SplitOpaqueScopeFacts separates the OpaqueScopeFactPrefix entries from the
// rest of a decoded map. The instruction-identity fact is for the
// cognitive-file proof only and is in neither. targets is returned unchanged
// when it has neither kind of entry.
func SplitOpaqueScopeFacts(targets map[string]string) (rest, facts map[string]string) {
	_, identity := targets[InstructionIdentityKey]
	for key, value := range targets {
		if strings.HasPrefix(key, OpaqueScopeFactPrefix) {
			if facts == nil {
				facts = make(map[string]string)
			}
			facts[key] = value
		}
	}
	if facts == nil && !identity {
		return targets, nil
	}
	rest = make(map[string]string, len(targets)-len(facts))
	for key, value := range targets {
		if !strings.HasPrefix(key, OpaqueScopeFactPrefix) && key != InstructionIdentityKey {
			rest[key] = value
		}
	}
	return rest, facts
}

// Target maps an absolute write operand through the links the command
// creates as Resolve does: a name that reaches one of the user's
// authorized-keys files maps to that file. ok is false when one of the names
// cannot be resolved.
func (l Links) Target(path string) (string, bool) {
	if len(l.links.aliases) == 0 {
		return path, true
	}
	return l.links.resolve(path, l.protected)
}

// copyLinkOptions reports a cp call with a static link option, and one with
// a word that is not static and may expand to an option.
func copyLinkOptions(args []*syntax.Word, words []string, static []bool) (option, dynamic bool) {
	for i, word := range words {
		if !static[i] {
			lit, isLit := args[i].Parts[0].(*syntax.Lit)
			dynamic = dynamic || !isLit || strings.HasPrefix(lit.Value, "-")
			continue
		}
		if word == "--" {
			break
		}
		option = option || copyLinkOption.MatchString(word)
	}
	return option, dynamic
}

// quotedDynamicCopySource accepts only a single scalar shell parameter.
// Double quoting makes its expansion one argv word, including when its value
// contains spaces or starts with a dash.
func quotedDynamicCopySource(word *syntax.Word) bool {
	if word == nil || len(word.Parts) != 1 {
		return false
	}
	quoted, ok := word.Parts[0].(*syntax.DblQuoted)
	if !ok || len(quoted.Parts) != 1 {
		return false
	}
	param, ok := quoted.Parts[0].(*syntax.ParamExp)
	if !ok || param.Param == nil || param.Excl || param.Length || param.Width || param.IsSet ||
		param.Index != nil || param.Slice != nil || param.Repl != nil || param.Names != 0 ||
		param.Exp != nil || param.Flags != nil || param.NestedParam != nil || len(param.Modifiers) != 0 {
		return false
	}
	name := param.Param.Value
	if name == "" {
		return false
	}
	for i, ch := range name {
		if ch != '_' && (ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z') &&
			(i == 0 || ch < '0' || ch > '9') {
			return false
		}
	}
	return true
}

// QuotedDynamicCopyDestinations lists the fixed destinations of cp calls
// whose only source is a quoted scalar parameter. The source is one argv
// word; an option value cannot turn the fixed destination into a write
// somewhere else because it leaves cp without a source operand.
func QuotedDynamicCopyDestinations(command, cwd, home string) []string {
	file, ok := parseShell(command)
	if !ok {
		return nil
	}
	var destinations []string
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) != 3 || !quotedDynamicCopySource(call.Args[1]) {
			return true
		}
		program, programOK := StaticWord(call.Args[0], home)
		dest, destOK := StaticWord(call.Args[2], home)
		if programOK && slices.Contains(copyPrograms, programBase(program)) &&
			destOK && dest != "" && !strings.HasPrefix(dest, "-") {
			destinations = append(destinations, OperandPath(dest, cwd))
		}
		return true
	})
	return destinations
}

// DynamicCopyProtectedBasename reports a copy whose source can expand to an
// option that selects a directory while the final fixed word names a key file.
func DynamicCopyProtectedBasename(command, home string) bool {
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) < 3 || found {
			return !found
		}
		program, static := StaticWord(call.Args[0], home)
		if !static || !slices.Contains(copyPrograms, programBase(program)) {
			return true
		}
		last, static := StaticWord(call.Args[len(call.Args)-1], home)
		if !static {
			return true
		}
		base := filepath.Base(last)
		if base != "authorized_keys" && base != "authorized_keys2" {
			return true
		}
		for _, arg := range call.Args[1 : len(call.Args)-1] {
			if _, static := StaticWord(arg, home); !static {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// ProcCWDWriteOperand identifies proc cwd aliases whose meaning depends on
// the process opening the path.
func ProcCWDWriteOperand(path string) bool {
	if !strings.HasPrefix(path, "/proc/") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(path, "/proc/"), "/")
	if len(parts) < 2 || parts[1] != "cwd" {
		return false
	}
	if parts[0] == "self" {
		return true
	}
	if parts[0] == "" {
		return false
	}
	for _, ch := range parts[0] {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

// archiveCopyDestination reads the final destination of an rsync, pax, or
// cpio copy. Their operand grammar differs from cp's option grammar.
func archiveCopyDestination(args []string, static []bool, cwd string) string {
	for i := len(args) - 1; i >= 0; i-- {
		if !static[i] {
			return ""
		}
		if args[i] == "--" {
			continue
		}
		if !strings.HasPrefix(args[i], "-") {
			path := args[i]
			if !filepath.IsAbs(path) {
				path = filepath.Join(cwd, path)
			}
			return filepath.Clean(path)
		}
	}
	return ""
}

// gitMaterializationScope identifies worktree operations that can install a
// link whose name is not available from the shell command. A fixed clone
// destination narrows the uncertainty; worktree updates can change any name
// in the repository, even when -C starts Git in a subdirectory.
//
// Only a materializing subcommand (clone or a worktree update) installs a
// link. Global options that redirect the repository or worktree, or that the
// parser does not know, only matter once such a subcommand is found, so the
// scan reaches the subcommand before it decides. A read subcommand such as
// show, diff or log installs no link whatever the global options are; the
// joined -C<path>, --git-dir=<path> and --bare forms are read the same way as
// their spaced spellings so they no longer force a global opaque scope.
func gitMaterializationScope(args []string, static []bool, cwd string) (string, bool) {
	working := cwd
	scopeUnknown := false
	for i := 0; i < len(args); i++ {
		if !static[i] {
			return working, true
		}
		arg := args[i]
		switch {
		case arg == "-C" || arg == "--chdir":
			i++
			if i >= len(args) || !static[i] || args[i] == "" {
				return "", true
			}
			working = OperandPath(args[i], working)
			continue
		case strings.HasPrefix(arg, "-C") && len(arg) > 2:
			working = OperandPath(arg[2:], working)
			continue
		case arg == "-c" || arg == "--config-env":
			i++
			if i >= len(args) || !static[i] {
				return "", true
			}
			if gitConfigRedirectsTree(args[i]) {
				scopeUnknown = true
			}
			continue
		case strings.HasPrefix(arg, "-c") && len(arg) > 2:
			if gitConfigRedirectsTree(arg[len("-c"):]) {
				scopeUnknown = true
			}
			continue
		case arg == "--git-dir" || arg == "--work-tree" ||
			arg == "--namespace" || arg == "--super-prefix":
			i++
			if i >= len(args) || !static[i] {
				return "", true
			}
			// The repository or worktree can be redirected by these options.
			scopeUnknown = true
			continue
		case strings.HasPrefix(arg, "--git-dir=") || strings.HasPrefix(arg, "--work-tree=") ||
			strings.HasPrefix(arg, "--namespace=") || strings.HasPrefix(arg, "--super-prefix="):
			scopeUnknown = true
			continue
		case strings.HasPrefix(arg, "-"):
			// An unknown global option may redirect the worktree, so the scope
			// is unknown; only a materializing subcommand installs a link.
			scopeUnknown = true
			continue
		}
		switch arg {
		case "clone":
			// Clone's final operand is a destination only when both source and
			// destination are explicit ordinary operands. Otherwise the name
			// depends on Git's option and URL grammar.
			if scopeUnknown {
				return "", true
			}
			if len(args)-i == 3 && static[i+1] && static[i+2] &&
				!strings.HasPrefix(args[i+1], "-") && !strings.HasPrefix(args[i+2], "-") {
				return OperandPath(args[i+2], working), true
			}
			return working, true
		case "checkout", "switch", "pull", "apply", "restore", "reset", "merge", "rebase", "cherry-pick", "am":
			if scopeUnknown {
				return "", true
			}
			return gitWorktreeRoot(working), true
		default:
			// A read or inspection subcommand (show, diff, log, config, ...)
			// installs no link, whatever the global options were.
			return "", false
		}
	}
	return "", false
}

// gitConfigRedirectsTree reports a -c/--config-env assignment that can move the
// repository's worktree or make it bare, changing where a later write lands.
func gitConfigRedirectsTree(assignment string) bool {
	option := strings.ToLower(assignment)
	return strings.HasPrefix(option, "core.worktree=") || strings.HasPrefix(option, "core.bare=")
}

// gitWorktreeRoot uses the nearest .git marker, as Git does for a worktree
// update from a subdirectory. Resolve directory aliases to the physical tree
// used by the write-path proof; if no worktree is found, the scope is global.
func gitWorktreeRoot(working string) string {
	working = filepath.Clean(working)
	resolved, err := filepath.EvalSymlinks(working)
	if err != nil {
		return ""
	}
	working = resolved
	for dir, depth := working, 0; depth < 64; dir, depth = filepath.Dir(dir), depth+1 {
		marker, err := os.Lstat(filepath.Join(dir, ".git"))
		if err == nil {
			if marker.IsDir() || marker.Mode().IsRegular() {
				return dir
			}
			return ""
		}
		if !os.IsNotExist(err) || filepath.Dir(dir) == dir {
			return ""
		}
	}
	return ""
}

// cpOperands reads the options that can change source and destination
// positions. Unknown or dynamic options make the destination unbounded.
type cpOperandsResult struct {
	sources     []string
	destination string
	preserves   bool
	hard        bool
	symbolic    bool
	noTargetDir bool
	targetDir   bool
	ok          bool
}

func cpOperands(args []string, static []bool) cpOperandsResult {
	var result cpOperandsResult
	var operands []string
	targetDir := ""
	options := true
	for i := 0; i < len(args); i++ {
		if !static[i] {
			return cpOperandsResult{preserves: true}
		}
		arg := args[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || arg == "-" || !strings.HasPrefix(arg, "-") {
			operands = append(operands, arg)
			continue
		}
		if strings.HasPrefix(arg, "--") {
			name, value, joined := strings.Cut(arg[2:], "=")
			option, unique := longOption(name, cpLongOptions)
			if !unique || option == "" {
				return cpOperandsResult{preserves: true}
			}
			switch option {
			case "archive", "recursive", "no-dereference":
				result.preserves = true
			case "link":
				if joined {
					return cpOperandsResult{preserves: true}
				}
				result.hard = true
			case "symbolic-link":
				if joined {
					return cpOperandsResult{preserves: true}
				}
				result.symbolic = true
			case "no-target-directory":
				if joined {
					return cpOperandsResult{preserves: true}
				}
				result.noTargetDir = true
			case "preserve":
				if joined && (value == "links" || strings.Contains(","+value+",", ",links,")) {
					result.preserves = true
				}
			case "target-directory", "suffix":
				if !joined {
					i++
					if i >= len(args) || !static[i] {
						return cpOperandsResult{preserves: true}
					}
					value = args[i]
				}
				if value == "" {
					return cpOperandsResult{preserves: true}
				}
				if option == "target-directory" {
					targetDir = value
				}
			case "no-preserve", "sparse", "reflink", "backup", "update", "context":
				// These take only an optional joined value.
			default:
				if joined {
					return cpOperandsResult{preserves: true}
				}
			}
			continue
		}
		for j := 1; j < len(arg); j++ {
			switch arg[j] {
			case 'a', 'P', 'd', 'r', 'R':
				result.preserves = true
			case 'l':
				result.hard = true
			case 's':
				result.symbolic = true
			case 'T':
				result.noTargetDir = true
			case 't', 'S':
				value := arg[j+1:]
				if value == "" {
					i++
					if i >= len(args) || !static[i] {
						return cpOperandsResult{preserves: true}
					}
					value = args[i]
				}
				if value == "" {
					return cpOperandsResult{preserves: true}
				}
				if arg[j] == 't' {
					targetDir = value
				}
				j = len(arg)
			case 'b', 'c', 'f', 'H', 'i', 'L', 'n', 'N', 'p', 'u', 'v', 'x', 'X', 'Z':
			default:
				return cpOperandsResult{preserves: true}
			}
		}
	}
	if targetDir != "" {
		if len(operands) == 0 || result.noTargetDir {
			return cpOperandsResult{preserves: result.preserves}
		}
		result.sources, result.destination, result.targetDir, result.ok = operands, targetDir, true, true
		return result
	}
	if len(operands) < 2 || result.noTargetDir && len(operands) > 2 {
		return cpOperandsResult{preserves: result.preserves}
	}
	result.sources, result.destination, result.ok = operands[:len(operands)-1], operands[len(operands)-1], true
	return result
}

func cpDestination(args []string, static []bool, cwd string) string {
	parsed := cpOperands(args, static)
	if !parsed.ok {
		return ""
	}
	destination := parsed.destination
	if !filepath.IsAbs(destination) {
		destination = filepath.Join(cwd, destination)
	}
	return filepath.Clean(destination)
}

// CopyDestination returns a statically understood cp destination.
func CopyDestination(argv []string, cwd string) string {
	args, ok := copyProgramArgs(argv)
	if !ok || len(args) == 0 {
		return ""
	}
	return cpDestination(args, makeStatic(len(args)), cwd)
}

// IsCopyProgram identifies a copy call, including a multicall applet.
func IsCopyProgram(argv []string) bool {
	_, ok := copyProgramArgs(argv)
	return ok
}

func copyProgramArgs(argv []string) ([]string, bool) {
	if len(argv) == 0 {
		return nil, false
	}
	program := programBase(argv[0])
	for depth := 0; slices.Contains(multicallPrograms, program); depth++ {
		if depth >= 4 || len(argv) < 2 {
			return nil, false
		}
		argv = argv[1:]
		program = programBase(argv[0])
	}
	return argv[1:], slices.Contains(copyPrograms, program)
}

func cpDiskSymlink(args []string, static []bool, cwd, home string, facts map[string]string, record bool) bool {
	parsed := cpOperands(args, static)
	if !parsed.ok {
		return true
	}
	for _, source := range parsed.sources {
		if diskSourceMayLink(source, cwd, home, facts, record, os.Lstat) {
			return true
		}
	}
	return false
}

func archiveCopiesDiskSymlink(program string, args []string, static []bool, cwd, home string, facts map[string]string, record bool) bool {
	operands := make([]string, 0, len(args))
	for i, arg := range args {
		if !static[i] || strings.HasPrefix(arg, "-") {
			continue
		}
		operands = append(operands, arg)
	}
	if len(operands) < 2 {
		// cpio/pax can take source names from stdin. A later write into the
		// destination must not assume those names were regular files.
		return true
	}
	for _, source := range operands[:len(operands)-1] {
		if program == "rsync" && !strings.HasPrefix(source, "/") &&
			!strings.HasPrefix(source, "./") && !strings.HasPrefix(source, "../") &&
			strings.Contains(source, ":") {
			// A remote source cannot be inspected by the hook client. It can
			// materialize a link at any name in the destination tree.
			return true
		}
		if diskSourceMayLink(source, cwd, home, facts, record, os.Lstat) {
			return true
		}
	}
	return false
}

func diskSourceMayLink(source, cwd, home string, facts map[string]string, record bool, lstat func(string) (os.FileInfo, error)) bool {
	path := OperandPath(source, cwd)
	key := SourceLinkFactPrefix + path
	if !record && facts != nil {
		if fact, ok := facts[key]; ok {
			return fact != "0"
		}
	}
	info, err := lstat(path)
	if err == nil {
		linked := info.Mode()&os.ModeSymlink != 0 || info.IsDir() && treeHasSymlink(path)
		if record {
			if linked {
				facts[key] = "1"
			} else {
				facts[key] = "0"
			}
		}
		return linked
	}
	if record {
		if os.IsNotExist(err) {
			facts[key] = "0"
			return false
		}
		facts[key] = "?"
		return true
	}
	// An older hook has no fact. ProtectHome and PrivateTmp turn even an
	// existing source into ENOENT for the gateway.
	return runtime.GOOS == "linux" &&
		((home != "" && (path == home || strings.HasPrefix(path, home+string(filepath.Separator)))) ||
			path == "/home" || strings.HasPrefix(path, "/home/") ||
			path == "/tmp" || strings.HasPrefix(path, "/tmp/") ||
			path == "/var/tmp" || strings.HasPrefix(path, "/var/tmp/"))
}

// treeHasSymlink reports a link inside a directory a recursive copy keeps.
// A tree that cannot be read or is larger than the bound counts as one.
func treeHasSymlink(root string) bool {
	seen, found := 0, false
	err := filepath.WalkDir(root, func(_ string, entry fs.DirEntry, err error) error {
		seen++
		if err != nil || seen > 4096 || entry.Type()&fs.ModeSymlink != 0 {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found || err != nil
}

// archiveDestination is the directory an archive call writes in, or "" when
// it can write anywhere.
func archiveDestination(program string, args []string, static []bool, cwd string) string {
	if program != "rsync" && !archiveCopiesLinks(program, args, static) && archiveNamesEscape(program, args, static) {
		return ""
	}
	destination := cwd
	if strings.HasSuffix(program, "tar") {
		var ok bool
		destination, ok = tarDestination(args, static, cwd)
		if !ok {
			return ""
		}
	} else if program == "rsync" || program == "ditto" ||
		(program == "pax" || program == "cpio" || program == "bsdcpio") && archiveCopiesLinks(program, args, static) {
		return archiveCopyDestination(args, static, cwd)
	} else if program == "unzip" || program == "cpio" || program == "bsdcpio" || strings.HasPrefix(program, "7z") {
		for i, arg := range args {
			option := ""
			switch {
			case program == "unzip" && arg == "-d":
				option = "-d"
			case (program == "cpio" || program == "bsdcpio") && (arg == "-D" || arg == "--directory"):
				option = arg
			case strings.HasPrefix(program, "7z") && arg == "-o":
				option = "-o"
			}
			if option != "" && i+1 < len(args) {
				if !static[i+1] {
					return ""
				}
				destination = args[i+1]
			} else if program == "unzip" && strings.HasPrefix(arg, "-d") && len(arg) > 2 {
				if !static[i] {
					return ""
				}
				destination = arg[2:]
			} else if strings.HasPrefix(program, "7z") && strings.HasPrefix(arg, "-o") && len(arg) > 2 {
				destination = arg[2:]
			}
		}
	}
	if !filepath.IsAbs(destination) {
		destination = filepath.Join(cwd, destination)
	}
	return filepath.Clean(destination)
}

// tarDestination reads destination-bearing tar options in short clusters,
// old-style option words, and unique long-option abbreviations. Ambiguity
// leaves the archive scope global.
func tarDestination(args []string, static []bool, cwd string) (string, bool) {
	destination := cwd
	changed := false
	consume := func(value string) bool {
		if value == "" || changed {
			return false
		}
		destination, changed = value, true
		return true
	}
	options := true
	for i := 0; i < len(args); i++ {
		if !static[i] {
			return "", false
		}
		arg := args[i]
		if arg == "--" {
			options = false
			continue
		}
		if !options {
			continue
		}
		if strings.HasPrefix(arg, "--") {
			name, value, joined := strings.Cut(arg[2:], "=")
			option, unique := longOption(name, []string{
				"directory", "dir", "cd", "one-top-level", "file", "strip-components",
				"exclude", "zstd", "absolute-names", "get", "extract", "list", "create",
			})
			if !unique {
				return "", false
			}
			switch option {
			case "directory", "dir", "cd":
				if !joined {
					i++
					if i >= len(args) || !static[i] {
						return "", false
					}
					value = args[i]
				}
				if !consume(value) {
					return "", false
				}
			case "one-top-level":
				if joined && !consume(value) {
					return "", false
				}
			case "file", "strip-components", "exclude":
				if !joined {
					i++
					if i >= len(args) || !static[i] || args[i] == "" {
						return "", false
					}
				}
			case "zstd", "absolute-names", "get", "extract", "list", "create":
				if joined {
					return "", false
				}
			default:
				// A future or unknown destination option cannot be scoped safely.
				return "", false
			}
			continue
		}
		oldStyle := i == 0 && !strings.HasPrefix(arg, "-")
		if !oldStyle && !strings.HasPrefix(arg, "-") {
			continue
		}
		cluster := strings.TrimPrefix(arg, "-")
		for j := 0; j < len(cluster); j++ {
			switch cluster[j] {
			case 'C':
				value := cluster[j+1:]
				if oldStyle || value == "" {
					i++
					if i >= len(args) || !static[i] {
						return "", false
					}
					value = args[i]
				}
				if !consume(value) {
					return "", false
				}
				if !oldStyle {
					j = len(cluster)
				}
			case 'f':
				if oldStyle || j+1 == len(cluster) {
					i++
					if i >= len(args) || !static[i] {
						return "", false
					}
				}
				if !oldStyle {
					j = len(cluster)
				}
			case 'a', 'x', 'z', 'j', 'J', 'v', 'O', 't', 'c', 'P', 'p', 'h', 'k', 'm', 'w', 'U':
			default:
				// Unknown short options may consume a path.
				return "", false
			}
		}
	}
	return destination, true
}

// opaqueProgram is a Windows program that creates links from operands this
// package does not read.
func opaqueProgram(program string) bool {
	switch program {
	case "mklink", "fsutil", "new-item":
		return true
	}
	return false
}

// archiveNamesEscape reports an extraction whose member names can leave the
// destination: cpio and pax keep absolute and parent names by default, as do
// tar -P, unzip -: and 7z -spf; an option supplied at runtime may be one.
func archiveNamesEscape(program string, args []string, static []bool) bool {
	if program == "cpio" || program == "bsdcpio" || program == "pax" {
		return true
	}
	tar := strings.HasSuffix(program, "tar")
	for i, arg := range args {
		if !static[i] {
			return true
		}
		if arg == "--" {
			return false
		}
		short := strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--")
		switch {
		case tar && (arg == "--absolute-names" || short && strings.ContainsRune(arg, 'P') ||
			i == 0 && !strings.HasPrefix(arg, "-") && strings.ContainsRune(arg, 'P')),
			program == "unzip" && short && strings.ContainsRune(arg, ':'),
			strings.HasPrefix(program, "7z") && strings.HasPrefix(arg, "-spf"):
			return true
		}
	}
	return false
}

func copyPreservesLinks(args []string, static []bool) bool {
	return cpOperands(args, static).preserves
}

func archiveCopiesLinks(program string, args []string, static []bool) bool {
	if program == "rsync" {
		for i, arg := range args {
			if static[i] && (arg == "--links" || arg == "--archive" ||
				strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.ContainsAny(arg[1:], "al")) {
				return true
			}
		}
	}
	if program == "cpio" || program == "bsdcpio" || program == "pax" {
		for i, arg := range args {
			if static[i] && strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") &&
				(program == "pax" && strings.ContainsRune(arg, 'w') || strings.ContainsRune(arg, 'p')) {
				return true
			}
		}
	}
	return false
}

// archiveMayLink reports an archive or sync call that can create links.
func archiveMayLink(program string, args []string, static []bool) bool {
	if program == "jar" {
		for i, arg := range args {
			if static[i] && (arg == "--extract" || arg == "-x" ||
				len(arg) > 0 && len(strings.TrimLeft(arg, "-")) > 0 &&
					strings.HasPrefix(strings.TrimLeft(arg, "-"), "x")) {
				return true
			}
		}
		return false
	}
	if program == "ditto" {
		for i, arg := range args {
			if static[i] && (arg == "-x" || arg == "--extract") {
				return true
			}
		}
		return false
	}
	tar := strings.HasSuffix(program, "tar")
	cpio := program == "cpio" || program == "bsdcpio"
	pax := program == "pax"
	if program == "unzip" || strings.HasPrefix(program, "7z") {
		// Listing and test modes do not extract. 7z needs an x or e command.
		if program == "unzip" {
			for i, arg := range args {
				if static[i] && (arg == "-l" || arg == "-t" || arg == "-Z") {
					return false
				}
			}
			return true
		}
		for i, arg := range args {
			if static[i] && (arg == "x" || arg == "e") {
				return true
			}
		}
		return false
	}
	for i, arg := range args {
		if !static[i] {
			continue
		}
		if arg == "--" {
			return false
		}
		if long, ok := strings.CutPrefix(arg, "--"); ok {
			name, _, _ := strings.Cut(long, "=")
			switch {
			case program == "rsync" && (name == "link-dest" || name == "hard-links"),
				cpio && (name == "link" || name == "extract"),
				tar && (name == "get" || len(name) >= 3 && strings.HasPrefix("extract", name)):
				return true
			}
			continue
		}
		cluster, option := strings.CutPrefix(arg, "-")
		switch {
		case !option:
			if i == 0 && tar && tarExtracts(arg) {
				return true
			}
		case program == "rsync" && strings.ContainsRune(cluster, 'H'),
			cpio && strings.ContainsAny(cluster, "il"),
			pax && strings.ContainsAny(cluster, "rl"),
			tar && tarExtracts(cluster):
			return true
		}
	}
	return false
}

// tarExtracts reports x in a tar option cluster, before an option that takes
// the rest of the word as its value.
func tarExtracts(cluster string) bool {
	for _, c := range cluster {
		switch {
		case c == 'x':
			return true
		case strings.ContainsRune("fCTXbIKNgVHFL", c):
			return false
		}
	}
	return false
}

func makeStatic(n int) []bool {
	static := make([]bool, n)
	for i := range static {
		static[i] = true
	}
	return static
}

// wrappedMayLink reads the words of a wrapper's text from the first ln, cp,
// or archive program on as that program's arguments and reports one that can
// link files; for cp a word with a parameter or a substitution counts as a
// link option. copyWord reports that a cp program word was found.
func wrappedMayLink(text string) (mayLink, copyWord bool) {
	words := strings.FieldsFunc(text, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune("\"'`;&|(){}<>=", r)
	})
	for i, word := range words {
		program, rest := programBase(word), words[i+1:]
		switch {
		case slices.Contains(linkPrograms, program):
			return true, copyWord
		case slices.Contains(copyPrograms, program):
			for _, arg := range rest {
				if strings.ContainsAny(arg, "$`") || copyLinkOption.MatchString(arg) {
					return true, true
				}
			}
			copyWord = true
		case slices.Contains(archivePrograms, program) && archiveMayLink(program, rest, makeStatic(len(rest))):
			return true, copyWord
		}
	}
	return false, copyWord
}

// programBase is a program's lowercased basename without ".exe".
func programBase(word string) string {
	if index := strings.LastIndexAny(word, `/\`); index >= 0 {
		word = word[index+1:]
	}
	return strings.TrimSuffix(strings.ToLower(word), ".exe")
}

// Long options of ln and cp that matter here, and the flags that share their
// prefixes; GNU accepts any unambiguous abbreviation.
var (
	lnLongOptions = []string{"symbolic", "relative", "no-target-directory", "target-directory", "suffix",
		"force", "no-dereference", "backup", "interactive", "logical", "physical", "verbose", "directory",
		"help", "version"}
	cpLongOptions = []string{"link", "symbolic-link", "no-target-directory", "target-directory", "suffix",
		"sparse", "no-preserve", "archive", "attributes-only", "backup", "copy-contents", "debug",
		"dereference", "force", "interactive", "keep-directory-symlink", "no-clobber", "no-dereference",
		"preserve", "parents", "recursive", "reflink", "remove-destination", "strip-trailing-slashes",
		"update", "verbose", "one-file-system", "context", "help", "version"}
	optionsWithValue = []string{"target-directory", "suffix"}
)

// longOption expands an abbreviated long option. ok is false when it is
// ambiguous; an unknown option is a flag.
func longOption(name string, options []string) (string, bool) {
	if slices.Contains(options, name) {
		return name, true
	}
	match := ""
	for _, option := range options {
		if strings.HasPrefix(option, name) {
			if match != "" {
				return "", false
			}
			match = option
		}
	}
	return match, true
}

// add records the links that one ln, link or cp call creates. It returns
// false when its options or operands are not understood.
func (l *shellLinks) add(program string, args []string, cwd string) bool {
	if program == "link" || program == "glink" {
		if len(args) != 2 || strings.HasPrefix(args[0], "-") {
			return false
		}
		l.record(args[0], args[1], false, cwd)
		return true
	}
	if slices.Contains(copyPrograms, program) {
		parsed := cpOperands(args, makeStatic(len(args)))
		if !parsed.ok || parsed.hard && parsed.symbolic {
			return false
		}
		if !parsed.hard && !parsed.symbolic {
			return true
		}
		dir := ""
		dest := parsed.destination
		if parsed.targetDir || len(parsed.sources) > 1 || !parsed.noTargetDir {
			dir = dest
		}
		literal := parsed.symbolic
		for _, source := range parsed.sources {
			if len(parsed.sources) == 1 && !parsed.targetDir {
				l.record(source, dest, literal, cwd)
			}
			if dir != "" {
				l.record(source, filepath.Join(dir, filepath.Base(filepath.Clean(source))), literal, cwd)
			}
		}
		return true
	}
	symbolic, relative, noTargetDir := false, false, false
	var targetDir string
	var operands []string
	optionsEnd := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if optionsEnd || arg == "-" || !strings.HasPrefix(arg, "-") {
			operands = append(operands, arg)
			continue
		}
		if arg == "--" {
			optionsEnd = true
			continue
		}
		if strings.HasPrefix(arg, "--") {
			name, value, hasValue := strings.Cut(arg[2:], "=")
			option, ok := longOption(name, lnLongOptions)
			if !ok {
				return false
			}
			if slices.Contains(optionsWithValue, option) && !hasValue {
				if i++; i >= len(args) {
					return false
				}
				value = args[i]
			}
			switch option {
			case "symbolic":
				symbolic = true
			case "relative":
				relative = true
			case "no-target-directory":
				noTargetDir = true
			case "target-directory":
				targetDir = value
			}
			continue
		}
		for j := 1; j < len(arg); j++ {
			switch c := arg[j]; {
			case c == 's':
				symbolic = true
			case c == 'r':
				relative = true
			case c == 'T':
				noTargetDir = true
			case c == 't' || c == 'S':
				value := arg[j+1:]
				if value == "" {
					if i++; i >= len(args) {
						return false
					}
					value = args[i]
				}
				if c == 't' {
					targetDir = value
				}
				j = len(arg)
			}
		}
	}
	sources, dest, dir := operands, "", targetDir
	switch {
	case targetDir != "":
	case len(operands) == 1:
		dir = cwd
		l.relative = true
	case len(operands) == 2:
		sources, dest = operands[:1], operands[1]
		if !noTargetDir {
			// The name is a directory when it exists as one.
			dir = dest
		}
	case len(operands) > 2:
		sources, dir = operands[:len(operands)-1], operands[len(operands)-1]
	}
	// A symbolic link stores its target as written, relative to the link's
	// directory; ln -r and a hard link name the source file.
	literal := symbolic && !relative
	for _, source := range sources {
		if dest != "" {
			l.record(source, dest, literal, cwd)
		}
		if dir != "" {
			l.record(source, filepath.Join(dir, filepath.Base(filepath.Clean(source))), literal, cwd)
		}
	}
	return true
}

// record adds the alias that a link at name to source creates, under the
// literal name and the name with its directory's existing links resolved.
func (l *shellLinks) record(source, name string, literal bool, cwd string) {
	if source == "" || name == "" {
		return
	}
	l.relative = l.relative || !filepath.IsAbs(source) || !filepath.IsAbs(name)
	name = absolutePath(name, cwd)
	target := source
	if !filepath.IsAbs(target) {
		base := cwd
		if literal {
			base = filepath.Dir(name)
		}
		target = base + string(filepath.Separator) + target
	}
	l.aliases = append(l.aliases, linkAlias{name: name, target: target})
	if dir, ok := resolveWritePath(filepath.Dir(name), 0); ok {
		if resolved := filepath.Join(dir, filepath.Base(name)); resolved != name {
			l.aliases = append(l.aliases, linkAlias{name: resolved, target: target})
		}
	}
}

func absolutePath(path, cwd string) string {
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	return filepath.Clean(path)
}

// maxLinkAliasSteps bounds the names one write operand is followed through.
const maxLinkAliasSteps = 256

// resolve maps an absolute write operand to its target as resolveWritePath
// and protectedFiles.target do, and also through the links the command
// creates: when a name the operand may denote, itself or under a linked
// directory, reaches a protected file, that file is the target. ok is false
// when one of those names cannot be resolved.
func (l shellLinks) resolve(path string, protected protectedFiles) (string, bool) {
	target := func(path string) (string, bool) {
		resolved, ok := resolveWritePath(path, 0)
		if ok {
			resolved, ok = protected.target(resolved)
		}
		return resolved, ok
	}
	resolved, ok := target(path)
	if !ok || len(l.aliases) == 0 || protected.has(resolved) {
		return resolved, ok
	}
	seen := map[string]bool{path: true}
	queue := []string{path}
	for steps := 0; len(queue) > 0; {
		name := queue[0]
		queue = queue[1:]
		forms := []string{name}
		if dir, ok := resolveWritePath(filepath.Dir(name), 0); ok {
			forms = append(forms, filepath.Join(dir, filepath.Base(name)))
		}
		if full, ok := resolveWritePath(name, 0); ok {
			forms = append(forms, full)
		}
		for _, form := range forms {
			for _, alias := range l.aliases {
				rest, under := cutPathPrefix(form, alias.name)
				if !under {
					continue
				}
				next := alias.target
				if rest != "" {
					next += string(filepath.Separator) + rest
				}
				if seen[next] {
					continue
				}
				seen[next] = true
				if steps++; steps > maxLinkAliasSteps {
					return "", false
				}
				linked, ok := target(next)
				if !ok {
					return "", false
				}
				if protected.has(linked) {
					return linked, true
				}
				queue = append(queue, next)
			}
		}
	}
	return resolved, true
}

// cutPathPrefix returns the rest of path under prefix. Names compare without
// case on macOS and Windows, whose file systems usually ignore it.
func cutPathPrefix(path, prefix string) (string, bool) {
	if len(path) < len(prefix) || !samePathName(path[:len(prefix)], prefix) {
		return "", false
	}
	rest := path[len(prefix):]
	if rest == "" {
		return "", true
	}
	if !os.IsPathSeparator(rest[0]) {
		return "", false
	}
	return rest[1:], true
}

func samePathName(a, b string) bool {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
