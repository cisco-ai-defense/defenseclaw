// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package hookpaths resolves tool write targets in the invoking user's process.
package hookpaths

import (
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
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
		name, static := staticShellWord(redirect.Word, env, home != "")
		if !static {
			dynamic = true
			return true
		}
		if name == "" {
			return true
		}
		if !filepath.IsAbs(name) && filepath.IsAbs(cwd) {
			name = filepath.Join(cwd, name)
		}
		operands = append(operands, filepath.Clean(name))
		return true
	})
	return operands, true, dynamic
}

// parseShell parses a command of at most MaxPayloadBytes as bash, or else as
// POSIX sh.
func parseShell(command string) (*syntax.File, bool) {
	if len(command) > MaxPayloadBytes {
		return nil, false
	}
	var file *syntax.File
	var err error
	for _, variant := range []syntax.LangVariant{syntax.LangBash, syntax.LangPOSIX} {
		file, err = syntax.NewParser(syntax.Variant(variant)).Parse(strings.NewReader(command), "")
		if err == nil {
			return file, true
		}
	}
	return nil, false
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
	resolved, _, _, ok := walkWritePath("", path, linkDepth, false)
	return resolved, ok
}

// walkWritePath resolves both ordinary operands and raw symlink targets. base
// is the already-resolved directory containing a relative target. When collect
// is true, forms includes every traversed name and link hop for opaque-scope
// checks. A missing component is permitted at the end (redirects create
// files), but it cannot be crossed by "..": its link status is unknown.
func walkWritePath(base, path string, linkDepth int, collect bool) (string, []string, int, bool) {
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
	// The stack records the status of components added after base. A link
	// remains marked even after its target is resolved: the following ".."
	// would otherwise erase the evidence of that hop.
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
				link, err := os.Readlink(candidate)
				if err != nil {
					return "", nil, linkDepth, false
				}
				var extra []string
				var nextDepth int
				var ok bool
				current, extra, nextDepth, ok = walkWritePath(current, link, linkDepth+1, collect)
				if !ok || collect && len(forms)+len(extra) > maxOpaquePathForms {
					return "", nil, linkDepth, false
				}
				linkDepth = nextDepth
				forms = append(forms, extra...)
				crossed = append(crossed, true)
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

// ResolveWriteTarget resolves an absolute write operand the way the hook
// client does: links are followed, including one whose final file does not
// exist yet. ok is false when the target cannot be resolved.
func ResolveWriteTarget(path string) (string, bool) {
	return resolveWritePath(path, 0)
}

// protectedFile is the identity of one of the user's authorized-keys files. A
// hard link elsewhere names the same file under another path, so a target is
// compared by file identity (device and inode on Unix, volume serial and file
// index on Windows) and not by pathname alone.
type protectedFile struct {
	path    string
	info    os.FileInfo
	unknown bool
}

type protectedFiles []protectedFile

func newProtectedFiles(home string) protectedFiles {
	files := make(protectedFiles, 0, len(AuthorizedKeysFiles))
	for _, path := range AuthorizedKeysPaths(home) {
		protected := protectedFile{path: path}
		info, err := os.Stat(path)
		switch {
		case err == nil:
			protected.info = info
		case !os.IsNotExist(err):
			protected.unknown = true
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
// the same file. When a protected file cannot be identified, a multiply
// linked target may be an alias of it and is reported as unresolvable.
func (files protectedFiles) target(resolved string) (string, bool) {
	var info os.FileInfo
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
		if linkCount(resolved, info) > 1 {
			return "", false
		}
	}
	return resolved, true
}

// Resolve returns a bounded, header-safe map from absolute write operands to
// their filesystem targets. An empty value means resolution was attempted but
// could not be trusted. A regular file maps to itself, unless it is a hard
// link to one of the user's authorized-keys files. An operand
// is never dropped silently: when one cannot be listed (over a bound, or the command exceeds
// the shell analysis limits) the map carries TruncatedKey.
func Resolve(payload []byte) string {
	if len(payload) > MaxPayloadBytes {
		return incompleteEvidence("")
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(payload, &envelope) != nil {
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
	links := shellLinks{known: true}
	var safeRedirects map[string]bool
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
				operands, parsed, _ = ShellWriteOperands(command, cwd, home)
				truncated = truncated || !parsed
				safeRedirects = SafeShellRedirects(command, cwd, home)
				// A link the command creates can make a later write a write
				// to a protected file (GAP-1505). The command of an
				// apply_patch tool is a patch envelope, not shell.
				if !isApplyPatchToolName(tool) {
					links = commandLinks(command, cwd, home)
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
		resolved, ok := "", false
		if links.known {
			resolved, ok = links.resolve(path, protected)
		} else if safeRedirect && safeRedirects[path] {
			if direct, directOK := resolveWritePath(path, 0); directOK {
				resolved, ok = protected.target(direct)
			}
		} else if links.opaque && (!links.opaqueTarget(path) || !links.opaqueTargetExceptCopy(path, path) && slices.Contains(links.copyDestinations, path)) {
			resolved, ok = links.resolve(path, protected)
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
	// Exact shell operands take precedence over a duplicate PathFact. Their
	// early-redirect exemption must not cover a later command writer.
	for _, operand := range operands {
		add(operand, true, true)
	}
	for _, candidate := range facts.Paths {
		if candidate.Access != actionfacts.PathAccessWrite && candidate.Access != actionfacts.PathAccessAppend {
			continue
		}
		path := candidate.Resolved
		if path == "" {
			path = candidate.Normalized
		}
		add(path, false, false)
	}
	// An apply_patch edit names its files in the patch envelope, not in a
	// redirect. Unknown targets make the map incomplete.
	patchTargets, patchKnown := ApplyPatchWriteTargets(tool, args, "", cwd, home)
	truncated = truncated || !patchKnown
	for _, target := range patchTargets {
		add(target, true, false)
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
	archivePrograms   = []string{"rsync", "cpio", "bsdcpio", "pax", "tar", "gtar", "bsdtar", "unzip", "7z", "7za", "7zr"}
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
		return true
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
	_, forms, _, ok := walkWritePath("", path, linkDepth, true)
	return forms, ok
}

// commandLinks lists the links that ln, link and cp --link or
// --symbolic-link create in command, in any order: a link made after a write
// only makes the result more conservative.
func commandLinks(command, cwd, home string) shellLinks {
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
	env := expand.ListEnviron("HOME=" + strings.TrimRight(home, "/"))
	renames, cds := false, false
	var copyScopes []string
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
			if slices.Contains(static, false) || !links.add(program, words[1:], cwd) {
				links.unknown(true)
			}
		case slices.Contains(copyPrograms, program):
			destination := cpDestination(words[1:], static[1:], cwd)
			if destination != "" {
				links.copyDestinations = append(links.copyDestinations, destination)
			}
			option, dynamic := copyLinkOptions(args[1:], words[1:], static[1:])
			if copyPreservesLinks(words[1:], static[1:]) {
				copyScopes = append(copyScopes, destination)
				if cpDiskSymlink(words[1:], static[1:], cwd) {
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
				if program == "rsync" && copiesDiskSymlink(words[1:], static[1:], cwd) {
					links.unknownIn(destination)
				}
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
	if len(links.aliases) > 0 && (renames || cds && links.relative) {
		links.unknown(true)
	}
	// Scopes are read against the starting directory; after a directory
	// change a relative write may land in a scope under another name.
	if cds && len(links.opaqueScopes) > 0 {
		links.globalOpaque = true
	}
	return links
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

// SafeShellRedirects reports operands opened by the shell before any command
// in this line can create a link. Redirects on an extracting command are
// opened before the command starts. Repeated writes to one path are safe only
// when every occurrence precedes link creation.
func SafeShellRedirects(command, cwd, home string) map[string]bool {
	result := make(map[string]bool)
	file, ok := parseShell(command)
	if !ok {
		return result
	}
	statements, linear := linearShellStatements(file)
	if !linear {
		return result
	}
	seenLink := false
	for _, stmt := range statements {
		for _, redirect := range stmt.Redirs {
			switch redirect.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
			default:
				continue
			}
			path, static := StaticWord(redirect.Word, home)
			if !static || path == "" {
				continue
			}
			if !filepath.IsAbs(path) {
				path = filepath.Join(cwd, path)
			}
			path = filepath.Clean(path)
			if earlier, present := result[path]; present {
				result[path] = earlier && !seenLink
			} else {
				result[path] = !seenLink
			}
		}
		start, end := int(stmt.Pos().Offset()), int(stmt.End().Offset())
		if start < 0 || end > len(command) || start >= end {
			seenLink = true
			continue
		}
		site := commandLinks(command[start:end], cwd, home)
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
				case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
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
	if command == "" || isApplyPatchToolName(tool) {
		return Links{links: shellLinks{known: true}}
	}
	links := Links{links: commandLinks(command, cwd, home)}
	if len(links.links.aliases) > 0 {
		links.protected = newProtectedFiles(home)
	}
	return links
}

// OpaqueTarget reports whether an unreadable link operation can affect path.
// Such operations include a wrapper or multicall binary running ln, an
// interpreter or Windows link call, an archive or sync link option, or an mv
// or relative cd with a link. Archive and copy scopes narrow the affected
// paths. A program word that is not static alone does not count (GAP-1523).
func (l Links) OpaqueTarget(path string) bool {
	return l.links.opaqueTarget(path)
}

// OpaqueTargetExceptOwnCopy checks all scopes except the scope created by
// this copy statement for its own destination.
func (l Links) OpaqueTargetExceptOwnCopy(path, ownCopy string) bool {
	return l.links.opaqueTargetExceptCopy(path, ownCopy)
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

func copyDestination(args []string, static []bool, cwd string) string {
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

// cpOperands reads the options that can change source and destination
// positions. Unknown or dynamic options make the destination unbounded.
func cpOperands(args []string, static []bool) (sources []string, destination string, preserves bool, ok bool) {
	var operands []string
	targetDir := ""
	options := true
	for i := 0; i < len(args); i++ {
		if !static[i] {
			return nil, "", true, false
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
				return nil, "", true, false
			}
			switch option {
			case "archive", "recursive", "no-dereference":
				preserves = true
			case "preserve":
				if joined && (value == "links" || strings.Contains(","+value+",", ",links,")) {
					preserves = true
				}
			case "target-directory", "suffix":
				if !joined {
					i++
					if i >= len(args) || !static[i] {
						return nil, "", true, false
					}
					value = args[i]
				}
				if value == "" {
					return nil, "", true, false
				}
				if option == "target-directory" {
					targetDir = value
				}
			case "no-preserve", "sparse", "reflink", "backup", "update", "context":
				// These take only an optional joined value.
			default:
				if joined {
					return nil, "", true, false
				}
			}
			continue
		}
		for j := 1; j < len(arg); j++ {
			switch arg[j] {
			case 'a', 'P', 'd', 'r', 'R':
				preserves = true
			case 't', 'S':
				value := arg[j+1:]
				if value == "" {
					i++
					if i >= len(args) || !static[i] {
						return nil, "", true, false
					}
					value = args[i]
				}
				if value == "" {
					return nil, "", true, false
				}
				if arg[j] == 't' {
					targetDir = value
				}
				j = len(arg)
			case 'b', 'f', 'H', 'i', 'L', 'l', 'n', 'p', 's', 'T', 'u', 'v', 'x':
			default:
				return nil, "", true, false
			}
		}
	}
	if targetDir != "" {
		if len(operands) == 0 {
			return nil, "", preserves, false
		}
		return operands, targetDir, preserves, true
	}
	if len(operands) < 2 {
		return nil, "", preserves, false
	}
	return operands[:len(operands)-1], operands[len(operands)-1], preserves, true
}

func cpDestination(args []string, static []bool, cwd string) string {
	_, destination, _, ok := cpOperands(args, static)
	if !ok {
		return ""
	}
	if !filepath.IsAbs(destination) {
		destination = filepath.Join(cwd, destination)
	}
	return filepath.Clean(destination)
}

// CopyDestination returns a statically understood cp destination.
func CopyDestination(argv []string, cwd string) string {
	if len(argv) < 2 || !slices.Contains(copyPrograms, programBase(argv[0])) {
		return ""
	}
	return cpDestination(argv[1:], makeStatic(len(argv)-1), cwd)
}

func cpDiskSymlink(args []string, static []bool, cwd string) bool {
	sources, _, _, ok := cpOperands(args, static)
	if !ok {
		return true
	}
	for _, source := range sources {
		if !filepath.IsAbs(source) {
			source = filepath.Join(cwd, source)
		}
		if info, err := os.Lstat(source); err == nil &&
			(info.Mode()&os.ModeSymlink != 0 || info.IsDir() && treeHasSymlink(source)) {
			return true
		}
	}
	return false
}

func copiesDiskSymlink(args []string, static []bool, cwd string) bool {
	operands := make([]string, 0, len(args))
	for i, arg := range args {
		if !static[i] || strings.HasPrefix(arg, "-") {
			continue
		}
		operands = append(operands, arg)
	}
	for _, source := range operands[:max(0, len(operands)-1)] {
		if !filepath.IsAbs(source) {
			source = filepath.Join(cwd, source)
		}
		if info, err := os.Lstat(source); err == nil &&
			(info.Mode()&os.ModeSymlink != 0 || info.IsDir() && treeHasSymlink(source)) {
			return true
		}
	}
	return false
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
	} else if program == "rsync" || (program == "pax" || program == "cpio" || program == "bsdcpio") && archiveCopiesLinks(program, args, static) {
		return copyDestination(args, static, cwd)
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
			option, unique := longOption(name, []string{"directory", "dir", "cd", "one-top-level"})
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
			case 'x', 'z', 'j', 'J', 'v', 'O', 't', 'c', 'P', 'p', 'h', 'k', 'm', 'w', 'U':
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
	_, _, preserves, _ := cpOperands(args, static)
	return preserves
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
	optionsWithValue = []string{"target-directory", "suffix", "sparse", "no-preserve"}
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
	copyCall := slices.Contains(copyPrograms, program)
	options := lnLongOptions
	if copyCall {
		options = cpLongOptions
	}
	hard, symbolic, relative, noTargetDir := false, false, false, false
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
			option, ok := longOption(name, options)
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
			case "symbolic", "symbolic-link":
				symbolic = true
			case "link":
				hard = true
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
			case c == 'l' && copyCall:
				hard = true
			case c == 'r' && !copyCall:
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
	if copyCall && !hard && !symbolic {
		return true
	}
	sources, dest, dir := operands, "", targetDir
	switch {
	case targetDir != "":
	case len(operands) == 1 && !copyCall:
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
	// directory; ln -r, a hard link and cp --link name the source file.
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
