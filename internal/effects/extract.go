// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/psparse"
)

// Extract is the pure entry point: one tool call -> its effects. It never
// panics (a recovered panic becomes a single parser_failure effect), never
// reads the filesystem, and never consults runtime.GOOS. Link resolution is a
// separate step (package fsres); every Target leaves here with
// Link = LinkNotChecked.
func Extract(call Call, o Options) (result Result) {
	defer func() {
		if r := recover(); r != nil {
			result = Result{Surface: call.Surface, Flavor: o.flavor(),
				Effects: []Effect{{Kind: KindOpaque, TargetState: TargetStateUnknown, RoleState: RoleStateUnknown,
					Reasons: []Reason{{Code: ReasonParserFailure, Scope: ScopeStructure}}}}}
		}
	}()

	switch call.Surface {
	case SurfaceFileTool:
		result = extractFileTool(call, o)
	case SurfacePatch:
		result = extractPatch(call, o)
	case SurfaceMCP:
		result = extractMCP(call, o)
	case SurfaceArgv:
		result = extractArgv(call, o)
	default:
		result = extractShell(call, o)
	}
	for i := range result.Effects {
		if result.Effects[i].Target.Link == "" {
			result.Effects[i].Target.Link = LinkNotChecked
		}
		// Case-fold the key on a case-insensitive filesystem (macOS, Windows):
		// one place so no target builder can forget it (review R5F-2).
		if o.CaseInsensitive && result.Effects[i].Target.Type == TargetPath {
			result.Effects[i].Target.CaseFold = true
		}
	}
	// Invariant (review HN-1 / §4): non-empty executable input must yield at
	// least one effect or one structural unknown with a reason. Nothing is
	// silently dropped.
	if executableContent(call) && len(result.Effects) == 0 && len(result.Unknowns) == 0 {
		result.addUnknown(ReasonUnparsedConstruct)
	}
	return result
}

func executableContent(call Call) bool {
	switch call.Surface {
	case SurfaceArgv:
		return len(call.Argv) > 0
	default:
		// Args counts for every surface, including a shell tool whose argument
		// shape Normalize did not recognize (review N1): the call still ran a
		// command, so a zero-effect/zero-reason result is a silent drop.
		return strings.TrimSpace(call.Command) != "" || len(call.Argv) > 0 || len(call.Args) > 0
	}
}

func extractShell(call Call, o Options) Result {
	res := Result{Surface: SurfaceShell, Flavor: o.flavor()}
	dialect := o.Dialect
	if dialect == DialectNone || dialect == "" {
		dialect = inferDialect(call, o)
	}
	res.Dialect = dialect
	var script *Script
	switch dialect {
	case DialectCMD:
		script = parseCMD(call.Command, o)
	case DialectPowerShell:
		script = parsePowerShell(call.Command, o)
	default:
		script = parsePOSIX(call.Command, o)
	}
	w := newWalker(&res, o)
	w.applyWorkdir(call.Workdir)
	w.walkScript(script, 0)
	return res
}

func extractArgv(call Call, o Options) Result {
	// A structured argv (SurfaceArgv): treat argv[0] as the program and the
	// rest as operands, parsed as one shell command without re-lexing (so a
	// space inside an argv element is preserved). We build a Script directly.
	res := Result{Surface: SurfaceArgv, Flavor: o.flavor(), Dialect: DialectPOSIX}
	if len(call.Argv) == 0 {
		return res
	}
	c := &Cmd{}
	for _, a := range call.Argv {
		c.Words = append(c.Words, Word{Value: a, Static: true, Segs: []WordSeg{{Lit: a}}})
	}
	s := &Script{Dialect: DialectPOSIX, Stmts: []*Stmt{{Cmds: []*Cmd{c}}}}
	w := newWalker(&res, o)
	w.applyWorkdir(call.Workdir)
	w.walkScript(s, 0)
	return res
}

// walker carries the in-call state: the running env (in-call assignments update
// it), the running cwd and home with a scope stack, defined functions and
// aliases, the link alias map, and the write that last produced each path key.
type walker struct {
	res        *Result
	o          Options
	cmdNo      int
	funcs      map[string]bool
	aliases    map[string]string
	links      map[string]string // link key -> target physical path (review R7)
	writeByKey map[string]int    // path key -> 1-based effect index that wrote it
	pathShadow bool

	env        map[string]string
	curCWD     string
	curHome    string
	cwdStack   []string
	lastPrim   int // 1-based index of the previous stage's primary effect (pipe join)
	work       int // remaining work budget; 0 -> stop and emit a limit unknown (R3-1)
	overBudget bool
}

const walkWorkBudget = 20000

func newWalker(res *Result, o Options) *walker {
	env := map[string]string{}
	for k, v := range o.Env {
		env[k] = v
	}
	return &walker{res: res, o: o, funcs: map[string]bool{}, aliases: map[string]string{},
		links: map[string]string{}, writeByKey: map[string]int{},
		env: env, curCWD: o.CWD, curHome: o.Home, work: walkWorkBudget}
}

// spend consumes one unit of the per-call work budget. It returns false once
// the budget is exhausted, after recording a single limit unknown; callers stop
// walking and never return a partial result as fully known (review R3-1).
func (w *walker) spend() bool {
	if w.overBudget {
		return false
	}
	w.work--
	if w.work <= 0 {
		w.overBudget = true
		w.res.addUnknown(ReasonLimit)
		return false
	}
	return true
}

// opts returns the Options with the running cwd/home/env, for path placement.
func (w *walker) opts() Options {
	o := w.o
	o.CWD = w.curCWD
	o.Home = w.curHome
	o.Env = w.env
	return o
}

func (w *walker) walkScript(s *Script, depth int) {
	if s == nil {
		return
	}
	for _, fn := range s.Funcs {
		w.funcs[fn] = true
	}
	for _, u := range s.Unknowns {
		w.res.addUnknown(u.Reason)
	}
	for _, st := range s.Stmts {
		for _, c := range st.Cmds {
			w.command(c, s.Dialect, depth, st.Cond || c.Cond)
		}
	}
}

func (w *walker) emit(e Effect) int {
	if len(w.res.Effects) >= w.o.maxEffects() {
		w.res.addUnknown(ReasonLimit)
		return 0
	}
	w.res.Effects = append(w.res.Effects, e)
	return len(w.res.Effects)
}

// resolveWord resolves a frontend Word against the running env, expanding a
// leading unquoted ~ to the running home and computing glob-ness from the
// per-segment quoting (review PX-2, PX-6, PX-8).
func (w *walker) resolveWord(wd Word) Word {
	if wd.Reason != "" {
		return wd
	}
	if wd.Segs == nil {
		// A pure literal with no segments (argv surface, cmd/ps frontends).
		out := wd
		if !wd.Quoted && looksGlob(wd.Value) {
			out.Glob = true
		}
		return out
	}
	var b strings.Builder
	glob := false
	quoted := false
	for i, s := range wd.Segs {
		if s.Var != "" {
			v, ok := w.env[s.Var]
			if !ok {
				return Word{Static: false, Reason: ReasonDynamicExpansion, Span: wd.Span}
			}
			// An unquoted variable undergoes field splitting and globbing: if
			// its value carries IFS whitespace or a glob metachar we cannot
			// resolve it to one static target (review N3 V14/V15).
			if !s.Quoted && w.o.flavor() != FlavorWindows {
				if strings.ContainsAny(v, " \t\n") {
					return Word{Static: false, Reason: ReasonDynamicExpansion, Span: wd.Span}
				}
				if looksGlob(v) {
					return Word{Static: true, Glob: true, Value: b.String() + v, Span: wd.Span}
				}
			}
			b.WriteString(v)
			continue
		}
		lit := s.Lit
		// A leading ~ (~/ on POSIX, ~\ or ~/ on Windows) expands to the running
		// home; with no known home it is dynamic (review N6).
		if i == 0 && isTilde(lit, w.o.flavor()) {
			if w.curHome == "" {
				return Word{Static: false, Reason: ReasonDynamicExpansion, Span: wd.Span}
			}
			// a glob/brace after the tilde still globs (review N10 V16).
			if s.Glob && !s.Quoted {
				glob = true
			}
			lit = w.curHome + lit[1:]
			b.WriteString(lit)
			continue
		}
		if s.Quoted {
			quoted = true
		}
		// A wildcard is a glob when unquoted (POSIX uses the frontend's
		// per-segment unescaped-metachar flag), or always on Windows, where
		// cmd/PowerShell expand wildcards even inside quotes (review CM-3, PS-6,
		// PX-6, N10).
		if w.o.flavor() == FlavorWindows {
			if looksGlob(lit) {
				glob = true
			}
		} else if s.Glob && !s.Quoted {
			glob = true
		}
		b.WriteString(lit)
	}
	return Word{Value: b.String(), Static: true, Quoted: quoted, Glob: glob, Span: wd.Span}
}

func (w *walker) resolveWords(in []Word) []Word {
	out := make([]Word, len(in))
	for i, wd := range in {
		out[i] = w.resolveWord(wd)
	}
	return out
}

// command processes one simple command / pipeline stage.
func (w *walker) command(c *Cmd, dialect Dialect, depth int, cond bool) {
	if !w.spend() {
		return
	}
	// Subshell: runs in a child shell; save/restore cwd/home/env.
	if c.Sub != nil {
		saved := w.saveScope()
		w.env = cloneEnv(w.env)
		w.walkScript(c.Sub, depth)
		w.restoreScope(saved)
		w.handleRedirs(c, dialect, w.cmdNo, depth, cond, nil)
		return
	}

	// A pipeline stage or a background command runs in a child shell: its cd and
	// assignments must not leak into the parent (review N2 V3/V7).
	if c.Pipeline || c.Async {
		saved := w.saveScope()
		defer w.restoreScope(saved)
	}

	w.cmdNo++
	cmdNo := w.cmdNo

	// 1. Assignments. A prefix assignment (command present) applies only to a
	// nested child's environment; the command's own argv is expanded with the
	// parent env first (POSIX order -- review N3 V11). A bare assignment updates
	// the running env.
	prefix := len(c.Words) > 0
	childEnv := w.env
	if prefix && len(c.Assigns) > 0 {
		childEnv = cloneEnv(w.env)
	}
	for _, a := range c.Assigns {
		rv := w.resolveWord(a.ValueWord)
		if role, ok := envRoles[a.Name]; ok && role == EnvCode {
			w.envCodeEffect(a.Name, dialect, cmdNo, depth, cond, c.Span)
		}
		if prefix {
			if rv.Static {
				childEnv[a.Name] = rv.Value
			} else {
				delete(childEnv, a.Name)
			}
			continue
		}
		if rv.Static {
			w.env[a.Name] = rv.Value
			// POSIX `~` follows HOME; PowerShell's `~` is fixed at session start
			// and a later $env:USERPROFILE must not rebind it (review R3-9).
			if a.Name == "HOME" && w.o.flavor() == FlavorPOSIX {
				w.curHome = rv.Value
			}
		} else {
			delete(w.env, a.Name)
			if a.Name == "HOME" && w.o.flavor() == FlavorPOSIX {
				w.curHome = "" // a dynamic home makes ~ dynamic (review N3 E2)
			}
		}
	}
	if len(c.Words) == 0 {
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		for _, sub := range c.Nested {
			s := w.saveScope()
			w.walkScript(sub, depth)
			w.restoreScope(s)
		}
		return
	}

	// Resolve the command's words against the parent env.
	words := w.resolveWords(c.Words)
	// Variables a for-loop rebinds are dropped via its own Unbind statement.

	// 2. Strip wrappers.
	inner, wrappers, foreign, fromInput, wrapperUA := w.stripWrappers(words)
	if len(inner) == 0 {
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		return
	}
	prog := inner[0]
	if !prog.Static {
		e := Effect{Kind: KindExec, Target: Target{Type: TargetProcess, Link: LinkNotChecked}, TargetState: TargetStateUnknown, RoleState: RoleStateUnknown, Cond: cond,
			Origin: Origin{Surface: w.res.Surface, Dialect: dialect, Command: cmdNo, Wrappers: wrappers, Depth: depth, Span: c.Span}}
		e.addReason(ReasonDynamicExpansion, ScopeTarget)
		w.lastPrim = w.emit(e)
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		return
	}
	program := programBasename(prog.Value, w.o.flavor())
	origin := Origin{Surface: w.res.Surface, Dialect: dialect, Command: cmdNo, Program: program, Wrappers: wrappers, Depth: depth, Span: c.Span}

	// Calling a user-defined function (including one that shadows cd) may change
	// the cwd unobservably: mark it dynamic (review R3-6 C06/C07).
	if w.funcs[program] {
		w.curCWD = ""
	} else if w.applyCWDChange(program, inner[1:], dialect, cond) {
		// 3. cwd changes (review PX-1/N2).
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		return
	}
	w.unbindReader(program, inner)

	// A per-command working directory from env -C / git -C / make -C / tar -C
	// (review N2): applied to this command's placements only, then restored.
	if dir := commandCWDOverride(program, words, inner); dir != "" {
		if abs, ok, _ := placePath(dir, w.opts()); ok {
			saved := w.curCWD
			w.curCWD = abs
			defer func() { w.curCWD = saved }()
		}
	}

	// 4. Shadowing.
	shadowed := w.funcs[program] || w.aliases[program] != ""
	if w.pathShadow && !strings.Contains(prog.Value, "/") {
		shadowed = true
	}
	if program == "alias" {
		for _, wd := range inner[1:] {
			if wd.Static {
				if eq := strings.IndexByte(wd.Value, '='); eq > 0 {
					w.aliases[wd.Value[:eq]] = wd.Value[eq+1:]
				}
			}
		}
	}

	entry, known := lookupProgram(program, w.o.flavor(), dialect)

	// 5. Base exec effect for every command (review PT-1: never zero effects).
	progTarget, progReason := w.programTarget(prog.Value)
	base := Effect{Kind: KindExec, Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateKnown,
		Target: progTarget, Origin: origin}
	if progReason != "" {
		base.addReason(progReason, ScopeTarget)
	}
	if !known {
		base.RoleState = RoleStateUnknown
		base.addReason(ReasonUnmodeledProgram, ScopeRole)
	}
	if foreign {
		base.Target.Type = TargetRemote
		base.addReason(ReasonForeignContext, ScopeRole)
	}
	if shadowed {
		base.addReason(ReasonProgramShadowed, ScopeRole)
	}
	prevPrim := w.lastPrim
	cmdStart := len(w.res.Effects) // first effect index (0-based) of this command
	unaccounted := wrapperUA
	nestedStart := -1
	// Single choke point (review N4-1 / R5-1): any step that leaves an argv
	// token unaccounted (wrapper, launcher, tar, operands) sets unaccounted;
	// every effect this command emitted (excluding nested substitutions) is
	// then demoted to not-fully-known.
	defer func() {
		if !unaccounted {
			return
		}
		end := len(w.res.Effects)
		if nestedStart >= 0 {
			end = nestedStart
		}
		for i := cmdStart; i < end; i++ {
			w.res.Effects[i].addReason(ReasonUnknownFlag, ScopeRole)
		}
	}()
	baseIdx := w.emit(base)
	w.lastPrim = baseIdx

	// 6. Interpreter reading piped / heredoc stdin as code (review PX-5).
	w.interpreterStdin(c, entry, known, dialect, depth, cond, origin, prevPrim)

	// A command that prints a secret to stdout (gh auth token, vault kv get, ...):
	// emit a read whose data is secret_output and make it this stage's primary,
	// so a pipe into a sender (curl -d @-) joins it (s7-flow). This runs even for
	// a program the table does not model, since the base exec stays unknown.
	if secretStdoutCommand(program, inner[1:]) {
		e := Effect{Kind: KindRead, Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateKnown,
			Target: Target{Type: TargetProcess, Link: LinkNotChecked}, Origin: origin,
			Data: &Data{Kind: DataSecretOutput}}
		if idx := w.emit(e); idx != 0 {
			w.lastPrim = idx
		}
	}

	if !known {
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		for _, sub := range c.Nested {
			s := w.saveScope()
			w.walkScript(sub, depth)
			w.restoreScope(s)
		}
		return
	}

	// cmd /c | /k: the rest is an inner command to unwrap (review CM-9); a cmd
	// reading its command from a pipe is opaque code (review N8 K6).
	if entry.CmdC {
		rest := inner[1:]
		found := false
		for j, a := range rest {
			if a.Static && (strings.EqualFold(a.Value, "/c") || strings.EqualFold(a.Value, "/k")) {
				found = true
				parts := make([]string, 0, len(rest)-j-1)
				allStatic := true
				for _, p2 := range rest[j+1:] {
					if !p2.Static {
						allStatic = false
						break
					}
					parts = append(parts, p2.Value)
				}
				if allStatic && len(parts) > 0 {
					w.unwrapCode(strings.Join(parts, " "), true, DialectCMD, depth, cond, origin)
				}
				break
			}
		}
		if !found && c.PipeIn {
			w.opaqueExec(origin, cond)
		}
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		return
	}

	// powershell/pwsh launched from any dialect: decode -enc and unwrap its
	// -Command / positional script as PowerShell (review N8 K4/K5).
	if entry.PSLaunch {
		// -EncodedArguments carries a base64 CLIXML argument payload for a child
		// host; we do not deserialize it, so the launch is opaque, never a trusted
		// KNOWN (psparse delta review 4 (c)).
		if powershellHasEncodedArgs(inner[1:]) {
			w.opaqueExec(origin, cond)
			w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
			return
		}
		if code, ok := powershellLaunchCode(inner[1:]); ok {
			w.unwrapCode(code, true, DialectPowerShell, depth, cond, origin)
			w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
			return
		}
		// no literal command: a stdin-reading powershell is opaque code.
		if c.PipeIn {
			w.opaqueExec(origin, cond)
		}
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		return
	}

	// tar: mode-dependent create/extract effects, never a silent KNOWN (N7).
	if entry.TarStyle {
		if tarHasUnknownFlag(inner[1:]) {
			unaccounted = true
		}
		w.tarEffects(inner[1:], origin, cond, depth)
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		return
	}
	// git -c <exec-key>=... / git config <exec-key> runs code (review N18).
	if program == "git" && gitHasExecConfig(inner[1:]) {
		w.opaqueExec(origin, cond)
	}
	// programs that run arbitrary code from their arguments (review N18).
	if codeRunsOpaque(program, inner[1:]) {
		w.opaqueExec(origin, cond)
	}
	// git worktree-writing subcommands write/delete an unknown path in the
	// worktree (review R3-4).
	if program == "git" {
		w.gitWorktreeEffects(inner[1:], origin, cond)
	}
	// curl -O / wget write a URL-named file into the output dir or cwd; the
	// basename is unknown (review R3-3).
	if entry.DownloadRemote {
		w.downloadRemoteWrite(program, inner[1:], origin, cond)
	}
	// unzip extracts unknown files into -d dir or the cwd (review R3-3 Z06).
	if program == "unzip" {
		dir := ""
		for i, a := range inner[1:] {
			if a.Static && a.Value == "-d" && i+1 < len(inner[1:]) && inner[1:][i+1].Static {
				dir = inner[1:][i+1].Value
			}
		}
		e := Effect{Kind: KindWrite, Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateUnknown,
			Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked}, Origin: origin}
		if dir != "" {
			e.Target.Spelling = cap4k(dir)
		} else if w.curCWD != "" {
			e.Target.Spelling = cap4k(w.curCWD)
		}
		e.addReason(ReasonOpaqueArchive, ScopeTarget)
		w.emit(e)
	}

	// 7. Operands.
	ops, execCmds, opsUA := w.classifyOperands(inner[1:], entry, dialect)
	if opsUA {
		unaccounted = true
	}
	// find/xargs -exec inner commands run with the matched paths; walk each so
	// its effects (incl. an inner sh -c) appear (review N4). The roots stay as
	// read operands below.
	for _, argv := range execCmds {
		w.command(&Cmd{Words: argv, Cond: cond}, dialect, depth, cond)
	}
	readIdx := []int{}
	readByKeyLocal := map[string]int{} // source path key -> read index, for the copy-label join
	emittedTargetEffect := false
	for _, op := range ops {
		e := w.effectForOperand(op, entry, origin, cond, foreign, fromInput, shadowed, dialect, depth)
		if e == nil {
			continue
		}
		idx := w.emit(*e)
		if idx == 0 {
			continue
		}
		if e.Target.Type == TargetPath || e.Target.Type == TargetRemote || e.Kind == KindNetworkSend {
			emittedTargetEffect = true
		}
		switch e.Kind {
		case KindRead:
			readIdx = append(readIdx, idx)
			if k := e.Target.Key(); k != "" {
				readByKeyLocal[k] = idx
			}
		case KindWrite, KindAppend:
			// A cp/mv/install/rsync destination carries the label of its source
			// read, so a policy label follows the copy (s7-flow).
			if op.copyFrom != "" {
				if abs, ok, _ := placePath(op.copyFrom, w.opts()); ok {
					srcKey := Target{Path: abs, Flavor: w.o.flavor()}.Key()
					if ri, ok := readByKeyLocal[srcKey]; ok && ri != idx {
						w.res.Effects[idx-1].Data = &Data{Kind: DataFile, Sources: []Source{{Kind: SourceEffect, Effect: ri}}}
					}
				}
			}
			if k := e.Target.Key(); k != "" {
				w.writeByKey[k] = idx
			}
		case KindLink:
			w.recordLink(op, ops)
		}
		if op.role == RoleExecCode && op.static && entry.ShellCode {
			childScope := !(program == "eval" || program == "source" || program == ".")
			w.unwrapCodeScoped(op.value, op.static, dialect, depth, cond, origin, childScope)
		}
	}
	// curl/wget/iwr: attach the destination host to the send and join an @- body
	// to the pipe (s7-flow).
	if isHTTPUploader(program) {
		w.finishNetworkSends(cmdStart, c.PipeIn, prevPrim)
	}

	// A cmdlet fed by a pipeline with no explicit path operand acts on the
	// piped input: emit its pipe-role effect with an unknown target (review N5).
	if c.PipeIn && !emittedTargetEffect && entry.PipeRole != "" {
		e := Effect{Kind: entry.PipeRole.kind(), Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateUnknown,
			Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked}, Origin: origin}
		e.addReason(ReasonDynamicExpansion, ScopeTarget)
		w.emit(e)
	}
	// A command run by xargs gets its operands from stdin: emit its positional
	// role with an unknown target so `ls | xargs rm` is a (dynamic) delete
	// rather than exec-only (review R3-3 / round-3 leftovers).
	if fromInput && !emittedTargetEffect {
		if role := posModeRole(entry.Pos); role != RoleNone {
			e := Effect{Kind: role.kind(), Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateUnknown,
				Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked}, Origin: origin}
			e.addReason(ReasonOperandsFromInput, ScopeTarget)
			w.emit(e)
		}
	}

	// 8. Redirections.
	w.handleRedirs(c, dialect, cmdNo, depth, cond, readIdx)

	// 9. Nested command substitutions (their own accounting; excluded above).
	nestedStart = len(w.res.Effects)
	for _, sub := range c.Nested {
		s := w.saveScope()
		w.walkScript(sub, depth)
		w.restoreScope(s)
	}
}

// applyCWDChange updates the running cwd for cd/pushd/popd/Set-Location, and
// returns true when the command is purely a directory change (no other effect).
func (w *walker) applyCWDChange(program string, args []Word, dialect Dialect, cond bool) bool {
	cd := program == "cd" || (dialect == DialectPowerShell && (program == "set-location" || program == "sl" || program == "cd"))
	pushd := program == "pushd" || (dialect == DialectPowerShell && program == "push-location")
	popd := program == "popd" || (dialect == DialectPowerShell && program == "pop-location")
	if !cd && !pushd && !popd {
		return false
	}
	if popd {
		// popd -n pops a stack entry without changing directory; a plain popd
		// rotates to the next. Either way the exact result is not modeled
		// cheaply: go dynamic (review N4-2).
		w.curCWD = ""
		if n := len(w.cwdStack); n > 0 {
			w.cwdStack = w.cwdStack[:n-1]
		}
		return true
	}
	// first non-switch arg is the directory. A bare "-" (cd -) is the previous
	// directory, which we cannot know (review N2/J6). cmd's /d is a switch.
	var dir Word
	found := false
	hasSlashD := false
	for _, a := range args {
		if a.Static && dialect == DialectCMD && (a.Value == "/d" || a.Value == "/D") {
			hasSlashD = true
			continue
		}
		if a.Static && a.Value != "-" && (strings.HasPrefix(a.Value, "-") ||
			(dialect == DialectCMD && strings.HasPrefix(a.Value, "/"))) {
			continue
		}
		dir = a
		found = true
		break
	}
	// pushd with no dir swaps the top two entries; pushd +N/-N rotates: not
	// modeled -> dynamic (review N4-2).
	if pushd {
		if !found || (dir.Static && (strings.HasPrefix(dir.Value, "+") || strings.HasPrefix(dir.Value, "-"))) {
			w.cwdStack = append(w.cwdStack, w.curCWD)
			w.curCWD = ""
			return true
		}
		w.cwdStack = append(w.cwdStack, w.curCWD)
	}
	// cmd `cd D:\x` without /d changes D:'s directory but leaves the active
	// drive's cwd unchanged (review N4-3).
	if cd && dialect == DialectCMD && found && dir.Static && !hasSlashD &&
		len(dir.Value) >= 2 && isDriveLetter(dir.Value[0]) && dir.Value[1] == ':' {
		if w.curCWD == "" || len(w.curCWD) < 2 || !strings.EqualFold(string(w.curCWD[0]), string(dir.Value[0])) {
			return true // different drive, no /d: active cwd unchanged
		}
	}
	switch {
	case !found:
		// bare cd -> the home directory.
		w.curCWD = w.curHome
	case !dir.Static || dir.Value == "-":
		w.curCWD = "" // cd - or a dynamic directory
	default:
		rel := !strings.HasPrefix(dir.Value, "/") && !strings.HasPrefix(dir.Value, "./") && !strings.HasPrefix(dir.Value, "../") && !strings.HasPrefix(dir.Value, "~")
		if w.env["CDPATH"] != "" && rel && !(len(dir.Value) >= 2 && isDriveLetter(dir.Value[0]) && dir.Value[1] == 58) {
			w.curCWD = "" // CDPATH may resolve a bare name elsewhere (review R3-6)
		} else if abs, ok, _ := placePath(dir.Value, w.opts()); ok {
			w.curCWD = abs
		} else {
			w.curCWD = ""
		}
	}
	// A conditional cd (in an if/case/loop/&&-tail/function) cannot be proven to
	// run, so afterwards the cwd is unknown (review N2).
	if cond {
		w.curCWD = ""
	}
	// Bound the cwd length so a long cd chain stays linear (review N4-5): a path
	// that has grown absurdly long goes dynamic instead of being re-cleaned.
	if len(w.curCWD) > maxCWDBytes {
		w.curCWD = ""
	}
	return true
}

const maxCWDBytes = 4096

// programTarget builds the target for a program spelling. A path spelling that
// cannot be placed (dynamic cwd, drive-relative) is reported unknown with the
// reason, never a KNOWN empty path (review N11); reason is "" when known.
func (w *walker) programTarget(spelling string) (Target, ReasonCode) {
	t := Target{Flavor: w.o.flavor(), Link: LinkNotChecked}
	hasSep := strings.Contains(spelling, "/") || (w.o.flavor() == FlavorWindows && strings.Contains(spelling, `\`))
	if hasSep {
		t.Type = TargetPath
		t.Spelling = cap4k(spelling)
		if abs, ok, reason := placePath(spelling, w.opts()); ok {
			t.Path = abs
			return t, ""
		} else {
			return t, reason
		}
	}
	t.Type = TargetProcess
	t.Spelling = cap4k(programBasename(spelling, w.o.flavor()))
	return t, ""
}

// interpreterStdin emits an exec for a shell/interpreter reading its code from a
// pipe or a heredoc/here-string (review PX-5).
func (w *walker) interpreterStdin(c *Cmd, entry Program, known bool, dialect Dialect, depth int, cond bool, origin Origin, baseIdx int) {
	if !known {
		return
	}
	interpreter := entry.ShellCode || entry.Pos == PosFirstExec || entry.Pos == PosFirstCode
	if !interpreter {
		return
	}
	var hdoc string
	hdocStatic := false
	hasStdin := c.PipeIn
	for _, r := range c.Redirs {
		if r.Op == RedirHeredoc || r.Op == RedirHereString {
			hasStdin = true
			if !r.BodyExpands {
				hdoc, hdocStatic = r.Body, true
			}
		}
	}
	if !hasStdin {
		return
	}
	if hdocStatic && entry.ShellCode {
		w.unwrapCode(hdoc, true, dialect, depth, cond, origin)
		return
	}
	e := Effect{Kind: KindExec, Cond: cond, Target: Target{Type: TargetProcess, Link: LinkNotChecked},
		TargetState: TargetStateUnknown, RoleState: RoleStateUnknown, Origin: origin}
	e.addReason(ReasonOpaqueCode, ScopeTarget)
	if c.PipeIn && baseIdx > 0 {
		e.Data = &Data{Kind: DataCode, Sources: []Source{{Kind: SourceEffect, Effect: baseIdx}}}
	}
	w.emit(e)
}

func cloneEnv(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// operand is one classified operand with its role.
type operand struct {
	value         string
	static        bool
	quoted        bool
	glob          bool
	role          Role
	pattern       bool
	remote        bool
	roleUncertain bool
	destMaybeDir  bool
	uploadIsFile  bool   // RoleSendData: the body is a file / stdin ("-"), not literal text
	copyFrom      string // a copy destination write: the source spelling whose read it carries (s7-flow)
}

// classifyOperands walks flags and positionals of a command against a table row.
func (w *walker) classifyOperands(words []Word, p Program, dialect Dialect) ([]operand, [][]Word, bool) {
	var out []operand
	var inner [][]Word
	var positionals []Word
	i := 0
	unknownFlag := false
	inPlace := false
	del := false
	hasExpr := false
	destDir := ""
	var srcFlags []Word
	var destFlag Word
	endOpts := false
	for i < len(words) {
		wd := words[i]
		name := wd.Value
		if endOpts || !wd.Static {
			positionals = append(positionals, wd)
			i++
			continue
		}
		if name == "--" {
			endOpts = true
			i++
			continue
		}
		// key=value operand (dd if=/of=, --reference=path): the key before '='
		// is a known flag.
		if eq := strings.IndexByte(name, '='); eq > 0 && name[0] != '-' {
			if fl, ok := flagLookup(p, name[:eq], dialect); ok {
				out = append(out, operandValue(fl, Word{Value: name[eq+1:], Static: true}, p))
				i++
				continue
			}
		}
		isFlag := isFlagToken(name, dialect)
		if !isFlag {
			positionals = append(positionals, wd)
			i++
			continue
		}
		// PowerShell / long --flag=value and -Param:Value inline value.
		fname, inlineVal, hasInline := splitInlineFlagValue(name, dialect)
		fl, ok := flagLookup(p, fname, dialect)
		if !ok {
			// POSIX combined short flags (-xzf, -sSLo): the split marks the
			// token unaccounted if any component is unlisted.
			if dialect == DialectPOSIX && len(name) > 2 && name[0] == '-' && name[1] != '-' {
				_, uf := w.splitShortFlags(name, words, &i, p, &out, &inPlace)
				if uf {
					unknownFlag = true
				}
				continue
			}
			// Any other flag token not in the table entry is unaccounted
			// (review N4-1): a lone short flag -Q, a cmd switch /Q, a PowerShell
			// -Bogus. The whole command is then not fully known.
			unknownFlag = true
			i++
			continue
		}
		if p.InPlace != "" && (fname == p.InPlace || fname == "--in-place" || strings.HasPrefix(fname, "--in-place=")) {
			inPlace = true
		}
		if p.DeleteFlag != "" && fname == p.DeleteFlag {
			del = true
		}
		if (p.Pos == PosSourcesDest) && (fname == "-t" || fname == "--target-directory" || strings.HasPrefix(fname, "--target-directory=")) {
			if v, iv, has := splitInlineFlagValue(name, dialect); has {
				destDir = iv
				_ = v
			} else if i+1 < len(words) && words[i+1].Static {
				destDir = words[i+1].Value
				i += 2
				continue
			}
			i++
			continue
		}
		if p.FirstPosIgnore && (fname == "-e" || fname == "-f" || fname == "--expression" || fname == "--file") {
			hasExpr = true
		}
		if fl.Role == RoleExecProgram {
			// find -exec / fd -x: the words up to ; or + are an inner command.
			// Keep the roots and resume after the terminator (review N4), and
			// walk the inner command (its {}/stdin operands are dynamic).
			rest := collectExecArgv(words[i+1:])
			if len(rest) > 0 {
				inner = append(inner, execPlaceholders(rest))
			}
			i += 1 + len(rest)
			if i < len(words) && words[i].Static && (words[i].Value == ";" || words[i].Value == "+" || words[i].Value == `\;`) {
				i++
			}
			continue
		}
		if hasInline {
			if routeSourcesDestFlag(p, fl, Word{Value: inlineVal, Static: true}, &srcFlags, &destFlag) {
				i++
				continue
			}
			out = append(out, operandValue(fl, Word{Value: inlineVal, Static: true}, p))
			i++
			continue
		}
		if fl.Value {
			if i+1 < len(words) {
				if routeSourcesDestFlag(p, fl, words[i+1], &srcFlags, &destFlag) {
					i += 2
					continue
				}
				out = append(out, operandValue(fl, words[i+1], p))
				i += 2
				continue
			}
		}
		i++
	}
	// Copy-Item/Move-Item etc. take their source and destination as -Path /
	// -Destination flags, not positionals: fold them into the sources/dest list
	// so the directory-destination join applies (review R5F-3).
	if p.Pos == PosSourcesDest && (len(srcFlags) > 0 || destFlag.Static) {
		combined := append(srcFlags, positionals...)
		if destFlag.Static {
			combined = append(combined, destFlag)
		}
		positionals = combined
	}
	// A PosNone program with operands it does not model leaves them unaccounted,
	// unless its entry declares the operands inert data (review R5-2).
	if p.Pos == PosNone && len(positionals) > 0 && !p.InertOperands {
		unknownFlag = true
	}
	out = append(out, w.positionalOperands(positionals, p, posCtx{unknownFlag: unknownFlag, inPlace: inPlace, del: del, hasExpr: hasExpr, destDir: destDir})...)
	return out, inner, unknownFlag
}

// execPlaceholders marks the {} and stdin (-) operands of a find/xargs inner
// command as dynamic (their real value comes from the match / stdin).
func execPlaceholders(in []Word) []Word {
	out := make([]Word, len(in))
	for i, wd := range in {
		if wd.Static && (wd.Value == "{}" || wd.Value == "-") {
			out[i] = Word{Reason: ReasonDynamicExpansion, Span: wd.Span}
			continue
		}
		out[i] = wd
	}
	return out
}

// isFlagToken decides whether a token is an option. On Windows a '/'-leading
// token is a switch only when it has no further path separator and is short
// (review CM-4): a forward-slash path is an operand.
func isFlagToken(name string, dialect Dialect) bool {
	if name == "" {
		return false
	}
	if name[0] == '-' {
		return name != "-"
	}
	if dialect != DialectPOSIX && name[0] == '/' {
		rest := name[1:]
		if rest == "" || strings.ContainsAny(rest, `/\`) || len(rest) > 12 {
			return false
		}
		return true
	}
	return false
}

// splitInlineFlagValue splits --flag=value and PowerShell -Name:value.
func splitInlineFlagValue(name string, dialect Dialect) (flag, value string, has bool) {
	if eq := strings.IndexByte(name, '='); eq >= 0 {
		return name[:eq], name[eq+1:], true
	}
	if dialect == DialectPowerShell && strings.HasPrefix(name, "-") {
		if c := strings.IndexByte(name, ':'); c > 0 {
			return name[:c], name[c+1:], true
		}
	}
	return name, "", false
}

// splitShortFlags expands a combined POSIX short-flag token (-xzf, -sSLo). A
// known value-taking short flag binds the rest of the token or the next arg;
// unknown single chars are harmless mode flags (no strict taint).
func (w *walker) splitShortFlags(name string, words []Word, i *int, p Program, out *[]operand, inPlace *bool) (consumed bool, unknownFlag bool) {
	body := name[1:]
	for j := 0; j < len(body); j++ {
		fn := "-" + string(body[j])
		if fn == p.InPlace {
			*inPlace = true
		}
		fl, ok := flagLookup(p, fn, DialectPOSIX)
		if !ok {
			unknownFlag = true // an unlisted short flag -> not fully modeled (round 3)
			continue
		}
		if fl.Role == RoleExecProgram {
			rest := collectExecArgv(words[*i+1:])
			if len(rest) > 0 && rest[0].Static {
				*out = append(*out, operand{value: rest[0].Value, static: true, role: RoleExecProgram})
			} else {
				*out = append(*out, operand{role: RoleExecProgram})
			}
			*i = len(words)
			return true, unknownFlag
		}
		if fl.Value {
			if j+1 < len(body) {
				*out = append(*out, operandValue(fl, Word{Value: body[j+1:], Static: true}, p))
				*i++
				return true, unknownFlag
			}
			if *i+1 < len(words) {
				*out = append(*out, operandValue(fl, words[*i+1], p))
				*i += 2
				return true, unknownFlag
			}
		}
	}
	*i++
	return true, unknownFlag
}

func operandValue(fl Flag, v Word, p Program) operand {
	op := operand{value: v.Value, static: v.Static, quoted: v.Quoted, glob: v.Glob, role: fl.Role}
	if fl.Role == RoleUploadFile {
		// -T / --upload-file / --post-file / -InFile: the value is always a local
		// file (or "-" for stdin); it is never inline literal data.
		op.uploadIsFile = true
		if v.Static {
			op.value = strings.TrimSpace(v.Value)
		}
	}
	if fl.Role == RoleSendData {
		// -d / --data* / -F / --form / --post-data / -Body: a request body that is
		// literal text unless it is @file (or @- / - for stdin) -- then a file
		// read follows the send (s7-flow).
		if v.Static {
			if at := strings.LastIndex(v.Value, "@"); at >= 0 {
				pth := v.Value[at+1:]
				if semi := strings.IndexByte(pth, ';'); semi >= 0 {
					pth = pth[:semi]
				}
				if pth != "" {
					op.value, op.uploadIsFile = pth, true
					return op
				}
			}
			op.value, op.uploadIsFile = v.Value, false
		}
		return op
	}
	if fl.Role == RoleURL {
		op.value = v.Value
	}
	return op
}

type posCtx struct {
	unknownFlag bool
	inPlace     bool
	del         bool
	hasExpr     bool
	destDir     string
}

func (w *walker) positionalOperands(ps []Word, p Program, ctx posCtx) []operand {
	// KNOWN is an allowlist (review round 3): ANY unlisted flag the call used
	// means the operand roles are not fully modeled, so each operand effect
	// carries an unknown_flag role reason (it is no longer fully known).
	taint := ctx.unknownFlag
	mk := func(wd Word, role Role) operand {
		return operand{value: wd.Value, static: wd.Static, quoted: wd.Quoted,
			glob: wd.Glob || (p.Pattern && !wd.Quoted), role: role, pattern: p.Pattern}
	}
	if p.FirstPosIgnore && !ctx.hasExpr && len(ps) > 0 {
		ps = ps[1:] // sed script / grep pattern is not a path (only when no -e/-f gave it)
	}
	var out []operand
	switch p.Pos {
	case PosAllRead:
		role := RoleRead
		if ctx.inPlace {
			role = RoleWrite
		}
		for _, wd := range ps {
			out = append(out, mk(wd, role))
			if ctx.del { // find -delete: the roots are also deleted
				out = append(out, mk(wd, RoleDelete))
			}
		}
	case PosGit:
		out = append(out, gitOperands(ps)...)
	case PosRobocopy:
		// robocopy SRC DST [files...]: DST is a directory; each file copies to
		// DST/basename(file); with no files the whole SRC tree copies into DST
		// (review R5F-3).
		if len(ps) >= 2 {
			out = append(out, mk(ps[0], RoleRead))
			dst := ps[1]
			files := ps[2:]
			if len(files) == 0 {
				op := mk(dst, RoleWrite)
				if dst.Static && isRemoteOperand(dst.Value) {
					op.remote = true
				} else {
					op.destMaybeDir = true
				}
				out = append(out, op)
			} else {
				for _, f := range files {
					if dst.Static && f.Static && !f.Glob {
						out = append(out, operand{value: joinDir(dst.Value, baseName2(f.Value)), static: true, role: RoleWrite})
					} else {
						out = append(out, operand{role: RoleWrite})
					}
				}
			}
		} else if len(ps) == 1 {
			out = append(out, mk(ps[0], RoleRead))
		}
	case PosURLArgs:
		for _, wd := range ps {
			if wd.Static {
				if host, ok := urlHost(wd.Value); ok {
					_ = host
					out = append(out, operand{value: wd.Value, static: true, role: RoleURL})
					continue
				}
			} else {
				out = append(out, operand{role: RoleURL})
			}
		}
	case PosAllDelete:
		for _, wd := range ps {
			out = append(out, mk(wd, RoleDelete))
		}
	case PosAllWrite:
		for _, wd := range ps {
			out = append(out, mk(wd, RoleWrite))
		}
	case PosAllPerm:
		for _, wd := range ps {
			if wd.Static && looksLikePermMode(wd.Value) {
				continue
			}
			out = append(out, mk(wd, RolePerm))
		}
	case PosSourcesDest:
		out = append(out, sourcesDestOperands(ps, ctx.destDir, p)...)
	case PosLinkTargetLink:
		if len(ps) == 2 {
			out = append(out, mk(ps[0], RoleLinkTarget))
			// ln -s T dir/ puts the link at dir/basename(T) (review R5F-3).
			link := ps[1]
			if link.Static && ps[0].Static && looksDir(link) {
				link = Word{Value: joinDir(link.Value, baseName2(ps[0].Value)), Static: true}
			}
			lo := mk(link, RoleLink)
			if link.Static && !looksDir(ps[1]) && ps[1].Static {
				// a bare link dest may itself be a directory
				lo.destMaybeDir = true
			}
			out = append(out, lo)
		} else {
			for _, wd := range ps {
				out = append(out, mk(wd, RoleLink))
			}
		}
	case PosReverseLink: // mklink LINK TARGET
		if len(ps) == 2 {
			out = append(out, mk(ps[0], RoleLink))
			out = append(out, mk(ps[1], RoleLinkTarget))
		} else {
			for _, wd := range ps {
				out = append(out, mk(wd, RoleLink))
			}
		}
	case PosFirstWrite:
		if len(ps) > 0 {
			out = append(out, mk(ps[0], RoleWrite))
		}
	case PosFirstCode:
		if len(ps) > 0 {
			out = append(out, operand{value: ps[0].Value, static: ps[0].Static, role: RoleExecCode})
		}
	case PosFirstExec:
		for i, wd := range ps {
			role := RoleExecProgram
			if i > 0 {
				role = RoleIgnore
			}
			out = append(out, operand{value: wd.Value, static: wd.Static, role: role})
		}
	}
	if taint {
		for i := range out {
			out[i].roleUncertain = true
		}
	}
	return out
}

// looksLikePermMode reports whether a token is a chmod/chown mode by shape
// (octal or symbolic), not by position (review PT-8).
func looksLikePermMode(s string) bool {
	if s == "" {
		return false
	}
	octal := true
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '7' {
			octal = false
			break
		}
	}
	if octal {
		return true
	}
	// symbolic: [ugoa]*[+-=][rwxXst]*  (also a leading owner like root:grp)
	i := 0
	for i < len(s) && strings.IndexByte("ugoa", s[i]) >= 0 {
		i++
	}
	if i < len(s) && strings.IndexByte("+-=", s[i]) >= 0 {
		return true
	}
	return false
}

func isRemoteOperand(s string) bool {
	c := strings.IndexByte(s, ':')
	if c <= 0 {
		return false
	}
	// not a Windows drive letter (C:...), and the colon is before any slash.
	if c == 1 && isDriveLetter(s[0]) {
		return false
	}
	slash := strings.IndexAny(s, `/\`)
	return slash < 0 || c < slash
}

// effectForOperand turns one classified operand into an effect, or nil.
func (w *walker) effectForOperand(op operand, p Program, origin Origin, cond, foreign, fromInput, shadowed bool, dialect Dialect, depth int) *Effect {
	if op.role == RoleIgnore || op.role == RoleNone {
		return nil
	}
	e := &Effect{Origin: origin, Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateKnown,
		Target: Target{Flavor: w.o.flavor(), Link: LinkNotChecked}}
	e.Kind = op.role.kind()
	if op.roleUncertain {
		e.addReason(ReasonUnknownFlag, ScopeRole)
	}
	if shadowed {
		e.addReason(ReasonProgramShadowed, ScopeRole)
	}
	if foreign {
		e.Target.Type = TargetRemote
		e.addReason(ReasonForeignContext, ScopeRole)
	}
	if fromInput {
		e.addReason(ReasonOperandsFromInput, ScopeRole)
	}

	switch op.role {
	case RoleURL:
		w.fillURL(e, op)
		return e
	case RoleURLUpload:
		w.fillURL(e, op)
		e.Kind = KindNetworkSend // git push etc. send to the URL (review N21)
		return e
	case RoleExecCode:
		e.Kind = KindExec
		e.Target.Type = TargetProcess
		if op.static && p.ShellCode {
			e.Data = &Data{Kind: DataCode, Bytes: len(op.value), Text: cap8k(op.value)}
		} else {
			e.addReason(ReasonOpaqueCode, ScopeTarget)
		}
		return e
	case RoleExecProgram:
		e.Kind = KindExec
		if op.static {
			t, reason := w.programTarget(op.value)
			e.Target = t
			if reason != "" {
				e.addReason(reason, ScopeTarget)
			}
		} else {
			e.Target.Type = TargetProcess
			e.addReason(ReasonDynamicExpansion, ScopeTarget)
		}
		return e
	case RoleUploadFile:
		e.Kind = KindNetworkSend
		e.Target.Type = TargetURL
		w.fillSendBody(e, op, true)
		return e
	case RoleSendData:
		e.Kind = KindNetworkSend
		e.Target.Type = TargetURL
		w.fillSendBody(e, op, op.uploadIsFile)
		return e
	}

	if op.role == RoleOutput {
		e.Kind = KindWrite
	}
	if op.remote {
		e.Target.Type = TargetRemote
		e.Target.Spelling = cap4k(op.value)
		e.addReason(ReasonForeignContext, ScopeTarget)
		return e
	}
	if !op.static {
		e.Target.Type = TargetPath
		e.addReason(ReasonDynamicExpansion, ScopeTarget)
		return e
	}
	if op.glob || (op.pattern && !op.quoted) || (op.pattern && op.quoted && w.o.flavor() == FlavorWindows) {
		e.Target.Type = TargetPath
		e.Target.Glob = cap4k(op.value)
		e.addReason(ReasonGlob, ScopeTarget)
		return e
	}
	e.Target.Type = TargetPath
	e.Target.Spelling = cap4k(op.value)
	if abs, ok, reason := placePath(op.value, w.opts()); ok {
		e.Target.Path = abs
		if tgt, ok := w.links[e.Target.Key()]; ok {
			e.Target.Physical = tgt
		}
	} else {
		e.addReason(reason, ScopeTarget)
	}
	// a destination that may be a directory: the real target is dir/basename,
	// so the known path alone is not trusted (review R3-2).
	if op.destMaybeDir {
		e.addReason(ReasonDestMayBeDir, ScopeTarget)
	}
	return e
}

func (w *walker) fillURL(e *Effect, op operand) {
	e.Kind = KindNetworkFetch
	e.Target.Type = TargetURL
	if !op.static {
		e.addReason(ReasonDynamicExpansion, ScopeTarget)
		return
	}
	scheme, host, port := parseURL(op.value)
	if host == "" {
		// a schemeless host like evil.example/x (review PT-5)
		if h, ok := urlHost(op.value); ok {
			host = h
		}
	}
	e.Target.URL = cap4k(op.value)
	e.Target.Scheme, e.Target.Host, e.Target.Port = scheme, host, port
	if host == "" {
		e.addReason(ReasonDynamicExpansion, ScopeTarget)
	}
}

// fillSendBody sets the Data of a network_send from a curl/wget/iwr body or
// upload operand: a file read (joined to a prior write of the same path), stdin
// (joined to the piped producer by finishNetworkSends), or literal text. The URL
// host is attached to the send by finishNetworkSends (s7-flow).
func (w *walker) fillSendBody(e *Effect, op operand, isFile bool) {
	if !op.static {
		e.Data = &Data{Kind: DataArgument}
		return
	}
	if isFile {
		if op.value == "-" || op.value == "" {
			e.Data = &Data{Kind: DataStdin}
			return
		}
		e.Data = &Data{Kind: DataFile, Sources: []Source{{Kind: SourcePath, Path: op.value}}}
		w.joinSourceWrite(e)
		return
	}
	e.Data = &Data{Kind: DataLiteral, Bytes: len(op.value), Text: cap8k(op.value)}
}

// finishNetworkSends puts the destination host of a curl/wget/iwr call on its
// network_send effects (not only on the sibling fetch), and joins a stdin body
// (@- / -) to the piped producer (s7-flow). It runs only for HTTP uploader
// programs so a git push (its own unknown-host send) is untouched.
func (w *walker) finishNetworkSends(start int, pipeIn bool, prevPrim int) {
	var host, scheme, url string
	var port int
	for i := start; i < len(w.res.Effects); i++ {
		e := &w.res.Effects[i]
		if e.Kind == KindNetworkFetch && e.Target.Host != "" && host == "" {
			host, scheme, url, port = e.Target.Host, e.Target.Scheme, e.Target.URL, e.Target.Port
		}
	}
	for i := start; i < len(w.res.Effects); i++ {
		e := &w.res.Effects[i]
		if e.Kind != KindNetworkSend {
			continue
		}
		if e.Data != nil && e.Data.Kind == DataStdin && len(e.Data.Sources) == 0 && pipeIn && prevPrim > 0 {
			e.Data.Sources = []Source{{Kind: SourceEffect, Effect: prevPrim}}
		}
		if e.Target.Type == TargetURL && e.Target.Host == "" {
			if host != "" {
				e.Target.Host, e.Target.Scheme, e.Target.URL, e.Target.Port = host, scheme, url, port
			} else {
				e.addReason(ReasonDynamicExpansion, ScopeTarget)
			}
		}
	}
}

// isHTTPUploader reports a program whose body/upload flags send to a URL that
// appears as a separate operand, so the host must be copied onto the send.
func isHTTPUploader(program string) bool {
	switch strings.ToLower(program) {
	case "curl", "wget", "invoke-webrequest", "invoke-restmethod", "iwr", "irm":
		return true
	}
	return false
}

func (w *walker) joinSourceWrite(e *Effect) {
	if e.Data == nil {
		return
	}
	for i, s := range e.Data.Sources {
		if s.Kind != SourcePath || s.Path == "" {
			continue
		}
		t := Target{Path: mustAbs(s.Path, w.opts()), Flavor: w.o.flavor()}
		if idx, ok := w.writeByKey[t.Key()]; ok {
			e.Data.Sources[i] = Source{Kind: SourceEffect, Effect: idx, Path: s.Path}
		}
	}
}

func mustAbs(p string, o Options) string {
	if abs, ok, _ := placePath(p, o); ok {
		return abs
	}
	return p
}

// handleRedirs emits write/append/read effects for redirections and binds a
// stdout write to the read effects of the same command (review PX-9: only
// FD 1 / unspecified carries the command's read bytes).
func (w *walker) handleRedirs(c *Cmd, dialect Dialect, cmdNo, depth int, cond bool, readIdx []int) {
	for _, r := range c.Redirs {
		switch r.Op {
		case RedirWrite, RedirAppend, RedirClobber:
			e := Effect{Kind: KindWrite, Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateKnown,
				Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked},
				Origin: Origin{Surface: w.res.Surface, Dialect: dialect, Command: cmdNo, Depth: depth, Span: c.Span}}
			if r.Op == RedirAppend {
				e.Kind = KindAppend
			}
			w.fillRedirTarget(&e, w.resolveWord(r.Target))
			if (r.FD == 1 || r.FD < 0) && len(readIdx) > 0 {
				for _, idx := range readIdx {
					e.Data = appendSource(e.Data, Source{Kind: SourceEffect, Effect: idx})
				}
			}
			idx := w.emit(e)
			if idx != 0 {
				if k := e.Target.Key(); k != "" {
					w.writeByKey[k] = idx
				}
			}
		case RedirRead:
			e := Effect{Kind: KindRead, Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateKnown,
				Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked},
				Origin: Origin{Surface: w.res.Surface, Dialect: dialect, Command: cmdNo, Depth: depth, Span: c.Span}}
			w.fillRedirTarget(&e, w.resolveWord(r.Target))
			w.emit(e)
		case RedirHeredoc, RedirHereString:
			// Body is data fed to stdin, never a path (handled by interpreterStdin).
		}
	}
}

func (w *walker) fillRedirTarget(e *Effect, t Word) {
	if !t.Static {
		e.addReason(ReasonDynamicExpansion, ScopeTarget)
		return
	}
	if t.Value == "/dev/null" || strings.EqualFold(t.Value, "nul") {
		e.Target.Type = TargetNone
		return
	}
	if strings.HasPrefix(t.Value, "/dev/tcp/") || strings.HasPrefix(t.Value, "/dev/udp/") {
		e.Kind = KindNetworkSend
		e.Target.Type = TargetHost
		rest := strings.TrimPrefix(strings.TrimPrefix(t.Value, "/dev/tcp/"), "/dev/udp/")
		if parts := strings.Split(rest, "/"); len(parts) >= 1 {
			e.Target.Host = parts[0]
		}
		return
	}
	if t.Glob {
		e.Target.Glob = cap4k(t.Value)
		e.addReason(ReasonGlob, ScopeTarget)
		return
	}
	e.Target.Spelling = cap4k(t.Value)
	if abs, ok, reason := placePath(t.Value, w.opts()); ok {
		e.Target.Path = abs
		if tgt, ok := w.links[e.Target.Key()]; ok {
			e.Target.Physical = tgt
		}
	} else {
		e.addReason(reason, ScopeTarget)
	}
}

func appendSource(d *Data, s Source) *Data {
	if d == nil {
		d = &Data{Kind: DataPipe}
	}
	d.Sources = append(d.Sources, s)
	return d
}

func (w *walker) envCodeEffect(name string, dialect Dialect, cmdNo, depth int, cond bool, span [2]int) {
	e := Effect{Kind: KindExec, Cond: cond, TargetState: TargetStateUnknown, RoleState: RoleStateUnknown,
		Target: Target{Type: TargetProcess, Link: LinkNotChecked},
		Origin: Origin{Surface: w.res.Surface, Dialect: dialect, Command: cmdNo, Program: name, Depth: depth, Span: span}}
	e.addReason(ReasonOpaqueCode, ScopeTarget)
	w.emit(e)
}

// unwrapCode parses one nested level of shell code (bash -c, eval of a literal,
// a static heredoc shell body).
func (w *walker) unwrapCode(code string, static bool, dialect Dialect, depth int, cond bool, origin Origin) {
	w.unwrapCodeScoped(code, static, dialect, depth, cond, origin, true)
}

// unwrapCodeScoped parses one nested level of code. childScope=true runs it in a
// child shell (bash -c, su -c, cmd /c: cwd/env restored afterwards);
// childScope=false runs it in the current shell (eval, source, .), so its
// cd/env changes persist (review R3-6 C08).
func (w *walker) unwrapCodeScoped(code string, static bool, dialect Dialect, depth int, cond bool, origin Origin, childScope bool) {
	if !static {
		return
	}
	if depth+1 > maxNestedDepth {
		w.res.addUnknown(ReasonNestingLimit)
		return
	}
	var sub *Script
	switch dialect {
	case DialectCMD:
		sub = parseCMD(code, w.o)
	case DialectPowerShell:
		sub = parsePowerShell(code, w.o)
	default:
		sub = parsePOSIX(code, w.o)
	}
	if !childScope {
		w.walkScript(sub, depth+1)
		return
	}
	s := w.saveScope()
	w.env = cloneEnv(w.env)
	w.walkScript(sub, depth+1)
	w.restoreScope(s)
}

func (w *walker) recordLink(op operand, ops []operand) {
	var linkPath, targetSpelling string
	for _, o2 := range ops {
		if o2.role == RoleLink && o2.static {
			if abs, ok, _ := placePath(o2.value, w.opts()); ok {
				linkPath = abs
			}
		}
		if o2.role == RoleLinkTarget && o2.static {
			targetSpelling = o2.value
		}
	}
	if linkPath == "" || targetSpelling == "" {
		return
	}
	// A relative link target resolves against the link's directory, not the
	// cwd (review PT-7).
	linkDir := parentDir(linkPath, w.o.flavor())
	lo := w.opts()
	lo.CWD = linkDir
	targetAbs := targetSpelling
	if abs, ok, _ := placePath(targetSpelling, lo); ok {
		targetAbs = abs
	}
	t := Target{Path: linkPath, Flavor: w.o.flavor()}
	w.links[t.Key()] = targetAbs
}

func parentDir(p string, flavor Flavor) string {
	sep := "/"
	if flavor == FlavorWindows {
		sep = `\`
	}
	if idx := strings.LastIndex(p, sep); idx > 0 {
		return p[:idx]
	}
	return p
}

// gitOperands models the common git subcommands that touch the network or write
// a tree (review PT-1): clone/fetch/pull read from a remote URL, clone writes
// the destination directory, push uploads.
func gitOperands(ps []Word) []operand {
	var sub string
	var rest []Word
	for _, wd := range ps {
		if wd.Static && sub == "" {
			sub = wd.Value
			continue
		}
		rest = append(rest, wd)
	}
	var out []operand
	switch sub {
	case "clone", "fetch", "pull":
		for i, wd := range rest {
			if wd.Static {
				if _, ok := urlHost(wd.Value); ok || strings.Contains(wd.Value, "://") || isRemoteOperand(wd.Value) {
					out = append(out, operand{value: wd.Value, static: true, role: RoleURL})
					continue
				}
			}
			if sub == "clone" && i == len(rest)-1 && i > 0 {
				out = append(out, operand{value: wd.Value, static: wd.Static, role: RoleWrite})
			}
		}
	case "push":
		sent := false
		for _, wd := range rest {
			if wd.Static {
				if _, ok := urlHost(wd.Value); ok || strings.Contains(wd.Value, "://") {
					out = append(out, operand{value: wd.Value, static: true, role: RoleURLUpload})
					sent = true
				}
			}
		}
		// push to a named ("origin") or default remote still sends to the network;
		// the host is unknown unless the remote was a literal URL (s7-flow / N21).
		if !sent {
			out = append(out, operand{role: RoleURLUpload, static: false})
		}
	case "add", "stage":
		// git add <paths>: each pathspec is a read of the working tree (s7-flow).
		for _, wd := range rest {
			out = append(out, operand{value: wd.Value, static: wd.Static, quoted: wd.Quoted, glob: wd.Glob, role: RoleRead})
		}
	}
	return out
}

// scopeState is the running state saved around a child shell (subshell,
// pipeline stage, background command, command substitution, unwrapped code).
type scopeState struct {
	cwd, home string
	stack     []string
	env       map[string]string
}

func (w *walker) saveScope() scopeState {
	return scopeState{cwd: w.curCWD, home: w.curHome, stack: w.cwdStack, env: w.env}
}

func (w *walker) restoreScope(s scopeState) {
	w.curCWD, w.curHome, w.cwdStack, w.env = s.cwd, s.home, s.stack, s.env
}

// unbindReader drops the variables a read-like builtin binds.
func (w *walker) unbindReader(program string, inner []Word) {
	switch program {
	case "read", "mapfile", "readarray", "getopts":
		for _, wd := range inner[1:] {
			if wd.Static && !strings.HasPrefix(wd.Value, "-") && wd.Value != "" {
				delete(w.env, wd.Value)
			}
		}
	}
}

// commandCWDOverride returns a per-command working directory from env -C DIR
// (a stripped wrapper, recovered from the full words) or git/tar/make -C DIR
// (an operand), else "".
func commandCWDOverride(program string, words, inner []Word) string {
	// env -C DIR cmd... : scan the leading words for the env wrapper's -C.
	for i := 0; i+1 < len(words); i++ {
		if !words[i].Static {
			break
		}
		b := programBasename(words[i].Value, FlavorPOSIX)
		if b == "env" {
			for j := i + 1; j+1 < len(words); j++ {
				if words[j].Static && (words[j].Value == "-C" || words[j].Value == "--chdir") && words[j+1].Static {
					return words[j+1].Value
				}
				if words[j].Static && !strings.HasPrefix(words[j].Value, "-") && !strings.Contains(words[j].Value, "=") {
					break // reached env's inner program
				}
			}
			break
		}
		if _, isWrap := wrapperSpecs[b]; !isWrap {
			break
		}
	}
	switch program {
	case "git", "make":
		for i := 1; i+1 < len(inner); i++ {
			if inner[i].Static && (inner[i].Value == "-C" || inner[i].Value == "--directory") && inner[i+1].Static {
				return inner[i+1].Value
			}
		}
	}
	return ""
}

// isTilde reports a leading ~ that expands to the home directory: ~ or ~/ on
// POSIX; ~, ~/ or ~\ on Windows (review N6).
func isTilde(lit string, flavor Flavor) bool {
	if lit == "~" {
		return true
	}
	if strings.HasPrefix(lit, "~/") {
		return true
	}
	return flavor == FlavorWindows && strings.HasPrefix(lit, `~\`)
}

// powershellLaunchCode returns the PowerShell command text a powershell/pwsh
// invocation runs: the value of -Command/-c, a decoded -EncodedCommand/-enc/-e,
// or the first positional script onward. ok is false when it only reads stdin.
// powershellHasEncodedArgs reports a powershell/pwsh host launched with an
// -EncodedArguments payload (a serialized CLIXML argument blob for a child
// runspace). PowerShell accepts any unambiguous prefix, so -encodedarguments,
// -encodeda and -ea all match; we never deserialize it (psparse delta review
// 4 (c)).
func powershellHasEncodedArgs(args []Word) bool {
	for _, a := range args {
		if !a.Static || !strings.HasPrefix(a.Value, "-") {
			continue
		}
		name := strings.ToLower(a.Value[1:])
		// -ea is the host's short switch for -EncodedArguments; any longer prefix
		// must reach "encodeda" to be unambiguous against -EncodedCommand.
		if name == "ea" || (strings.HasPrefix(name, "encodeda") && strings.HasPrefix("encodedarguments", name)) {
			return true
		}
	}
	return false
}

func powershellLaunchCode(args []Word) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !a.Static {
			continue
		}
		lc := strings.ToLower(a.Value)
		isCmd := lc == "-command" || lc == "-c"
		isEnc := lc == "-encodedcommand" || lc == "-enc" || lc == "-ec" || lc == "-e"
		if (isCmd || isEnc) && i+1 < len(args) && args[i+1].Static {
			v := args[i+1].Value
			if isEnc {
				if dec, ok := psparse.DecodeEncodedCommand(v); ok {
					return dec, true
				}
				return "", false
			}
			return v, true
		}
		if strings.HasPrefix(a.Value, "-") {
			continue // another switch (-NoProfile, -File handled as a read elsewhere)
		}
		// a bare positional: the rest is a PowerShell command (review N8 K5/S5).
		var parts []string
		for _, w := range args[i:] {
			if !w.Static {
				return "", false
			}
			parts = append(parts, w.Value)
		}
		return strings.Join(parts, " "), true
	}
	return "", false
}

func (w *walker) opaqueExec(origin Origin, cond bool) {
	e := Effect{Kind: KindExec, Cond: cond, Target: Target{Type: TargetProcess, Link: LinkNotChecked},
		TargetState: TargetStateUnknown, RoleState: RoleStateUnknown, Origin: origin}
	e.addReason(ReasonOpaqueCode, ScopeTarget)
	w.emit(e)
}

// tarEffects models tar: create (c) reads its source operands and writes the
// archive; extract (x) writes into -C dir or cwd with an unknown target (the
// archive contents are not modeled -- review N7); --to-command runs code. It
// never reports a silent KNOWN.
func (w *walker) tarEffects(args []Word, origin Origin, cond bool, depth int) {
	mode := byte(0) // 'c','x','t'
	archive := ""
	archivePending := false
	cdir := ""
	var files []Word
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !a.Static {
			if archivePending {
				archivePending = false
			} else {
				files = append(files, a)
			}
			continue
		}
		v := a.Value
		switch {
		case v == "-C" || v == "--directory":
			if i+1 < len(args) && args[i+1].Static {
				cdir = args[i+1].Value
				i++
			}
		case v == "-f" || v == "--file":
			if i+1 < len(args) && args[i+1].Static {
				archive = args[i+1].Value
				i++
			}
		case v == "--to-command" || v == "--checkpoint-action":
			w.opaqueExec(origin, cond)
			if i+1 < len(args) {
				i++
			}
		case strings.HasPrefix(v, "--"):
			// unknown long option: ignore
		case strings.HasPrefix(v, "-") || isTarModeBundle(v):
			// a flag bundle like -xzf / xzf / czf: read the mode and whether -f
			// takes the next token as the archive.
			body := strings.TrimPrefix(v, "-")
			for k := 0; k < len(body); k++ {
				switch body[k] {
				case 'c':
					mode = 'c'
				case 'x':
					mode = 'x'
				case 't':
					mode = 't'
				case 'f':
					archivePending = true
				}
			}
		case archivePending:
			archive = v
			archivePending = false
		default:
			files = append(files, a)
		}
	}
	mk := func(kind Kind, spelling string, state TargetState, reason ReasonCode) {
		e := Effect{Kind: kind, Cond: cond, RoleState: RoleStateKnown, TargetState: state,
			Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked}, Origin: origin}
		if spelling != "" {
			e.Target.Spelling = cap4k(spelling)
			if abs, ok, r := placePath(spelling, w.opts()); ok {
				e.Target.Path = abs
			} else {
				e.TargetState = TargetStateUnknown
				e.addReason(r, ScopeTarget)
			}
		}
		if reason != "" {
			e.addReason(reason, ScopeTarget)
		}
		w.emit(e)
	}
	switch mode {
	case 'c':
		if archive != "" && archive != "-" {
			mk(KindWrite, archive, TargetStateKnown, "")
		}
		for _, f := range files {
			if f.Static {
				mk(KindRead, f.Value, TargetStateKnown, "")
			}
		}
	case 'x':
		if archive != "" && archive != "-" {
			mk(KindRead, archive, TargetStateKnown, "")
		}
		// extraction writes unknown files into the destination directory.
		dest := cdir
		if dest == "" {
			dest = "."
		}
		mk(KindWrite, dest, TargetStateUnknown, ReasonOpaqueArchive)
	default: // list or unknown mode
		if archive != "" && archive != "-" {
			mk(KindRead, archive, TargetStateKnown, "")
		}
	}
}

func isTarModeBundle(v string) bool {
	if v == "" || strings.ContainsAny(v, "/\\.=") {
		return false
	}
	has := false
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case 'c', 'x', 't':
			has = true
		case 'f', 'z', 'j', 'v', 'J', 'a', 'p', 'h':
		default:
			return false
		}
	}
	return has
}

// gitHasExecConfig reports a git -c <key>=... or `git config <key> ...` with a
// config key that runs an external program (review N18).
func gitHasExecConfig(args []Word) bool {
	execKey := func(k string) bool {
		k = strings.ToLower(k)
		for _, p := range []string{"core.pager", "core.sshcommand", "core.fsmonitor", "core.hookspath",
			"core.editor", "credential.helper", "diff.external", "alias.", "sequence.editor", "pager."} {
			if strings.HasPrefix(k, p) {
				return true
			}
		}
		return false
	}
	sub := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !a.Static {
			continue
		}
		if a.Value == "-c" && i+1 < len(args) && args[i+1].Static {
			kv := args[i+1].Value
			if eq := strings.IndexByte(kv, '='); eq > 0 && execKey(kv[:eq]) {
				return true
			}
			i++
			continue
		}
		if !strings.HasPrefix(a.Value, "-") && sub == "" {
			sub = a.Value
		}
	}
	if sub == "config" {
		for _, a := range args {
			if a.Static && execKey(a.Value) {
				return true
			}
		}
	}
	return false
}

// codeRunsOpaque reports a program/argument shape that runs arbitrary code we
// cannot see: go run/test/generate, an interpreter -m module (review N18).
func codeRunsOpaque(program string, args []Word) bool {
	switch program {
	case "go":
		for _, a := range args {
			if a.Static {
				switch a.Value {
				case "run", "test", "generate":
					return true
				}
				if !strings.HasPrefix(a.Value, "-") {
					return false
				}
			}
		}
	case "python", "python3", "node", "nodejs", "ruby", "perl", "php":
		for _, a := range args {
			if a.Static && a.Value == "-m" {
				return true
			}
		}
	}
	return false
}

// secretStdoutCommand reports a command invocation that prints a secret / token
// to stdout, so its read effect can be joined to a downstream send (s7-flow).
// It matches the precise subcommand shape, not just the program name, so an
// unrelated use (gh pr list, kubectl get pods) is not treated as a secret read.
func secretStdoutCommand(program string, args []Word) bool {
	lc := func(w Word) string { return strings.ToLower(w.Value) }
	has := func(v string) bool {
		for _, a := range args {
			if a.Static && lc(a) == v {
				return true
			}
		}
		return false
	}
	seq := func(a, b string) bool {
		for i := 0; i+1 < len(args); i++ {
			if args[i].Static && args[i+1].Static && lc(args[i]) == a && lc(args[i+1]) == b {
				return true
			}
		}
		return false
	}
	containsSecret := func() bool {
		for _, a := range args {
			if a.Static && strings.Contains(lc(a), "secret") {
				return true
			}
		}
		return false
	}
	switch strings.ToLower(program) {
	case "gh":
		return seq("auth", "token")
	case "aws":
		if seq("configure", "get") && containsSecret() {
			return true
		}
		return has("get-secret-value") || has("get-parameter") || has("get-parameters")
	case "security": // macOS keychain
		return (has("find-generic-password") || has("find-internet-password")) && has("-w")
	case "op": // 1Password CLI
		return has("read") || has("get")
	case "vault":
		return seq("kv", "get") || has("read")
	case "kubectl", "oc":
		return has("get") && (has("secret") || has("secrets"))
	case "gcloud":
		return seq("auth", "print-access-token") || seq("auth", "print-identity-token") || seq("secrets", "versions")
	case "doppler":
		return has("secrets")
	}
	return false
}

// sourcesDestOperands models cp/mv/scp/rsync/copy-item/move-item: the sources
// are reads, the destination a write. A directory destination (trailing
// separator, ., ~, .., a -t/--target-directory dir, or more than one source)
// writes <dir>/<basename(source)>; a bare destination that could be a directory
// is unknown (dest_may_be_dir) so the resolver can decide (review R3-2/R3-8).
func sourcesDestOperands(ps []Word, destDir string, p Program) []operand {
	var out []operand
	var sources []Word
	var dest Word
	haveDest := false
	if destDir != "" {
		dest = Word{Value: destDir, Static: true}
		haveDest = true
		sources = ps
	} else if len(ps) >= 2 {
		dest = ps[len(ps)-1]
		sources = ps[:len(ps)-1]
		haveDest = true
	} else {
		sources = ps // a single operand with no dest: a read
	}
	remoteOf := func(wd Word) bool { return p.Remote && wd.Static && isRemoteOperand(wd.Value) }
	for _, s := range sources {
		op := operand{value: s.Value, static: s.Static, quoted: s.Quoted, glob: s.Glob, role: RoleRead}
		if remoteOf(s) {
			op.remote = true
		}
		out = append(out, op)
	}
	if !haveDest {
		return out
	}
	if remoteOf(dest) {
		w := operand{value: dest.Value, static: dest.Static, role: RoleWrite, remote: true}
		if len(sources) == 1 && sources[0].Static {
			w.copyFrom = sources[0].Value // the local read's label follows the upload
		}
		out = append(out, w)
		return out
	}
	dirDest := destDir != "" || len(sources) > 1 || looksDir(dest)
	if !dest.Static {
		out = append(out, operand{role: RoleWrite}) // dynamic dest
		return out
	}
	if dirDest {
		for _, s := range sources {
			if !s.Static {
				out = append(out, operand{role: RoleWrite})
				continue
			}
			out = append(out, operand{value: joinDir(dest.Value, baseName2(s.Value)), static: true, role: RoleWrite, copyFrom: s.Value})
		}
		if len(sources) == 0 {
			out = append(out, operand{value: dest.Value, static: true, role: RoleWrite})
		}
		return out
	}
	// a single source into a bare destination: a rename to a new file, or a
	// write into a directory of that name -- unknown until the resolver knows.
	wr := operand{value: dest.Value, static: true, role: RoleWrite, destMaybeDir: true}
	if len(sources) == 1 && sources[0].Static {
		wr.copyFrom = sources[0].Value // the source read's label follows the copy
	}
	out = append(out, wr)
	return out
}

// looksDir reports a destination spelling that is certainly a directory.
func looksDir(wd Word) bool {
	if !wd.Static {
		return false
	}
	v := wd.Value
	if v == "." || v == ".." || v == "~" {
		return true
	}
	if strings.HasSuffix(v, "/") || strings.HasSuffix(v, `\`) ||
		strings.HasSuffix(v, "/.") || strings.HasSuffix(v, "/..") || strings.HasSuffix(v, `\.`) || strings.HasSuffix(v, `\..`) {
		return true
	}
	return false
}

func baseName2(p string) string {
	p = strings.TrimRight(p, `/\`)
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func joinDir(dir, base string) string {
	sep := "/"
	if strings.Contains(dir, `\`) && !strings.Contains(dir, "/") {
		sep = `\`
	}
	return strings.TrimRight(dir, `/\`) + sep + base
}

// gitWorktreeEffects emits a write (or delete) with an unknown target scoped to
// the worktree for a git subcommand that modifies the working tree (review
// R3-4). Read-only subcommands produce nothing here.
func (w *walker) gitWorktreeEffects(args []Word, origin Origin, cond bool) {
	sub := ""
	worktree := w.curCWD
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !a.Static {
			continue
		}
		if (a.Value == "-C" || a.Value == "--work-tree") && i+1 < len(args) && args[i+1].Static {
			if abs, ok, _ := placePath(args[i+1].Value, w.opts()); ok {
				worktree = abs
			}
			i++
			continue
		}
		if strings.HasPrefix(a.Value, "--work-tree=") {
			if abs, ok, _ := placePath(a.Value[len("--work-tree="):], w.opts()); ok {
				worktree = abs
			}
			continue
		}
		if sub == "" && !strings.HasPrefix(a.Value, "-") {
			sub = a.Value
		}
	}
	kind := KindWrite
	switch sub {
	case "checkout", "switch", "restore", "reset", "apply", "am", "stash",
		"merge", "rebase", "cherry-pick", "revert", "worktree", "mv":
		kind = KindWrite
	case "clean", "rm":
		kind = KindDelete
	default:
		return // read-only or non-worktree subcommand
	}
	e := Effect{Kind: kind, Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateUnknown,
		Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked}, Origin: origin}
	if worktree != "" {
		e.Target.Spelling = cap4k(worktree)
	}
	e.addReason(ReasonDynamicExpansion, ScopeTarget) // the exact files are not statically known
	w.emit(e)
}

// downloadRemoteWrite emits the file a URL download writes: curl only with a
// -O/-J/--remote-name form (an -o output is already modeled), wget whenever no
// -O is given. The basename comes from the URL, so the target is unknown; the
// directory is --output-dir / -P, else cwd (review R3-3).
func (w *walker) downloadRemoteWrite(program string, args []Word, origin Origin, cond bool) {
	dir := ""
	remoteName := program == "wget" // wget writes by default
	hasOutput := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !a.Static {
			continue
		}
		switch {
		case a.Value == "--output-dir" || a.Value == "-P" || a.Value == "--directory-prefix":
			if i+1 < len(args) && args[i+1].Static {
				dir = args[i+1].Value
				i++
			}
		case a.Value == "-O" || a.Value == "-J" || a.Value == "-OJ" || a.Value == "--remote-name" || a.Value == "--remote-header-name":
			remoteName = true
		case a.Value == "-o" || a.Value == "--output" || a.Value == "--output-document":
			hasOutput = true
			if i+1 < len(args) {
				i++
			}
		case program == "curl" && strings.HasPrefix(a.Value, "-O"):
			remoteName = true
		}
	}
	if program == "wget" && hasOutput {
		return // -O gives an explicit output (already modeled)
	}
	if !remoteName {
		return
	}
	e := Effect{Kind: KindWrite, Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateUnknown,
		Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked}, Origin: origin}
	if dir != "" {
		e.Target.Spelling = cap4k(dir)
	} else if w.curCWD != "" {
		e.Target.Spelling = cap4k(w.curCWD)
	}
	e.addReason(ReasonDynamicExpansion, ScopeTarget) // basename from the URL
	w.emit(e)
}

// applyWorkdir sets the running cwd from the connector-supplied per-call
// working directory, resolved against the session cwd (review R3-10).
func (w *walker) applyWorkdir(workdir string) {
	if workdir == "" {
		return
	}
	if abs, ok, _ := placePath(workdir, w.opts()); ok {
		w.curCWD = abs
	} else {
		w.curCWD = workdir
	}
}

// posModeRole maps a positional mode to the role its operands carry, for the
// xargs-from-stdin case where the operands are not on the command line.
func posModeRole(p PosMode) Role {
	switch p {
	case PosAllRead:
		return RoleRead
	case PosAllDelete:
		return RoleDelete
	case PosAllWrite:
		return RoleWrite
	case PosAllPerm:
		return RolePerm
	}
	return RoleNone
}

// tarHasUnknownFlag reports a tar flag the model does not account for, so the
// command is not fully known (review R5-1).
func tarHasUnknownFlag(args []Word) bool {
	known := map[string]bool{
		"--directory": true, "--file": true, "--files-from": true, "--to-command": true,
		"--checkpoint-action": true, "--exclude": true, "--exclude-from": true, "--strip-components": true,
		"--gzip": true, "--gunzip": true, "--bzip2": true, "--xz": true, "--zstd": true, "--lzma": true,
		"--verbose": true, "--extract": true, "--create": true, "--list": true, "--get": true,
		"--preserve-permissions": true, "--same-owner": true, "--no-same-owner": true, "--overwrite": true,
		"--owner": true, "--group": true, "--mode": true, "--transform": true, "--wildcards": true,
		"--no-recursion": true, "--one-file-system": true, "--dereference": true, "--keep-old-files": true,
		"--absolute-names": true, "--numeric-owner": true, "--no-same-permissions": true,
	}
	for _, a := range args {
		if !a.Static {
			continue
		}
		v := a.Value
		if strings.HasPrefix(v, "--") {
			k := v
			if eq := strings.IndexByte(v, '='); eq >= 0 {
				k = v[:eq]
			}
			if !known[k] {
				return true
			}
			continue
		}
		if strings.HasPrefix(v, "-") || isTarModeBundle(v) {
			for _, ch := range strings.TrimPrefix(v, "-") {
				if !strings.ContainsRune("cxtfzjJvphakmrunwOWCT", ch) {
					return true
				}
			}
		}
	}
	return false
}

// routeSourcesDestFlag collects a PosSourcesDest program's -Path (read) and
// -Destination (write) flag values as sources and dest instead of emitting them
// directly, so the directory-destination join applies (review R5F-3). It
// returns true when it consumed the value.
func routeSourcesDestFlag(p Program, fl Flag, v Word, srcFlags *[]Word, destFlag *Word) bool {
	if p.Pos != PosSourcesDest {
		return false
	}
	switch fl.Role {
	case RoleRead:
		*srcFlags = append(*srcFlags, v)
		return true
	case RoleWrite:
		*destFlag = v
		return true
	}
	return false
}
