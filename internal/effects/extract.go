// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "strings"

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
	case SurfaceFileTool, SurfacePatch, SurfaceMCP:
		return len(call.Args) > 0 || call.Command != ""
	case SurfaceArgv:
		return len(call.Argv) > 0
	default:
		return strings.TrimSpace(call.Command) != "" || len(call.Argv) > 0
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

	env      map[string]string
	curCWD   string
	curHome  string
	cwdStack []string
	lastPrim int // 1-based index of the previous stage's primary effect (pipe join)
}

func newWalker(res *Result, o Options) *walker {
	env := map[string]string{}
	for k, v := range o.Env {
		env[k] = v
	}
	return &walker{res: res, o: o, funcs: map[string]bool{}, aliases: map[string]string{},
		links: map[string]string{}, writeByKey: map[string]int{},
		env: env, curCWD: o.CWD, curHome: o.Home}
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
			b.WriteString(v)
			continue
		}
		lit := s.Lit
		if i == 0 && !s.Quoted && (lit == "~" || strings.HasPrefix(lit, "~/")) && w.curHome != "" {
			lit = w.curHome + strings.TrimPrefix(lit, "~")
			b.WriteString(lit)
			continue
		}
		if s.Quoted {
			quoted = true
		}
		// A wildcard is a glob when unquoted (POSIX), or always on Windows,
		// where cmd/PowerShell expand wildcards even inside quotes (review
		// CM-3, PS-6, PX-6).
		if looksGlob(lit) && (!s.Quoted || w.o.flavor() == FlavorWindows) {
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
	// Subshell: runs in a child shell; save/restore cwd/home/env.
	if c.Sub != nil {
		savedCWD, savedHome, savedStack := w.curCWD, w.curHome, w.cwdStack
		savedEnv := w.env
		w.env = cloneEnv(w.env)
		w.walkScript(c.Sub, depth)
		w.curCWD, w.curHome, w.cwdStack, w.env = savedCWD, savedHome, savedStack, savedEnv
		w.handleRedirs(c, dialect, w.cmdNo, depth, cond, nil)
		return
	}

	w.cmdNo++
	cmdNo := w.cmdNo

	// 1. Assignments. A prefix assignment (command present) applies only to this
	// command via a temporary env; a bare assignment statement updates the
	// running env (review PX-2, E3).
	prefix := len(c.Words) > 0
	cmdEnv := w.env
	if prefix && len(c.Assigns) > 0 {
		cmdEnv = cloneEnv(w.env)
	}
	for _, a := range c.Assigns {
		rv := w.resolveWord(a.ValueWord)
		if role, ok := envRoles[a.Name]; ok && role == EnvCode {
			w.envCodeEffect(a.Name, dialect, cmdNo, depth, cond, c.Span)
		}
		if !rv.Static {
			if !prefix {
				delete(w.env, a.Name)
			}
			continue
		}
		if prefix {
			cmdEnv[a.Name] = rv.Value
		} else {
			w.env[a.Name] = rv.Value
			if a.Name == "HOME" || a.Name == "USERPROFILE" {
				w.curHome = rv.Value
			}
		}
	}
	if len(c.Words) == 0 {
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		for _, sub := range c.Nested {
			w.walkScript(sub, depth)
		}
		return
	}

	// Resolve the command's words against the (possibly prefixed) env.
	savedEnv := w.env
	w.env = cmdEnv
	words := w.resolveWords(c.Words)
	w.env = savedEnv

	// 2. Strip wrappers.
	inner, wrappers, foreign, fromInput := w.stripWrappers(words)
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

	// 3. cwd changes (review PX-1).
	if w.applyCWDChange(program, inner[1:], dialect) {
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		return
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

	entry, known := lookupProgram(program, w.o.flavor())

	// 5. Base exec effect for every command (review PT-1: never zero effects).
	base := Effect{Kind: KindExec, Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateKnown,
		Target: w.programTarget(prog.Value), Origin: origin}
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
	baseIdx := w.emit(base)
	w.lastPrim = baseIdx

	// 6. Interpreter reading piped / heredoc stdin as code (review PX-5).
	w.interpreterStdin(c, entry, known, dialect, depth, cond, origin, prevPrim)

	if !known {
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		for _, sub := range c.Nested {
			w.walkScript(sub, depth)
		}
		return
	}

	// cmd /c | /k: the rest is an inner command to unwrap (review CM-9).
	if entry.CmdC {
		rest := inner[1:]
		for j, a := range rest {
			if a.Static && (strings.EqualFold(a.Value, "/c") || strings.EqualFold(a.Value, "/k")) {
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
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		return
	}

	// 7. Operands.
	ops := w.classifyOperands(inner[1:], entry, dialect)
	readIdx := []int{}
	for _, op := range ops {
		e := w.effectForOperand(op, entry, origin, cond, foreign, fromInput, shadowed, dialect, depth)
		if e == nil {
			continue
		}
		idx := w.emit(*e)
		if idx == 0 {
			continue
		}
		switch e.Kind {
		case KindRead:
			readIdx = append(readIdx, idx)
		case KindWrite, KindAppend:
			if k := e.Target.Key(); k != "" {
				w.writeByKey[k] = idx
			}
		case KindLink:
			w.recordLink(op, ops)
		}
		if op.role == RoleExecCode && op.static && entry.ShellCode {
			w.unwrapCode(op.value, op.static, dialect, depth, cond, origin)
		}
	}

	// 8. Redirections.
	w.handleRedirs(c, dialect, cmdNo, depth, cond, readIdx)

	// 9. Nested command substitutions.
	for _, sub := range c.Nested {
		w.walkScript(sub, depth)
	}
}

// applyCWDChange updates the running cwd for cd/pushd/popd/Set-Location, and
// returns true when the command is purely a directory change (no other effect).
func (w *walker) applyCWDChange(program string, args []Word, dialect Dialect) bool {
	cd := program == "cd" || (dialect == DialectPowerShell && (program == "set-location" || program == "sl" || program == "cd"))
	pushd := program == "pushd" || (dialect == DialectPowerShell && program == "push-location")
	popd := program == "popd" || (dialect == DialectPowerShell && program == "pop-location")
	if !cd && !pushd && !popd {
		return false
	}
	if popd {
		if n := len(w.cwdStack); n > 0 {
			w.curCWD = w.cwdStack[n-1]
			w.cwdStack = w.cwdStack[:n-1]
		}
		return true
	}
	// first non-flag arg is the directory
	var dir Word
	found := false
	for _, a := range args {
		if a.Static && strings.HasPrefix(a.Value, "-") {
			continue
		}
		dir = a
		found = true
		break
	}
	if pushd {
		w.cwdStack = append(w.cwdStack, w.curCWD)
	}
	if !found {
		return true // bare cd -> home; leave cwd (benign)
	}
	if !dir.Static || dir.Value == "-" {
		w.curCWD = "" // dynamic cd: later relative targets become dynamic_cwd
		return true
	}
	if abs, ok, _ := placePath(dir.Value, w.opts()); ok {
		w.curCWD = abs
	} else {
		w.curCWD = ""
	}
	return true
}

func (w *walker) programTarget(spelling string) Target {
	t := Target{Flavor: w.o.flavor(), Link: LinkNotChecked}
	hasSep := strings.Contains(spelling, "/") || (w.o.flavor() == FlavorWindows && strings.Contains(spelling, `\`))
	if hasSep {
		t.Type = TargetPath
		t.Spelling = cap4k(spelling)
		if abs, ok, _ := placePath(spelling, w.opts()); ok {
			t.Path = abs
		}
		return t
	}
	t.Type = TargetProcess
	t.Spelling = cap4k(programBasename(spelling, w.o.flavor()))
	return t
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
}

// classifyOperands walks flags and positionals of a command against a table row.
func (w *walker) classifyOperands(words []Word, p Program, dialect Dialect) []operand {
	var out []operand
	var positionals []Word
	i := 0
	unknownFlag := false
	inPlace := false
	del := false
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
			// POSIX combined short flags: -xzf, -sSLo.
			if dialect == DialectPOSIX && len(name) > 2 && name[0] == '-' && name[1] != '-' {
				consumed, uf := w.splitShortFlags(name, words, &i, p, &out, &inPlace)
				if consumed {
					continue
				}
				unknownFlag = unknownFlag || uf
			}
			if strings.HasPrefix(fname, "--") {
				unknownFlag = true
			}
			i++
			continue
		}
		if p.InPlace != "" && fname == p.InPlace {
			inPlace = true
		}
		if p.DeleteFlag != "" && fname == p.DeleteFlag {
			del = true
		}
		if fl.Role == RoleExecProgram {
			rest := collectExecArgv(words[i+1:])
			if len(rest) > 0 && rest[0].Static {
				out = append(out, operand{value: rest[0].Value, static: true, role: RoleExecProgram})
			} else {
				out = append(out, operand{role: RoleExecProgram})
			}
			return out
		}
		if hasInline {
			out = append(out, operandValue(fl, Word{Value: inlineVal, Static: true}, p))
			i++
			continue
		}
		if fl.Value {
			if i+1 < len(words) {
				out = append(out, operandValue(fl, words[i+1], p))
				i += 2
				continue
			}
		}
		i++
	}
	out = append(out, w.positionalOperands(positionals, p, posCtx{unknownFlag: unknownFlag, inPlace: inPlace, del: del})...)
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
			continue // unknown short flag: treat as a mode flag
		}
		if fl.Role == RoleExecProgram {
			rest := collectExecArgv(words[*i+1:])
			if len(rest) > 0 && rest[0].Static {
				*out = append(*out, operand{value: rest[0].Value, static: true, role: RoleExecProgram})
			} else {
				*out = append(*out, operand{role: RoleExecProgram})
			}
			*i = len(words)
			return true, false
		}
		if fl.Value {
			if j+1 < len(body) {
				*out = append(*out, operandValue(fl, Word{Value: body[j+1:], Static: true}, p))
				*i++
				return true, false
			}
			if *i+1 < len(words) {
				*out = append(*out, operandValue(fl, words[*i+1], p))
				*i += 2
				return true, false
			}
		}
	}
	*i++
	return true, false
}

func operandValue(fl Flag, v Word, p Program) operand {
	op := operand{value: v.Value, static: v.Static, quoted: v.Quoted, glob: v.Glob, role: fl.Role}
	if fl.Role == RoleUploadFile {
		path, ok := uploadPath(v.Value)
		if !ok {
			op.role = RoleIgnore // inline data, not a file
			return op
		}
		op.value = path
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
}

func (w *walker) positionalOperands(ps []Word, p Program, ctx posCtx) []operand {
	taint := ctx.unknownFlag && p.Strict
	mk := func(wd Word, role Role) operand {
		return operand{value: wd.Value, static: wd.Static, quoted: wd.Quoted,
			glob: wd.Glob || (p.Pattern && !wd.Quoted), role: role, pattern: p.Pattern}
	}
	if p.FirstPosIgnore && len(ps) > 0 {
		ps = ps[1:] // sed script / grep pattern is not a path
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
		for i, wd := range ps {
			switch i {
			case 0:
				out = append(out, mk(wd, RoleRead))
			case 1:
				op := mk(wd, RoleWrite)
				if wd.Static && isRemoteOperand(wd.Value) {
					op.remote = true
				}
				out = append(out, op)
			}
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
		for i, wd := range ps {
			role := RoleRead
			if i == len(ps)-1 && len(ps) > 1 {
				role = RoleWrite
			}
			op := mk(wd, role)
			if p.Remote && wd.Static {
				if isRemoteOperand(wd.Value) {
					op.remote = true
				}
			}
			out = append(out, op)
		}
	case PosLinkTargetLink:
		if len(ps) == 2 {
			out = append(out, mk(ps[0], RoleLinkTarget))
			out = append(out, mk(ps[1], RoleLink))
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
			e.Target = w.programTarget(op.value)
		} else {
			e.Target.Type = TargetProcess
			e.addReason(ReasonDynamicExpansion, ScopeTarget)
		}
		return e
	case RoleUploadFile:
		e.Kind = KindNetworkSend
		if op.value != "" {
			e.Data = &Data{Kind: DataFile, Sources: []Source{{Kind: SourcePath, Path: op.value}}}
			w.joinSourceWrite(e)
		} else {
			e.addReason(ReasonDynamicExpansion, ScopeTarget)
		}
		e.Target.Type = TargetURL
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
	w.walkScript(sub, depth+1)
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
		for _, wd := range rest {
			if wd.Static {
				if _, ok := urlHost(wd.Value); ok || strings.Contains(wd.Value, "://") {
					out = append(out, operand{value: wd.Value, static: true, role: RoleURL})
				}
			}
		}
	}
	return out
}
