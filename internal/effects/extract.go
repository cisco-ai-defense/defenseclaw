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
	inferred := dialect == DialectNone || dialect == ""
	if inferred {
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
	// A guessed dialect must not place a leading / as a drive path (review 6 #1):
	// path trust uses DialectNone unless the dialect was given explicitly.
	if inferred {
		w.pathDialect = DialectNone
	} else {
		w.pathDialect = dialect
	}
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
	w.pathDialect = DialectPOSIX // argv is an explicit POSIX-style command vector
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

	env      map[string]string
	curCWD   string
	curHome  string
	cwdStack []string
	lastPrim int // 1-based index of the previous stage's primary effect (pipe join)
	// stageIn is what the current command reads on stdin from the previous
	// pipeline stage; stageOut is what the last finished stage passes on. Each
	// names the reads whose bytes the stage may print and a literal it was fed
	// (echo/printf). They tie a pipe or a redirect to the data behind it, so a
	// secret read upstream is a source of the send or write downstream (s7-flow,
	// rel-1-0-10 GAP-0128/GAP-0130). literalOut is the literal the current
	// command prints; redirOut the 1-based indices of its stdout redirects.
	stageIn, stageOut stageData
	literalOut        string
	redirOut          []int
	work              int // remaining work budget; 0 -> stop and emit a limit unknown (R3-1)
	overBudget        bool
	// pathDialect is the dialect of the frontend currently walking the text,
	// used only to decide how a leading / is placed on Windows (review 6 #1). It
	// is DialectNone when the top-level dialect was only guessed, so a guessed
	// Windows dialect never fabricates a drive path from a POSIX-absolute path.
	pathDialect Dialect
	// cdpathMaybeSet is sticky once CDPATH is assigned anywhere in the call (a
	// bare/prefix/exported assignment, or an env-wrapper CDPATH=): a relative
	// cd/pushd is then dynamic, because CDPATH can resolve it elsewhere (review 6
	// B).
	cdpathMaybeSet bool
	// cmdHome carries a prefix HOME= assignment to the cd builtin of the current
	// command (POSIX only); cmdHomeSet is reset per command (review 6 C).
	cmdHome    string
	cmdHomeSet bool

	// Certainty state (round 8, GAP-0133..0136). The cwd is a small candidate set
	// {curCWD} U cwdAlt rather than one value: a cd that may fail leaves the old
	// directory possible, so a relative target is placed under every candidate
	// (the alternatives are cond effects) and an overflowing set is dynamic. An
	// empty curCWD is "unknown", and then cwdAlt is empty.
	cwdAlt []string
	// cdChain narrows the candidate set for the `&&` / `||` tail that directly
	// depends on the status of a plain cd (see enterStmt).
	cdChain *cdChain
	// narrowed is the state a linked statement runs under; narrowedFor restores
	// the joined state afterwards.
	narrowed *cwdState
	// narrowedOther is the state when the narrowed statement does not run (the
	// other side of the cd's outcome); a statement that moves the cwd joins its
	// result with it (round 10, GAP-0183 class N).
	narrowedOther *cwdState
	// exported records which shell variables a child process inherits (POSIX
	// frontends only; cmd and PowerShell variables are all environment).
	exported   map[string]bool
	curDialect Dialect
	// aliasDrive: drive letters that subst / net use / New-PSDrive may have bound
	// to another directory; a path on one is not what its letter says. aliasAll
	// is set when the letter could not be read (round 8, K43/S34).
	aliasDrive map[byte]bool
	aliasAll   bool
	// varsOwned: env and exported are this scope's own copies (see ownVars).
	varsOwned bool
	// cdUnreliable: the cd builtin was disabled or made to resolve names as
	// variables (enable -n cd, shopt -s cdable_vars), or cd was aliased: its
	// target and effect are no longer what the argument says.
	cdUnreliable bool
	// namerefSeen: a `declare -n` was seen, so any later assignment may land on
	// HOME or CDPATH through the reference; both stay dynamic for the call.
	namerefSeen bool
	// curProgram is the program of the command being classified (a table row can
	// serve several names, e.g. gzip and gunzip).
	curProgram string
	// spec is the environment change the command being walked applies to the
	// child process it starts (prefix assignments, env/sudo wrapper options).
	spec *childSpec
}

// cwdState is one cwd certainty value: the primary candidate and the others.
type cwdState struct {
	cwd string
	alt []string
}

// cdChain is the outcome pair of the last plain cd for its &&/|| tail.
type cdChain struct {
	succ, fail, joined cwdState
	andOK, orOK        bool
}

// childSpec is the environment a child process starts with, relative to the
// shell's own exported environment.
type childSpec struct {
	assigns  map[string]childAssign
	clear    bool // nothing is inherited (env -i, sudo/doas/su env reset)
	dropHome bool // HOME is the target user's / unknown
	cwdDyn   bool // the child starts in an unknown directory (login shells)
	// chdir is the directory env -C / sudo -D start the child in.
	chdir    string
	chdirSet bool
}

type childAssign struct {
	val string
	ok  bool // false: the value is dynamic (the variable is unknown)
}

func (s *childSpec) set(name, val string, ok bool) {
	if s.assigns == nil {
		s.assigns = map[string]childAssign{}
	}
	s.assigns[name] = childAssign{val: val, ok: ok}
}

const walkWorkBudget = 20000

func newWalker(res *Result, o Options) *walker {
	env := map[string]string{}
	for k, v := range o.Env {
		env[k] = v
	}
	exported := map[string]bool{}
	for k := range o.Env {
		exported[k] = true // the caller's trusted environment is the process environment
	}
	if o.Home != "" {
		exported["HOME"] = true // the shell's HOME is inherited from the process
	}
	return &walker{res: res, o: o, funcs: map[string]bool{}, aliases: map[string]string{},
		links: map[string]string{}, writeByKey: map[string]int{},
		env: env, exported: exported, varsOwned: true, spec: &childSpec{},
		curCWD: o.CWD, curHome: o.Home, work: walkWorkBudget, pathDialect: o.Dialect, curDialect: o.Dialect}
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
	o.Dialect = w.pathDialect // place leading / by the walking frontend (review 6 #1)
	return o
}

func (w *walker) walkScript(s *Script, depth int) {
	if s == nil {
		return
	}
	// The narrowing state belongs to the frame that set it: an eval / source /
	// nested body walked inside a linked statement must neither consume nor reset
	// the enclosing statement's narrowing (round 9, GAP-0183).
	prevDialect, prevNarrowed, prevOther, prevChain := w.curDialect, w.narrowed, w.narrowedOther, w.cdChain
	w.curDialect, w.narrowed, w.narrowedOther, w.cdChain = s.Dialect, nil, nil, nil
	defer func() {
		w.curDialect, w.narrowed, w.narrowedOther, w.cdChain = prevDialect, prevNarrowed, prevOther, prevChain
	}()
	for _, fn := range s.Funcs {
		w.funcs[funcKey(fn, s.Dialect)] = true
	}
	for _, u := range s.Unknowns {
		w.res.addUnknown(u.Reason)
	}
	for _, st := range s.Stmts {
		w.enterStmt(st)
		for _, c := range st.Cmds {
			w.commandStage(c, s.Dialect, depth, st.Cond || c.Cond)
		}
		w.leaveStmt()
	}
}

// funcKey is the name a function is stored and looked up under: cmd and
// PowerShell command names are case-insensitive, so a function can shadow a
// cmdlet in any case spelling (round 8 H).
func funcKey(name string, d Dialect) string {
	if d == DialectPOSIX {
		return name
	}
	return strings.ToLower(name)
}

// cwdNow is the walker's current cwd certainty state.
func (w *walker) cwdNow() cwdState {
	return cwdState{cwd: w.curCWD, alt: append([]string(nil), w.cwdAlt...)}
}

func (w *walker) setCWDState(s cwdState) {
	w.curCWD = s.cwd
	w.cwdAlt = nil
	if s.cwd != "" {
		w.cwdAlt = append([]string(nil), s.alt...)
	}
}

// setCWDDynamic makes the cwd unknown: every relative target is dynamic_cwd.
func (w *walker) setCWDDynamic() {
	w.curCWD = ""
	w.cwdAlt = nil
}

func (s cwdState) equal(o cwdState) bool {
	if s.cwd != o.cwd || len(s.alt) != len(o.alt) {
		return false
	}
	for i := range s.alt {
		if s.alt[i] != o.alt[i] {
			return false
		}
	}
	return true
}

// enterStmt narrows the cwd candidate set for a statement whose execution
// depends on the status of the cd just before it: the right side of `cd X && ..`
// only runs when the cd succeeded (the cwd is X), and the right side of
// `cd X || ..` only when it failed (the cwd is unchanged). Every other statement
// sees the joined set {X, old} (round 8 F).
func (w *walker) enterStmt(st *Stmt) {
	w.narrowed, w.narrowedOther = nil, nil
	ch := w.cdChain
	if st.Link == OpNone {
		w.cdChain = nil
		return
	}
	if ch == nil {
		return
	}
	switch st.Link {
	case OpAnd:
		if ch.andOK {
			ch.orOK = false
			n, o := ch.succ, ch.fail
			w.narrowed, w.narrowedOther = &n, &o
		} else {
			w.cdChain = nil
		}
	case OpOr:
		if ch.orOK {
			ch.andOK = false
			n, o := ch.fail, ch.succ
			w.narrowed, w.narrowedOther = &n, &o
		} else {
			w.cdChain = nil
		}
	}
	if w.narrowed != nil {
		w.setCWDState(*w.narrowed)
	}
}

// leaveStmt restores the joined set after a narrowed statement, unless the
// statement itself changed the cwd (then its own result stands).
func (w *walker) leaveStmt() {
	if w.narrowed != nil && w.cdChain != nil {
		if w.cwdNow().equal(*w.narrowed) {
			w.setCWDState(w.cdChain.joined)
		} else {
			// The statement moved the cwd itself (a nested eval / source / function
			// that cds). It ran only on one side of the cd's outcome; on the other
			// side the cwd is that side's state, so the result is the union.
			if w.narrowedOther != nil {
				w.setCWDState(joinCWD(w.cwdNow(), *w.narrowedOther))
			} else {
				w.setCWDDynamic()
			}
			w.cdChain = nil
		}
	}
	w.narrowed, w.narrowedOther = nil, nil
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

// stageData is what one pipeline stage passes on to the next: the 1-based
// indices of the reads whose bytes it may print, and a literal it was fed.
type stageData struct {
	reads   []int
	literal string
}

// maxStageSources bounds the sources one stage carries, so a long pipeline of
// many reads stays O(1) per effect.
const maxStageSources = 32

// commandStage walks one command or pipeline stage and records what it passes
// on: a stage's stdout carries what it read, what it was piped and what it
// printed (s7-flow, rel-1-0-10 GAP-0128/GAP-0130). It also links a command
// substitution's reads to the dynamic data the command sends or writes.
func (w *walker) commandStage(c *Cmd, dialect Dialect, depth int, cond bool) {
	savedIn, savedLit, savedRedir := w.stageIn, w.literalOut, w.redirOut
	in := stageData{}
	if c.PipeIn {
		in = w.stageOut
	}
	w.stageIn, w.literalOut, w.redirOut = in, "", nil
	start, own := len(w.res.Effects), w.cmdNo+1
	w.command(c, dialect, depth, cond)
	out := stageData{literal: w.literalOut}
	if out.literal == "" {
		out.literal = in.literal
	}
	out.reads = appendCapped(out.reads, in.reads...)
	var nested []int
	for i := start; i < len(w.res.Effects); i++ {
		e := &w.res.Effects[i]
		if e.Kind != KindRead {
			continue
		}
		out.reads = appendCapped(out.reads, i+1)
		if e.Origin.Command != own {
			nested = appendCapped(nested, i+1)
		}
	}
	if len(c.Nested) > 0 && len(nested) > 0 {
		w.linkSubstitutionData(start, own, nested)
	}
	w.stageOut = out
	w.stageIn, w.literalOut, w.redirOut = savedIn, savedLit, savedRedir
}

// linkSubstitutionData records that the data a command sends or writes, when
// the frontend could not resolve it, is the output of a command substitution
// in its arguments (a dynamic body, URL or redirected echo argument).
// (s7-flow, rel-1-0-10 GAP-0128). A static operand is never linked.
func (w *walker) linkSubstitutionData(start, own int, reads []int) {
	redir := map[int]bool{}
	for _, idx := range w.redirOut {
		redir[idx] = true
	}
	for i := start; i < len(w.res.Effects); i++ {
		e := &w.res.Effects[i]
		if e.Origin.Command != own {
			continue
		}
		switch {
		case e.Kind == KindNetworkSend && e.Data != nil && e.Data.Kind == DataArgument && len(e.Data.Sources) == 0:
		case (e.Kind == KindNetworkSend || e.Kind == KindNetworkFetch) && e.Target.Type == TargetURL && e.Target.URL == "" && e.Data == nil:
			// The URL itself is built from the substitution: its bytes leave.
			e.Data = &Data{Kind: DataArgument}
		case redir[i+1] && (e.Data == nil || len(e.Data.Sources) == 0) && (e.Data == nil || e.Data.Text == ""):
			if e.Data == nil {
				e.Data = &Data{Kind: DataArgument}
			}
		default:
			continue
		}
		e.Data.Sources = appendStageSources(e.Data.Sources, reads, 0)
	}
}

func appendCapped(dst []int, vs ...int) []int {
	for _, v := range vs {
		if len(dst) >= maxStageSources {
			return dst
		}
		dst = append(dst, v)
	}
	return dst
}

// appendStageSources adds each read index as an effect source, skipping skip
// and any index already present.
func appendStageSources(dst []Source, reads []int, skip int) []Source {
	for _, r := range reads {
		if r == skip || len(dst) >= maxStageSources {
			continue
		}
		dup := false
		for _, s := range dst {
			if s.Kind == SourceEffect && s.Effect == r {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, Source{Kind: SourceEffect, Effect: r})
		}
	}
	return dst
}

// literalPrinted returns what echo/printf (Write-Output in PowerShell) print
// when every argument is static: the bytes a redirect or a pipe then carries
// (s7-flow, rel-1-0-10 GAP-0130). Leading echo switches are dropped; a printf
// format and its arguments are kept as words, so each value is still a token.
func literalPrinted(program string, args []Word, dialect Dialect) string {
	switch {
	case program == "echo" || program == "printf":
	case dialect == DialectPowerShell && program == "write-output":
	default:
		return ""
	}
	parts := make([]string, 0, len(args))
	for _, a := range args {
		if !a.Static {
			return ""
		}
		if program == "echo" && len(parts) == 0 && isEchoSwitch(a.Value) {
			continue
		}
		parts = append(parts, a.Value)
	}
	return cap8k(strings.Join(parts, " "))
}

func isEchoSwitch(v string) bool {
	if len(v) < 2 || v[0] != '-' {
		return false
	}
	for _, r := range v[1:] {
		if r != 'n' && r != 'e' && r != 'E' {
			return false
		}
	}
	return true
}

// command processes one simple command / pipeline stage.
func (w *walker) command(c *Cmd, dialect Dialect, depth int, cond bool) {
	if !w.spend() {
		return
	}
	// Subshell: runs in a child shell; save/restore cwd/home/env.
	if c.Sub != nil {
		saved := w.saveScope() // installs a copy of the env and cwd set
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
	w.cmdHomeSet = false // a prefix HOME= applies only to this command's cd (review 6 C)
	w.spec = &childSpec{}
	for _, a := range c.Assigns {
		rv := w.resolveWord(a.ValueWord)
		// A name keeps a certain value only after a plain NAME=value. `+=` adds to
		// the old value, an attribute (-l -u -i ...) transforms the new one, and a
		// nameref makes the name an alias for another variable: each leaves the
		// value dynamic (round 10, GAP-0184 class X).
		if a.Append || a.Attr || a.NameRef || w.namerefSeen {
			rv = Word{Reason: ReasonDynamicExpansion}
		}
		if a.NameRef {
			w.noteNameRef()
		}
		if role, ok := envRoles[a.Name]; ok && role == EnvCode {
			w.envCodeEffect(a.Name, dialect, cmdNo, depth, cond, c.Span)
		}
		// Any CDPATH assignment (bare, prefix or exported) means a relative cd can
		// resolve elsewhere, so cd/pushd goes dynamic (review 6 B).
		if a.Name == "CDPATH" {
			w.cdpathMaybeSet = true
		}
		if prefix {
			// A prefix HOME= applies to the cd builtin of this command (POSIX): a
			// bare cd then follows it (review 6 C, W5/W6). The assignment is also
			// part of the environment of the child the command starts (round 8 E).
			if a.Name == "HOME" && dialect == DialectPOSIX {
				w.cmdHomeSet = true
				w.cmdHome = w.placedHome(rv)
			}
			w.spec.set(a.Name, rv.Value, rv.Static)
			continue
		}
		if a.Exported {
			w.ownVars()
			w.exported[a.Name] = true
		}
		if a.Unexport {
			w.ownVars()
			delete(w.exported, a.Name) // declare +x / export -n: the child no longer inherits it
		}
		if a.NoValue {
			continue // an attribute change only: the value is untouched
		}
		if rv.Static {
			w.ownVars()
			w.env[a.Name] = rv.Value
			// A reassigned HOME re-roots `~` and a bare cd under POSIX shell
			// semantics, on every flavor incl. Git Bash (review 6 C). PowerShell's
			// `~` is fixed at session start, so $env:USERPROFILE must not rebind it
			// (review R3-9) -- hence the dialect, not the flavor, gates this.
			if a.Name == "HOME" && dialect == DialectPOSIX {
				w.curHome = w.placedHome(rv)
			}
		} else {
			w.ownVars()
			delete(w.env, a.Name)
			if a.Name == "HOME" && dialect == DialectPOSIX {
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
	spec := w.spec // the child-process environment this command applies (round 8 E)
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
	w.literalOut = literalPrinted(program, inner[1:], dialect)

	// Calling a user-defined function (including one that shadows cd) may change
	// the cwd unobservably: mark it dynamic (review R3-6 C06/C07).
	lprog := funcKey(program, dialect)
	w.noteShellOptions(program, inner[1:])
	if w.funcs[lprog] || (w.cdUnreliable && isCDName(lprog)) {
		w.setCWDDynamic()
	} else if w.applyCWDChange(program, inner[1:], dialect, cond) {
		// 3. cwd changes (review PX-1/N2). A cd in a pipeline stage or a
		// background command changes a child's cwd only.
		if c.Pipeline || c.Async {
			w.cdChain = nil
		}
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		return
	}
	nameOpaque := w.unbindReader(program, inner)
	declUA := false
	if dialect == DialectPOSIX && isDeclBuiltin(program) && len(inner) > 1 {
		ok, opq := w.declWords(program, inner[1:])
		declUA = !ok
		nameOpaque = nameOpaque || opq
	}
	if nameOpaque {
		w.opaqueExec(origin, cond) // a name operand bash evaluates (GAP-0197)
	}
	// A prefix assignment on a builtin that keeps it (export, declare, readonly,
	// local, the special builtins) is not temporary: the name is uncertain.
	if prefix && persistentPrefixBuiltins[program] {
		for _, a := range c.Assigns {
			w.makeUncertain(a.Name)
		}
	}

	// A per-command working directory from env -C / git -C / make -C / tar -C
	// (review N2): applied to this command's placements only, then restored.
	// su / runuser start the target user's environment (HOME and the rest are
	// not the shell's); a login form (su -, su -l, runuser -l) also starts in the
	// target's home (round 8 G).
	if program == "su" || program == "runuser" {
		spec.clear = true
		for _, a := range inner[1:] {
			if a.Static && (a.Value == "-" || a.Value == "-l" || a.Value == "--login") {
				spec.cwdDyn = true
			}
		}
	}
	dir, dyn := commandCWDOverride(program, inner)
	if spec.chdirSet {
		dir = spec.chdir // env -C / sudo -D name the directory of the command they start
	}
	if dyn || spec.cwdDyn || dir != "" {
		savedCWD := w.cwdNow()
		defer w.setCWDState(savedCWD)
		if dyn || spec.cwdDyn {
			w.setCWDDynamic()
		} else {
			w.setCWDState(w.placeCDTarget(dir, savedCWD))
		}
	}

	// 4. Shadowing.
	shadowed := w.funcs[lprog] || w.aliases[program] != ""
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
	unaccounted := wrapperUA || declUA
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
	w.interpreterStdin(c, entry, known, inner[1:], dialect, depth, cond, origin, prevPrim)

	// A command that prints a secret to stdout (gh auth token, vault kv get, ...):
	// emit a read whose data is secret_output and make it this stage's primary,
	// stages, not only the previous stage's own output (case ids in
	// secretflow_stage_test.go).
	// a program the table does not model, since the base exec stays unknown.
	if secretStdoutCommand(program, inner[1:]) {
		e := Effect{Kind: KindRead, Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateKnown,
			Target: Target{Type: TargetProcess, Link: LinkNotChecked}, Origin: origin,
			Data: &Data{Kind: DataSecretOutput}}
		if idx := w.emit(e); idx != 0 {
			w.lastPrim = idx
		}
	}

	// A launcher (wt, conhost, cmd's start, ...) with an argument tail runs a
	// shell with a payload we cannot reconstruct -> opaque (psparse delta review
	// 6 (c) / R6-4). Runs before the unmodeled-program return so the opacity is
	// explicit, not just unmodeled_program.
	if isLauncherName(program) && len(inner) > 1 {
		w.opaqueExec(origin, cond)
	}

	w.noteDriveAlias(program, inner[1:])
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
	if entry.CmdC && c.Host != nil {
		// psparse read this cmd host call: unwrap its payload only from a Static
		// verdict, with psparse's text; a NotStatic one is opaque, and the walker's
		// own /c scan must not turn an off-table shape into a known payload (R9-3).
		w.hostPayload(c, dialect, depth, cond, origin)
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		return
	}
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
				} else if len(rest[j+1:]) > 0 {
					// a /c payload with a dynamic part (a %VAR% / !VAR! delayed
					// expansion) is code we cannot resolve -> opaque, never dropped
					// (review D K15c).
					w.opaqueExec(origin, cond)
				}
				break
			}
		}
		// A cmd invocation with arguments but no recognized /c|/k payload (a splat,
		// a fused /crd, /d/c, or a quoted "/c ...") runs a command we did not
		// extract: unknown, never fully known (psparse delta review 6 (b)).
		// And a bare cmd whose standard input is a pipe, a `<` redirect or a
		// here-string reads its commands from there: opaque, never fully known
		// (round 8 R, GAP-0132 -- the R6-2(b) change had dropped this).
		if !found && (len(rest) > 0 || hasStdinSource(c)) {
			w.opaqueExec(origin, cond)
		}
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		return
	}

	// powershell/pwsh launched from any dialect: decode -enc and unwrap its
	// -Command / positional script as PowerShell (review N8 K4/K5).
	if entry.PSLaunch && c.Host != nil {
		w.hostPayload(c, dialect, depth, cond, origin)
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		return
	}
	if entry.PSLaunch {
		// -EncodedArguments carries a base64 CLIXML argument payload for a child
		// host; we do not deserialize it, so the launch is opaque, never a trusted
		// KNOWN (psparse delta review 4 (c)).
		if powershellHasEncodedArgs(inner[1:]) {
			w.opaqueExec(origin, cond)
			w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
			return
		}
		code, ok, opq := powershellLaunchCode(inner[1:])
		if opq {
			w.opaqueExec(origin, cond)
			w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
			return
		}
		if ok {
			// A -Command / positional value of exactly "-" reads the script from
			// stdin, which we never see; the piped-in text does not change that
			// (psparse delta review 6 (a)).
			if strings.TrimSpace(code) == "-" {
				w.opaqueExec(origin, cond)
				w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
				return
			}
			// A -Command payload whose source carries a " is not trusted: effects
			// never knows the child's edition, and under Windows PowerShell 5.1 /
			// legacy native argument passing the child drops the quotes, so a
			// command hidden inside the quoted span would be missed. Treat the
			// launch as opaque (psparse delta review 5 (b)).
			if strings.Contains(code, `"`) {
				w.opaqueExec(origin, cond)
				w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
				return
			}
			w.unwrapCode(code, true, DialectPowerShell, depth, cond, origin)
			w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
			return
		}
		// no literal command: a stdin-reading powershell is opaque code.
		if hasStdinSource(c) {
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
	// git is fully known only for the subcommands the model accounts for; any
	// other can rewrite the tree or the history unseen, in the -C directory or
	// the cwd (round 8, EFF-ARCHIVE-GIT-C).
	if program == "git" {
		sub := gitSubcommand(inner[1:])
		switch {
		case sub == "":
			if !hasWordFold(inner[1:], "--version") && !hasWordFold(inner[1:], "--help") && !hasWordFold(inner[1:], "-h") {
				unaccounted = true
			}
		case !gitKnownSubcommands[sub]:
			unaccounted = true
		case sub == "config" && gitConfigWrites(inner[1:]):
			unaccounted = true
		}
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
	// certutil -decode / -encode write the output file; -urlcache -f URL file
	// downloads to the file (review D K36/K37).
	if program == "certutil" {
		w.certutilEffects(inner[1:], origin, cond)
	}
	// (see the stage-link cases in secretflow_stage_test.go).
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
			Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked, CaseFold: w.o.CaseInsensitive}, Origin: origin}
		if dir != "" {
			e.Target.Spelling = cap4k(dir)
		} else if w.curCWD != "" {
			e.Target.Spelling = cap4k(w.curCWD)
		}
		e.addReason(ReasonOpaqueArchive, ScopeTarget)
		w.emit(e)
	}

	// 7. Operands.
	w.curProgram = program
	operandWords := inner[1:]
	if dialect != DialectPOSIX && (lprog == "new-item" || lprog == "ni") {
		operandWords = w.joinNewItemName(operandWords)
	}
	ops, execCmds, opsUA := w.classifyOperands(operandWords, entry, dialect)
	if opsUA {
		unaccounted = true
	}
	// find/xargs -exec inner commands run with the matched paths; walk each so
	// its effects (incl. an inner sh -c) appear (review N4). The roots stay as
	// read operands below.
	printed := w.literalOut
	for _, ec := range execCmds {
		if ec.dirDyn {
			saved := w.cwdNow()
			w.setCWDDynamic()
			w.command(&Cmd{Words: ec.argv, Cond: cond}, dialect, depth, cond)
			w.setCWDState(saved)
			continue
		}
		w.command(&Cmd{Words: ec.argv, Cond: cond}, dialect, depth, cond)
	}
	w.literalOut = printed // an -exec child must not lend its literal to this command's redirect
	w.spec = spec
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
		w.emitCWDAlternatives(e, func() *Effect {
			return w.effectForOperand(op, entry, origin, cond, foreign, fromInput, shadowed, dialect, depth)
		})
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
					srcKey := Target{Path: abs, Flavor: w.o.flavor(), CaseFold: w.o.CaseInsensitive}.Key()
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
			childScope := program != "eval" && program != "source" && program != "."
			w.spec = spec
			w.unwrapCodeScoped(op.value, op.static, dialect, depth, cond, origin, childScope)
		}
	}
	// (see the stage-link cases in secretflow_stage_test.go).
	// to the pipe (s7-flow).
	if isHTTPUploader(program) {
		w.finishNetworkSends(cmdStart, c.PipeIn, prevPrim)
	}

	// A cmdlet fed by a pipeline with no explicit path operand acts on the
	// piped input: emit its pipe-role effect with an unknown target (review N5).
	if c.PipeIn && !emittedTargetEffect && entry.PipeRole != "" {
		e := Effect{Kind: entry.PipeRole.kind(), Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateUnknown,
			Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked, CaseFold: w.o.CaseInsensitive}, Origin: origin}
		e.addReason(ReasonDynamicExpansion, ScopeTarget)
		w.emit(e)
	}
	// A command run by xargs gets its operands from stdin: emit its positional
	// role with an unknown target so `ls | xargs rm` is a (dynamic) delete
	// rather than exec-only (review R3-3 / round-3 leftovers).
	if fromInput && !emittedTargetEffect {
		if role := posModeRole(entry.Pos); role != RoleNone {
			e := Effect{Kind: role.kind(), Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateUnknown,
				Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked, CaseFold: w.o.CaseInsensitive}, Origin: origin}
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

// placedHome resolves a HOME= value to the absolute path a bare cd / ~ should
// use, or "" (dynamic) when the value is non-literal or cannot be placed.
func (w *walker) placedHome(rv Word) string {
	if !rv.Static {
		return ""
	}
	return w.placeHomeValue(rv.Value)
}

// placeHomeValue places a HOME value. Only an absolute value is placed: a shell
// uses a relative HOME literally, relative to the cwd at the moment `~` or a
// bare cd is evaluated, so a relative value is dynamic (round 9, GAP-0184).
func (w *walker) placeHomeValue(v string) string {
	if w.namerefSeen || !absoluteSpelling(v, w.o.flavor()) {
		return ""
	}
	if abs, ok, _ := placePath(v, w.opts()); ok {
		return abs
	}
	return ""
}

// absoluteSpelling reports a path spelling that does not depend on the cwd.
func absoluteSpelling(v string, flavor Flavor) bool {
	if strings.HasPrefix(v, "/") {
		return true
	}
	if flavor == FlavorWindows {
		if strings.HasPrefix(v, `\`) {
			return true
		}
		return len(v) >= 3 && isDriveLetter(v[0]) && v[1] == ':' && (v[2] == '\\' || v[2] == '/')
	}
	return false
}

// applyCWDChange updates the running cwd for cd/pushd/popd/Set-Location, and
// returns true when the command is purely a directory change (no other effect).
//
// A cd can fail (the directory may not exist), and a failed cd leaves the old
// directory in place. So the state after a plain cd is the candidate set
// {new} U {old}; the statements that depend on the cd's status are narrowed to
// one side by enterStmt (round 8 F, GAP-0133).
func (w *walker) applyCWDChange(program string, args []Word, dialect Dialect, cond bool) bool {
	lower := strings.ToLower(program)
	cd := program == "cd" || (dialect == DialectPowerShell && (lower == "set-location" || lower == "sl" || lower == "cd" || lower == "chdir")) ||
		(dialect == DialectCMD && (lower == "cd" || lower == "chdir"))
	pushd := program == "pushd" || (dialect != DialectPOSIX && (lower == "push-location" || lower == "pushd"))
	popd := program == "popd" || (dialect != DialectPOSIX && (lower == "pop-location" || lower == "popd"))
	if !cd && !pushd && !popd {
		return false
	}
	if popd {
		// popd -n pops a stack entry without changing directory; a plain popd
		// rotates to the next. Either way the exact result is not modeled
		// cheaply: go dynamic (review N4-2).
		w.setCWDDynamic()
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
	// cmd's cd with no argument only prints the current directory; it does not
	// go home (round 8, K3/K25).
	if cd && dialect == DialectCMD && !found {
		return true
	}
	// pushd with no dir swaps the top two entries; pushd +N/-N rotates: not
	// modeled -> dynamic (review N4-2).
	if pushd {
		if !found || (dir.Static && (strings.HasPrefix(dir.Value, "+") || strings.HasPrefix(dir.Value, "-"))) {
			w.cwdStack = append(w.cwdStack, w.curCWD)
			w.setCWDDynamic()
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
	old := w.cwdNow()
	succ := cwdState{}
	mayFail := true
	switch {
	case !found:
		// bare cd -> the home directory; a prefix HOME= on this command wins (W5/W6).
		if w.cmdHomeSet {
			succ = cwdState{cwd: w.cmdHome}
		} else {
			succ = cwdState{cwd: w.curHome}
		}
		mayFail = false
	case !dir.Static || dir.Value == "-":
		// cd - or a dynamic directory: unknown.
	default:
		rel := !strings.HasPrefix(dir.Value, "/") && !strings.HasPrefix(dir.Value, "./") && !strings.HasPrefix(dir.Value, "../") && !strings.HasPrefix(dir.Value, "~")
		if (w.env["CDPATH"] != "" || w.cdpathMaybeSet) && rel && (len(dir.Value) < 2 || !isDriveLetter(dir.Value[0]) || dir.Value[1] != 58) {
			break // CDPATH may resolve a bare name elsewhere (review R3-6 / review 6 B)
		}
		succ = w.placeCDTarget(dir.Value, old)
	}
	// A conditional cd (in an if/case/loop/&&-tail/function) cannot be proven to
	// run, so afterwards the cwd is unknown (review N2).
	if cond {
		succ = cwdState{}
		mayFail = false
	}
	joined := succ
	if mayFail {
		joined = joinCWD(succ, old)
	}
	w.setCWDState(joined)
	if mayFail && succ.cwd != "" {
		w.cdChain = &cdChain{succ: succ, fail: old, joined: joined, andOK: true, orOK: true}
	}
	return true
}

// placeCDTarget places the directory of a cd under every candidate cwd. A
// failure under any candidate makes the result unknown.
func (w *walker) placeCDTarget(dir string, old cwdState) cwdState {
	bases := append([]string{old.cwd}, old.alt...)
	var out cwdState
	saved := w.curCWD
	defer func() { w.curCWD = saved }()
	for i, b := range bases {
		w.curCWD = b
		abs, ok, _ := placePath(dir, w.opts())
		if !ok || len(abs) > maxCWDBytes {
			return cwdState{}
		}
		if i == 0 {
			out.cwd = abs
			continue
		}
		out = addCWD(out, abs)
	}
	return out
}

// joinCWD unions two candidate sets; an unknown side or an overflow is unknown.
func joinCWD(a, b cwdState) cwdState {
	if a.cwd == "" || b.cwd == "" {
		return cwdState{}
	}
	out := cwdState{cwd: a.cwd, alt: append([]string(nil), a.alt...)}
	for _, c := range append([]string{b.cwd}, b.alt...) {
		out = addCWD(out, c)
		if out.cwd == "" {
			return out
		}
	}
	return out
}

// maxCWDCandidates bounds the candidate set; a larger set is dynamic.
const maxCWDCandidates = 4

func addCWD(s cwdState, c string) cwdState {
	if c == s.cwd {
		return s
	}
	for _, x := range s.alt {
		if x == c {
			return s
		}
	}
	if len(s.alt)+1 >= maxCWDCandidates {
		return cwdState{}
	}
	s.alt = append(s.alt, c)
	return s
}

const maxCWDBytes = 4096

// placeRel places a path under the running cwd, but a cwd-relative path is
// dynamic_cwd while the cwd is a candidate set (the callers that cannot emit one
// effect per candidate use this instead of placePath).
func (w *walker) placeRel(spelling string) (string, bool, ReasonCode) {
	if len(w.cwdAlt) > 0 && cwdDependent(spelling, w.opts()) {
		return "", false, ReasonDynamicCWD
	}
	return placePath(spelling, w.opts())
}

// cwdDependent reports whether a spelling places differently under two
// different working directories (it is relative to the cwd or its drive).
func cwdDependent(spelling string, o Options) bool {
	a, b := o, o
	if o.flavor() == FlavorWindows {
		a.CWD, a.Drive = `C:\__a`, "C"
		b.CWD, b.Drive = `D:\__b`, "D"
	} else {
		a.CWD, b.CWD = "/__a", "/__b"
	}
	pa, oka, _ := placePath(spelling, a)
	pb, okb, _ := placePath(spelling, b)
	return oka != okb || pa != pb
}

// emitCWDAlternatives re-places a cwd-relative effect under every other
// candidate cwd and emits it as a conditional effect when it lands elsewhere, so
// a rule that blocks any protected target sees every directory the command may
// run in (round 8 F). build recomputes the effect under the swapped cwd.
func (w *walker) emitCWDAlternatives(primary *Effect, build func() *Effect) {
	if len(w.cwdAlt) == 0 || primary.Target.Type != TargetPath {
		return
	}
	saved := w.cwdNow()
	defer w.setCWDState(saved)
	for _, c := range saved.alt {
		w.curCWD, w.cwdAlt = c, nil
		e2 := build()
		if e2 == nil || e2.Target.Type != TargetPath {
			continue
		}
		if e2.Target.Path == primary.Target.Path && e2.Target.Glob == primary.Target.Glob && e2.TargetState == primary.TargetState {
			continue
		}
		e2.Cond = true
		w.emit(*e2)
	}
}

// programTarget builds the target for a program spelling. A path spelling that
// cannot be placed (dynamic cwd, drive-relative) is reported unknown with the
// reason, never a KNOWN empty path (review N11); reason is "" when known.
func (w *walker) programTarget(spelling string) (Target, ReasonCode) {
	t := Target{Flavor: w.o.flavor(), Link: LinkNotChecked}
	hasSep := strings.Contains(spelling, "/") || (w.o.flavor() == FlavorWindows && strings.Contains(spelling, `\`))
	if hasSep {
		t.Type = TargetPath
		t.Spelling = cap4k(spelling)
		if abs, ok, reason := w.placeRel(spelling); ok {
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
func (w *walker) interpreterStdin(c *Cmd, entry Program, known bool, args []Word, dialect Dialect, depth int, cond bool, origin Origin, baseIdx int) {
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
		// `sh < file`: with no script or -c operand, the interpreter reads its
		// code from that file, which we cannot see (round 8 R, GAP-0132).
		if r.Op == RedirRead && stdinFD(r) && !hasCodeOperand(args, entry.ShellCode) {
			hasStdin = true
		}
	}
	if !hasStdin {
		return
	}
	// A shell given a script or -c operand reads that, not its standard input:
	// a heredoc / here-string is then data for the script, not code to unwrap.
	if entry.ShellCode && !c.PipeIn && hasCodeOperand(args, true) {
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

// stdinFD reports a redirect that feeds standard input (`< f`, `0< f`).
func stdinFD(r Redir) bool { return r.FD <= 0 }

// hasCodeOperand reports a script operand or an inline-code flag (-c, -e, -m)
// among an interpreter's arguments; without one the interpreter's code is its
// standard input. A lone `-` operand names stdin, so it is not a script.
func hasCodeOperand(args []Word, shell bool) bool {
	for _, a := range args {
		if !a.Static {
			continue
		}
		switch a.Value {
		case "-c", "--command":
			return true
		case "-e", "-m", "-E", "-C", "--eval":
			if !shell { // for a shell -e is errexit; for python/node/ruby/perl it is code
				return true
			}
			continue
		case "-", "-s", "-i", "-l", "--":
			continue
		}
		if !strings.HasPrefix(a.Value, "-") {
			return true
		}
	}
	return false
}

// hasStdinSource reports that the command's standard input comes from a pipe,
// a `<` redirect, a heredoc or a here-string.
func hasStdinSource(c *Cmd) bool {
	if c.PipeIn {
		return true
	}
	for _, r := range c.Redirs {
		switch r.Op {
		case RedirHeredoc, RedirHereString:
			return true
		case RedirRead:
			if stdinFD(r) {
				return true
			}
		}
	}
	return false
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
	subtree       bool   // the write covers the whole directory tree below the path (git clone / init)
}

func hasWordFold(words []Word, v string) bool {
	for _, wd := range words {
		if wd.Static && strings.EqualFold(wd.Value, v) {
			return true
		}
	}
	return false
}

// hasAppendFlag reports the append switch among the arguments, alone, as the
// long form, or inside a cluster of short switches (tee -ai).
func hasAppendFlag(words []Word, flag string) bool {
	for _, wd := range words {
		if !wd.Static {
			continue
		}
		v := wd.Value
		if v == "--" {
			return false
		}
		if v == flag || v == "--append" {
			return true
		}
		if len(v) > 2 && v[0] == '-' && v[1] != '-' && strings.ContainsRune(v[1:], rune(flag[1])) {
			return true
		}
	}
	return false
}

// execCmd is an inner command a find/fd/xargs-style flag runs.
type execCmd struct {
	argv []Word
	// dirDyn: the command runs in a directory chosen per match (-execdir).
	dirDyn bool
}

// classifyOperands walks flags and positionals of a command against a table row.
func (w *walker) classifyOperands(words []Word, p Program, dialect Dialect) ([]operand, []execCmd, bool) {
	var out []operand
	var inner []execCmd
	var positionals []Word
	i := 0
	unknownFlag := false
	inPlace := false
	del := false
	hasExpr := false
	destDir := ""
	var srcFlags []Word
	var destFlag Word
	destFlagSet := false
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
				_, uf := w.splitShortFlags(name, words, &i, p, &out, &inPlace, &destDir)
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
				// find -execdir / -okdir run the command in the matched file's
				// directory, not in the cwd (round 8 G).
				inner = append(inner, execCmd{argv: execPlaceholders(rest), dirDyn: fname == "-execdir" || fname == "-okdir"})
			}
			i += 1 + len(rest)
			if i < len(words) && words[i].Static && (words[i].Value == ";" || words[i].Value == "+" || words[i].Value == `\;`) {
				i++
			}
			continue
		}
		if hasInline && textBad(fl.Text, Word{Value: inlineVal, Static: true}) {
			unknownFlag = true // a script / format / config the closed grammar does not accept
		}
		if hasInline {
			if routeSourcesDestFlag(p, fl, Word{Value: inlineVal, Static: true}, &srcFlags, &destFlag) {
				if fl.Role == RoleWrite {
					destFlagSet = true
				}
				i++
				continue
			}
			out = append(out, operandValue(fl, Word{Value: inlineVal, Static: true}, p))
			i++
			continue
		}
		if fl.Value {
			if i+1 < len(words) {
				if textBad(fl.Text, words[i+1]) {
					unknownFlag = true
				}
				if routeSourcesDestFlag(p, fl, words[i+1], &srcFlags, &destFlag) {
					if fl.Role == RoleWrite {
						destFlagSet = true
					}
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
	if p.Pos == PosSourcesDest && (len(srcFlags) > 0 || destFlagSet) {
		combined := append(srcFlags, positionals...)
		if destFlagSet {
			// a non-static -Destination still names a write; keep it (as a dynamic
			// dest) rather than dropping the write entirely (review 6 #4).
			combined = append(combined, destFlag)
		}
		positionals = combined
	}
	// The script / pattern positional a FirstPosIgnore program takes is accounted
	// only if its closed grammar accepts it (sed script, awk program).
	if p.FirstPosIgnore && !hasExpr && len(positionals) > 0 && textBad(p.FirstPosText, positionals[0]) {
		unknownFlag = true
	}
	// A PosNone program with operands it does not model leaves them unaccounted,
	// unless its entry declares the operands inert data (review R5-2).
	if p.Pos == PosNone && len(positionals) > 0 && !p.InertOperands {
		unknownFlag = true
	}
	out = append(out, w.positionalOperands(positionals, p, posCtx{unknownFlag: unknownFlag, inPlace: inPlace, del: del, hasExpr: hasExpr, destDir: destDir,
		appendMode: p.AppendFlag != "" && hasAppendFlag(words, p.AppendFlag),
		upload:     p.Pos == PosBits && hasWordFold(words, "/upload"), program: w.curProgram, words: words})...)
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
func (w *walker) splitShortFlags(name string, words []Word, i *int, p Program, out *[]operand, inPlace *bool, destDir *string) (consumed bool, unknownFlag bool) {
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
			// cp -tDIR / mv -tDIR: the fused value is the target directory, so each
			// source is written at DIR/name, not at DIR (round 9, GAP-0186).
			if p.Pos == PosSourcesDest && fn == "-t" {
				if j+1 < len(body) {
					*destDir = body[j+1:]
					*i++
					return true, unknownFlag
				}
				if *i+1 < len(words) && words[*i+1].Static {
					*destDir = words[*i+1].Value
					*i += 2
					return true, unknownFlag
				}
				*i++
				return true, true // a dynamic target directory is not accounted
			}
			if j+1 < len(body) {
				if textBad(fl.Text, Word{Value: body[j+1:], Static: true}) {
					unknownFlag = true
				}
				*out = append(*out, operandValue(fl, Word{Value: body[j+1:], Static: true}, p))
				*i++
				return true, unknownFlag
			}
			if *i+1 < len(words) {
				if textBad(fl.Text, words[*i+1]) {
					unknownFlag = true
				}
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
	appendMode  bool // tee -a: the file operands are appended to, not rewritten
	words       []Word
	upload      bool // bitsadmin /upload: the local file is read and sent
	program     string
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
	case PosInOut:
		// uniq / xxd [INPUT [OUTPUT]]: the second operand is the file written; "-"
		// is standard input / output; more than two operands is not accounted.
		for i, wd := range ps {
			switch {
			case wd.Static && wd.Value == "-":
			case i == 0:
				out = append(out, mk(wd, RoleRead))
			case i == 1:
				out = append(out, mk(wd, RoleWrite))
			default:
				out = append(out, operand{role: RoleWrite, roleUncertain: true})
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
		role := RoleWrite
		if ctx.appendMode {
			role = RoleAppend
		}
		for _, wd := range ps {
			out = append(out, mk(wd, role))
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
	case PosZip:
		// zip ARCHIVE FILE...: the first operand is the archive it writes (zip adds
		// .zip when the name has no extension, so the final name is not certain),
		// the rest are read.
		for i, wd := range ps {
			if i == 0 {
				op := mk(wd, RoleWrite)
				op.destMaybeDir = true
				out = append(out, op)
				continue
			}
			out = append(out, mk(wd, RoleRead))
		}
	case PosCompress:
		out = append(out, compressOperands(ps, ctx, mk)...)
	case PosBits:
		// bitsadmin /transfer JOB [/download|/upload] URL LOCAL (and /addfile JOB
		// URL LOCAL): a download writes LOCAL, an upload reads it and sends it to
		// URL (round 8, EFF-BITSADMIN-NONE).
		if len(ps) == 2 {
			if ctx.upload {
				out = append(out, operand{value: ps[0].Value, static: ps[0].Static, role: RoleURLUpload})
				out = append(out, mk(ps[1], RoleRead))
			} else {
				out = append(out, operand{value: ps[0].Value, static: ps[0].Static, role: RoleURL})
				out = append(out, mk(ps[1], RoleWrite))
			}
		} else {
			for _, wd := range ps {
				out = append(out, operand{value: wd.Value, static: wd.Static, role: RoleURL, roleUncertain: true})
			}
			if len(ps) > 0 {
				out = append(out, operand{role: RoleWrite, roleUncertain: true}) // some local file, not named
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
		Target: Target{Flavor: w.o.flavor(), Link: LinkNotChecked, CaseFold: w.o.CaseInsensitive}}
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
	// PowerShell expands * ? [ ] inside quotes too, on every platform, so a
	// wildcard metachar in a PowerShell path argument is a glob regardless of
	// flavor or quoting (psparse delta review 5 (c)).
	if op.glob || (op.pattern && !op.quoted) || (op.pattern && op.quoted && w.o.flavor() == FlavorWindows) ||
		(dialect == DialectPowerShell && looksGlob(op.value)) {
		e.Target.Type = TargetPath
		e.Target.Glob = cap4k(op.value)
		e.addReason(ReasonGlob, ScopeTarget)
		return e
	}
	e.Target.Type = TargetPath
	e.Target.Subtree = op.subtree
	e.Target.Spelling = cap4k(op.value)
	if abs, ok, reason := placePath(op.value, w.opts()); ok {
		e.Target.Path = abs
		if tgt, ok := w.links[e.Target.Key()]; ok {
			e.Target.Physical = tgt
		}
		if w.onAliasedDrive(abs) {
			e.addReason(ReasonNonCanonicalPath, ScopeTarget)
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

// (see the stage-link cases in secretflow_stage_test.go).
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

// (see the stage-link cases in secretflow_stage_test.go).
// network_send effects (not only on the sibling fetch), and joins a stdin body
// (@- / -) to the piped producer (s7-flow). It runs only for HTTP uploader
// programs so a git push (its own unknown-host send) is untouched.
func (w *walker) finishNetworkSends(start int, pipeIn bool, prevPrim int) {
	// Collect the distinct destination hosts this command fetched from. Only when
	// there is exactly one can we attribute it to a send; with several we cannot
	// tell which send goes where, so the send host stays unknown (review 6 #6).
	var host, scheme, url string
	var port int
	distinct := 0
	for i := start; i < len(w.res.Effects); i++ {
		e := &w.res.Effects[i]
		if e.Kind == KindNetworkFetch && e.Target.Host != "" {
			if e.Target.Host != host {
				distinct++
			}
			host, scheme, url, port = e.Target.Host, e.Target.Scheme, e.Target.URL, e.Target.Port
		}
	}
	single := distinct == 1
	for i := start; i < len(w.res.Effects); i++ {
		e := &w.res.Effects[i]
		if e.Kind != KindNetworkSend {
			continue
		}
		if e.Data != nil && e.Data.Kind == DataStdin && len(e.Data.Sources) == 0 && pipeIn && prevPrim > 0 {
			e.Data.Sources = []Source{{Kind: SourceEffect, Effect: prevPrim}}
			// The piped bytes also carry what the upstream stages read or were
			// fed, not only the previous stage's own output.
			e.Data.Sources = appendStageSources(e.Data.Sources, w.stageIn.reads, prevPrim)
			if e.Data.Text == "" && w.stageIn.literal != "" {
				e.Data.Text, e.Data.Bytes = w.stageIn.literal, len(w.stageIn.literal)
			}
		}
		if e.Target.Type == TargetURL && e.Target.Host == "" {
			if single {
				e.Target.Host, e.Target.Scheme, e.Target.URL, e.Target.Port = host, scheme, url, port
			} else {
				e.addReason(ReasonDynamicExpansion, ScopeTarget)
			}
		}
	}
}

// launcherNames are the programs whose argument tail is itself a command line
// (or a script) they start: Windows Terminal, the console host, cmd's start verb,
// task scheduling, run-as and remote execution, file iteration, script hosts and
// proxy-execution binaries, and their POSIX counterparts. The tail is a payload
// we cannot reconstruct (quoting, host-specific parsing), so a call that uses
// one is opaque code, never merely an unmodeled program (psparse delta review 6
// (c) / R6-4; round 8 EFF-LAUNCHERS). Names are lower-case, without .exe.
var launcherNames = set(
	// Windows
	"wt", "conhost", "start", "schtasks", "runas", "psexec", "psexec64", "at", "forfiles", "wmic",
	"mshta", "wscript", "cscript", "rundll32", "regsvr32", "msiexec", "cmstp", "installutil", "msbuild",
	"mmc", "odbcconf", "pcalua", "scriptrunner", "regasm", "regsvcs", "winrs", "presentationhost",
	// POSIX
	"batch", "systemd-run", "nsenter", "unshare", "script", "watch", "flock", "parallel", "setpriv", "taskset",
	"strace", "ltrace", "gdb", "expect", "screen", "tmux", "busybox", "run-parts", "lxc-attach", "sg", "newgrp",
	"pkexec", "capsh", "osascript", "launchctl",
)

// isLauncherName reports a launcher program (see launcherNames).
func isLauncherName(program string) bool {
	return launcherNames[strings.TrimSuffix(strings.ToLower(program), ".exe")]
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
		t := Target{Path: mustAbs(s.Path, w.opts()), Flavor: w.o.flavor(), CaseFold: w.o.CaseInsensitive}
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
				Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked, CaseFold: w.o.CaseInsensitive},
				Origin: Origin{Surface: w.res.Surface, Dialect: dialect, Command: cmdNo, Depth: depth, Span: c.Span}}
			if r.Op == RedirAppend {
				e.Kind = KindAppend
			}
			w.fillRedirTarget(&e, w.resolveWord(r.Target))
			stdout := r.FD == 1 || r.FD < 0
			if stdout {
				for _, idx := range readIdx {
					e.Data = appendSource(e.Data, Source{Kind: SourceEffect, Effect: idx})
				}
				if len(readIdx) == 0 && c.PipeIn {
					// A filter's redirect carries what was piped into it (s7-flow
					// GAP-0130).
					for _, idx := range w.stageIn.reads {
						e.Data = appendSource(e.Data, Source{Kind: SourceEffect, Effect: idx})
					}
				}
				switch {
				case w.literalOut != "":
					// echo/printf with static arguments: the write lays down this
					// literal (s7-flow GAP-0130).
					if e.Data == nil {
						e.Data = &Data{Kind: DataLiteral}
					}
					e.Data.Text, e.Data.Bytes = w.literalOut, len(w.literalOut)
				case c.PipeIn && w.stageIn.literal != "":
					// The literal fed into this filter, before its transform; the
					// value lane decodes common re-encodings.
					if e.Data == nil {
						e.Data = &Data{Kind: DataPipe}
					}
					e.Data.Text, e.Data.Bytes = w.stageIn.literal, len(w.stageIn.literal)
				}
			}
			idx := w.emit(e)
			if idx != 0 {
				if k := e.Target.Key(); k != "" {
					w.writeByKey[k] = idx
				}
				if stdout {
					w.redirOut = append(w.redirOut, idx)
				}
				proto := e
				w.emitCWDAlternatives(&e, func() *Effect {
					e2 := proto
					e2.Target = Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked, CaseFold: w.o.CaseInsensitive}
					e2.Reasons, e2.TargetState = nil, TargetStateKnown
					w.fillRedirTarget(&e2, w.resolveWord(r.Target))
					return &e2
				})
			}
		case RedirRead:
			e := Effect{Kind: KindRead, Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateKnown,
				Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked, CaseFold: w.o.CaseInsensitive},
				Origin: Origin{Surface: w.res.Surface, Dialect: dialect, Command: cmdNo, Depth: depth, Span: c.Span}}
			w.fillRedirTarget(&e, w.resolveWord(r.Target))
			if w.emit(e) != 0 {
				proto := e
				w.emitCWDAlternatives(&e, func() *Effect {
					e2 := proto
					e2.Target = Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked, CaseFold: w.o.CaseInsensitive}
					e2.Reasons, e2.TargetState = nil, TargetStateKnown
					w.fillRedirTarget(&e2, w.resolveWord(r.Target))
					return &e2
				})
			}
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
		if w.onAliasedDrive(abs) {
			e.addReason(ReasonNonCanonicalPath, ScopeTarget)
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
	// Nested code has a concrete dialect, so place its leading-/ paths by it: a
	// POSIX body under cmd/PowerShell (bash -c '... /etc/x') is virtual-rooted
	// (review 6 #1).
	savedPD := w.pathDialect
	w.pathDialect = dialect
	defer func() { w.pathDialect = savedPD }()
	if !childScope {
		w.walkScript(sub, depth+1)
		return
	}
	s := w.saveScope()
	env, exp, home := w.childEnvironment(dialect)
	w.env, w.exported = env, exp
	w.varsOwned = true
	if dialect == DialectPOSIX {
		w.curHome = home
	}
	w.walkScript(sub, depth+1)
	w.restoreScope(s)
}

// childEnvironment is the environment a child shell starts with: what the
// shell exports plus the command's own prefix / env-wrapper changes, nothing at
// all after env -i or an identity wrapper's environment reset. home is the
// child's HOME for its `~` and bare cd; "" means unknown (round 8 E).
func (w *walker) childEnvironment(childDialect Dialect) (env map[string]string, exp map[string]bool, home string) {
	spec := w.spec
	if spec == nil {
		spec = &childSpec{}
	}
	env = map[string]string{}
	exp = map[string]bool{}
	posixParent := w.curDialect == DialectPOSIX
	// The child's HOME comes from the child's exported environment: when the
	// shell's HOME is not exported (declare +x, export -n, unset then assigned)
	// the child's `~` is the passwd home and a bare cd does not follow the
	// shell's value (round 9, GAP-0184).
	home = w.curHome
	if posixParent && !w.exported["HOME"] {
		home = ""
	}
	if spec.clear {
		home = ""
	} else {
		for k, v := range w.env {
			if posixParent && !w.exported[k] {
				continue // an unexported shell variable is not in the child's environment
			}
			env[k] = v
			exp[k] = true
		}
	}
	if spec.dropHome {
		delete(env, "HOME")
		home = ""
	}
	for k, a := range spec.assigns {
		if a.ok {
			env[k] = a.val
			exp[k] = true
			if k == "HOME" {
				home = w.placeHomeValue(a.val)
			}
		} else {
			delete(env, k)
			if k == "HOME" {
				home = ""
			}
		}
	}
	return env, exp, home
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
	t := Target{Path: linkPath, Flavor: w.o.flavor(), CaseFold: w.o.CaseInsensitive}
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
		remote := ""
		var dest *Word
		for i, wd := range rest {
			if wd.Static {
				// git takes a schemeless name as a local path; only scheme:// and
				// scp-style host:path are network remotes (a destination such as
				// .ssh must not be read as a host).
				if strings.Contains(wd.Value, "://") || isRemoteOperand(wd.Value) {
					out = append(out, operand{value: wd.Value, static: true, role: RoleURL})
					if remote == "" {
						remote = wd.Value
					}
					continue
				}
			}
			if sub == "clone" {
				if remote == "" && i == 0 {
					remote = wd.Value // a local path or an alias used as the source
				} else {
					d := wd
					dest = &d
				}
			}
		}
		// git clone SRC [DIR] creates DIR (or ./<name of SRC>) and everything in
		// it: a write of the whole tree below it, not of the directory alone
		// (round 8, Z16 / EFF-Z16-CLONE-SUBTREE).
		if sub == "clone" {
			switch {
			case dest != nil:
				out = append(out, operand{value: dest.Value, static: dest.Static, role: RoleWrite, subtree: true})
			case remote != "":
				if n := cloneDefaultName(remote); n != "" {
					out = append(out, operand{value: n, static: true, role: RoleWrite, subtree: true})
				} else {
					out = append(out, operand{role: RoleWrite, subtree: true})
				}
			}
		}
	case "init":
		// git init [DIR] writes DIR/.git and may add files below DIR.
		for _, wd := range rest {
			out = append(out, operand{value: wd.Value, static: wd.Static, role: RoleWrite, subtree: true})
		}
		if len(rest) == 0 {
			out = append(out, operand{value: ".", static: true, role: RoleWrite, subtree: true})
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
	cwd, home     string
	alt           []string
	stack         []string
	env           map[string]string
	exported      map[string]bool
	chain         *cdChain
	narrowed      *cwdState
	narrowedOther *cwdState
	// varsOwned: the saved scope owned its env / exported maps.
	varsOwned bool
}

// saveScope returns the current state and installs private copies of the
// mutable parts (env, exported set, cwd candidates), so nothing the child does
// to them can leak into the parent when restoreScope puts the originals back.
func (w *walker) saveScope() scopeState {
	s := scopeState{cwd: w.curCWD, home: w.curHome, alt: w.cwdAlt, stack: w.cwdStack, env: w.env,
		exported: w.exported, chain: w.cdChain, narrowed: w.narrowed, narrowedOther: w.narrowedOther}
	// The env and exported maps are shared with the saved state until the child
	// first writes one (ownVars): most scopes (a command substitution, a pipeline
	// stage) never assign, so copying on every entry would cost the deep-nesting
	// cases for nothing.
	s.varsOwned = w.varsOwned
	w.varsOwned = false
	w.cwdAlt = append([]string(nil), w.cwdAlt...)
	w.cdChain, w.narrowed, w.narrowedOther = nil, nil, nil
	return s
}

// ownVars makes the env and exported maps private to the current scope before a
// write.
func (w *walker) ownVars() {
	if w.varsOwned {
		return
	}
	w.env = cloneEnv(w.env)
	w.exported = cloneBools(w.exported)
	w.varsOwned = true
}

func (w *walker) restoreScope(s scopeState) {
	w.curCWD, w.curHome, w.cwdAlt, w.cwdStack, w.env = s.cwd, s.home, s.alt, s.stack, s.env
	w.exported, w.cdChain, w.narrowed, w.narrowedOther = s.exported, s.chain, s.narrowed, s.narrowedOther
	w.varsOwned = s.varsOwned
}

func cloneBools(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// unsetVar records that a builtin (read, printf -v, unset, ...) assigned or
// removed a variable by name: the walker no longer knows its value, and a
// variable that steers path resolution makes that resolution dynamic (round 8
// E: HOME re-roots `~` and a bare cd, CDPATH redirects a relative cd).
func (w *walker) unsetVar(name string) {
	w.ownVars()
	delete(w.env, name)
	delete(w.exported, name) // an unset variable is not exported; a later assignment makes a plain one
	switch name {
	case "HOME":
		if w.curDialect == DialectPOSIX {
			w.curHome = ""
		}
	case "CDPATH":
		w.cdpathMaybeSet = true
	}
}

// unbindReader drops the variables a builtin binds by name: read-like builtins,
// printf -v, getopts, unset. A name given through an expansion could be any
// variable, so it makes HOME and CDPATH uncertain too.
func (w *walker) unbindReader(program string, inner []Word) (opaque bool) {
	args := inner[1:]
	// name checks a word a builtin reads as a variable name: only a plain
	// identifier counts; anything else (NAME[subscript], a quoted or computed
	// name) is evaluated by bash and is opaque code (round 10, GAP-0197).
	name := func(wd Word) {
		if !wd.Static || !plainIdent(wd.Value) {
			opaque = true
			w.unsetVar("HOME")
			w.unsetVar("CDPATH")
			return
		}
		w.unsetVar(wd.Value)
	}
	// skipValues are the options whose next word is a value, not a name.
	skip := func(opts ...string) map[string]bool { return set(opts...) }
	namesAfterOptions := func(valued map[string]bool, nameOpts map[string]bool) {
		for i := 0; i < len(args); i++ {
			a := args[i]
			if !a.Static {
				name(a)
				continue
			}
			switch {
			case nameOpts[a.Value]:
				if i+1 < len(args) {
					i++
					name(args[i])
				}
			case valued[a.Value]:
				i++
			case strings.HasPrefix(a.Value, "-") && a.Value != "-":
			default:
				name(a)
			}
		}
	}
	switch program {
	case "read":
		namesAfterOptions(skip("-d", "-i", "-n", "-N", "-p", "-t", "-u"), skip("-a"))
	case "mapfile", "readarray":
		namesAfterOptions(skip("-d", "-n", "-O", "-s", "-u", "-C", "-c"), nil)
	case "getopts":
		// getopts OPTSTRING NAME [ARG...]: only NAME is a variable name.
		if len(args) >= 2 {
			name(args[1])
		}
	case "unset":
		// unset does not evaluate a subscript; a non-identifier name is ignored.
		for _, wd := range args {
			if wd.Static && plainIdent(wd.Value) {
				w.unsetVar(wd.Value)
			} else if !wd.Static {
				w.unsetVar("HOME")
				w.unsetVar("CDPATH")
			}
		}
	case "printf":
		for i := 0; i+1 < len(args); i++ {
			if args[i].Static && args[i].Value == "-v" {
				name(args[i+1])
			}
		}
	case "test", "[":
		for i := 0; i+1 < len(args); i++ {
			if args[i].Static && (args[i].Value == "-v" || args[i].Value == "-R") {
				if !args[i+1].Static || !plainIdent(args[i+1].Value) {
					opaque = true
				}
			}
		}
	case "wait":
		for i := 0; i+1 < len(args); i++ {
			if args[i].Static && args[i].Value == "-p" {
				name(args[i+1])
			}
		}
	case "let":
		for _, wd := range args {
			if !wd.Static || strings.ContainsAny(wd.Value, "$`[(") {
				opaque = true // an arithmetic operand is evaluated, subscripts and all
			}
		}
	}
	return opaque
}

// commandCWDOverride returns the per-command working directory a git/make -C
// DIR operand names. dyn is true when the directory is named but not statically.
// (env -C / sudo -D come from the wrapper options, recorded on the child spec.)
func commandCWDOverride(program string, inner []Word) (dir string, dyn bool) {
	switch program {
	case "git", "make":
		for i := 1; i+1 < len(inner); i++ {
			if inner[i].Static && (inner[i].Value == "-C" || inner[i].Value == "--directory") {
				if inner[i+1].Static {
					return inner[i+1].Value, false
				}
				return "", true
			}
		}
	}
	return "", false
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

// psHostSwitches and psHostValued are the powershell / pwsh options the walker's
// own host parser knows (names without the dash, lower case). Any other option
// makes the launch opaque: an option it does not know may take a value, and that
// value would be read as the program (round 10, GAP-0198).
var psHostSwitches = set("noprofile", "nop", "noninteractive", "noni", "nologo", "nol", "noexit", "noe", "sta", "mta", "interactive", "i", "login", "l")
var psHostValued = set("executionpolicy", "ep", "windowstyle", "w", "inputformat", "if", "in", "outputformat", "of", "o", "version", "v",
	"configurationname", "config", "settingsfile", "custompipename", "psconsolefile")

// powershellLaunchCode returns the PowerShell command text a powershell/pwsh
// launch runs (a -Command / -EncodedCommand value or the positional tail). opaque
// is true when the launch carries an option the parser does not know -- a
// working directory, a script file, anything else -- so no text is trusted.
func powershellLaunchCode(args []Word) (code string, ok, opaque bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !a.Static {
			return "", false, true // a dynamic word could be an option or its value
		}
		lc := strings.ToLower(a.Value)
		isCmd := lc == "-command" || lc == "-c"
		isEnc := lc == "-encodedcommand" || lc == "-enc" || lc == "-ec" || lc == "-e"
		if isCmd || isEnc {
			if i+1 < len(args) && args[i+1].Static {
				v := args[i+1].Value
				if isEnc {
					if dec, ok := psparse.DecodeEncodedCommand(v); ok {
						return dec, true, false
					}
					return "", false, true
				}
				return v, true, false
			}
			return "", false, true
		}
		if strings.HasPrefix(a.Value, "-") && a.Value != "-" {
			name := strings.TrimPrefix(lc, "-")
			if eq := strings.IndexByte(name, ':'); eq >= 0 {
				return "", false, true // -Option:value is not modeled
			}
			switch {
			case psHostSwitches[name]:
				continue
			case psHostValued[name]:
				i++ // the value belongs to the option
				continue
			}
			return "", false, true // -wd, -File, -Version-less abbreviations, anything unknown
		}
		// a bare positional (incl. a lone "-" = read script from stdin, handled as
		// opaque by the caller): the rest is a PowerShell command (review N8 K5/S5,
		// psparse delta review 6 (a)).
		var parts []string
		for _, w := range args[i:] {
			if !w.Static {
				return "", false, true
			}
			parts = append(parts, w.Value)
		}
		return strings.Join(parts, " "), true, false
	}
	return "", false, false
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
		// Long options may carry their value inline as --name=value (review D A33).
		long, inlineVal, hasInline := v, "", false
		if strings.HasPrefix(v, "--") {
			if eq := strings.IndexByte(v, '='); eq >= 0 {
				long, inlineVal, hasInline = v[:eq], v[eq+1:], true
			}
		}
		switch {
		case long == "--extract" || long == "--get":
			mode = 'x'
		case long == "--create":
			mode = 'c'
		case long == "--list":
			mode = 't'
		case long == "--append" || long == "--update" || long == "--concatenate" || long == "--catenate" || long == "--delete":
			mode = 'a' // the archive itself is rewritten
		case v == "-C" || long == "--directory":
			if hasInline {
				cdir = inlineVal
			} else if i+1 < len(args) && args[i+1].Static {
				cdir = args[i+1].Value
				i++
			}
		case v == "-f" || long == "--file":
			if hasInline {
				archive = inlineVal
			} else if i+1 < len(args) && args[i+1].Static {
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
				case 'r', 'u', 'A':
					mode = 'a' // append / update / concatenate: the archive is rewritten
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
			Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked, CaseFold: w.o.CaseInsensitive}, Origin: origin}
		if spelling != "" {
			e.Target.Spelling = cap4k(spelling)
			if abs, ok, r := w.placeRel(spelling); ok {
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
	case 'a':
		if archive != "" && archive != "-" {
			mk(KindWrite, archive, TargetStateKnown, "")
		} else {
			mk(KindWrite, "", TargetStateUnknown, ReasonDynamicExpansion)
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
		case 'c', 'x', 't', 'r', 'u', 'A':
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
		// mv / move / ren / Move-Item remove each source from where it was: the
		// source is mutated (deleted), not only read.
		if p.MovesSources && haveDest {
			del := op
			del.role = RoleDelete
			out = append(out, del)
		}
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
			// rsync SRC/ copies the contents of SRC into the destination, not
			// SRC itself: the files written are not SRC's basename but unknown
			// names under the destination directory (round 8, Z38).
			if len(p.Names) > 0 && p.Names[0] == "rsync" && strings.HasSuffix(s.Value, "/") {
				out = append(out, operand{value: dest.Value, static: true, role: RoleWrite, destMaybeDir: true, copyFrom: s.Value})
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
	var kind Kind
	switch sub {
	case "checkout", "switch", "restore", "reset", "apply", "am", "stash",
		"merge", "rebase", "cherry-pick", "revert", "worktree", "mv", "pull":
		kind = KindWrite // pull merges fetched objects into the working tree (review D Z15)
	case "clean", "rm":
		kind = KindDelete
	default:
		return // read-only or non-worktree subcommand
	}
	e := Effect{Kind: kind, Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateUnknown,
		Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked, CaseFold: w.o.CaseInsensitive}, Origin: origin}
	if worktree != "" {
		e.Target.Spelling = cap4k(worktree)
	}
	e.addReason(ReasonDynamicExpansion, ScopeTarget) // the exact files are not statically known
	w.emit(e)
}

// certutilEffects models certutil's file-writing verbs (review D K36/K37):
//   - -decode / -decodehex / -encode / -encodehex IN OUT: OUT is written, IN read.
//   - -urlcache [-split] -f URL FILE: FILE is written (the URL fetch is modeled
//     by PosURLArgs). The last non-flag, non-URL positional is the output.
func (w *walker) certutilEffects(args []Word, origin Origin, cond bool) {
	decode := false
	urlcache := false
	var pos []Word
	for _, a := range args {
		if a.Static && strings.HasPrefix(a.Value, "-") {
			switch strings.ToLower(a.Value) {
			case "-decode", "-decodehex", "-encode", "-encodehex":
				decode = true
			case "-urlcache":
				urlcache = true
			}
			continue
		}
		pos = append(pos, a)
	}
	writeTgt := func(wd Word) {
		e := Effect{Kind: KindWrite, Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateKnown,
			Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked, CaseFold: w.o.CaseInsensitive}, Origin: origin}
		if !wd.Static {
			e.addReason(ReasonDynamicExpansion, ScopeTarget)
		} else {
			e.Target.Spelling = cap4k(wd.Value)
			if abs, ok, r := w.placeRel(wd.Value); ok {
				e.Target.Path = abs
			} else {
				e.addReason(r, ScopeTarget)
			}
		}
		if idx := w.emit(e); idx != 0 {
			if k := e.Target.Key(); k != "" {
				w.writeByKey[k] = idx
			}
		}
	}
	switch {
	case decode && len(pos) >= 2:
		rd := Effect{Kind: KindRead, Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateKnown,
			Target: w.operandTarget(pos[0]), Origin: origin}
		if !pos[0].Static {
			rd.addReason(ReasonDynamicExpansion, ScopeTarget)
		} else if rd.Target.Path == "" {
			rd.addReason(ReasonDynamicCWD, ScopeTarget)
		}
		w.emit(rd)
		writeTgt(pos[len(pos)-1])
	case decode && len(pos) == 1:
		writeTgt(pos[0]) // in-place / single argument
	case urlcache:
		// the cache output is the last positional that is not the source URL.
		for i := len(pos) - 1; i >= 0; i-- {
			if pos[i].Static {
				if _, isURL := urlHost(pos[i].Value); isURL || strings.Contains(pos[i].Value, "://") {
					continue
				}
			}
			writeTgt(pos[i])
			break
		}
	}
}

// operandTarget builds a path target for a static/dynamic operand word.
func (w *walker) operandTarget(wd Word) Target {
	t := Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked, CaseFold: w.o.CaseInsensitive}
	if wd.Static {
		t.Spelling = cap4k(wd.Value)
		if abs, ok, _ := w.placeRel(wd.Value); ok {
			t.Path = abs
		}
	}
	return t
}

// (see the stage-link cases in secretflow_stage_test.go).
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
		Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked, CaseFold: w.o.CaseInsensitive}, Origin: origin}
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
	// A connector's workdir is handed to chdir as is, not shell-expanded: a
	// leading ~ is a directory literally named ~ (or the connector's own
	// expansion), so it is not the home directory (rv7-L82).
	if strings.HasPrefix(workdir, "~") {
		w.setCWDDynamic()
		return
	}
	if abs, ok, _ := placePath(workdir, w.opts()); ok {
		w.curCWD = abs
	} else {
		w.setCWDDynamic()
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
		"--append": true, "--update": true, "--concatenate": true, "--catenate": true, "--delete": true,
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
				if !strings.ContainsRune("cxtfzjJvphakmrunwOWCTA", ch) {
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

// noteDriveAlias records the drive letters a drive-mapping command may rebind.
func (w *walker) noteDriveAlias(program string, args []Word) {
	letter := func(wd Word) (byte, bool) {
		v := strings.TrimSuffix(strings.Trim(wd.Value, `"`), ":")
		if wd.Static && len(v) == 1 && ((v[0] >= 'a' && v[0] <= 'z') || (v[0] >= 'A' && v[0] <= 'Z')) {
			return v[0] | 0x20, true
		}
		return 0, false
	}
	mark := func(wd Word) {
		if b, ok := letter(wd); ok {
			if w.aliasDrive == nil {
				w.aliasDrive = map[byte]bool{}
			}
			w.aliasDrive[b] = true
			return
		}
		w.aliasAll = true
	}
	switch strings.ToLower(program) {
	case "subst":
		if len(args) > 0 {
			mark(args[0])
		}
	case "net":
		if len(args) > 1 && args[0].Static && strings.EqualFold(args[0].Value, "use") && strings.HasSuffix(strings.Trim(args[1].Value, `"`), ":") {
			mark(args[1])
		} else if len(args) > 0 && args[0].Static && strings.EqualFold(args[0].Value, "use") {
			w.aliasAll = true
		}
	case "new-psdrive", "new-smbmapping", "mount-diskimage":
		w.aliasAll = true // the letter is a -Name / -LocalPath value: keep it simple and conservative
	case "pushd":
		for _, a := range args {
			if a.Static && strings.HasPrefix(a.Value, `\\`) {
				w.aliasAll = true // pushd \\server\share maps a free drive letter
			}
		}
	}
}

// onAliasedDrive reports an absolute Windows path on a drive letter that was
// rebound in this call.
func (w *walker) onAliasedDrive(abs string) bool {
	if w.o.flavor() != FlavorWindows || len(abs) < 2 || abs[1] != ':' {
		return false
	}
	b := abs[0] | 0x20
	return w.aliasDrive[b] || (w.aliasAll && b != 'c')
}

// joinNewItemName rewrites New-Item -Path D -Name N into -Path D\N: the item
// created is the name inside the path, not the path itself and not N under the
// cwd (round 8, S10/S24/X23). A name or path that is not a literal makes the
// target dynamic.
func (w *walker) joinNewItemName(args []Word) []Word {
	prefixOf := func(wd Word, full string, min int) bool {
		if !wd.Static || !strings.HasPrefix(wd.Value, "-") {
			return false
		}
		n := strings.ToLower(strings.TrimPrefix(wd.Value, "-"))
		return len(n) >= min && strings.HasPrefix(full, n)
	}
	nameAt, pathAt := -1, -1
	for i, a := range args {
		switch {
		case prefixOf(a, "name", 1):
			nameAt = i
		case prefixOf(a, "path", 2) || prefixOf(a, "literalpath", 2):
			pathAt = i
		}
	}
	if nameAt < 0 || nameAt+1 >= len(args) {
		return args
	}
	if pathAt >= 0 && pathAt+1 >= len(args) {
		return args
	}
	name := args[nameAt+1]
	var joined Word
	switch {
	case !name.Static:
		joined = Word{Reason: ReasonDynamicExpansion}
	case pathAt < 0:
		joined = Word{Value: name.Value, Static: true}
	case !args[pathAt+1].Static:
		joined = Word{Reason: ReasonDynamicExpansion}
	default:
		sep := "/"
		if w.o.flavor() == FlavorWindows {
			sep = `\`
		}
		d := strings.TrimRight(args[pathAt+1].Value, `\/`)
		joined = Word{Value: d + sep + name.Value, Static: true}
	}
	var out []Word
	for i := 0; i < len(args); i++ {
		switch {
		case i == nameAt || i == nameAt+1:
		case pathAt >= 0 && (i == pathAt || i == pathAt+1):
		default:
			out = append(out, args[i])
		}
	}
	out = append(out, Word{Value: "-Path", Static: true}, joined)
	return out
}

// cloneDefaultName is the directory git clone creates when no DIR is given: the
// last path segment of the source with a trailing .git removed.
func cloneDefaultName(src string) string {
	s := strings.TrimRight(src, "/\\")
	if i := strings.LastIndexAny(s, "/:\\"); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimSuffix(s, ".git")
	if s == "" || strings.ContainsAny(s, "*?[]{}$`") {
		return ""
	}
	return s
}

// gitSubcommand returns the git subcommand, skipping the global options that
// take a value.
func gitSubcommand(args []Word) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !a.Static {
			return ""
		}
		if strings.HasPrefix(a.Value, "-") {
			switch a.Value {
			case "-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix", "--config-env":
				i++
			}
			continue
		}
		return a.Value
	}
	return ""
}

// gitKnownSubcommands is the allowlist of git subcommands the model accounts
// for: the read-only ones, and the ones whose file effects gitOperands /
// gitWorktreeEffects emit (they change the working tree, an unknown target
// scoped to the worktree, or only .git). Any other subcommand (filter-branch,
// gc, update-ref, submodule, sparse-checkout, ...) can rewrite the tree or the
// history in ways not modeled, so a git call using one is not fully known, in a
// protected directory via -C or anywhere (round 8, EFF-ARCHIVE-GIT-C).
var gitKnownSubcommands = set(
	// read-only
	"status", "log", "diff", "show", "blame", "rev-parse", "rev-list", "ls-files", "ls-tree", "ls-remote", "cat-file",
	"describe", "shortlog", "grep", "show-ref", "name-rev", "whatchanged", "fsck", "count-objects", "help", "version",
	"diff-tree", "diff-index", "diff-files", "merge-base", "for-each-ref", "var", "check-ignore", "cherry", "range-diff",
	// refs only (.git)
	"branch", "tag", "remote", "commit", "reflog", "stash",
	// modeled file effects
	"add", "stage", "push", "clone", "fetch", "pull", "init", "checkout", "switch", "restore", "reset", "apply", "am",
	"merge", "rebase", "cherry-pick", "revert", "worktree", "mv", "rm", "clean", "config", "archive",
)

// gitConfigWrites reports a git config call that sets or removes a value (the
// read forms --get / --list are accounted): a key plus a value, or an
// edit/unset flag.
func gitConfigWrites(args []Word) bool {
	seenConfig := false
	words := 0
	for _, a := range args {
		if !a.Static {
			return true
		}
		if !seenConfig {
			if a.Value == "config" {
				seenConfig = true
			}
			continue
		}
		switch a.Value {
		case "--unset", "--unset-all", "--add", "--replace-all", "--rename-section", "--remove-section", "-e", "--edit":
			return true
		}
		if !strings.HasPrefix(a.Value, "-") {
			words++
		}
	}
	return words >= 2
}

// compressOperands models gzip / bzip2 / xz: each operand file is replaced by its
// compressed (or decompressed) file -- the operand is deleted (unless -k) and the
// derived file is written -- while -c / -t / -l only read it (round 8, the archive
// half of EFF-ARCHIVE-GIT-C: these were modeled as pure reads).
func compressOperands(ps []Word, ctx posCtx, mk func(Word, Role) operand) []operand {
	var out []operand
	readOnly, keep, decompress := false, false, false
	switch ctx.program {
	case "gunzip", "bunzip2", "unxz", "zcat", "bzcat", "xzcat":
		decompress = true
	}
	switch ctx.program {
	case "zcat", "bzcat", "xzcat":
		readOnly = true
	}
	for _, wd := range ctx.words {
		if !wd.Static {
			continue
		}
		switch wd.Value {
		case "-c", "--stdout", "--to-stdout", "-t", "--test", "-l", "--list":
			readOnly = true
		case "-k", "--keep":
			keep = true
		case "-d", "--decompress", "--uncompress":
			decompress = true
		default:
			if len(wd.Value) > 2 && wd.Value[0] == '-' && wd.Value[1] != '-' {
				for _, ch := range wd.Value[1:] {
					switch ch {
					case 'c', 't', 'l':
						readOnly = true
					case 'k':
						keep = true
					case 'd':
						decompress = true
					}
				}
			}
		}
	}
	suffix := ".gz"
	switch ctx.program {
	case "bzip2", "bunzip2", "bzcat":
		suffix = ".bz2"
	case "xz", "unxz", "xzcat":
		suffix = ".xz"
	}
	for _, wd := range ps {
		if readOnly || !wd.Static {
			out = append(out, mk(wd, RoleRead))
			if !readOnly {
				out = append(out, operand{role: RoleWrite}) // an unnamed output
			}
			continue
		}
		var derived string
		if decompress {
			switch {
			case strings.HasSuffix(wd.Value, suffix):
				derived = strings.TrimSuffix(wd.Value, suffix)
			case suffix == ".gz" && strings.HasSuffix(wd.Value, ".tgz"):
				derived = strings.TrimSuffix(wd.Value, ".tgz") + ".tar"
			}
		} else {
			derived = wd.Value + suffix
		}
		if !keep {
			out = append(out, mk(wd, RoleDelete))
		} else {
			out = append(out, mk(wd, RoleRead))
		}
		if derived == "" {
			out = append(out, operand{role: RoleWrite}) // unknown suffix: the output name is not known
		} else {
			out = append(out, operand{value: derived, static: true, quoted: wd.Quoted, role: RoleWrite})
		}
	}
	return out
}

func isCDName(p string) bool {
	switch p {
	case "cd", "pushd", "popd", "chdir", "set-location", "sl", "push-location", "pop-location":
		return true
	}
	return false
}

// noteShellOptions records the builtins that change what cd means: `enable -n
// cd` removes it, `shopt -s cdable_vars` makes its argument a variable name, and
// an alias for cd redirects it.
func (w *walker) noteShellOptions(program string, args []Word) {
	switch program {
	case "enable":
		for _, a := range args {
			if !a.Static || a.Value == "cd" || a.Value == "pushd" || a.Value == "popd" || a.Value == "-n" {
				w.cdUnreliable = true
			}
		}
	case "shopt":
		on := false
		for _, a := range args {
			if !a.Static {
				w.cdUnreliable = true
				continue
			}
			if a.Value == "-s" || a.Value == "-o" {
				on = true
			}
			if on && a.Value == "cdable_vars" {
				w.cdUnreliable = true
			}
		}
	case "alias":
		for _, a := range args {
			if a.Static && (strings.HasPrefix(a.Value, "cd=") || strings.HasPrefix(a.Value, "pushd=") || strings.HasPrefix(a.Value, "popd=")) {
				w.cdUnreliable = true
			}
			if !a.Static {
				w.cdUnreliable = true
			}
		}
	}
}

// isDeclBuiltin reports a builtin that assigns variables by name when it is
// reached as a program word (after command / builtin / exec): the frontend
// lowers the direct form to assignments, but `command export HOME=x` arrives as
// words (round 9, GAP-0184).
func isDeclBuiltin(program string) bool {
	switch program {
	case "export", "declare", "typeset", "local", "readonly":
		return true
	}
	return false
}

// declWords applies a declaration builtin given as words: NAME=value assigns,
// NAME alone changes attributes only, -x / export put the name in the
// environment, +x / export -n take it out. It returns false when an operand
// could not be understood (a name or value that is not literal): the call is
// then unaccounted and HOME and CDPATH are uncertain.
func (w *walker) declWords(program string, args []Word) (ok, opaque bool) {
	exported := program == "export"
	unexport, attr, nameref := false, false, false
	ok = true
	var operands []Word
	for _, a := range args {
		if a.Static && len(a.Value) > 1 && (a.Value[0] == '-' || a.Value[0] == '+') && !strings.Contains(a.Value, "=") {
			switch {
			case a.Value[0] == '+' && strings.Contains(a.Value, "x"):
				unexport = true
			case a.Value[0] == '-' && strings.Contains(a.Value, "x"):
				exported = true
			case a.Value[0] == '-' && program == "export" && strings.Contains(a.Value, "n"):
				unexport, exported = true, false
			case a.Value == "-p" || a.Value == "-f" || a.Value == "-F":
				ok = false // listing / function mode: names are not variables
			}
			if a.Value[0] == '-' && program != "export" && strings.Contains(a.Value, "n") {
				nameref = true
			}
			if strings.ContainsAny(a.Value[1:], "luciaAnftC") && (program != "export" || a.Value != "-n") {
				attr = true
			}
			continue
		}
		operands = append(operands, a)
	}
	for _, a := range operands {
		if !a.Static {
			ok = false
			w.unsetVar("HOME")
			w.unsetVar("CDPATH")
			continue
		}
		name, val, hasVal := a.Value, "", false
		if eq := strings.IndexByte(a.Value, '='); eq > 0 {
			name, val, hasVal = a.Value[:eq], a.Value[eq+1:], true
		}
		if !plainIdent(name) {
			// NAME[subscript]=v and computed names are evaluated (GAP-0197)
			ok, opaque = false, true
			w.unsetVar("HOME")
			w.unsetVar("CDPATH")
			continue
		}
		w.ownVars()
		if exported && !unexport {
			w.exported[name] = true
		}
		if unexport {
			delete(w.exported, name)
		}
		if name == "CDPATH" {
			w.cdpathMaybeSet = true
		}
		if nameref {
			w.noteNameRef()
		}
		if !hasVal {
			continue
		}
		if attr || nameref || w.namerefSeen {
			delete(w.env, name) // the stored value is transformed or aliased
			if name == "HOME" && w.curDialect == DialectPOSIX {
				w.curHome = ""
			}
			continue
		}
		w.env[name] = val
		if name == "HOME" && w.curDialect == DialectPOSIX {
			w.curHome = w.placeHomeValue(val)
		}
	}
	return ok, opaque
}

// hostPayload applies psparse's verdict for a host call: opaque, or the Static
// payload text walked as its own grammar in program order.
func (w *walker) hostPayload(c *Cmd, dialect Dialect, depth int, cond bool, origin Origin) {
	if c.Host.Opaque {
		w.opaqueExec(origin, cond)
		return
	}
	w.unwrapCode(c.Host.Text, true, c.Host.Dialect, depth, cond, origin)
}

// noteNameRef records a nameref declaration: HOME and CDPATH can be written
// through the reference from now on, so they are no longer certain.
func (w *walker) noteNameRef() {
	w.namerefSeen = true
	if w.curDialect == DialectPOSIX {
		w.curHome = ""
	}
	w.cdpathMaybeSet = true
}

// persistentPrefixBuiltins are the builtins whose prefix assignment is not
// confined to the command: export / declare / readonly / local assign the
// variable with that value, and the POSIX special builtins keep it in POSIX mode.
// A certainty name given a prefix on one of them is dynamic afterwards.
var persistentPrefixBuiltins = set("export", "declare", "typeset", "readonly", "local", "eval", "source", ".", ":", "set", "unset",
	"read", "mapfile", "readarray", "getopts", "printf", "let", "trap", "shift", "break", "continue", "return", "exec", "wait", "umask", "alias")

// plainIdent reports a plain shell identifier: the only form of a name operand
// that a builtin reads as a variable name without evaluating it. bash evaluates
// the subscript of NAME[...] -- and a command substitution inside it -- even when
// the word is quoted (round 10, GAP-0197).
func plainIdent(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

// makeUncertain forgets what the walker knew about a variable after a prefix
// assignment it can not confine to one command.
func (w *walker) makeUncertain(name string) {
	w.ownVars()
	delete(w.env, name)
	switch name {
	case "HOME":
		if w.curDialect == DialectPOSIX {
			w.curHome = ""
		}
	case "CDPATH":
		w.cdpathMaybeSet = true
	}
}
