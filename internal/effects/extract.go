// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/awkprog"
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
	if inferred && dialect != DialectPOSIX && o.flavor() == FlavorWindows && posixOnlySyntax(call.Command) {
		unionPOSIXReading(&res, dialect, script.RunsNothing, call, o)
	}
	return res
}

// posixOnlySyntax reports text that uses a construct only the POSIX grammar
// gives a meaning to: the quote splice '\” (close, escaped quote, reopen), a
// here-document or here-string (<< and <<<: PowerShell reserves < and cmd
// has no << operator), or find's escaped \; terminator. PowerShell and cmd
// read them as literal text (or a parse error), so a guessed Windows dialect
// reads such a command differently from the shell it was written for.
func posixOnlySyntax(c string) bool {
	return strings.Contains(c, `'\''`) || strings.Contains(c, "<<") || strings.Contains(c, ` \;`)
}

// unionPOSIXReading adds the POSIX reading of a call whose Windows dialect was
// only guessed (no dialect hint) and whose text is POSIX-only syntax: Git Bash
// and WSL are Windows shells too, and the guessed reading of POSIX text loses
// the targets its quoting names (GAP-1915: '\” read by PowerShell leaves a
// stray \' on a redirection target or a switch). Every added effect is marked
// Cond (it happens only under that shell). Raise-only: no effect of the
// guessed reading is dropped.
//
// When the guessed reading is PowerShell that pwsh itself refuses to parse
// (runsNothing: a parse error the parser port reports, psparse
// Diagnostic.Syntax) and the POSIX reading parses, the POSIX reading is the
// only one that runs: all of its effects are added and the PowerShell parse
// error unknowns are cleared (psparse read <<< without an error, T21a; the
// port reports < as reserved, as pwsh does). A note the reader makes on
// PowerShell that runs (a dialect-ambiguous escape, a construct it does not
// model) or a script the port declined never clears them: that script runs
// (GAP-1945).
//
// Otherwise only the known mutations of the POSIX reading are added (a write,
// append, delete, link or permission change whose target and role it
// resolves), and only when the guessed reading lacks the same kind on the
// same target fully known. An unresolved guessed effect of that kind and
// target is the misread of the known one: it takes the known target and role
// and keeps what else it carried (mergeGuessedInto, GAP-1946), or the
// projection would hold the target Maybe (holdKnownOnNameMaybe).
func unionPOSIXReading(res *Result, guessed Dialect, runsNothing bool, call Call, o Options) {
	alt := Result{Surface: SurfaceShell, Flavor: o.flavor(), Dialect: DialectPOSIX}
	w := newWalker(&alt, o)
	w.pathDialect = DialectNone
	w.applyWorkdir(call.Workdir)
	w.walkScript(parsePOSIX(call.Command, o), 0)
	posixRuns := guessed == DialectPowerShell && runsNothing && len(alt.Unknowns) == 0 && onlyParseErrors(res.Unknowns)
	have := make(map[unionKey]bool, len(res.Effects))
	for _, e := range res.Effects {
		if e.TargetState == TargetStateKnown && e.RoleState == RoleStateKnown {
			have[unionKeyOf(e)] = true
		}
	}
	// placedAt maps an alt effect (1-based, as Source.Effect) to its 1-based
	// place in res, so the data sources of the added effects point into res.
	placedAt := make(map[int]int, len(alt.Effects))
	// placed is an added alt effect: its places in res, and the effects of
	// the guessed reading it takes the place of (misread).
	type placed struct {
		alt     int
		at      []int
		misread []Effect
	}
	var added []placed
	guessedLen := len(res.Effects)
	for i, e := range alt.Effects {
		known := e.TargetState == TargetStateKnown && e.RoleState == RoleStateKnown
		mutation := false
		switch e.Kind {
		case KindWrite, KindAppend, KindDelete, KindLink, KindPermissionChange:
			mutation = true
		}
		if !posixRuns && (!mutation || !known) {
			continue
		}
		k := unionKeyOf(e)
		if known && have[k] {
			continue
		}
		e.Cond = true
		p := placed{alt: i}
		if known && mutation && e.Target.Type == TargetPath && e.Target.Path != "" {
			have[k] = true
			// In place, so the data sources of the guessed reading stay valid.
			for gi, g := range res.Effects {
				if g.Kind == e.Kind && g.Target.Path == e.Target.Path {
					p.at = append(p.at, gi)
					p.misread = append(p.misread, g)
				}
			}
		}
		if len(p.at) == 0 {
			res.Effects = append(res.Effects, e)
			p.at = []int{len(res.Effects) - 1}
		}
		placedAt[i+1] = p.at[0] + 1
		added = append(added, p)
	}
	// An alt effect not added (a read, when only the known mutations are) is
	// the guessed reading effect of the same kind on the same file when it
	// has one: a POSIX write of what that read produced keeps the read as its
	// source (GAP-2084: cat ~/.git-credentials > "C:\Temp\o.txt" lost its src,
	// so the read had no content flow). Only a producer with no such twin is
	// dropped.
	twin := make(map[unionKey]int, guessedLen)
	for gi := 0; gi < guessedLen; gi++ {
		if g := res.Effects[gi]; g.Target.Type == TargetPath && g.Target.Path != "" {
			if _, dup := twin[unionKeyOf(g)]; !dup {
				twin[unionKeyOf(g)] = gi + 1
			}
		}
	}
	for i, e := range alt.Effects {
		if _, ok := placedAt[i+1]; ok || e.Target.Type != TargetPath || e.Target.Path == "" {
			continue
		}
		if at, ok := twin[unionKeyOf(e)]; ok {
			placedAt[i+1] = at
		}
	}
	// The sources are remapped before the merge, so mergeGuessedInto weighs
	// the producers the effect keeps in res, not the alt indices it named.
	for _, p := range added {
		e := alt.Effects[p.alt]
		e.Cond = true
		e.Data = remapSources(e.Data, placedAt)
		for _, g := range p.misread {
			e = mergeGuessedInto(e, g)
		}
		for _, at := range p.at {
			res.Effects[at] = e
		}
	}
	if posixRuns {
		res.Unknowns = nil
	}
}

// unionKey identifies an effect across the two readings of one call: a path
// target by its resolved path (the readings spell it differently), any other
// target by what it names.
type unionKey struct {
	k                   Kind
	t                   TargetType
	path, url, spelling string
}

func unionKeyOf(e Effect) unionKey {
	if e.Target.Type == TargetPath {
		return unionKey{k: e.Kind, t: TargetPath, path: e.Target.Path}
	}
	return unionKey{k: e.Kind, t: e.Target.Type, path: e.Target.Path, url: e.Target.URL, spelling: e.Target.Spelling}
}

// mergeGuessedInto folds an unresolved effect of the guessed reading into the
// known POSIX effect of the same kind on the same target (GAP-1946): the POSIX
// target and role stay (they are the resolved ones) and the effect stays Cond;
// the guessed effect's data is kept when it is the stronger (the POSIX effect
// has none, or the guessed one names its producers or carries more), and a
// link-target role of either is kept. Both data index res: the POSIX
// sources are remapped before the merge.
func mergeGuessedInto(e, g Effect) Effect {
	if g.Data != nil && (e.Data == nil || (len(e.Data.Sources) == 0 && len(g.Data.Sources) > 0) || g.Data.Bytes > e.Data.Bytes) {
		d := *g.Data
		e.Data = &d
	}
	e.LinkTarget = e.LinkTarget || g.LinkTarget
	return e
}

// remapSources points the data sources of an effect taken from the POSIX
// reading at the places their producers got in res; a producer that was not
// added is dropped (its index named an alt effect).
func remapSources(d *Data, placedAt map[int]int) *Data {
	if d == nil || len(d.Sources) == 0 {
		return d
	}
	c := *d
	c.Sources = make([]Source, 0, len(d.Sources))
	for _, s := range d.Sources {
		if s.Effect != 0 {
			at, ok := placedAt[s.Effect]
			if !ok {
				continue
			}
			s.Effect = at
		}
		c.Sources = append(c.Sources, s)
	}
	if len(c.Sources) == 0 {
		c.Sources = nil
	}
	return &c
}

// onlyParseErrors reports a non-empty list of structure unknowns that are all
// parse errors (a construct the frontend could not parse, invalid syntax).
func onlyParseErrors(us []Reason) bool {
	for _, u := range us {
		if u.Code != ReasonUnparsedConstruct && u.Code != ReasonInvalidSyntax {
			return false
		}
	}
	return len(us) > 0
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
	wrapOuts   []wrapperOutput // files the current command's wrappers open themselves (time -o, script FILE)
	funcs      map[string]bool
	aliases    map[string]string
	links      map[string]string // link key -> target physical path (review R7)
	writeByKey map[string]int    // path key -> 1-based effect index that wrote it

	env         map[string]string
	captured    map[string][]int // bounded reads assigned from a command substitution
	capturedOut []int            // content printed by the substitution being walked
	curCWD      string
	curHome     string
	cwdStack    []string
	lastPrim    int // 1-based index of the previous stage's primary effect (pipe join)
	// stageIn is what the current command reads on stdin from the previous
	// pipeline stage; stageOut is what the last finished stage passes on. Each
	// names the reads whose bytes the stage may print and a literal it was fed
	// (echo/printf). They tie a pipe or a redirect to the data behind it, so a
	// secret read upstream is a source of the send or write downstream (s7-flow,
	// rel-1-0-10 GAP-0128/GAP-0130). literalOut is the literal the current
	// command prints; redirOut the 1-based indices of its stdout redirects.
	stageIn, stageOut stageData
	literalOut        string
	// printsOut: the current command prints the bytes it reads on its
	// stdout (stagePrints); hidden counts the enclosing stages whose output
	// does not reach the call's own stdout (piped on, redirected, captured in
	// a substitution), so no read under them is shown (GAP-1846).
	printsOut  bool
	hidden     int
	redirOut   []int
	work       int // remaining work budget; 0 -> stop and emit a limit unknown (R3-1)
	overBudget bool
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
	// allExportMaybe is sticky once `set -a` / `set -o allexport` (or a dynamic
	// set argument) is seen: every later plain assignment may be exported, so
	// it reaches the environment of later programs (GAP-0217).
	allExportMaybe bool
	// pathMaybeSet is sticky once PATH is assigned in the shell (bare, export,
	// declare): a later bare program name may run another binary (GAP-0217).
	pathMaybeSet bool
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
	// remote counts the remote-host bodies being walked (ssh HOST CMD...: the
	// joined words run in the login shell of another host, GAP-0662 ruling).
	// Every effect emitted inside one is placed on that host (remoteTarget).
	remote int
	// cdUnreliable: the cd builtin was disabled or made to resolve names as
	// variables (enable -n cd, shopt -s cdable_vars), or cd was aliased: its
	// target and effect are no longer what the argument says.
	cdUnreliable bool
	// lastpipe: shopt -s lastpipe is in effect (see command).
	lastpipe bool
	// pwdFunc is what a pwd function defined earlier in this shell prints,
	// when its definition ran on every path and its body is one echo of a
	// static word; nil when no such definition is the current one
	// (rel-1-0-10:GAP-1043).
	pwdFunc *string
	// pwdOwn: the call assigned PWD after its last cd, so $PWD is that value
	// and not the tracked folder.
	pwdOwn bool
	// execState: an unconditional `set -n` (or another unreviewed set option),
	// `exec CMD`, `exit` or DEBUG/RETURN trap ran in this shell, so whether a
	// later statement runs is not modeled: every later effect of the shell is
	// unaccounted. It belongs to one shell: saved and restored around a child
	// shell (rel-1-0-10 GAP-0218).
	execState bool
	// debugTrap: a DEBUG trap that may end the shell or skip commands is set in
	// this shell; a child shell does not inherit it (no set -T modeling).
	debugTrap bool
	// execMarks holds the execution state at each compound-redirect mark.
	execMarks map[*Stmt][2]bool
	// childDepth counts the enclosing commands that run in a child shell.
	childDepth int
	// dead counts the enclosing statements behind a provably false `&&` / true
	// `||`: their effects never run, so each is unaccounted (GAP-0218).
	dead int
	// condFrame counts the eval / source / child-shell bodies walked under a
	// condition: a statement in one is conditional although its own Cond is not.
	condFrame int
	// disabled names the builtins an `enable` call may have turned off or
	// replaced; enableDyn: an enable call the walker could not read (GAP-0218).
	disabled  map[string]bool
	enableDyn bool
	// execfailMaybe: shopt may have set execfail (a failed exec does not end the
	// shell); extdebugMaybe: shopt may have set extdebug (a DEBUG trap that
	// fails skips the command).
	execfailMaybe, extdebugMaybe bool
	// namerefSeen: a `declare -n` was seen, so any later assignment may land on
	// HOME or CDPATH through the reference; both stay dynamic for the call.
	namerefSeen bool
	// curProgram is the program of the command being classified (a table row can
	// serve several names, e.g. gzip and gunzip).
	curProgram string
	// edStdin is the static standard input of the ed call being read (its
	// script, edOperands); edStdinOK is false when it is not known.
	edStdin   string
	edStdinOK bool
	// spec is the environment change the command being walked applies to the
	// child process it starts (prefix assignments, env/sudo wrapper options).
	spec *childSpec
	// fileText holds the text earlier statements of the call wrote to a file
	// (a here-document, a static echo), by path key: a later sh FILE, . FILE,
	// ./FILE or sh < FILE runs that text (DET111 R1, GAP-1502).
	fileText map[string]fileBody
	// exactOK / exactText: the command being walked prints exactly exactText
	// on stdout (exactOutput); literalKind is the data kind of literalOut.
	exactOK     bool
	exactText   string
	literalKind DataKind
	// positional, when positionalSet, are the $0 $1 ... the next child body
	// lowered by unwrapCodeScoped binds (sh -c BODY ARG0 ARG1, sh FILE ARG1).
	positional     []Word
	positionalSet  bool
	foreignContext bool // a nested shell body runs under a named non-root account wrapper
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
	if o.loginHome == "" {
		o.loginHome = o.Home // ~Login stays the passwd home when the call sets HOME
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
		if st.ExecMark {
			if w.execMarks == nil {
				w.execMarks = map[*Stmt][2]bool{}
			}
			w.execMarks[st] = [2]bool{w.execState, w.debugTrap}
			continue
		}
		var afterBody [2]bool
		if st.ExecFrom != nil {
			if m, ok := w.execMarks[st.ExecFrom]; ok {
				afterBody = [2]bool{w.execState, w.debugTrap}
				w.execState, w.debugTrap = m[0], m[1]
			}
		}
		dead := w.deadStatement(st, s.Dialect)
		if dead {
			w.dead++
		}
		w.enterStmt(st)
		for i, c := range st.Cmds {
			// A stage piped on or redirected shows none of its reads, nor do
			// the bodies it runs (sh -c); the last stage on the call's own
			// stdout shows what it prints (GAP-1846).
			hide := c.Pipeline && !c.PipeLast || i+1 < len(st.Cmds) && st.Cmds[i+1].PipeIn ||
				stdoutRedirected(c.Redirs) && !stdoutToAgentStderr(c.Redirs)
			if hide {
				w.hidden++
			}
			w.commandStage(c, s.Dialect, depth, st.Cond || c.Cond)
			if hide {
				w.hidden--
			} else if w.hidden == 0 {
				w.markShown(w.stageOut.content)
				w.markShown(w.stageOut.agentContent)
			}
		}
		w.leaveStmt()
		if dead {
			w.dead--
		}
		if st.ExecFrom != nil {
			if _, ok := w.execMarks[st.ExecFrom]; ok {
				w.execState, w.debugTrap = afterBody[0], afterBody[1]
			}
		}
	}
}

// walkCaptured walks a command substitution body: its output is the value
// of a word, not the call's output, so none of its reads is shown (GAP-1846).
func (w *walker) walkCaptured(sub *Script, depth int) {
	w.hidden++
	defer func() { w.hidden-- }()
	w.walkScript(sub, depth)
	w.capturedOut = appendCapped(w.capturedOut, w.stageOut.content...)
}

// markShown marks the reads a stage prints on the call's own stdout.
func (w *walker) markShown(reads []int) {
	for _, idx := range reads {
		if idx > 0 && idx <= len(w.res.Effects) && w.res.Effects[idx-1].Kind == KindRead {
			w.res.Effects[idx-1].Shown = true
		}
	}
}

// stagePrints reports a command whose stdout carries the bytes it reads: a
// reader (cat, head, grep, sed without -i) or a program that prints what it
// is piped (tee), unless it prints only a summary (wc, a digest, grep -c,
// diff -q, cmp without -l or -b) or edits in place (DET111 GAP-1846). A copy, an upload or an
// archive prints none of its reads: their bytes go to the destination.
func stagePrints(p Program, words []Word) bool {
	if p.Summary && !hasRowFlag(words, p, p.ShowFlags) || hasRowFlag(words, p, p.SummaryFlags) {
		return false
	}
	if p.InPlace != "" && hasRowFlag(words, p, append([]string{p.InPlace}, p.InPlaceFlags...)) {
		return false
	}
	return p.Prints || p.Pos == PosAllRead && !p.MetadataOnly
}

// deadStatement reports a statement the frontend found behind a constant
// guard (false &&, true ||) whose builtins are still the builtins: a function
// or alias of that name can return anything, so the statement may run.
func (w *walker) deadStatement(st *Stmt, d Dialect) bool {
	if len(st.DeadGuard) == 0 {
		return false
	}
	for _, n := range st.DeadGuard {
		if !w.isBuiltin(n, d) {
			return false
		}
	}
	return true
}

// isBuiltin reports that a shell builtin name is not shadowed by a function or
// an alias defined earlier in the call, and not turned off (or replaced) with
// enable.
func (w *walker) isBuiltin(name string, d Dialect) bool {
	return !w.funcs[funcKey(name, d)] && w.aliases[name] == "" && !w.enableDyn && !w.disabled[name]
}

// endsExecution reports a command after which the shell runs nothing the walker
// can account for (GAP-0218): `exec CMD` replaces the shell (unless execfail
// may be on), `exit` ends it, and `set -n` / `-o noexec` (also through
// `shopt -s -o`) reads commands without running them. trap reports a DEBUG
// trap whose action may end the shell or skip commands: it holds in this
// shell only, a subshell does not inherit it. words is the command's argv,
// inner the argv after its wrappers. A builtin shadowed by a function or
// alias, or turned off with enable, is not the builtin: the caller keeps
// today's reading. Options that do not stop a command (-e, -E, -f, -C, -t,
// -o posix, ...; -t / onecmd is ignored under bash -c) never count, so a
// prefix cannot hide a real write.
func (w *walker) endsExecution(words, inner []Word, d Dialect) (ends, trap bool) {
	wrapped := len(words) - len(inner)
	k := 0
	for k < wrapped && words[k].Static && (words[k].Value == "command" || words[k].Value == "builtin") && w.isBuiltin(words[k].Value, d) {
		k++
	}
	if k < wrapped {
		return words[k].Static && words[k].Value == "exec" && w.isBuiltin("exec", d) && !w.execfailMaybe, false
	}
	if len(inner) == 0 || !inner[0].Static || !w.isBuiltin(inner[0].Value, d) {
		return false, false
	}
	switch inner[0].Value {
	case "exit":
		return true, false
	case "set":
		return setStopsExecution(inner[1:]), false
	case "shopt":
		return shoptStopsExecution(inner[1:]), false
	case "trap":
		return false, w.trapChangesExecution(inner[1:], d)
	}
	return false, false
}

// stopSetLetters and stopSetOptions are the set options that stop execution:
// -n / noexec reads commands without running them. (-t / onecmd
// exits after one command.
const stopSetLetters = "n"

var stopSetOptions = set("noexec")

// setStopsExecution reports a `set` call that turns on an option that stops
// execution, or one whose words the walker cannot read.
func setStopsExecution(args []Word) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !a.Static {
			return true
		}
		v := a.Value
		if v == "--" || v == "-" || len(v) < 2 || (v[0] != '-' && v[0] != '+') {
			return false // the positional parameters follow
		}
		on := v[0] == '-'
		named := 0
		for _, ch := range v[1:] {
			if ch == 'o' {
				named++
			} else if on && strings.ContainsRune(stopSetLetters, ch) {
				return true
			}
		}
		for ; named > 0 && i+1 < len(args); named-- {
			i++
			if !args[i].Static || (on && stopSetOptions[args[i].Value]) {
				return true
			}
		}
	}
	return false
}

// shoptStopsExecution reports `shopt -s -o noexec` (the set -o options through
// shopt) or a shopt call the walker cannot read.
func shoptStopsExecution(args []Word) bool {
	setOn, setOpts := false, false
	for _, a := range args {
		if !a.Static {
			return true
		}
		if strings.HasPrefix(a.Value, "-") {
			setOn = setOn || strings.Contains(a.Value, "s")
			setOpts = setOpts || strings.Contains(a.Value, "o")
			continue
		}
		if setOn && setOpts && stopSetOptions[a.Value] {
			return true
		}
	}
	return false
}

// trapChangesExecution reports a `trap` call that sets a DEBUG trap whose
// action may end the shell or skip commands, or a trap call the walker cannot
// read. A static action is parsed and demotes only when one of its commands
// ends or stops execution (trapActionChangesExecution); a dynamic or
// unparseable action, or any action once extdebug may be on (a failing DEBUG
// trap then skips the command), demotes. A trap that only prints or logs
// (`echo $BASH_COMMAND`, `set +x`) leaves every command running. RETURN and
// ERR traps are not modeled (they fire only on a return / a failure).
func (w *walker) trapChangesExecution(args []Word, d Dialect) bool {
	i := 0
	if i < len(args) {
		if !args[i].Static {
			return true
		}
		switch v := args[i].Value; {
		case v == "--":
			i++
		case v == "-p" || v == "-l" || v == "-lp" || v == "-pl":
			return false // lists the traps
		case len(v) > 1 && v[0] == '-':
			return true
		}
	}
	rest := args[i:]
	if len(rest) < 2 {
		return false // nothing, or one signal reset
	}
	action := rest[0]
	if action.Static && (action.Value == "-" || action.Value == "" || allDigits(action.Value)) {
		return false // resets or ignores the named signals
	}
	flow := false
	for _, s := range rest[1:] {
		if !s.Static {
			return true
		}
		switch strings.TrimPrefix(strings.ToUpper(s.Value), "SIG") {
		case "DEBUG":
			flow = true
		}
	}
	if !flow {
		return false
	}
	if !action.Static || w.extdebugMaybe {
		return true
	}
	return w.trapActionChangesExecution(parsePOSIX(action.Value, w.o), d, 0)
}

// trapActionChangesExecution reads a parsed DEBUG trap action: true when the
// parse left an unknown, a command word is dynamic, or a command can end the
// shell or skip what follows: exit / exec CMD / kill / return / logout /
// suspend, set or shopt that stop execution, a nested trap, eval / source / .
// (their text is not read here), a function or alias of the call, or a
// builtin turned off with enable. Command substitutions and subshell bodies of
// the action are read the same way.
func (w *walker) trapActionChangesExecution(s *Script, d Dialect, depth int) bool {
	if s == nil {
		return false
	}
	if len(s.Unknowns) > 0 || depth > 4 {
		return true
	}
	for _, st := range s.Stmts {
		for _, c := range st.Cmds {
			if c.Sub != nil && w.trapActionChangesExecution(c.Sub, d, depth+1) {
				return true
			}
			for _, n := range c.Nested {
				if w.trapActionChangesExecution(n, d, depth+1) {
					return true
				}
			}
			words := c.Words
			for len(words) > 1 && words[0].Static && (words[0].Value == "command" || words[0].Value == "builtin") {
				words = words[1:]
			}
			if len(words) == 0 {
				continue
			}
			if !words[0].Static {
				return true
			}
			name := words[0].Value
			if !w.isBuiltin(name, d) {
				return true
			}
			switch name {
			case "exit", "kill", "return", "logout", "suspend", "trap", "eval", "source", ".", "enable":
				return true
			case "exec":
				if len(words) > 1 {
					return true
				}
			case "set":
				if setStopsExecution(words[1:]) {
					return true
				}
			case "shopt":
				if shoptStopsExecution(words[1:]) {
					return true
				}
			}
		}
	}
	return false
}

// mutatesTarget reports a kind that changes its target (the kinds the
// restricted tier can block on).
func mutatesTarget(k Kind) bool {
	switch k {
	case KindWrite, KindAppend, KindDelete, KindLink, KindPermissionChange:
		return true
	}
	return false
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
	if w.remote > 0 {
		remoteTarget(&e)
	}
	if (w.execState || w.debugTrap || w.dead > 0) && mutatesTarget(e.Kind) {
		// The shell may never run it: not a fully known mutation (GAP-0218). A
		// read or run that may not happen keeps its reading, as before.
		e.addReason(ReasonExecutionState, ScopeRole)
	}
	w.forgetFileBody(e)
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
		if s.Subst == "pwd" {
			// $(pwd) prints the working folder unless pwd is a function, an
			// alias or disabled; a pwd function whose definition the walk read
			// prints its static word (rel-1-0-10:GAP-1043).
			v, ok := "", false
			switch {
			case w.isBuiltin("pwd", DialectPOSIX):
				v, ok = w.cwdWord(i == 0)
			case w.pwdFunc != nil && w.aliases["pwd"] == "" && w.isBuiltin("echo", DialectPOSIX):
				v, ok = *w.pwdFunc, true
			}
			if !ok {
				return Word{Static: false, Reason: ReasonDynamicExpansion, Span: wd.Span, Tail: segTail(wd.Segs[i+1:])}
			}
			b.WriteString(v)
			continue
		}
		if s.Var != "" {
			v, ok := w.env[s.Var]
			if s.Var == psHomeVar && !ok {
				v, ok = w.curHome, w.curHome != "" // PowerShell's automatic $HOME, unless this call assigned it
			}
			if s.Var == "SHELL" && !ok && w.o.Account.Shell != "" {
				v, ok = w.o.Account.Shell, true
			}
			if s.Var == "PWD" && !w.pwdOwn && !w.namerefSeen {
				v, ok = w.cwdWord(i == 0)
			}
			if ok && s.Op != nil {
				if v == "." && s.Var == "PWD" {
					ok = false
				} else {
					v, ok = applyParamOp(v, s.Op)
				}
			}
			if !ok || (s.Var == psHomeVar && v == "") {
				// The segments stay on the word, so a reader of its literal part
				// (env NAME=$V: the name) still sees them; the Reason keeps the
				// word unresolved. Tail is the literal after the dynamic part.

				return Word{Static: false, Reason: ReasonDynamicExpansion, Span: wd.Span, Segs: wd.Segs, Tail: segTail(wd.Segs[i+1:])}
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
		if i == 0 && s.Quoted && strings.HasPrefix(lit, "~") {
			// A quoted tilde is a literal folder named ~ (bash expands only an
			// unquoted tilde prefix): never the home.
			lit = "./" + lit
			b.WriteString(lit)
			quoted = true
			continue
		}
		if i == 0 && !s.Quoted && strings.HasPrefix(lit, "~") && !isTilde(lit, w.o.flavor(), w.curDialect) {
			v, ok := w.tildePrefix(lit)
			if !ok {
				// An account the walker cannot place (~x): the home is unknown,
				// the path below it is not (~x/.aws/credentials keeps its
				// literal tail for the classifier, rel-1-0-10:GAP-0898).
				return Word{Static: false, Reason: ReasonDynamicExpansion, Span: wd.Span, Tail: tildeTail(lit, wd.Segs[1:])}
			}
			if s.Glob {
				glob = true
			}
			b.WriteString(v)
			continue
		}
		if i == 0 && isTilde(lit, w.o.flavor(), w.curDialect) {
			if w.curHome == "" {
				return Word{Static: false, Reason: ReasonDynamicExpansion, Span: wd.Span, Tail: tildeTail(lit, wd.Segs[1:])}
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

// cwdWord is the value of $PWD or ~+: the working folder when the walk knows
// it as one folder, else "." when the word starts with it (placed like a
// relative name under every candidate folder).
func (w *walker) cwdWord(leading bool) (string, bool) {
	if cwd, ok := w.knownCWD(); ok {
		return cwd, true
	}
	if leading {
		return ".", true
	}
	return "", false
}

// knownCWD is the working folder when the walk knows it as one folder.
func (w *walker) knownCWD() (string, bool) {
	if w.curCWD == "" || len(w.cwdAlt) > 0 {
		return "", false
	}
	return w.curCWD, true
}

// tildePrefix expands an unquoted POSIX tilde prefix other than ~ and ~/:
// ~+ is the working folder and ~- the previous one (unknown here); ~login is
// that account's home through tildeAccount (the active login, an account the
// caller vouched for, or the literal folder of a name no login can have).
func (w *walker) tildePrefix(lit string) (string, bool) {
	name, rest := lit[1:], ""
	if i := strings.IndexAny(name, `/`); i >= 0 {
		name, rest = name[:i], name[i:]
	}
	if name == "+" {
		cwd, ok := w.cwdWord(true)
		if !ok {
			return "", false
		}
		if w.o.flavor() == FlavorWindows {
			return strings.TrimRight(cwd, `\`) + rest, true
		}
		return strings.TrimRight(cwd, "/") + rest, true
	}
	if w.o.flavor() == FlavorWindows {
		return "", false
	}
	o := w.o
	o.Home = w.curHome
	h, ok, _ := tildeAccount(lit, o)
	return h, ok
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
	reads []int
	// fetches are literal network responses proven to reach this stage's
	// stdout. They are provenance for a shell that reads its script on stdin.
	fetches []int
	// content: the reads whose bytes the stage prints on its stdout (a
	// summary or a redirect drops them; GAP-1846).
	content []int
	// agentContent reaches visible stderr but not a downstream pipe.
	agentContent []int
	literal      string
	// exact: the stage printed exactly text (an exact printer, see
	// exactOutput), so a shell reading the pipe runs that text.
	exact bool
	text  string
}

// maxStageSources bounds the sources one stage carries, so a long pipeline of
// many reads stays O(1) per effect.
const maxStageSources = 32

// commandStage walks one command or pipeline stage and records what it passes
// on: a stage's stdout carries what it read, what it was piped and what it
// printed (s7-flow, rel-1-0-10 GAP-0128/GAP-0130). It also links a command
// substitution's reads to the dynamic data the command sends or writes.
func (w *walker) commandStage(c *Cmd, dialect Dialect, depth int, cond bool) {
	savedIn, savedLit, savedRedir, savedPrints := w.stageIn, w.literalOut, w.redirOut, w.printsOut
	savedExact, savedText, savedKind := w.exactOK, w.exactText, w.literalKind
	savedCapturedOut := w.capturedOut
	w.capturedOut = nil
	in := stageData{}
	if c.PipeIn {
		in = w.stageOut
	}
	w.stageIn, w.literalOut, w.redirOut, w.printsOut = in, "", nil, false
	w.exactOK, w.exactText, w.literalKind = false, "", ""
	start, own := len(w.res.Effects), w.cmdNo+1
	w.command(c, dialect, depth, cond)
	capturedOut := w.capturedOut
	w.capturedOut = savedCapturedOut
	out := stageData{literal: w.literalOut, exact: w.exactOK && !stdoutRedirected(c.Redirs), text: w.exactText}
	printsArgs := printerProgram(c.Words)
	if !printsArgs {
		if out.literal == "" {
			out.literal = in.literal
		}
		out.reads = appendCapped(out.reads, in.reads...)
	}
	// A fetched response is executable script data only when stdout carries
	// it. The direct fetch and a one-argument printf of a sole command
	// substitution use the same bounded source edge.
	if fetch := w.fetchedStdout(c, start, len(w.res.Effects)); fetch != 0 {
		out.fetches = []int{fetch}
	} else if len(c.Assigns) == 0 && len(c.Redirs) == 0 && len(c.Words) == 3 &&
		c.Words[0].Static && c.Words[0].Value == "printf" && c.Words[1].Static &&
		(c.Words[1].Value == "%s" || c.Words[1].Value == "%s\\n") &&
		!c.Words[2].Static && len(c.Nested) == 1 {
		sub := c.Nested[0]
		if len(sub.Unknowns) == 0 && len(sub.Stmts) == 1 && len(sub.Stmts[0].Cmds) == 1 {
			if fetch := w.fetchedStdout(sub.Stmts[0].Cmds[0], start, len(w.res.Effects)); fetch != 0 {
				out.fetches = []int{fetch}
			}
		}
	}
	shows := w.printsOut && !stdoutRedirected(c.Redirs)
	showsStderr := w.printsOut && stdoutToAgentStderr(c.Redirs)
	if !printsArgs {
		if shows {
			out.content = appendCapped(out.content, in.content...)
		}
		if showsStderr {
			out.agentContent = appendCapped(out.agentContent, in.content...)
		}
	}
	var nested []int
	for i := start; i < len(w.res.Effects); i++ {
		e := &w.res.Effects[i]
		if e.Kind != KindRead {
			continue
		}
		out.reads = appendCapped(out.reads, i+1)
		if e.Origin.Command == own {
			if shows {
				out.content = appendCapped(out.content, i+1)
			}
			if showsStderr {
				out.agentContent = appendCapped(out.agentContent, i+1)
			}
		}
		if e.Origin.Command != own {
			nested = appendCapped(nested, i+1)
		}
	}
	if len(c.Nested) > 0 && len(nested) > 0 {
		w.linkSubstitutionData(start, own, nested)
	}
	if len(c.Words) == 0 {
		// A bare assignment stores a substitution's output for later echo.
		// Other assignments already cleared the previous source.
		for _, a := range c.Assigns {
			if !a.ValueWord.Static && len(capturedOut) > 0 && len(c.Redirs) == 0 {
				if w.captured == nil {
					w.captured = make(map[string][]int)
				}
				w.captured[a.Name] = appendCapped(nil, capturedOut...)
			}
		}
	} else if w.printsOut && printerArguments(c.Words) {
		for _, word := range c.Words[1:] {
			for _, seg := range word.Segs {
				if seg.Var != "" {
					if shows {
						out.content = appendCapped(out.content, w.captured[seg.Var]...)
					}
					if showsStderr {
						out.agentContent = appendCapped(out.agentContent, w.captured[seg.Var]...)
					}
				}
			}
			if word.Reason == ReasonDynamicExpansion && len(capturedOut) > 0 {
				if shows {
					out.content = appendCapped(out.content, capturedOut...)
				}
				if showsStderr {
					out.agentContent = appendCapped(out.agentContent, capturedOut...)
				}
			}
		}
	}
	w.stageOut = out
	w.stageIn, w.literalOut, w.redirOut, w.printsOut = savedIn, savedLit, savedRedir, savedPrints
	w.exactOK, w.exactText, w.literalKind = savedExact, savedText, savedKind
}

// printerArguments identifies a command that prints the bytes of its
// arguments; the program table accounts for its operands as data.
func printerProgram(words []Word) bool {
	if len(words) == 0 || !words[0].Static {
		return false
	}
	switch programBasename(words[0].Value, FlavorPOSIX) {
	case "echo", "printf":
		return true
	}
	return false
}

func printerArguments(words []Word) bool {
	return len(words) > 1 && printerProgram(words)
}

// fetchedStdout returns a literal fetch whose response is this command's
// stdout. An output file or redirect severs the source-to-script edge.
func (w *walker) fetchedStdout(c *Cmd, start, end int) int {
	if c == nil || len(c.Words) == 0 || !c.Words[0].Static || len(c.Nested) != 0 || stdoutRedirected(c.Redirs) {
		return 0
	}
	program := programBasename(c.Words[0].Value, w.o.flavor())
	switch program {
	case "curl":
		for _, word := range c.Words[1:] {
			if word.Static && (word.Value == "-O" || word.Value == "-OJ" ||
				word.Value == "--remote-name" || word.Value == "--remote-header-name") {
				return 0
			}
		}
	case "wget":
		stdout := false
		for i, word := range c.Words[1:] {
			if !word.Static {
				return 0
			}
			if word.Value == "-O-" || word.Value == "--output-document=-" ||
				(word.Value == "-O" || word.Value == "--output-document") &&
					i+2 < len(c.Words) && c.Words[i+2].Static && c.Words[i+2].Value == "-" {
				stdout = true
			}
		}
		if !stdout {
			return 0
		}
	default:
		return 0
	}
	fetch := 0
	for i := start; i < end && i < len(w.res.Effects); i++ {
		e := w.res.Effects[i]
		switch e.Kind {
		case KindWrite, KindAppend, KindDelete, KindLink:
			return 0
		case KindExec:
			if e.Origin.Program == program && len(e.Reasons) != 0 {
				return 0
			}
		case KindNetworkFetch:
			if e.Origin.Program != program || e.TargetState != TargetStateKnown ||
				e.RoleState != RoleStateKnown || e.Target.Type != TargetURL ||
				e.Target.URL == "" || len(e.Reasons) != 0 || fetch != 0 {
				return 0
			}
			fetch = i + 1
		}
	}
	return fetch
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
	if c.MayCallFunc {
		defer w.setCWDDynamic()
	}
	if !w.spend() {
		return
	}
	// A pipeline stage, a background command and a command of a backgrounded
	// list run in a child shell, with the eval / source text they walk: an exit
	// or exec there does not end this shell (GAP-0218).
	if c.Pipeline || c.Async || c.ChildList {
		w.childDepth++
		defer func() { w.childDepth-- }()
	}
	// A pwd function definition: $(pwd) after it prints the function's static
	// word when the definition runs on every path; any other definition
	// leaves $(pwd) unknown (rel-1-0-10:GAP-1043).
	if d := c.Defines; d != nil && d.Name == "pwd" && dialect == DialectPOSIX {
		w.pwdFunc = nil
		if d.Static && !d.Cond {
			out := d.Out
			w.pwdFunc = &out
		}
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
		switch {
		case c.PipeLast && !c.Async && dialect == DialectPOSIX && w.lastpipe:
			// shopt -s lastpipe: bash runs the last stage in this shell
			// (non-interactive, so no job control), so its cd and assignments
			// stay (rel-1-0-10:GAP-1037).
		case c.PipeLast && !c.Async && dialect == DialectPOSIX:
			// Without lastpipe bash runs it in a child, but zsh and a lastpipe
			// set where the walk cannot see it run it here: the folder after it
			// is either one.
			saved := w.saveScope()
			defer func() {
				after := w.cwdNow()
				w.restoreScope(saved)
				if before := w.cwdNow(); !after.equal(before) {
					w.setCWDState(joinCWD(before, after))
				}
			}()
		default:
			saved := w.saveScope()
			defer w.restoreScope(saved)
		}
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
		// The shell looks programs up in its own PATH, exported or not: any
		// assignment can move a later bare program name (GAP-0217).
		if a.Name == "PATH" && !prefix {
			w.pathMaybeSet = true
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
		if a.Exported || (w.allExportMaybe && !a.Unexport) {
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
		w.ownVars()
		delete(w.captured, a.Name)
		if rv.Static {
			w.ownVars()
			w.env[a.Name] = rv.Value
			if a.Name == "PWD" {
				w.pwdOwn = true
			}
			// A reassigned HOME re-roots `~` and a bare cd under POSIX shell
			// semantics, on every flavor incl. Git Bash (review 6 C). PowerShell's
			// `~` is fixed at session start, so $env:USERPROFILE must not rebind it
			// (review R3-9) -- hence the dialect, not the flavor, gates this.
			if a.Name == "HOME" && dialect == DialectPOSIX {
				w.curHome = w.placedHome(rv)
			}
		} else {
			w.ownVars()
			if a.Name == psHomeVar && dialect == DialectPowerShell {
				w.env[a.Name] = "" // explicitly reassigned to a dynamic value; do not restore the automatic home
			} else {
				delete(w.env, a.Name)
			}
			if a.Name == "HOME" && dialect == DialectPOSIX {
				w.curHome = "" // a dynamic home makes ~ dynamic (review N3 E2)
			}
		}
	}
	if len(c.Words) == 0 {
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		for _, sub := range c.Nested {
			s := w.saveScope()
			w.walkCaptured(sub, depth)
			w.restoreScope(s)
		}
		return
	}

	// Resolve the command's words against the parent env.
	words := w.resolveWords(c.Words)
	// Variables a for-loop rebinds are dropped via its own Unbind statement.

	// 2. Strip wrappers.
	inner, wrappers, foreign, fromInput, wrapperUA := w.stripWrappers(words)
	// bareXargs: the command is xargs CMD with no xargs option, so xargs
	// splits its input on blanks and newlines into one run of CMD.
	bareXargs := fromInput && len(inner) > 0 && len(inner) < len(words) &&
		words[len(words)-len(inner)-1].Static &&
		programBasename(words[len(words)-len(inner)-1].Value, w.o.flavor()) == "xargs"
	foreign = foreign || w.foreignContext
	spec := w.spec // the child-process environment this command applies (round 8 E)
	if len(inner) == 0 {
		if n := len(wrappers); n > 0 && wrappers[n-1] != "exec" && wrappers[n-1] != "command" && wrappers[n-1] != "builtin" {
			// a wrapper with no child word (`nohup`, `timeout 5`): nothing we can
			// read runs, so the call is never clean. A bare exec only applies its
			// redirections to the shell.
			e := Effect{Kind: KindExec, Target: Target{Type: TargetProcess, Link: LinkNotChecked}, TargetState: TargetStateKnown, RoleState: RoleStateKnown, Cond: cond,
				Origin: Origin{Surface: w.res.Surface, Dialect: dialect, Command: cmdNo, Program: wrappers[len(wrappers)-1], Wrappers: wrappers, Depth: depth, Span: c.Span}}
			e.addReason(ReasonUnmodeledProgram, ScopeRole)
			w.lastPrim = w.emit(e)
		}
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		return
	}
	// The files a wrapper opens itself are placed in the caller's folder,
	// before a wrapper's own folder change applies to the child.
	var wrapEffects []Effect
	for _, wo := range w.wrapOuts {
		op := operand{value: wo.word.Value, static: wo.word.Static, quoted: wo.word.Quoted, glob: wo.word.Glob, role: wo.role}
		if e := w.effectForOperand(op, Program{}, Origin{Surface: w.res.Surface, Dialect: dialect, Command: cmdNo, Program: wrappers[0], Wrappers: wrappers, Depth: depth, Span: c.Span}, cond, false, false, false, dialect, depth); e != nil {
			wrapEffects = append(wrapEffects, *e)
		}
	}
	prog := inner[0]
	if !prog.Static {
		e := Effect{Kind: KindExec, Target: Target{Type: TargetProcess, Link: LinkNotChecked}, TargetState: TargetStateUnknown, RoleState: RoleStateUnknown, Cond: cond,
			Origin: Origin{Surface: w.res.Surface, Dialect: dialect, Command: cmdNo, Wrappers: wrappers, Depth: depth, Span: c.Span}}
		e.addReason(ReasonDynamicExpansion, ScopeTarget)
		w.lastPrim = w.emit(e)
		for _, we := range wrapEffects {
			w.emit(we)
		}
		// A program named by a variable ("$SHELL" -c BODY, "$s" <<< BODY) may be
		// a shell: its body is lowered as a possible one (DET111 R1, GAP-1538,
		// GAP-1554), and the substitutions in its words still run.
		rawProgram := rawWordsFor(inner[:1], c.Words)[0]
		possibleStart := len(w.res.Effects)
		w.possibleShell(c, rawProgram, inner[1:], dialect, depth, e.Origin)
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		nestedStart := len(w.res.Effects)
		for _, sub := range c.Nested {
			s := w.saveScope()
			w.walkCaptured(sub, depth)
			w.restoreScope(s)
		}
		// With only a variable program and one here-string, the sole
		// substitution supplies its script. Link only a fetch proven to print
		// to stdout; an unrelated substitution cannot become a script source.
		if shellVariable(rawProgram) && len(c.Words) == 1 && len(c.Assigns) == 0 && len(c.Redirs) == 1 &&
			c.Redirs[0].Op == RedirHereString && !c.Redirs[0].Target.Static &&
			len(c.Nested) == 1 {
			sub := c.Nested[0]
			if len(sub.Unknowns) == 0 && len(sub.Stmts) == 1 && len(sub.Stmts[0].Cmds) == 1 {
				if fetch := w.fetchedStdout(sub.Stmts[0].Cmds[0], nestedStart, len(w.res.Effects)); fetch != 0 {
					for i := possibleStart; i < nestedStart; i++ {
						if w.res.Effects[i].Kind == KindExec && w.res.Effects[i].Data == nil &&
							w.res.Effects[i].TargetState == TargetStateUnknown {
							w.res.Effects[i].Data = &Data{Kind: DataCode, Sources: []Source{{Kind: SourceEffect, Effect: fetch}}}
						}
					}
				}
			}
		}
		return
	}
	program := programBasename(prog.Value, w.o.flavor())
	// su's -c body may be lowered through the program's ShellCode row before
	// stripWrappers can carry the account context. Use the same wrapper metadata
	// to identify its account operand, then carry that context only while this
	// command's nested body is being walked.
	prevForeignContext := w.foreignContext
	if row, ok := wrapperTable[program]; ok && row.userOperand {
		p := wrapperParse{w: w, row: row, name: program}
		i := p.options(inner, 1)
		if i < len(inner) && inner[i].Static && inner[i].Value != "" && !strings.HasPrefix(inner[i].Value, "-") {
			p.markForeignUser(inner[i])
		} else if i < len(inner) && !inner[i].Static {
			wrapperUA = true
		}
		foreign = foreign || p.foreignUser
	}
	w.foreignContext = prevForeignContext || foreign
	defer func() { w.foreignContext = prevForeignContext }()
	origin := Origin{Surface: w.res.Surface, Dialect: dialect, Command: cmdNo, Program: program, Wrappers: wrappers, Depth: depth, Span: c.Span}
	w.literalOut = literalPrinted(program, inner[1:], dialect)
	if dialect == DialectPOSIX {
		if text, ok := exactOutput(program, inner[1:], c.Redirs, w.resolveWord); ok {
			w.exactOK, w.exactText = true, text
			if w.literalOut == "" && text != "" {
				w.literalOut, w.literalKind = cap8k(text), DataHeredoc
			}
		}
	}

	// Calling a user-defined function (including one that shadows cd) may change
	// the cwd unobservably: mark it dynamic (review R3-6 C06/C07).
	lprog := funcKey(program, dialect)
	w.noteShellOptions(program, inner[1:])
	// A user function, a source or an eval may define pwd again in text the
	// walk does not read here (a definition inside a function body runs only
	// when the function is called; a sourced file or a dynamic eval is not
	// read): $(pwd) after it is unknown, never the word of the earlier
	// definition (GAP-2082). The pwd function itself, whose body the walk
	// read as one echo, defines nothing; a static eval or source body the
	// walk lowers below sets the value again when it defines pwd.
	if w.pwdFunc != nil && dialect == DialectPOSIX &&
		(w.funcs[lprog] && lprog != funcKey("pwd", dialect) || runsCodeInThisShell(program) && w.isBuiltin(program, dialect)) {
		w.pwdFunc = nil
	}
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
	if program == "read" && dialect == DialectPOSIX {
		w.bindRead(c, inner[1:]) // read NAME <<< WORD binds NAME (GAP-1554)
	}
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
	if program == "alias" {
		for _, wd := range inner[1:] {
			if wd.Static {
				if eq := strings.IndexByte(wd.Value, '='); eq > 0 {
					w.aliases[wd.Value[:eq]] = wd.Value[eq+1:]
				}
			}
		}
	}

	// 4b. Execution state (GAP-0218): after an unconditional exec CMD, exit, an
	// unreviewed set option or a DEBUG/RETURN trap in this shell, nothing later
	// is a fully known effect. A conditional one leaves later effects as they
	// are: they run on the paths where it did not.
	if dialect == DialectPOSIX && !cond && w.condFrame == 0 && w.childDepth == 0 {
		if ends, trap := w.endsExecution(words, inner, dialect); ends || trap {
			defer func() { w.execState, w.debugTrap = w.execState || ends, w.debugTrap || trap }()
		}
	}

	bsdHost := w.o.BSDUserland && bsdSystemProgram(prog.Value)
	entry, known := lookupProgram(program, w.o.flavor(), dialect, bsdHost)
	// A flag the BSD tool rejects (GAP-0219): /bin/cp and the rest are the BSD
	// tools, which exit without a change. The GNU reading is kept (its effects
	// stay visible) and the whole command is unaccounted: never a fully known
	// claim, never dropped. A bare name never gets here (bsdSystemProgram).
	bsdReject := false
	if bsd, ok := bsdTable[program]; ok && known && bsdHost && w.o.flavor() != FlavorWindows &&
		dialect != DialectCMD && dialect != DialectPowerShell && bsdRejectsFlag(bsd, posixTable[program], inner[1:]) {
		entry, bsdReject = posixTable[program], true
	}

	// 5. Base exec effect for every command (review PT-1: never zero effects).
	progTarget, progReason := w.programTarget(prog.Value)
	base := Effect{Kind: KindExec, Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateKnown,
		Target: progTarget, Origin: origin}
	if progReason != "" {
		base.addReason(progReason, ScopeTarget)
	}
	if !known || entry.BuiltinUnknown {
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
	// 4c. Environment and startup-file inputs (GAP-0217): a name the call puts
	// in the program's environment that the allow list does not account for,
	// or a shell that sources startup files. A program's own effects are then
	// unaccounted; a shell or code runner keeps the effects of the code it
	// runs and gets one unaccounted exec for the input.
	envUA, envShell := false, false
	shellCode := known && entry.ShellCode
	if dialect == DialectPOSIX && (w.unreviewedEnvInput(program, strings.Contains(prog.Value, "/"), shellCode, spec) != "" || shellStartupFlag(program, inner[1:])) {
		if shellCode {
			envShell = true
		} else {
			envUA = true
		}
	}
	unaccounted := wrapperUA || declUA || bsdReject || entry.BuiltinUnknown || envUA
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
	for _, e := range wrapEffects {
		w.emit(e)
	}
	if envShell {
		w.envInputEffect(origin, cond)
	}

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
		// ./FILE of a file the call wrote runs that text (GAP-1502).
		if dialect == DialectPOSIX && strings.Contains(prog.Value, "/") {
			if b, ok := w.scriptBody(prog.Value); ok {
				w.unwrapWithArgs(b.text, DialectPOSIX, depth, cond || b.cond, origin, inner)
			}
		}
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		for _, sub := range c.Nested {
			s := w.saveScope()
			w.walkCaptured(sub, depth)
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
	// The cmd frontend kept the verbatim text after /c: the child cmd runs it
	// with its quotes and operators, so it is read as a cmd line, not rebuilt
	// from words whose quotes are gone (DET111 R1).
	if entry.CmdC && c.CmdBodySet && dialect == DialectCMD && len(inner) == len(words) {
		if strings.TrimSpace(c.CmdBody) != "" {
			w.unwrapCode(c.CmdBody, true, DialectCMD, depth, cond, origin)
		}
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		return
	}
	if entry.CmdC {
		rest := inner[1:]
		found := false
		for j, a := range rest {
			// Git Bash (MSYS) turns a leading // into /, so cmd //c is cmd's
			// /c there: the spelling that runs a body from a POSIX shell (DET111
			// R1, GAP-1667).
			if a.Static && (strings.EqualFold(a.Value, "/c") || strings.EqualFold(a.Value, "/k") ||
				dialect == DialectPOSIX && (strings.EqualFold(a.Value, "//c") || strings.EqualFold(a.Value, "//k"))) {
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
	if entry.PSLaunch && c.Host != nil && (!c.Host.Opaque || !powerShellPositionalWD(inner[1:])) {
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
		code, ok, opq := powershellLaunchCode(inner[0].Value, inner[1:])
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
		case sub == "config" && (hasGitFileOption(inner[1:]) || hasWordFold(inner[1:], "-f")):
			// git config --file FILE: the file it names is the whole effect
			// (GAP-0506); a form gitConfigFile does not accept is unaccounted.
			if file, role, ok := gitConfigFile(inner[1:]); ok {
				w.emitOperand(operand{value: file.Value, static: true, quoted: file.Quoted, role: role}, origin, cond, dialect, depth)
			} else {
				unaccounted = true
			}
		case sub == "config" && gitConfigWrites(inner[1:]):
			unaccounted = true
		case hasGitFileOption(inner[1:]):
			// commit / tag / notes --file FILE read the message from FILE.
			if file, ok := gitFileOptionValue(inner[1:]); ok {
				w.emitOperand(operand{value: file.Value, static: true, quoted: file.Quoted, role: RoleRead}, origin, cond, dialect, depth)
			} else {
				unaccounted = true
			}
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
		dir, dirSet, dirDyn := "", false, false
		for i, a := range inner[1:] {
			if a.Static && a.Value == "-d" && i+1 < len(inner[1:]) {
				dirSet = true
				nx := inner[1:][i+1]
				dir, dirDyn = nx.Value, !nx.Static
			}
		}
		e := Effect{Kind: KindWrite, Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateUnknown,
			Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked, CaseFold: w.o.CaseInsensitive}, Origin: origin}
		if !dirSet {
			dir = "."
		}
		// The -d folder is placed by the one path resolver like every other
		// target (a ~ in Git Bash is the Windows home: DET111 R1, GAP-1173); a
		// dynamic -d is an unknown folder, never the cwd.
		if dirDyn {
			e.addReason(ReasonDynamicExpansion, ScopeTarget)
		} else {
			e.Target.Spelling = cap4k(dir)
			if abs, ok, r := w.placeRel(dir); ok {
				e.Target.Path = abs
			} else {
				e.addReason(r, ScopeTarget)
			}
		}
		e.addReason(ReasonOpaqueArchive, ScopeTarget)
		w.emit(e)
	}

	// 7. Operands.
	w.curProgram = program
	w.edStdin, w.edStdinOK = "", false
	if program == "ed" && dialect == DialectPOSIX {
		w.edStdin, _, w.edStdinOK = w.stdinText(c)
	}
	operandWords := inner[1:]
	// xargs appends stdin words after its command. When the preceding stage
	// printed exactly one literal filename, feed that word through the same
	// source/destination grammar as ordinary argv; otherwise keep the dynamic
	// unknown operand path below. This lets cp's table role retain a literal
	// destination (or -t source) for the protected classifier. A bare xargs
	// (no option) of a linker, or of a copier fed several words, whose input
	// the call shows exactly (stdinText: the last stdin redirect, else the
	// exact output of the stage before it) gets every word it splits from it,
	// and its operands are then the call's own, so echo SRC DST | xargs ln -s
	// reads as ln -s SRC DST (GAP-2214). A redirect of xargs's own stdin
	// replaces the pipe, so the piped words are never its input then.
	allStatic := true
	for _, word := range operandWords {
		if !word.Static {
			allStatic = false
			break
		}
	}
	if fromInput && allStatic {
		inText, inCond, inExact := w.stdinText(c)
		inExact = inExact && !inCond
		piped := strings.TrimSpace(w.stageIn.literal)
		if slices.ContainsFunc(c.Redirs, stdinRedirect) {
			piped = ""
			if inExact {
				piped = strings.TrimSpace(inText)
			}
		}
		switch {
		case entry.Pos == PosSourcesDest && piped != "" && !strings.ContainsAny(piped, " \t\r\n\x00"):
			// One word to a copier: as before, its write keeps the operands
			// from input reason (GAP-1317).
			operandWords = append(append([]Word(nil), operandWords...), Word{Value: piped, Static: true})
		case bareXargs && inExact && (entry.Pos == PosSourcesDest || entry.Pos == PosLinkTargetLink):
			if items, ok := xargsInputItems(inText); ok {
				operandWords = append([]Word(nil), operandWords...)
				for _, item := range items {
					operandWords = append(operandWords, Word{Value: item, Static: true})
				}
				fromInput = false
			}
		}
	}
	if dialect != DialectPOSIX && (lprog == "new-item" || lprog == "ni") {
		operandWords = w.joinNewItemName(operandWords)
	}
	ops, execCmds, opsUA := w.classifyOperands(operandWords, entry, dialect)
	w.printsOut = stagePrints(entry, operandWords) || !known && c.PipeIn
	if entry.Pos == PosInOut {
		for _, op := range ops {
			if op.role == RoleWrite {
				w.printsOut = false
				break
			}
		}
	}
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
	// Inline interpreter code is Data: its path literals and the path arguments
	// handed to it are opaque path effects, and its positionals are arguments,
	// not a program to run (GAP-0893, GAP-0662, GAP-1653).
	inlineCode := dialect == DialectPOSIX && isCodeInterpreter(program) && w.inlineCode(c, inner[1:], origin, cond)
	shellPOSIX := dialect == DialectPOSIX && isPOSIXShell(program)
	sc := shellInvocation(inner[1:])
	codeOps := 0
	w.nestedBodies(c, program, inner, dialect, depth, cond, origin)
	emittedKinds := map[Kind]bool{}
	for _, op := range ops {
		if inlineCode && op.role == RoleExecProgram {
			continue
		}
		if shellPOSIX && op.role == RoleExecCode {
			codeOps++
			if sc.hasC && codeOps > 1 {
				continue // a word after sh -c CODE is $0, $1 ...: an argument, not code
			}
		}
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
			emittedKinds[e.Kind] = true
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
		if op.role == RoleExecCode && op.static && op.shellCode && dialect == DialectPOSIX {
			// sed e COMMAND: the command runs in a child /bin/sh, once for
			// each input line its address selects, so only when the input
			// has one: its effects are conditional (GAP-1500).
			w.spec = spec
			w.unwrapCodeScoped(op.value, true, dialect, depth, true, origin, true)
		} else if op.role == RoleExecCode && op.static && entry.ShellCode {
			childScope := program != "eval" && program != "source" && program != "."
			w.spec = spec
			switch {
			case dialect == DialectPOSIX && program == "eval":
				// lowered whole by nestedBodies (all arguments joined)
			case shellPOSIX && sc.hasC:
				w.unwrapWithArgs(op.value, dialect, depth, cond, origin, sc.rest)
			case !childScope && isStdinPath(op.value):
				// source /dev/stdin: the text on stdin (nestedBodies)
			default:
				w.unwrapCodeScoped(op.value, op.static, dialect, depth, cond, origin, childScope)
				w.runWrittenScript(op.value, program, sc, dialect, depth, cond, origin, childScope)
			}
		}
	}
	if (program == "tee" && dialect == DialectPOSIX) || (program == "tee-object" && dialect == DialectPowerShell) {
		w.teeData(c, inner[1:], cmdNo, cmdStart, entry.AppendFlag, dialect)
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
	// A copier fed by xargs (`xargs cp SRC`) takes its destination from stdin
	// too: the write is there even when the source was read (GAP-1317).
	fedRole := posModeRole(entry.Pos)
	if entry.Pos == PosSourcesDest {
		fedRole = RoleWrite
	}
	if fromInput && !emittedKinds[fedRole.kind()] {
		if role := fedRole; role != RoleNone {
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
		w.walkCaptured(sub, depth)
		w.restoreScope(s)
	}
}

// runsCodeInThisShell reports a builtin that runs text in the calling shell
// (eval, source, .), so a function it defines is defined here.
func runsCodeInThisShell(program string) bool {
	return program == "eval" || program == "source" || program == "."
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
	w.pwdOwn = false // cd sets PWD to the folder it changed to
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
	hasStdin := c.PipeIn
	for _, r := range c.Redirs {
		if r.Op == RedirHeredoc || r.Op == RedirHereString {
			hasStdin = true
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
	if entry.ShellCode && !entry.StdinCode && !c.PipeIn && hasCodeOperand(args, true) {
		return
	}
	// The text the call feeds it (here-document, here-string, an exact printer
	// upstream of the pipe, a printing process substitution, a file the call
	// wrote) is the script it runs (DET111 R1, GAP-1151, GAP-1593).
	if text, tcond, ok := w.stdinText(c); ok && entry.ShellCode && (entry.StdinCode || !hasCodeOperand(args, true)) {
		w.unwrapCodeScopedInput(text, true, dialect, depth, cond || tcond, origin, true, true)
		return
	}
	e := Effect{Kind: KindExec, Cond: cond, Target: Target{Type: TargetProcess, Link: LinkNotChecked},
		TargetState: TargetStateUnknown, RoleState: RoleStateUnknown, Origin: origin}
	e.addReason(ReasonOpaqueCode, ScopeTarget)
	if c.PipeIn {
		source := baseIdx
		if len(w.stageIn.fetches) == 1 && !hasCodeOperand(args, true) {
			source = w.stageIn.fetches[0]
		}
		if source > 0 {
			e.Data = &Data{Kind: DataCode, Sources: []Source{{Kind: SourceEffect, Effect: source}}}
		}
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
	tail          string // Word.Tail of a dynamic operand
	// findName / findFiltered: a find -delete root deletes only the files its
	// predicates select: one -name/-iname pattern (findName), or a predicate the
	// walk does not read as a pattern (findFiltered alone).
	findName     string
	findFiltered bool
	// shellCode: a RoleExecCode value that is POSIX shell text whatever the
	// program's row says (a sed e COMMAND, which sed runs with /bin/sh): it
	// is lowered as sh -c COMMAND is (rel-1-0-10:GAP-1500).
	shellCode bool
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
func hasAppendFlag(words []Word, flag string, dialect Dialect) bool {
	for _, wd := range words {
		if !wd.Static {
			continue
		}
		v := wd.Value
		if v == "--" {
			return false
		}
		if (dialect == DialectPowerShell && (strings.EqualFold(v, flag) || strings.EqualFold(v, "--append"))) || (dialect != DialectPowerShell && (v == flag || v == "--append")) {
			return true
		}
		if len(flag) == 2 && len(v) > 2 && v[0] == '-' && v[1] != '-' && strings.ContainsRune(v[1:], rune(flag[1])) {
			return true
		}
	}
	return false
}

// maxXargsInputItems bounds the input words xargsInputItems feeds to one
// command; more read as the dynamic operands they were.
const maxXargsInputItems = 64

// xargsInputItems splits text the way a bare xargs splits its input: on
// blanks and newlines. False when xargs would read it its own way (a quote,
// a backslash, NUL, another control space), for a word _ (an end-of-file
// marker in some xargs builds), for no word and past maxXargsInputItems.
func xargsInputItems(text string) ([]string, bool) {
	if strings.ContainsAny(text, "'\"\\\x00\v\f\r") {
		return nil, false
	}
	items := strings.FieldsFunc(text, func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' })
	if len(items) == 0 || len(items) > maxXargsInputItems {
		return nil, false
	}
	for _, item := range items {
		if item == "_" {
			return nil, false
		}
	}
	return items, true
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
	permissionChange := p.Pos == PosConditionalPerm && hasPermissionMode(words, p.PermissionFlags)
	inPlace := false
	inPlaceSuffix := "" // sed -i[SUFFIX] / --in-place=SUFFIX: the backup name
	del := false
	findName, findOpaque := "", false
	hasExpr := false
	destDir := ""
	var srcFlags []Word
	var destFlag Word
	destFlagSet := false
	endOpts := false
	for i < len(words) {
		wd := words[i]
		name := wd.Value
		dynamicInline := false
		dynamicValue := Word{}
		if !wd.Static {
			if flag, value, ok := splitDynamicKeyValueOperand(wd, p, dialect); ok {
				name, dynamicValue, dynamicInline = flag, value, true
			} else if flag, value, ok := splitDynamicAttachedFlag(wd, p, dialect); ok {
				name, dynamicValue, dynamicInline = flag, value, true
			} else {
				positionals = append(positionals, wd)
				i++
				continue
			}
		}
		if endOpts {
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
			// A BSD tool's getopt stops at the first operand: every later word is
			// an operand, even one that starts with - (GAP-0219).
			endOpts = endOpts || p.OptionsFirst
			continue
		}
		// A native -xVALUE value comes before PowerShell's -Name:Value syntax:
		// the colon after a drive letter belongs to the attached path.
		var (
			fname, inlineVal string
			hasInline        bool
			inlineWord       Word
		)
		if flag, value, attached := splitAttachedNativeValue(name, p, dialect); attached {
			fname, inlineWord, hasInline = flag, value, true
			inlineVal = value.Value
		} else {
			fname, inlineVal, hasInline = splitInlineFlagValue(name, dialect)
			inlineWord = Word{Value: inlineVal, Static: true}
		}
		if dynamicInline {
			fname, inlineWord, hasInline = name, dynamicValue, true
			inlineVal = dynamicValue.Value
		}
		fl, ok := flagLookup(p, fname, dialect)
		if !ok && !dynamicInline && dialect != DialectPOSIX {
			// A PowerShell or cmd word whose colon is the value's own (7z
			// -oC:\x: not -Name:value) is a table flag with its value glued on
			// (DET111 R1, GAP-1663).
			if flag, value, split := splitDynamicAttachedFlag(wd, p, dialect); split {
				fname, inlineWord, hasInline, inlineVal = flag, value, true, value.Value
				fl, ok = flagLookup(p, fname, dialect)
			}
		}
		if ok && dialect == DialectPOSIX {
			fname, _, _ = flagResolve(p, fname) // an abbreviation reads as its full name (--target= is --target-directory=)
		}
		if !ok {
			// POSIX combined short flags (-xzf, -sSLo): the split marks the
			// token unaccounted if any component is unlisted.
			if dialect == DialectPOSIX && len(name) > 2 && name[0] == '-' && name[1] != '-' {
				_, uf := w.splitShortFlags(name, words, &i, p, &out, &inPlace, &inPlaceSuffix, &destDir)
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
		if isInPlaceFlag(p, fname) || fname == "--in-place" || strings.HasPrefix(fname, "--in-place=") {
			inPlace = true
		}
		if p.DeleteFlag != "" && fname == p.DeleteFlag {
			del = true
		} else if p.DeleteFlag != "" {
			findName, findOpaque = findPredicate(fname, words, i, findName, findOpaque)
		}
		if (p.Pos == PosSourcesDest) && (fname == "-t" || fname == "--target-directory") {
			if hasInline {
				destDir = inlineVal
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
		if hasInline {
			tops, bad := w.textOperands(fl.Text, inlineWord)
			out = append(out, tops...)
			if bad {
				unknownFlag = true // a script / format / config the closed grammar does not accept
			}
		}
		if hasInline && dialect == DialectPOSIX && !fl.Value {
			// A switch with a value attached (--in-place=SUFFIX, --color=WHEN):
			// only an Optional switch takes one. The sed backup suffix is read by
			// the row; any other non-empty value is not modeled, and a plain
			// switch given a value makes getopt reject the call (GAP-0216).
			// A short option has no '=' separator: -i=bak is -i with suffix "=bak".
			val := inlineVal
			if !strings.HasPrefix(fname, "--") {
				val = name[len(fname):]
			}
			switch {
			case fl.Optional && val == "":
			case fl.Optional && inPlace && p.InPlace != "" && (fname == p.InPlace || fname == "--in-place"):
				inPlaceSuffix = val
			case fl.Optional && fl.Role == RoleNone && fl.Text == TextNone && p.InPlace == "":
				// grep --color=WHEN: the value only selects output colouring
			default:
				unknownFlag = true
			}
			i++
			continue
		}
		if hasInline {
			if routeSourcesDestFlag(p, fl, inlineWord, &srcFlags, &destFlag) {
				if fl.Role == RoleWrite {
					destFlagSet = true
				}
				i++
				continue
			}
			out = append(out, operandValue(fl, inlineWord, p))
			i++
			if fl.Extra > 0 {
				i, unknownFlag = skipExtraValues(words, i, fl.Extra, unknownFlag)
			}
			continue
		}
		if fl.Value {
			if i+1 < len(words) {
				tops, bad := w.textOperands(fl.Text, words[i+1])
				out = append(out, tops...)
				if bad {
					unknownFlag = true
				}
				if fl.Extra > 0 {
					// find -fprintf FILE FORMAT: the first value has the flag's role,
					// the next Extra words are inert data (GAP-0216).
					out = append(out, operandValue(fl, words[i+1], p))
					i, unknownFlag = skipExtraValues(words, i+2, fl.Extra, unknownFlag)
					continue
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
	if p.FirstPosIgnore && !hasExpr && len(positionals) > 0 {
		tops, bad := w.textOperands(p.FirstPosText, positionals[0])
		out = append(out, tops...)
		if bad {
			unknownFlag = true
		}
	}
	// A PosNone program with operands it does not model leaves them unaccounted,
	// unless its entry declares the operands inert data (review R5-2).
	if p.Pos == PosNone && len(positionals) > 0 && !p.InertOperands {
		unknownFlag = true
	}
	if del {
		for _, wd := range positionals {
			if wd.Static && (wd.Value == "!" || wd.Value == "(" || wd.Value == ")" || wd.Value == ",") {
				findOpaque = true // a negated or grouped expression: not one pattern
			}
		}
	}
	// A backup suffix with '*' (the file's base name) or '/' (a backup folder)
	// names the backup by a rule the table does not model (GAP-0216).
	if inPlace && strings.ContainsAny(inPlaceSuffix, "*/") {
		unknownFlag, inPlaceSuffix = true, ""
	}
	posOps := w.positionalOperands(positionals, p, posCtx{unknownFlag: unknownFlag, inPlace: inPlace, inPlaceSuffix: inPlaceSuffix, del: del, findName: findName, findOpaque: findOpaque, hasExpr: hasExpr, destDir: destDir,
		appendMode:       p.AppendFlag != "" && hasAppendFlag(words, p.AppendFlag, dialect),
		permissionChange: permissionChange,
		upload:           p.Pos == PosBits && hasWordFold(words, "/upload"), program: w.curProgram, words: words})
	recursive := hasRowFlag(words, p, p.Recursive)
	dry := hasRowFlag(words, p, p.DryRun)
	for _, op := range posOps {
		if dry && op.role != RoleRead {
			continue // a dry run writes, links and deletes none of its operands
		}
		if recursive && op.role == RoleWrite && !op.remote {
			op.subtree = true // a tree copy writes every file below the destination
		}
		out = append(out, op)
	}
	if p.AppendFlag != "" && hasAppendFlag(words, p.AppendFlag, dialect) {
		for i := range out {
			if out[i].role == RoleWrite {
				out[i].role = RoleAppend
			}
		}
	}
	return out, inner, unknownFlag
}

func hasPermissionMode(words []Word, flags []string) bool {
	for _, word := range words {
		if !word.Static {
			continue
		}
		value := strings.ToLower(word.Value)
		if value == "--" {
			break
		}
		for _, flag := range flags {
			flag = strings.ToLower(flag)
			if value == flag || strings.HasPrefix(value, flag+":") {
				return true
			}
		}
	}
	return false
}

func isInPlaceFlag(p Program, name string) bool {
	if p.InPlace == name {
		return true
	}
	for _, flag := range p.InPlaceFlags {
		if flag == name {
			return true
		}
	}
	return false
}

// hasRowFlag reports one of the row options names among the words, before
// "--": the word itself, its --name=value form, its GNU abbreviation, or a
// letter of a short cluster (up to the first letter that takes a value).
// noTargetDirFlags are GNU cp/mv/install/ln -T: the destination is the target itself.
var noTargetDirFlags = []string{"-T", "--no-target-directory"}

// rowFlags is the names of names that are flags of the row p: a spelling
// the row does not list leaves the call unknown, never read by its meaning.
func rowFlags(p Program, names []string) []string {
	var out []string
	for _, n := range names {
		if _, ok := p.Flags[n]; ok {
			out = append(out, n)
		}
	}
	return out
}

func hasRowFlag(words []Word, p Program, names []string) bool {
	if len(names) == 0 {
		return false
	}
	for _, wd := range words {
		if !wd.Static || len(wd.Value) < 2 || wd.Value[0] != '-' {
			continue
		}
		v := wd.Value
		if v == "--" {
			return false
		}
		if strings.HasPrefix(v, "--") {
			if eq := strings.IndexByte(v, '='); eq > 0 {
				v = v[:eq]
			}
			full, _, _ := flagResolve(p, v)
			if hasName(names, full) {
				return true
			}
			continue
		}
		for _, ch := range v[1:] {
			f := "-" + string(ch)
			if hasName(names, f) {
				return true
			}
			if fl, ok := p.Flags[f]; ok && fl.Value {
				break
			}
		}
	}
	return false
}

// textOperands reads a script or program value through the closed grammar its
// row names (DESIGN D2): the files and commands the text names become operands
// of the call (a sed w file is written, an r file read, an e command run; an
// awk print redirect writes its file, a gawk /inet file is a connection), and
// bad reports a value the grammar does not accept, so the call is
// unaccounted. An awk program with a redirect stays unaccounted (the scan lists
// only literal targets) but its literal writes are kept.
func (w *walker) textOperands(kind TextKind, v Word) (ops []operand, bad bool) {
	switch kind {
	case TextSed:
		if !v.Static || len(v.Value) > maxGrammarSource {
			return nil, true
		}
		rd, ok := readSedScript(v.Value)
		if !ok {
			return nil, true
		}
		for _, f := range rd.writes {
			if f == "/dev/stdout" || f == "/dev/stderr" {
				continue // GNU sed writes these streams, not a file
			}
			ops = append(ops, operand{value: f, static: true, quoted: true, role: RoleWrite})
		}
		for _, f := range rd.reads {
			ops = append(ops, operand{value: f, static: true, quoted: true, role: RoleRead})
		}
		// r / R put the file's bytes in the output, which the call does not
		// track: the read is kept, the call is not fully known.
		bad = len(rd.reads) > 0
		for _, c := range rd.execs {
			ops = append(ops, operand{value: c, static: true, role: RoleExecCode, shellCode: true})
		}
		if rd.execDyn {
			ops = append(ops, operand{role: RoleExecCode})
		}
		return ops, bad
	case TextAwk:
		if !v.Static || len(v.Value) > maxGrammarSource {
			return nil, true
		}
		if awkProgramOK(v.Value) {
			return nil, false
		}
		for _, o := range awkprog.Parse(v.Value).Outputs {
			if hostPort, ok := awkInetTarget(o.Target); ok {
				ops = append(ops, operand{value: hostPort, static: true, role: RoleURLUpload})
				continue
			}
			role := RoleWrite
			if o.Append {
				role = RoleAppend
			}
			ops = append(ops, operand{value: o.Target, static: true, quoted: true, role: role})
		}
		return ops, true
	}
	return nil, textBad(kind, v)
}

// awkInetTarget reads a gawk special file /inet[46]/PROTO/LPORT/HOST/RPORT: a
// print redirect into it is a network connection to HOST:RPORT, not a file
// write (rel-1-0-10 GAP-1571). It returns the connection as a URL.
func awkInetTarget(t string) (string, bool) {
	parts := strings.Split(t, "/")
	if len(parts) != 6 || parts[0] != "" || (parts[1] != "inet" && parts[1] != "inet4" && parts[1] != "inet6") {
		return "", false
	}
	proto, host, port := parts[2], parts[4], parts[5]
	if (proto != "tcp" && proto != "udp") || host == "" {
		return "", false
	}
	return proto + "://" + host + ":" + port, true
}

// skipExtraValues steps over the n inert extra value words of a multi-value
// flag starting at words[i]. Fewer than n words left: the program rejects the
// call, so it is not accounted.
func skipExtraValues(words []Word, i, n int, unknownFlag bool) (int, bool) {
	if i+n > len(words) {
		return len(words), true
	}
	return i + n, unknownFlag
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

// splitDynamicKeyValueOperand applies a table-valued key=value option when the value remains unresolved.
func splitDynamicKeyValueOperand(wd Word, p Program, dialect Dialect) (string, Word, bool) {
	name := dynamicLead(wd)
	eq := strings.IndexByte(name, '=')
	if eq <= 0 {
		return "", Word{}, false
	}
	flag := name[:eq]
	fl, ok := flagLookup(p, flag, dialect)
	if !ok || !fl.Value {
		return "", Word{}, false
	}
	value := attachedValueWord(name[eq+1:], wd)
	value.Glob = wd.Glob
	return flag, value, true
}

func attachedValueWord(value string, source Word) Word {
	out := Word{Value: value, Static: source.Static, Quoted: source.Quoted}
	if !source.Static {
		out.Reason = ReasonDynamicExpansion
		out.Tail = source.Tail // the literal after the unresolved part names the place
	}
	return out
}

// dynamicLead is the text a word starts with: its value when static, else the
// literal segments before its first unresolved one (7z -o$env:X\y: "-o"). A
// resolved word that did not resolve keeps its Segs but no Value (DET111 R1,
// GAP-1663).
func dynamicLead(wd Word) string {
	if wd.Static || wd.Value != "" {
		return wd.Value
	}
	var b strings.Builder
	for _, s := range wd.Segs {
		if s.Var != "" || s.Op != nil {
			break
		}
		b.WriteString(s.Lit)
	}
	return b.String()
}

// splitDynamicAttachedFlag lets the table consume an attached option value whose
// value still contains an unresolved expansion (for example 7z -o$env:USERPROFILE).
// The frontend owns tokenization; this only separates a known table flag from its value.
func splitDynamicAttachedFlag(wd Word, p Program, dialect Dialect) (string, Word, bool) {
	name := dynamicLead(wd)
	if flag, value, has := splitInlineFlagValue(name, dialect); has {
		if fl, ok := flagLookup(p, flag, dialect); ok && fl.Value {
			return flag, attachedValueWord(value, wd), true
		}
	}
	best := ""
	for flag, fl := range p.Flags {
		// A word whose whole literal lead is the flag still has a value: the
		// unresolved part after it (-o$env:X).
		if !fl.Value || len(flag) < 2 || !strings.HasPrefix(name, flag) || len(name) == len(flag) && wd.Static {
			continue
		}
		if flag[0] != '-' || strings.HasPrefix(flag, "--") || dialect != DialectPOSIX && len(flag) != 2 {
			continue
		}
		if len(flag) > len(best) {
			best = flag
		}
	}
	if best == "" {
		return "", Word{}, false
	}
	return best, attachedValueWord(name[len(best):], wd), true
}

// splitAttachedNativeValue consumes -xVALUE for a one-letter table option in
// CMD/PowerShell native argument grammars. POSIX short clusters stay with
// splitShortFlags so their left-to-right value and unknown-flag rules apply.
func splitAttachedNativeValue(name string, p Program, dialect Dialect) (string, Word, bool) {
	if dialect == DialectPOSIX || (dialect != DialectCMD && dialect != DialectPowerShell) ||
		len(name) <= 2 || name[0] != '-' || strings.HasPrefix(name, "--") {
		return "", Word{}, false
	}
	for flag, fl := range p.Flags {
		if len(flag) == 2 && flag[0] == '-' && fl.Value && strings.EqualFold(name[:2], flag) {
			return flag, Word{Value: name[2:], Static: true}, true
		}
	}
	return "", Word{}, false
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
func (w *walker) splitShortFlags(name string, words []Word, i *int, p Program, out *[]operand, inPlace *bool, inPlaceSuffix *string, destDir *string) (consumed bool, unknownFlag bool) {
	body := name[1:]
	for j := 0; j < len(body); j++ {
		fn := "-" + string(body[j])
		if isInPlaceFlag(p, fn) {
			*inPlace = true
		}
		fl, ok := flagLookup(p, fn, DialectPOSIX)
		if !ok {
			unknownFlag = true // an unlisted short flag -> not fully modeled (round 3)
			continue
		}
		if fl.Optional {
			// -iSUFFIX: the rest of the token is the optional value, never the
			// next word and never more flags (sed -ie is -i with suffix "e").
			if rest := body[j+1:]; rest != "" {
				if fn == p.InPlace {
					*inPlaceSuffix = rest
				} else {
					unknownFlag = true
				}
			}
			*i++
			return true, unknownFlag
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
				tops, bad := w.textOperands(fl.Text, Word{Value: body[j+1:], Static: true})
				*out = append(*out, tops...)
				if bad {
					unknownFlag = true
				}
				*out = append(*out, operandValue(fl, Word{Value: body[j+1:], Static: true}, p))
				*i++
				return true, unknownFlag
			}
			if *i+1 < len(words) {
				tops, bad := w.textOperands(fl.Text, words[*i+1])
				*out = append(*out, tops...)
				if bad {
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
	op := operand{value: v.Value, static: v.Static, quoted: v.Quoted, glob: v.Glob, role: fl.Role, subtree: fl.Subtree, tail: v.Tail}
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
	// inPlaceSuffix is the sed backup suffix: each file is also written at
	// FILE+suffix (GAP-0216). Empty: no backup.
	inPlaceSuffix    string
	del              bool
	findName         string
	findOpaque       bool
	hasExpr          bool
	destDir          string
	appendMode       bool // tee -a: the file operands are appended to, not rewritten
	words            []Word
	upload           bool // bitsadmin /upload: the local file is read and sent
	program          string
	permissionChange bool
}

func (w *walker) positionalOperands(ps []Word, p Program, ctx posCtx) []operand {
	// KNOWN is an allowlist (review round 3): ANY unlisted flag the call used
	// means the operand roles are not fully modeled, so each operand effect
	// carries an unknown_flag role reason (it is no longer fully known).
	taint := ctx.unknownFlag
	mk := func(wd Word, role Role) operand {
		return operand{value: wd.Value, static: wd.Static, quoted: wd.Quoted,
			glob: wd.Glob || (p.Pattern && !wd.Quoted), role: role, pattern: p.Pattern, tail: wd.Tail}
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
		// find defaults its search root to the current directory. Preserve that
		// root for -delete too: a nested shell may cd before running a rootless
		// find, whose predicate can then delete matching descendants anywhere
		// under the resulting cwd.
		if len(ps) == 0 && p.DeleteFlag != "" && ctx.del {
			ps = []Word{{Value: ".", Static: true}}
		}
		for _, wd := range ps {
			// A metadata-only program (stat, du, find) names the file but never
			// reads its content: no read effect; find -delete still deletes below.
			if !p.MetadataOnly || ctx.inPlace {
				out = append(out, mk(wd, role))
			}
			if ctx.inPlace && ctx.inPlaceSuffix != "" {
				bk := wd
				if bk.Static {
					bk.Value += ctx.inPlaceSuffix
				}
				out = append(out, mk(bk, RoleWrite)) // the backup copy
			}
			if ctx.del { // find -delete: the roots and the files below them are deleted
				d := mk(wd, RoleDelete)
				d.subtree = true
				d.findName = ctx.findName
				d.findFiltered = ctx.findOpaque || ctx.findName != ""
				out = append(out, d)
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
	case PosSQLite:
		out = append(out, sqliteOperands(ps, ctx, mk)...)
	case PosEd:
		out = append(out, w.edOperands(ps, mk)...)
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
	case PosConditionalPerm:
		role := RoleRead
		if ctx.permissionChange {
			role = RolePerm
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
		out = append(out, sourcesDestOperands(ps, ctx.destDir, p, hasRowFlag(ctx.words, p, rowFlags(p, noTargetDirFlags)))...)
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
			role := RoleWrite
			if p.AppendFlag != "" && ctx.appendMode {
				role = RoleAppend
			}
			out = append(out, mk(ps[0], role))
		}
	case PosArchive:
		// 7z command ARCHIVE [MEMBER...]. Extraction/list/test read the archive;
		// add/update/delete mutate it. Member selectors are not filesystem paths.
		if len(ps) >= 2 {
			mode := strings.ToLower(ps[0].Value)
			out = append(out, mk(ps[0], RoleIgnore))
			switch mode {
			case "x", "e", "l", "t", "test":
				out = append(out, mk(ps[1], RoleRead))
			case "a", "u":
				out = append(out, mk(ps[1], RoleWrite))
				for _, wd := range ps[2:] {
					out = append(out, mk(wd, RoleRead))
				}
			case "d":
				out = append(out, mk(ps[1], RoleWrite))
			default:
				op := mk(ps[1], RoleWrite)
				op.roleUncertain = true
				out = append(out, op)
			}
		} else if len(ps) == 1 {
			op := mk(ps[0], RoleWrite)
			op.roleUncertain = true
			out = append(out, op)
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
	e.LinkTarget = op.role == RoleLinkTarget
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
		if op.static && (p.ShellCode || op.shellCode) {
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
		e.Target.Subtree = op.subtree
		e.Target.Spelling = dynamicSpelling(op.tail)
		if e.Target.Spelling == "" {
			e.Target.Spelling = cap4k(op.value)
		}
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
		e.Target.Lexical = cap4k(lexicalCandidate(op.value, w.opts()))
		e.addReason(ReasonGlob, ScopeTarget)
		return e
	}
	e.Target.Type = TargetPath
	e.Target.Subtree = op.subtree
	e.Target.Spelling = cap4k(op.value)
	if abs, ok, reason := placePath(op.value, w.opts()); ok {
		e.Target.Path = abs
		e.Target.Physical = w.callLinkPhysical(e.Target)
		if op.findFiltered {
			// find deletes only the files below the root its predicates select:
			// the -name pattern at any depth, or any file for a predicate the
			// walk does not read as a pattern. The classifier intersects it with
			// the protected sets; the root's own delete stays as before.
			name := op.findName
			if name == "" || op.findOpaqueName() {
				name = "*"
			}
			// A root that is a link this call created walks the link's
			// target (rel-1-0-10:GAP-1573c): join the pattern there.
			root := abs
			if e.Target.Physical != "" {
				root = e.Target.Physical
			}
			e.Target.Lexical = cap4k(joinPattern(root, name, w.o.flavor()))
		}
		if w.onAliasedDrive(abs) {
			e.addReason(ReasonNonCanonicalPath, ScopeTarget)
		}
	} else {
		if reason == ReasonNonCanonicalPath {
			e.Target.Lexical = cap4k(lexicalCandidate(e.Target.Spelling, w.opts()))
		}
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
						kind := DataLiteral
						if w.literalKind != "" {
							kind = w.literalKind
						}
						e.Data = &Data{Kind: kind}
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
				if stdout && w.exactOK && r.Op != RedirAppend && len(w.exactText) <= maxDataText {
					w.noteFileBody(e, w.exactText)
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
			if r.Target.ProcSub != nil {
				continue // `< <(...)`: the pipe of a process substitution, walked as nested
			}
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
		e.Target.Spelling = dynamicSpelling(t.Tail)
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
		e.Target.Lexical = cap4k(lexicalCandidate(t.Value, w.opts()))
		e.addReason(ReasonGlob, ScopeTarget)
		return
	}
	e.Target.Spelling = cap4k(t.Value)
	if abs, ok, reason := placePath(t.Value, w.opts()); ok {
		e.Target.Path = abs
		e.Target.Physical = w.callLinkPhysical(e.Target)
		if w.onAliasedDrive(abs) {
			e.addReason(ReasonNonCanonicalPath, ScopeTarget)
		}
	} else {
		if reason == ReasonNonCanonicalPath {
			e.Target.Lexical = cap4k(lexicalCandidate(e.Target.Spelling, w.opts()))
		}
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
	w.unwrapCodeScopedInput(code, static, dialect, depth, cond, origin, childScope, false)
}

func (w *walker) unwrapCodeScopedInput(code string, static bool, dialect Dialect, depth int, cond bool, origin Origin, childScope, scriptOnStdin bool) {
	if !static {
		w.positional, w.positionalSet = nil, false
		return
	}
	if depth+1 > maxNestedDepth {
		w.positional, w.positionalSet = nil, false
		w.res.addUnknown(ReasonNestingLimit)
		return
	}
	if cond {
		w.condFrame++
		defer func() { w.condFrame-- }()
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
	if scriptOnStdin && dialect == DialectPOSIX {
		bindStdinScriptTail(sub, code)
	}
	if hasUnknown(sub, ReasonInvalidSyntax) {
		// A body the shell cannot parse runs nothing from the error on (watch's
		// joined words, GAP-0662/var6 ruling), but the walk does not know what
		// the program makes of it: one opaque exec carries the unread text
		// (R-CODE), never an invented reading. The lines before the error are
		// lowered as usual (parsePOSIX).
		unread := code
		if sub.Unread != "" {
			unread = sub.Unread
		}
		e := Effect{Kind: KindExec, Cond: cond, TargetState: TargetStateUnknown, RoleState: RoleStateUnknown,
			Target: Target{Type: TargetProcess, Link: LinkNotChecked}, Origin: origin,
			Data: &Data{Kind: DataCode, Bytes: len(unread), Text: cap8k(unread)}}
		e.Origin.Depth = depth + 1
		e.addReason(ReasonInvalidSyntax, ScopeTarget)
		e.addReason(ReasonOpaqueCode, ScopeTarget)
		w.emit(e)
	}
	// Nested code has a concrete dialect, so place its leading-/ paths by it: a
	// POSIX body under cmd/PowerShell (bash -c '... /etc/x') is virtual-rooted
	// (review 6 #1).
	savedPD := w.pathDialect
	w.pathDialect = dialect
	defer func() { w.pathDialect = savedPD }()
	if !childScope {
		w.positional, w.positionalSet = nil, false
		w.walkScript(sub, depth+1)
		return
	}
	s := w.saveScope()
	env, exp, home := w.childEnvironment(dialect)
	remote := remoteOrigin(origin)
	if remote {
		// ssh HOST CMD...: the login shell of another host runs the body. Its
		// environment, home and folder are that host's, none of them ours; the
		// body is still read, and each effect is placed on that host.
		env, exp, home = map[string]string{}, map[string]bool{}, ""
		w.setCWDDynamic()
		w.remote++
	}
	w.env, w.exported = env, exp
	w.varsOwned = true
	w.bindPositional()
	if dialect == DialectPOSIX || remote {
		w.curHome = home
	}
	w.walkScript(sub, depth+1)
	if remote {
		w.remote--
	}
	w.restoreScope(s)
}

// remoteOrigin reports that origin's command was started by a wrapper that
// runs its joined words as shell text on another host (ssh).
func remoteOrigin(o Origin) bool {
	for _, n := range o.Wrappers {
		if r, ok := wrapperTable[n]; ok && r.kind == wrapForeign && r.joinShell {
			return true
		}
	}
	return false
}

// remoteTarget places an effect of a remote-host body on that host (GAP-0662
// ruling: ssh runs its body on a remote host). The host may be this one (ssh
// localhost), so the effect is still graded, but nothing of the local file
// system names it: a placed path keeps only its spelling behind an unknown
// root ("$?/home/u/.ssh/authorized_keys"), which the protected-set
// classifier reads by name (Maybe, R-NAME), never as a known local member.
func remoteTarget(e *Effect) {
	e.addReason(ReasonForeignContext, ScopeTarget)
	t := &e.Target
	if t.Type != TargetPath || t.Path == "" {
		return
	}
	p := t.Path
	if !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, `\`) {
		p = "/" + p
	}
	t.Spelling = cap4k("$?" + p)
	t.Path, t.Physical, t.Lexical = "", "", ""
}

// tildeTail is the Word.Tail of a leading tilde the walker cannot expand (no
// known home, or another account's): the literal path after the tilde
// prefix, so the classifier can still read a protected name in it
// (~/.ssh/authorized_keys under an unknown home).
func tildeTail(lit string, rest []WordSeg) string {
	i := strings.IndexAny(lit, `/\`)
	if i < 0 {
		return segTail(rest)
	}
	return segTail(append([]WordSeg{{Lit: lit[i:]}}, rest...))
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
	maybeDir := false
	for _, o2 := range ops {
		if o2.role == RoleLink && o2.static {
			if abs, ok, _ := placePath(o2.value, w.opts()); ok {
				linkPath = abs
				maybeDir = o2.destMaybeDir
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
	if maybeDir {
		// ln -s T d where d is an existing folder puts the link at
		// d/basename(T); a later d/<name>/... may walk T (GAP-1573c).
		t.Path = joinDir(linkPath, baseName2(targetSpelling))
		w.links[t.Key()] = targetAbs
	}
}

// callLinkPhysical is where a target lands when it is, or lies below, a link
// an earlier command of this call created (ln -s T d; ... d/x): the longest
// recorded link prefix, joined with the rest of the path. Empty when no in-call
// link covers it. The link does not exist on disk at hook time, so the
// classifier grades such a target maybe, never known (DET111 F1).
func (w *walker) callLinkPhysical(t Target) string {
	if len(w.links) == 0 {
		return ""
	}
	key := t.Key()
	if tgt, ok := w.links[key]; ok {
		return tgt
	}
	if len(key) != len(t.Path) {
		return "" // a case fold changed the byte length: no prefix split
	}
	sep := "/"
	if t.Flavor == FlavorWindows {
		sep = `\`
	}
	for i := len(key) - 1; i > 0; i-- {
		if key[i] != sep[0] {
			continue
		}
		if tgt, ok := w.links[key[:i]]; ok {
			rest := t.Path[i:]
			if t.Flavor == FlavorWindows {
				rest = strings.ReplaceAll(rest, "/", `\`)
			}
			return strings.TrimRight(tgt, `/\`) + rest
		}
	}
	return ""
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
	captured      map[string][]int
	exported      map[string]bool
	chain         *cdChain
	narrowed      *cwdState
	narrowedOther *cwdState
	// varsOwned: the saved scope owned its env / exported maps.
	varsOwned bool
	execState bool
	debugTrap bool
	pwdOwn    bool
	pwdFunc   *string
}

// saveScope returns the current state and installs private copies of the
// mutable parts (env, exported set, cwd candidates), so nothing the child does
// to them can leak into the parent when restoreScope puts the originals back.
func (w *walker) saveScope() scopeState {
	s := scopeState{cwd: w.curCWD, home: w.curHome, alt: w.cwdAlt, stack: w.cwdStack, env: w.env, captured: w.captured,
		exported: w.exported, chain: w.cdChain, narrowed: w.narrowed, narrowedOther: w.narrowedOther,
		execState: w.execState, debugTrap: w.debugTrap, pwdOwn: w.pwdOwn, pwdFunc: w.pwdFunc}
	w.debugTrap = false // a subshell does not inherit a DEBUG trap
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
	w.captured = cloneCaptured(w.captured)
	w.varsOwned = true
}

func (w *walker) restoreScope(s scopeState) {
	w.curCWD, w.curHome, w.cwdAlt, w.cwdStack, w.env = s.cwd, s.home, s.alt, s.stack, s.env
	w.captured = s.captured
	w.exported, w.cdChain, w.narrowed, w.narrowedOther = s.exported, s.chain, s.narrowed, s.narrowedOther
	w.varsOwned = s.varsOwned
	w.execState = s.execState
	w.debugTrap = s.debugTrap
	w.pwdOwn = s.pwdOwn
	w.pwdFunc = s.pwdFunc
}

func cloneCaptured(in map[string][]int) map[string][]int {
	if in == nil {
		return nil
	}
	out := make(map[string][]int, len(in))
	for name, reads := range in {
		out[name] = reads
	}
	return out
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
	delete(w.captured, name)
	delete(w.exported, name) // an unset variable is not exported; a later assignment makes a plain one
	switch name {
	case "HOME":
		if w.curDialect == DialectPOSIX {
			w.curHome = ""
		}
	case "PATH":
		w.pathMaybeSet = true
	case "CDPATH":
		w.cdpathMaybeSet = true
	case "PWD":
		w.pwdOwn = true // unset or rebound: no longer the tracked folder
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
			w.unsetVar("PATH") // a computed name may be PATH (GAP-0217)
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
			if !wd.Static || wd.Value == "pwd" {
				w.pwdFunc = nil // unset may remove the pwd function (GAP-1043)
			}
			if wd.Static && plainIdent(wd.Value) {
				w.unsetVar(wd.Value)
			} else if !wd.Static {
				w.unsetVar("HOME")
				w.unsetVar("CDPATH")
				w.unsetVar("PATH") // a computed name may be PATH (GAP-0217)
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
// POSIX; ~, ~/ or ~\ on Windows (review N6), and in PowerShell on every
// platform: its FileSystem provider takes \ as a separator on Linux and
// macOS too (rel-1-0-10:GAP-1255, New-Item -Path ~\.defenseclaw\config.yaml).
func isTilde(lit string, flavor Flavor, dialect Dialect) bool {
	if lit == "~" {
		return true
	}
	if strings.HasPrefix(lit, "~/") {
		return true
	}
	return (flavor == FlavorWindows || dialect == DialectPowerShell) && strings.HasPrefix(lit, `~\`)
}

// powerShellPositionalWD identifies the one host shape psparse deliberately
// leaves opaque: -wd with a positional body. The native 5.1 and pwsh 7
// readings differ here (GAP-1557); a -Command or encoded value keeps
// psparse's existing working-directory reading.
func powerShellPositionalWD(args []Word) bool {
	sawWD := false
	for i := 0; i < len(args); i++ {
		if !args[i].Static {
			return false
		}
		value := strings.ToLower(args[i].Value)
		if strings.HasPrefix(value, "-") && value != "-" {
			name := strings.TrimPrefix(value, "-")
			if strings.Contains(name, ":") {
				return false
			}
			switch {
			case name == "wd" || len(name) >= 3 && strings.HasPrefix("workingdirectory", name):
				if i+1 >= len(args) || !args[i+1].Static {
					return false
				}
				sawWD = true
				i++
			case name == "command" || name == "c" || name == "encodedcommand" ||
				name == "enc" || name == "ec" || name == "e":
				return false
			case psHostSwitches[name]:
				continue
			case psHostValued[name]:
				if i+1 >= len(args) || !args[i+1].Static {
					return false
				}
				i++
			default:
				return false
			}
			continue
		}
		return sawWD
	}
	return false
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
// is true when the launch carries an option the parser cannot settle -- a
// pwsh working directory with a positional file, an unknown option, or a
// script file. Windows PowerShell 5.1 consumes -wd without moving a
// positional body (native TST-16012, GAP-1557).
func powershellLaunchCode(host string, args []Word) (code string, ok, opaque bool) {
	// Windows PowerShell 5.1 accepts -wd/-WorkingDirectory as a valued
	// parameter but leaves a positional command in the caller's cwd (native
	// TST-16012, GAP-1557). pwsh 7 binds that positional as -File instead,
	// so its existing opaque reading must remain. A bare powershell host outside Windows has no proven edition: taking
	// the writing 5.1 reading is the max of that and pwsh 7 no-write.
	mayWrite51 := psLeaf(host) == "powershell"
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
			case name == "wd" || len(name) >= 3 && strings.HasPrefix("workingdirectory", name):
				if !mayWrite51 || i+1 >= len(args) || !args[i+1].Static {
					return "", false, true
				}
				i++ // 5.1 consumes the value but does not move the body
				continue
			case psHostSwitches[name]:
				continue
			case psHostValued[name]:
				i++ // the value belongs to the option
				continue
			}
			return "", false, true // -File, -Version-less abbreviations, anything unknown
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
	cdir := ""
	var files []Word
	var lists []string // -T / --files-from: the members are named in these files
	// pending are the value letters of an old-style bundle (`tar xfC a.tar dir`)
	// still waiting for their word, in order.
	var pending []byte
	setValue := func(letter byte, val Word) {
		v := val.Value
		switch letter {
		case 'f':
			if val.Static {
				archive = v
			}
		case 'C':
			if val.Static {
				cdir = v
			}
		case 'T':
			if val.Static {
				lists = append(lists, v)
			} else {
				lists = append(lists, "")
			}
		case 'I', 'F':
			w.opaqueExec(origin, cond) // a compress program or a volume script is run
		}
	}
	tarLongs := posixTable["tar"].Longs
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(pending) > 0 {
			setValue(pending[0], a)
			pending = pending[1:]
			continue
		}
		if !a.Static {
			files = append(files, a)
			continue
		}
		v := a.Value
		// Long options may carry their value inline as --name=value (review D
		// A33), and GNU tar (argp) takes an unambiguous prefix of any of its long
		// options (--ext, --dir: rel-1-0-10 GAP-0661).
		long, inlineVal, hasInline := v, "", false
		if strings.HasPrefix(v, "--") {
			if eq := strings.IndexByte(v, '='); eq >= 0 {
				long, inlineVal, hasInline = v[:eq], v[eq+1:], true
			}
			if full, ok := resolveLong(long, tarLongs); ok {
				long = full
			}
		}
		longValue := func() Word {
			if hasInline {
				return Word{Value: inlineVal, Static: true}
			}
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return Word{}
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
			setValue('C', longValue())
		case v == "-f" || long == "--file":
			setValue('f', longValue())
		case v == "-T" || long == "--files-from":
			setValue('T', longValue())
		case long == "--to-command" || long == "--checkpoint-action" || long == "--use-compress-program" ||
			long == "--info-script" || long == "--new-volume-script" || long == "--rsh-command" || long == "--rmt-command":
			w.opaqueExec(origin, cond)
			longValue()
		case strings.HasPrefix(v, "--"):
			if tarValuedLongs[long] {
				longValue() // the option's value is not a member
			}
		case strings.HasPrefix(v, "-") || (i == 0 && isTarModeBundle(v)):
			// a flag bundle like -xzf / xzf / czf: the modes, and the letters that
			// take a value: with a dash the rest of the word or the next word,
			// old style (no dash) the next words in order.
			dash := strings.HasPrefix(v, "-")
			body := strings.TrimPrefix(v, "-")
			for k := 0; k < len(body); k++ {
				switch c := body[k]; c {
				case 'c':
					mode = 'c'
				case 'x':
					mode = 'x'
				case 't':
					mode = 't'
				case 'r', 'u', 'A':
					mode = 'a' // append / update / concatenate: the archive is rewritten
				default:
					if strings.IndexByte(tarValueLetters, c) < 0 {
						continue
					}
					if !dash {
						pending = append(pending, c)
						continue
					}
					if k+1 < len(body) {
						setValue(c, Word{Value: body[k+1:], Static: true})
					} else if i+1 < len(args) {
						i++
						setValue(c, args[i])
					}
					k = len(body)
				}
			}
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
	for _, l := range lists {
		if l != "" && l != "-" {
			mk(KindRead, l, TargetStateKnown, "")
		}
	}
	switch mode {
	case 'c':
		if archive != "" && archive != "-" {
			mk(KindWrite, archive, TargetStateKnown, "")
		}
		if len(lists) > 0 {
			mk(KindRead, "", TargetStateUnknown, ReasonOperandsFromInput) // the members the list names
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
		// A member the call names lands at dest/member when the archive holds
		// it (DET111 R1, GAP-1173). tar strips a leading / and refuses .., so
		// only a plain relative name is joined.
		memberPathsKnown := true
		for _, arg := range args {
			if !arg.Static {
				continue
			}
			name := arg.Value
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				name = name[:eq]
			}
			if full, ok := resolveLong(name, tarLongs); ok {
				name = full
			}
			if name == "--strip-components" || name == "--transform" || name == "--xform" {
				memberPathsKnown = false
			}
		}
		for _, f := range files {
			if f.Static && f.Value != "" && !f.Glob && !looksGlob(f.Value) && !absoluteSpelling(f.Value, w.o.flavor()) &&
				!strings.Contains("/"+strings.ReplaceAll(f.Value, `\`, "/")+"/", "/../") {
				state, reason := TargetStateUnknown, ReasonOpaqueArchive
				if memberPathsKnown {
					state, reason = TargetStateKnown, ""
				}
				mk(KindWrite, joinDir(dest, f.Value), state, reason)
			}
		}
	default: // list or unknown mode
		if archive != "" && archive != "-" {
			mk(KindRead, archive, TargetStateKnown, "")
		}
	}
}

// tarValueLetters are the GNU tar short options that take a value.
const tarValueLetters = "fCTXbFgHIKLNV"

// tarValuedLongs are the GNU tar long options whose value is required, so a
// separate next word is the value, not a member.
var tarValuedLongs = map[string]bool{
	"--exclude": true, "--exclude-from": true, "--transform": true, "--xform": true, "--strip-components": true,
	"--owner": true, "--group": true, "--mode": true, "--newer": true, "--newer-mtime": true, "--after-date": true,
	"--label": true, "--suffix": true, "--format": true, "--blocking-factor": true, "--record-size": true,
	"--tape-length": true, "--index-file": true, "--volno-file": true, "--listed-incremental": true, "--level": true,
	"--warning": true, "--quoting-style": true, "--owner-map": true, "--group-map": true, "--mtime": true,
	"--starting-file": true, "--exclude-tag": true, "--exclude-tag-all": true, "--exclude-tag-under": true,
	"--checkpoint-action": true, "--to-command": true, "--use-compress-program": true, "--info-script": true,
	"--new-volume-script": true, "--rsh-command": true, "--rmt-command": true,
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
		case 'f', 'z', 'j', 'v', 'J', 'a', 'p', 'h', 'C', 'T':
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
// With -T / --no-target-directory (GNU) the destination is never a directory
// to write into: a single source lands at the destination itself (cp -rT x
// ~/.defenseclaw merges x into the folder; rel-1-0-10:GAP-1261).
func sourcesDestOperands(ps []Word, destDir string, p Program, noTarget bool) []operand {
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
	if noTarget && destDir == "" && len(sources) == 1 && sources[0].Static {
		return append(out, operand{value: dest.Value, static: true, role: RoleWrite, copyFrom: sources[0].Value})
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
	case PosConditionalPerm:
		return RoleRead
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
			if full, ok := resolveLong(k, posixTable["tar"].Longs); ok {
				k = full
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
	case "set":
		w.allExportMaybe = w.allExportMaybe || setAllExport(args)
	case "enable":
		for _, a := range args {
			if !a.Static || a.Value == "cd" || a.Value == "pushd" || a.Value == "popd" || a.Value == "-n" {
				w.cdUnreliable = true
			}
			// GAP-0218: a named builtin may be off (or replaced) from here on; -f
			// loads and -d deletes builtins from a shared object.
			switch {
			case !a.Static || strings.HasPrefix(a.Value, "-") && strings.ContainsAny(a.Value, "fd"):
				w.enableDyn = true
			case !strings.HasPrefix(a.Value, "-"):
				if w.disabled == nil {
					w.disabled = map[string]bool{}
				}
				w.disabled[a.Value] = true
			}
		}
	case "shopt":
		on := false
		for _, a := range args {
			if !a.Static {
				w.cdUnreliable = true
				w.execfailMaybe, w.extdebugMaybe = true, true
				continue
			}
			switch a.Value {
			case "execfail":
				w.execfailMaybe = true
			case "extdebug":
				w.extdebugMaybe = true
			case "lastpipe":
				w.lastpipe = on
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

// setAllExport reports set arguments that may turn on allexport: -a in an
// option cluster, -o allexport, or a dynamic word (GAP-0217).
func setAllExport(args []Word) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !a.Static {
			return true
		}
		v := a.Value
		if v == "--" || v == "-" || len(v) < 2 || (v[0] != '-' && v[0] != '+') {
			return false
		}
		if v[0] == '+' {
			if strings.ContainsRune(v[1:], 'o') {
				i++ // +o NAME turns NAME off
			}
			continue
		}
		if strings.ContainsRune(v[1:], 'a') {
			return true
		}
		if strings.ContainsRune(v[1:], 'o') {
			// -o NAME, also in a cluster (-eo NAME): NAME is the next word.
			i++
			if i < len(args) && (!args[i].Static || args[i].Value == "allexport") {
				return true
			}
		}
	}
	return false
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
			w.unsetVar("PATH") // a computed name may be PATH (GAP-0217)
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
			w.unsetVar("PATH") // a computed name may be PATH (GAP-0217)
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
		if name == "PATH" {
			w.pathMaybeSet = true
		}
		if nameref {
			w.noteNameRef()
		}
		if !hasVal {
			continue
		}
		delete(w.captured, name)
		if attr || nameref || w.namerefSeen {
			delete(w.env, name) // the stored value is transformed or aliased
			if name == "PWD" {
				w.pwdOwn = true
			}
			if name == "HOME" && w.curDialect == DialectPOSIX {
				w.curHome = ""
			}
			continue
		}
		w.env[name] = val
		if name == "PWD" {
			w.pwdOwn = true
		}
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
		if c.Host.Maybe != "" {
			if c.Host.MaybeCWD != "" {
				saved := w.cwdNow()
				w.setCWDState(w.placeCDTarget(c.Host.MaybeCWD, saved))
				defer w.setCWDState(saved)
			}
			w.unwrapUncertain(c.Host.Maybe, c.Host.Dialect, depth, origin, nil, true)
		}
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
	w.pathMaybeSet = true // a nameref may alias PATH (GAP-0217)
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
	case "PATH":
		w.pathMaybeSet = true
	case "CDPATH":
		w.cdpathMaybeSet = true
	case "PWD":
		w.pwdOwn = true
	}
}

// findPredicate reads one find predicate before -delete: -name/-iname with a
// static pattern is kept as the one name pattern; the predicates that select
// every file (type, traversal and output options) are ignored; any other
// predicate, or a second name, makes the selection opaque.
func findPredicate(fname string, words []Word, i int, name string, opaque bool) (string, bool) {
	switch fname {
	case "-type", "-xtype", "-xdev", "-mount", "-depth", "-print", "-print0", "-noleaf",
		"-ignore_readdir_race", "-noignore_readdir_race", "-warn", "-nowarn", "-follow", "-H", "-L", "-P", "-a", "-and":
		return name, opaque
	case "-name", "-iname":
		if name != "" || i+1 >= len(words) || !words[i+1].Static {
			return name, true
		}
		v := words[i+1].Value
		if fname == "-iname" {
			v = strings.ToLower(v)
		}
		return v, opaque
	}
	return name, true
}

// findOpaqueName reports a -name pattern that cannot be one path component
// (a / in it never matches a base name, so the pattern selects nothing; keep
// it opaque rather than reason about it).
func (op operand) findOpaqueName() bool {
	return strings.ContainsAny(op.findName, `/\`)
}

// joinPattern is root/**/name in the flavor's separator.
func joinPattern(root, name string, flavor Flavor) string {
	sep := "/"
	if flavor == FlavorWindows {
		sep = `\`
	}
	return strings.TrimRight(root, `/\`) + sep + "**" + sep + name
}

// dynamicSpelling is the Spelling of a target whose word is not static: "$?"
// and the literal path tail after the last dynamic part, so the classifier can
// read a protected name in it (R-NAME); empty when the tail is no path step.
func dynamicSpelling(tail string) string {
	if !strings.HasPrefix(tail, "/") && !strings.HasPrefix(tail, `\`) || len(tail) < 2 {
		return ""
	}
	return cap4k("$?" + tail)
}

// applyParamOp applies a parameter operator with static operands to a value.
// Pattern removal matches the shell way (* and ? match any character, / too);
// a pattern the matcher cannot read is not applied (ok false).
func applyParamOp(v string, op *ParamOp) (string, bool) {
	switch op.Kind {
	case "#", "##":
		best := -1
		for i := 0; i <= len(v); i++ {
			if m, ok := shellPatternMatch(op.Pat, v[:i]); !ok {
				return "", false
			} else if m {
				best = i
				if op.Kind == "#" {
					break
				}
			}
		}
		if best < 0 {
			return v, true
		}
		return v[best:], true
	case "%", "%%":
		best := -1
		for i := len(v); i >= 0; i-- {
			if m, ok := shellPatternMatch(op.Pat, v[i:]); !ok {
				return "", false
			} else if m {
				best = i
				if op.Kind == "%" {
					break
				}
			}
		}
		if best < 0 {
			return v, true
		}
		return v[:best], true
	case "/":
		return strings.Replace(v, op.Pat, op.With, 1), true
	case "//":
		return strings.ReplaceAll(v, op.Pat, op.With), true
	case "/#":
		if strings.HasPrefix(v, op.Pat) {
			return op.With + v[len(op.Pat):], true
		}
		return v, true
	case "/%":
		if strings.HasSuffix(v, op.Pat) {
			return v[:len(v)-len(op.Pat)] + op.With, true
		}
		return v, true
	case ":":
		// bash counts characters: a value with a multi-byte character is
		// not cut here.
		for i := 0; i < len(v); i++ {
			if v[i] >= 0x80 {
				return "", false
			}
		}
		off := op.Off
		if off < 0 {
			// A negative offset counts from the end; past the start the
			// expansion is empty.
			if off += len(v); off < 0 {
				return "", true
			}
		}
		if off > len(v) {
			return "", true
		}
		r := v[off:]
		if op.HasLen {
			n := op.Len
			if n < 0 {
				// A negative length is an end offset from the end of the
				// value; one before the start is an expansion error (the
				// command does not run), left unresolved.
				if n += len(r); n < 0 {
					return "", false
				}
			}
			if n < len(r) {
				r = r[:n]
			}
		}
		return r, true
	}
	return "", false
}

// shellPatternMatch matches a shell pattern of a parameter operator, where *
// and ? also match /. Bracket expressions and escapes are not read (ok false).
func shellPatternMatch(pat, s string) (match, ok bool) {
	if strings.ContainsAny(pat, `[\`) {
		return false, false
	}
	const sep = "\x00"
	if strings.Contains(s, sep) {
		return false, false
	}
	m, err := path.Match(strings.ReplaceAll(pat, "/", sep), strings.ReplaceAll(s, "/", sep))
	if err != nil {
		return false, false
	}
	return m, true
}

// segTail is the literal text of the segments after a dynamic one, when they
// are all literals (the Word.Tail of a word the walker could not resolve).
func segTail(segs []WordSeg) string {
	var b strings.Builder
	for _, s := range segs {
		if s.Var != "" || s.Subst != "" {
			b.Reset()
			continue
		}
		b.WriteString(s.Lit)
	}
	return b.String()
}

// hasUnknown reports an unknown node of the given reason in a parsed script.
func hasUnknown(s *Script, r ReasonCode) bool {
	for _, u := range s.Unknowns {
		if u.Reason == r {
			return true
		}
	}
	return false
}
