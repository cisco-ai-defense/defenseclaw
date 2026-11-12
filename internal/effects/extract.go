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
		return extractFileTool(call, o)
	case SurfacePatch:
		return extractPatch(call, o)
	case SurfaceMCP:
		return extractMCP(call, o)
	}
	return extractShell(call, o)
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
	w := &walker{res: &res, o: o, links: map[string]string{}, writeByKey: map[string]int{}, funcs: map[string]bool{}, aliases: map[string]string{}}
	for _, fn := range script.Funcs {
		w.funcs[fn] = true
	}
	w.walkScript(script, 0)
	return res
}

// walker carries the in-call state: resolved variables, defined functions and
// aliases, a running copy of the trusted env (so an in-call HOME= moves ~), the
// link alias map, and the index of the write that last produced each path key.
type walker struct {
	res        *Result
	o          Options
	cmdNo      int
	funcs      map[string]bool
	aliases    map[string]string
	links      map[string]string // link key -> target key (review R7)
	writeByKey map[string]int    // path key -> 1-based effect index that wrote it
	pathShadow bool              // PATH was reassigned in this call
}

func (w *walker) walkScript(s *Script, depth int) {
	if s == nil {
		return
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
	return len(w.res.Effects) // 1-based index
}

// command processes one simple command / pipeline stage.
func (w *walker) command(c *Cmd, dialect Dialect, depth int, cond bool) {
	w.cmdNo++
	cmdNo := w.cmdNo

	// 1. Assignments: track variables and flag env roles.
	localEnv := map[string]string{}
	for _, a := range c.Assigns {
		if a.Static {
			localEnv[a.Name] = a.Value
		}
		if role, ok := envRoles[a.Name]; ok {
			w.envAssign(a, role, dialect, cmdNo, depth, cond, c.Span)
		}
	}
	// A bare assignment statement (no program) defines variables only.
	if len(c.Words) == 0 {
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		return
	}

	// 2. Strip wrappers.
	words, wrappers, foreign, fromInput := w.stripWrappers(c.Words)
	if len(words) == 0 {
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		return
	}
	prog := words[0]
	if !prog.Static {
		// The program word itself is dynamic: an opaque exec.
		e := Effect{Kind: KindExec, TargetState: TargetStateUnknown, RoleState: RoleStateUnknown, Cond: cond,
			Origin: Origin{Surface: SurfaceShell, Dialect: dialect, Command: cmdNo, Wrappers: wrappers, Depth: depth, Span: c.Span}}
		e.addReason(ReasonDynamicExpansion, ScopeTarget)
		w.emit(e)
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		return
	}
	program := programBasename(prog.Value, w.o.flavor())
	origin := Origin{Surface: SurfaceShell, Dialect: dialect, Command: cmdNo, Program: program, Wrappers: wrappers, Depth: depth, Span: c.Span}

	// 3. Shadowing: a function / alias / PATH change in this call that redefines
	// the program means the table's effects may be wrong (review R2).
	shadowed := (w.funcs != nil && w.funcs[program]) || (w.aliases != nil && w.aliases[program] != "")
	if w.pathShadow && !strings.Contains(prog.Value, "/") {
		shadowed = true
	}
	// `alias x=cmd` defines an alias that shadows x in the rest of the call.
	if program == "alias" {
		for _, wd := range words[1:] {
			if wd.Static {
				if eq := strings.IndexByte(wd.Value, '='); eq > 0 {
					w.aliases[wd.Value[:eq]] = wd.Value[eq+1:]
				}
			}
		}
	}

	entry, known := lookupProgram(program, w.o.flavor())
	if !known {
		// Unmodeled program: the exec is known, its file/network effects are not.
		e := Effect{Kind: KindExec, Target: Target{Type: TargetPath, Spelling: cap4k(prog.Value), Flavor: w.o.flavor(), Link: LinkNotChecked},
			TargetState: TargetStateKnown, RoleState: RoleStateUnknown, Cond: cond, Origin: origin}
		if abs, ok, _ := placePath(prog.Value, w.o); ok {
			e.Target.Path = abs
		}
		e.addReason(ReasonUnmodeledProgram, ScopeRole)
		if foreign {
			e.Target.Type = TargetRemote
			e.addReason(ReasonForeignContext, ScopeRole)
		}
		w.emit(e)
		w.handleRedirs(c, dialect, cmdNo, depth, cond, nil)
		return
	}

	// 4. Walk the operands against the table row.
	ops := w.classifyOperands(words[1:], entry, dialect)
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
		// exec_code we can read as shell: unwrap one level.
		if op.role == RoleExecCode && op.static && entry.ShellCode {
			w.unwrapCode(op.value, op.static, dialect, depth, cond, origin)
		}
	}

	// 5. Redirections carry the command's read bytes to the write target.
	w.handleRedirs(c, dialect, cmdNo, depth, cond, readIdx)

	// 6. Nested command substitutions run their own commands.
	for _, sub := range c.Nested {
		w.walkScript(sub, depth)
	}
}

// operand is one classified operand with its role.
type operand struct {
	value          string
	static         bool
	quoted         bool
	glob           bool
	role           Role
	pattern        bool
	fromURL        bool
	uploadFromPath string
	// roleUncertain marks an operand whose role may be wrong because a strict
	// program carried an unknown flag; the effect keeps its kind but gains a
	// role-scoped unknown_flag reason (review P2, balanced default).
	roleUncertain bool
}

// classifyOperands walks flags and positionals of a command against a table row.
func (w *walker) classifyOperands(words []Word, p Program, dialect Dialect) []operand {
	var out []operand
	var positionals []Word
	i := 0
	unknownFlag := false
	for i < len(words) {
		wd := words[i]
		name := wd.Value
		isFlag := wd.Static && len(name) > 0 && (name[0] == '-' || (dialect != DialectPOSIX && name[0] == '/'))
		if dialect == DialectPowerShell && wd.Static && strings.HasPrefix(name, "-") {
			// PowerShell params are case-insensitive, allow prefix abbreviation.
			name = strings.ToLower(name)
		}
		if isFlag {
			fl, ok := flagLookup(p, name, dialect)
			if !ok {
				unknownFlag = true
				i++
				continue
			}
			if fl.Role == RoleExecProgram {
				// find -exec / xargs: the rest (until ; or +) is a program+argv.
				rest := collectExecArgv(words[i+1:])
				if len(rest) > 0 && rest[0].Static {
					out = append(out, operand{value: rest[0].Value, static: true, role: RoleExecProgram})
				} else {
					out = append(out, operand{role: RoleExecProgram})
				}
				return out // the exec consumes the remainder
			}
			if fl.Value {
				if i+1 < len(words) {
					v := words[i+1]
					out = append(out, operandFromFlag(fl, v, p))
					i += 2
					continue
				}
			}
			i++
			continue
		}
		positionals = append(positionals, wd)
		i++
	}
	out = append(out, w.positionalOperands(positionals, p, unknownFlag)...)
	return out
}

func operandFromFlag(fl Flag, v Word, p Program) operand {
	op := operand{value: v.Value, static: v.Static, quoted: v.Quoted, glob: v.Glob, role: fl.Role}
	if fl.Role == RoleUploadFile {
		op.uploadFromPath = uploadPath(v.Value)
		op.value = op.uploadFromPath
	}
	if fl.Role == RoleURL {
		op.fromURL = true
	}
	return op
}

func (w *walker) positionalOperands(ps []Word, p Program, unknownFlag bool) []operand {
	taint := unknownFlag && p.Strict
	mk := func(wd Word, role Role) operand {
		return operand{value: wd.Value, static: wd.Static, quoted: wd.Quoted, glob: wd.Glob || p.Pattern, role: role, pattern: p.Pattern}
	}
	var out []operand
	switch p.Pos {
	case PosAllRead:
		for _, wd := range ps {
			out = append(out, mk(wd, RoleRead))
		}
	case PosURLArgs:
		for _, wd := range ps {
			if wd.Static {
				if _, host, _ := parseURL(wd.Value); host != "" {
					out = append(out, operand{value: wd.Value, static: true, role: RoleURL, fromURL: true})
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
		// chmod MODE f1 f2 ...: first positional is the mode, rest are targets.
		for i, wd := range ps {
			if i == 0 && !strings.HasPrefix(wd.Value, "/") && !strings.Contains(wd.Value, "/") {
				continue
			}
			out = append(out, mk(wd, RolePerm))
		}
	case PosSourcesDest:
		for i, wd := range ps {
			if i == len(ps)-1 {
				out = append(out, mk(wd, RoleWrite))
			} else {
				out = append(out, mk(wd, RoleRead))
			}
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
	case PosFirstCode:
		if len(ps) > 0 {
			out = append(out, operand{value: ps[0].Value, static: ps[0].Static, role: RoleExecCode})
		}
	case PosFirstExec:
		if len(ps) > 0 {
			out = append(out, operand{value: ps[0].Value, static: ps[0].Static, role: RoleExecProgram})
		}
	}
	if taint {
		for i := range out {
			// a strict program with an unknown flag may have shifted roles;
			// keep the kind, flag the uncertainty (never silently drop it).
			out[i].roleUncertain = true
		}
	}
	return out
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
			// shell code we can read and unwrap one level (bash/sh/zsh/eval).
			e.Data = &Data{Kind: DataCode, Bytes: len(op.value), Text: cap8k(op.value)}
		} else {
			// a non-shell interpreter's code (python -c, node -e), an opaque
			// exec-flag value (go -exec, rsync -e), or a dynamic string: we
			// cannot parse it as shell, so it stays opaque code.
			e.addReason(ReasonOpaqueCode, ScopeTarget)
		}
		return e
	case RoleExecProgram:
		e.Kind = KindExec
		e.Target.Type = TargetPath
		if op.static {
			e.Target.Spelling = cap4k(op.value)
			if abs, ok, reason := placePath(op.value, w.o); ok {
				e.Target.Path = abs
			} else {
				e.addReason(reason, ScopeTarget)
			}
		} else {
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

	// Path-shaped roles (read/write/append/delete/link/perm/output).
	if op.role == RoleOutput {
		e.Kind = KindWrite
	}
	if !op.static {
		e.Target.Type = TargetPath
		e.addReason(op.reasonForDynamic(), ScopeTarget)
		return e
	}
	if op.glob || op.pattern {
		e.Target.Type = TargetPath
		e.Target.Glob = cap4k(op.value)
		e.addReason(ReasonGlob, ScopeTarget)
		return e
	}
	e.Target.Type = TargetPath
	e.Target.Spelling = cap4k(op.value)
	if abs, ok, reason := placePath(op.value, w.o); ok {
		e.Target.Path = abs
		// link alias: a write through a known in-call link resolves to its target
		if tgt, ok := w.links[e.Target.Key()]; ok {
			e.Target.Physical = tgt
		}
	} else {
		e.addReason(reason, ScopeTarget)
	}
	return e
}

func (op operand) reasonForDynamic() ReasonCode {
	return ReasonDynamicExpansion
}

func (w *walker) fillURL(e *Effect, op operand) {
	e.Kind = KindNetworkFetch
	e.Target.Type = TargetURL
	if !op.static {
		e.addReason(ReasonDynamicExpansion, ScopeTarget)
		return
	}
	scheme, host, port := parseURL(op.value)
	e.Target.URL = cap4k(op.value)
	e.Target.Scheme, e.Target.Host, e.Target.Port = scheme, host, port
	if host == "" {
		e.addReason(ReasonDynamicExpansion, ScopeTarget)
	}
}

// joinSourceWrite links an upload's source file to the write that produced it.
func (w *walker) joinSourceWrite(e *Effect) {
	if e.Data == nil {
		return
	}
	for i, s := range e.Data.Sources {
		if s.Kind != SourcePath || s.Path == "" {
			continue
		}
		t := Target{Path: mustAbs(s.Path, w.o), Flavor: w.o.flavor()}
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
// stdout write to the read effects of the same command (the bytes it saves).
func (w *walker) handleRedirs(c *Cmd, dialect Dialect, cmdNo, depth int, cond bool, readIdx []int) {
	_ = dialect
	for _, r := range c.Redirs {
		switch r.Op {
		case RedirWrite, RedirAppend, RedirClobber:
			e := Effect{Kind: KindWrite, Cond: cond, RoleState: RoleStateKnown, TargetState: TargetStateKnown,
				Target: Target{Type: TargetPath, Flavor: w.o.flavor(), Link: LinkNotChecked},
				Origin: Origin{Surface: SurfaceShell, Dialect: c.dialectOf(dialect), Command: cmdNo, Depth: depth, Span: c.Span}}
			if r.Op == RedirAppend {
				e.Kind = KindAppend
			}
			w.fillRedirTarget(&e, r.Target)
			if len(readIdx) > 0 {
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
				Origin: Origin{Surface: SurfaceShell, Dialect: c.dialectOf(dialect), Command: cmdNo, Depth: depth, Span: c.Span}}
			w.fillRedirTarget(&e, r.Target)
			w.emit(e)
		case RedirHeredoc, RedirHereString:
			// Body is data fed to the command's stdin, never a path. No effect
			// for the redirect itself; apply_patch detection reads it elsewhere.
		}
	}
}

func (c *Cmd) dialectOf(d Dialect) Dialect { return d }

func (w *walker) fillRedirTarget(e *Effect, t Word) {
	if !t.Static {
		e.addReason(ReasonDynamicExpansion, ScopeTarget)
		return
	}
	if t.Value == "/dev/null" {
		e.Target.Type = TargetNone
		e.Kind = KindWrite
		return
	}
	if strings.HasPrefix(t.Value, "/dev/tcp/") || strings.HasPrefix(t.Value, "/dev/udp/") {
		e.Kind = KindNetworkSend
		e.Target.Type = TargetHost
		parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(t.Value, "/dev/tcp/"), "/dev/udp/"), "/")
		if len(parts) >= 1 {
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
	if abs, ok, reason := placePath(t.Value, w.o); ok {
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

func (w *walker) envAssign(a Assign, role EnvRole, dialect Dialect, cmdNo, depth int, cond bool, span [2]int) {
	switch role {
	case EnvCode:
		e := Effect{Kind: KindExec, Cond: cond, TargetState: TargetStateUnknown, RoleState: RoleStateUnknown,
			Target: Target{Type: TargetProcess}, Origin: Origin{Surface: SurfaceShell, Dialect: dialect, Command: cmdNo, Program: a.Name, Depth: depth, Span: span}}
		e.addReason(ReasonOpaqueCode, ScopeTarget)
		w.emit(e)
	case EnvHome:
		if a.Static {
			w.o.Home = a.Value // a later ~ in this call points here
		}
	case EnvPath:
		// PATH change: a later unqualified program may be shadowed.
		w.pathShadow = true
	}
}

// unwrapCode parses one nested level of shell code (bash -c, eval of a literal).
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
	var linkPath, targetPath string
	for _, o2 := range ops {
		if o2.role == RoleLink && o2.static {
			if abs, ok, _ := placePath(o2.value, w.o); ok {
				linkPath = abs
			}
		}
		if o2.role == RoleLinkTarget && o2.static {
			if abs, ok, _ := placePath(o2.value, w.o); ok {
				targetPath = abs
			}
		}
	}
	if linkPath != "" && targetPath != "" {
		t := Target{Path: linkPath, Flavor: w.o.flavor()}
		w.links[t.Key()] = targetPath
	}
}
