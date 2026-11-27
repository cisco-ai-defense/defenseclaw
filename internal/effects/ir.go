// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

// The dialect-neutral intermediate representation. Each frontend (POSIX, cmd,
// PowerShell) lowers its own grammar into these types; the extractor and the
// program table walk only the IR, so they are dialect-independent.

// Script is one parsed command text at one nesting level.
type Script struct {
	Dialect  Dialect
	Stmts    []*Stmt
	Unknowns []UnknownNode
	// Funcs names the functions the text defines; a later call of one of these
	// names is shadowed (review R2).
	Funcs []string
	// Unread is the text a frontend could not read (from the line of a syntax
	// error on), with an invalid_syntax unknown; "" when the text was read.
	Unread string
	// RunsNothing: a PowerShell script the parser port read with a parse error
	// pwsh reports too (psparse Diagnostic.Syntax): pwsh runs none of it.
	RunsNothing bool
}

// Op is the control operator that joins a statement to the next.
type Op string

const (
	OpNone    Op = ""
	OpSeq     Op = ";"
	OpAnd     Op = "&&"
	OpOr      Op = "||"
	OpPipe    Op = "|"
	OpBackund Op = "&"
)

// Stmt is one statement: a command or pipeline, with its control context.
type Stmt struct {
	Cmds []*Cmd
	Op   Op
	// Cond is true when the statement runs only on some execution paths.
	Cond       bool
	Background bool
	// Link is OpAnd / OpOr when this statement runs only on the success /
	// failure of the statement before it (the right side of `a && b`, `a || b`).
	// The walker uses it to know a cd's outcome (round 8 F); OpNone otherwise.
	Link Op
	// DeadGuard names the builtins (true, false, :) whose constant status makes
	// this statement unreachable: the right side of a provably false `&&` or a
	// provably true `||` (GAP-0218). The walker treats the statement as dead only
	// while none of these names is a function or an alias.
	DeadGuard []string
	// ExecMark marks an empty statement placed before the body of a compound
	// command that has redirects; ExecFrom, on the compound's redirect-only
	// statement, points at it. The shell opens those redirects before the body
	// runs, so the walker reads them under the execution state of the mark, not
	// the state an exec / exit in the body left (GAP-0218 review round 3).
	ExecMark bool
	ExecFrom *Stmt
	Span     [2]int
}

// Cmd is one simple command or pipeline stage.
type Cmd struct {
	// MayCallFunc marks a call whose program is dynamic (& $name) in a
	// PowerShell script that defines functions: it may run one, whose body
	// may move the folder, so the folder after it is unknown
	// (rel-1-0-10:GAP-1156; a plain call is lowered as the body).
	MayCallFunc bool

	Assigns []Assign
	// Words is argv; Words[0] is the program when present.
	Words  []Word
	Redirs []Redir
	// PipeIn is true when stdin comes from the previous pipeline stage.
	PipeIn bool
	// Nested holds command substitution / subshell bodies whose commands run
	// but whose value is dynamic.
	Nested []*Script
	// Sub, when set, is a subshell body `( ... )`: it runs in a child shell,
	// so a cd inside it does not change the parent's cwd. The walker saves and
	// restores cwd/env around it.
	Sub *Script
	// Pipeline marks a command that is one stage of a pipeline, and Async a
	// background (`&`) command: both run in a child shell, so a cd/assignment
	// inside them must not change the parent's cwd/env (review N2).
	Pipeline bool
	// PipeLast marks the last stage of a POSIX pipeline (see Pipeline).
	PipeLast bool
	Async    bool
	// ChildList marks a command inside a backgrounded compound or && / || list
	// (`{ ...; } &`, `a || b &`): bash runs the whole list in a child shell, so
	// an exit or exec there does not end this one (GAP-0218).
	ChildList bool
	Cond      bool
	Span      [2]int
	// Host is psparse's verdict on a cmd / powershell / pwsh host call that the
	// PowerShell frontend lowered, nil when psparse gave none. The walker unwraps
	// the payload only from a Static verdict, with psparse's text; a NotStatic
	// verdict is opaque and is never unwrapped by the walker's own parsing
	// (psparse review 9 R9-3, GAP-0193).
	Host *HostPayload
	// CmdBody is the verbatim text after the /c or /k switch of a cmd call the
	// cmd frontend lowered, with cmd's outer quote pair removed: the command
	// line the child cmd runs (its quotes and operators intact).
	CmdBody    string
	CmdBodySet bool
	// Defines, on the statement of a POSIX function definition, is what the
	// walker knows of the function at that point (rel-1-0-10:GAP-1043).
	Defines *FuncDef
}

// FuncDef is a POSIX function definition (name() { body; }). Out is what the
// body prints when it is one echo of one static word (Static); Cond is true
// when the definition runs only on some paths or in a child shell.
type FuncDef struct {
	Name   string
	Out    string
	Static bool
	Cond   bool
}

// HostPayload is psparse's reading of one host call's payload.
type HostPayload struct {
	Opaque  bool    // not static, or unsafe to trust: no unwrap
	Text    string  // the payload text when !Opaque
	Dialect Dialect // the payload's grammar when !Opaque, or of Maybe
	// Maybe is one possible reading of an Opaque payload (the verbatim text a
	// child gets when the parent does not expand it): the walker lowers it as
	// maybe effects and the call stays opaque (DET111 R1, GAP-1550).
	Maybe string
	// MaybeCWD is the folder the Maybe reading runs in (-WorkingDirectory),
	// placed against the caller's folder; "" keeps the caller's.
	MaybeCWD string
}

// WordSeg is one piece of a word: a literal run (Lit) or a simple variable
// expansion (Var is the name). Exactly one of Lit/Var is set. Quoted marks a
// literal that was inside quotes (so a metachar in it is not a glob). The
// walker resolves Var against the running env, so in-call assignments take
// effect (review PX-2).
type WordSeg struct {
	Lit    string
	Var    string
	Quoted bool
	// Glob marks a literal segment that holds an unescaped glob/brace
	// metacharacter (so an escaped `\*` is literal but an unescaped `{a,b}`
	// alongside it still globs -- review N10).
	Glob bool
	// Op is a parameter operator on Var with static operands (${V%pat},
	// ${V#pat}, ${V/a/b}, ${V:off:len}); the walker applies it to the value.
	Op *ParamOp
	// Subst names a command substitution the walker can evaluate itself:
	// "pwd" for $(pwd), `pwd` and $(pwd -L): the working folder, or what a
	// pwd function defined earlier in the call prints when the walk can read
	// it; unknown for any other shadowed pwd (rel-1-0-10:GAP-1043, GAP-1608).
	Subst string
}

// ParamOp is one parameter operator with static operands.
type ParamOp struct {
	// Kind is "#", "##", "%", "%%" (pattern removal), "/", "//" (replace
	// first / every literal match), "/#", "/%" (replace a literal prefix /
	// suffix), or ":" (substring; a negative Off or Len counts from the end).
	Kind     string
	Pat      string
	With     string
	Off, Len int
	HasLen   bool
}

// Word is one argv element. The frontend fills Segs for a word built only of
// literals and simple $VAR/${VAR} expansions; the walker resolves it. A word
// with a command substitution, arithmetic or a complex parameter op has
// Static=false, no Segs and a Reason.
type Word struct {
	Value string
	// Static is true when the whole word resolves to a fixed string with no
	// variable expansion at all (a pure literal). A word needing env resolution
	// has Static=false but non-nil Segs.
	Static bool
	Quoted bool
	// Glob is true for an unquoted word that is a shell glob pattern.
	Glob bool
	// Reason, when set, is why the word is not static (dynamic_expansion, etc.).
	Reason ReasonCode
	Segs   []WordSeg
	Span   [2]int
	// ProcSub is the body of a word that is one input process substitution
	// <(...) (it is also in the command's Nested): a consumer that reads the
	// word as a file (source, a `<` redirect) reads what the body prints.
	ProcSub *Script
	// Tail is the literal text after the last dynamic part of a word that is
	// not static ($(f)/.ssh/id_rsa -> /.ssh/id_rsa): the classifier's reach
	// rule reads a protected name in it (R-NAME, rel-1-0-10:GAP-1043).
	Tail string
}

// Assign is a VAR=value prefix on a command (or an export/declare).
type Assign struct {
	Name      string
	ValueWord Word
	Exported  bool
	// Unbind marks a name a for-loop rebinds: the walker drops it so later
	// commands do not read a stale static value (review N3).
	Unbind bool
	// NoValue marks a declaration that names the variable without giving it a
	// value (`export X`, `declare +x X`): only its attributes change.
	NoValue bool
	// Unexport removes the export attribute (`export -n`, `declare +x`).
	Unexport bool
	// Append is `NAME+=value`: the value is concatenated (or added), not assigned.
	Append bool
	// Attr marks a declaration with an attribute that transforms the value or the
	// variable's type (-l -u -c -i -a -A): the value is no longer what was written.
	Attr bool
	// NameRef marks `declare -n`: the name is a reference to another variable.
	NameRef bool
}

// RedirOp is the kind of a redirection.
type RedirOp string

const (
	RedirWrite      RedirOp = ">"
	RedirAppend     RedirOp = ">>"
	RedirRead       RedirOp = "<"
	RedirDup        RedirOp = ">&"
	RedirHeredoc    RedirOp = "<<"
	RedirHereString RedirOp = "<<<"
	RedirClobber    RedirOp = ">|"
)

// Redir is one redirection on a command.
type Redir struct {
	FD     int
	Op     RedirOp
	Target Word
	// Body is the heredoc / here-string body (data, never a path).
	Body        string
	BodyExpands bool
	// In marks an input operator (<&, <>) written without a descriptor
	// number: it opens the standard input, although FD stays -1.
	In bool
}

// UnknownNode marks a span the frontend could not place in the allowlist.
type UnknownNode struct {
	Reason ReasonCode
	Span   [2]int
}
