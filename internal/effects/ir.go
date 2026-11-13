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
	Span [2]int
}

// Cmd is one simple command or pipeline stage.
type Cmd struct {
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
	Async    bool
	Cond     bool
	Span     [2]int
	// Host is psparse's verdict on a cmd / powershell / pwsh host call that the
	// PowerShell frontend lowered, nil when psparse gave none. The walker unwraps
	// the payload only from a Static verdict, with psparse's text; a NotStatic
	// verdict is opaque and is never unwrapped by the walker's own parsing
	// (psparse review 9 R9-3, GAP-0193).
	Host *HostPayload
}

// HostPayload is psparse's reading of one host call's payload.
type HostPayload struct {
	Opaque  bool    // not static, or unsafe to trust: no unwrap
	Text    string  // the payload text when !Opaque
	Dialect Dialect // the payload's grammar when !Opaque
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
}

// UnknownNode marks a span the frontend could not place in the allowlist.
type UnknownNode struct {
	Reason ReasonCode
	Span   [2]int
}
