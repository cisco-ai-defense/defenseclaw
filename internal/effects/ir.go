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
	Span       [2]int
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
	Sub  *Script
	Cond bool
	Span [2]int
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
