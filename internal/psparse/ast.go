// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

// Node is any AST node. Span returns the source byte range it covers.
type Node interface{ Span() (start, end int) }

type span struct{ start, end int }

func (s span) Span() (int, int) { return s.start, s.end }

// Reason codes mark the parts of a script the parser could not resolve
// statically. They are stable strings so rules and the effects lane can key
// on them.
const (
	ReasonNone             = ""
	ReasonUnterminated     = "ps_unterminated"      // unterminated string/here-string/block/comment
	ReasonUnknownToken     = "ps_unknown_token"     // a lexeme the lexer could not classify
	ReasonUnbalanced       = "ps_unbalanced"        // mismatched (), {}, [], @()
	ReasonDynamicName      = "ps_dynamic_command"   // command name is a non-literal expression (& $var)
	ReasonDynamicMember    = "ps_dynamic_member"    // member/method name is computed
	ReasonStopParsing      = "ps_stop_parsing"      // --% verbatim remainder (not structured)
	ReasonNonLiteral       = "ps_non_literal"       // a value that is not a static literal
	ReasonDepthLimit       = "ps_depth_limit"       // recursion/size guard tripped
	ReasonTruncated        = "ps_truncated"         // input exceeded the byte budget
	ReasonIncompleteExpr   = "ps_incomplete_expr"   // expression ended unexpectedly
	ReasonDialectAmbiguous = "ps_dialect_ambiguous" // escape decodes differently under PS 5.1 vs 7
)

// Script is the root: an ordered list of statements plus the parameter block
// if any. Diagnostics collects every Reason the parser attached anywhere.
type Script struct {
	span
	Params      []*Variable // from a top-level param( ) block, names only
	Statements  []Statement
	Diagnostics []Diagnostic
	Dialect     Dialect
}

// Dialect flags the PowerShell edition assumed while parsing. Windows
// PowerShell 5.1 has no && / || pipeline chain operators (they are parse
// errors there); pwsh 7+ does.
type Dialect int

const (
	DialectPwsh7       Dialect = iota // pwsh 6/7+: && || null-coalescing, etc.
	DialectWindowsPS51                // Windows PowerShell 5.1
	DialectUnknown                    // edition unknown: a dialect-divergent escape is not static
)

// Diagnostic is one place the parser gave up on precise structure.
type Diagnostic struct {
	span
	Reason string
	Detail string
}

// Statement is a top-level or block-level statement.
type Statement interface {
	Node
	stmt()
}

// Pipeline is one or more commands joined by | , or a bare expression.
// PipelineChain (&& / ||) is represented by chaining Pipelines via Chain.
type Pipeline struct {
	span
	Elements []PipelineElement // joined by |
	// Chain, when non-nil, means this pipeline is the left side of a
	// &&/|| chain whose right side is ChainRHS.
	ChainOp    string // "" | "&&" | "||"
	ChainRHS   *Pipeline
	Redirs     []*Redirection
	Background bool // trailing &
}

func (*Pipeline) stmt() {}

// PipelineElement is one stage of a pipeline: either a command invocation or
// a bare expression used as a value / command.
type PipelineElement interface {
	Node
	pipeElem()
}

// Command is a command invocation: a name plus elements (arguments,
// parameters) and redirections. InvokeOp distinguishes a bare call, the call
// operator &, and dot-sourcing .
type Command struct {
	span
	InvokeOp string // "" (normal), "&", "."
	Name     Expr   // the command name expression (usually *StringLit); nil if dynamic-only
	Elements []CommandElement
	Redirs   []*Redirection
	// StopParsing holds the verbatim text after a --% token, if present.
	StopParsing string
}

func (*Command) stmt()     {}
func (*Command) pipeElem() {}

// CommandElement is an argument, a parameter, or an expression argument.
type CommandElement interface {
	Node
	cmdElem()
}

// Parameter is a -Name or -Name:value command parameter.
type Parameter struct {
	span
	Name     string // without the leading dash
	HasColon bool   // -Name: form
	Colon    Expr   // inline value for -Name:value, else nil
}

func (*Parameter) cmdElem() {}

// Arg is a positional expression argument to a command.
type Arg struct {
	span
	Value Expr
}

func (*Arg) cmdElem() {}

// Redirection models > >> 2> *> 1>&2 etc. Op is the operator text; Target is
// the destination expression (a file) or empty for stream merges.
type Redirection struct {
	span
	Op     string // ">", ">>", "2>", "2>>", "*>", "*>>", "3>", "4>", "5>", "6>", "<"
	Merge  string // e.g. "2>&1" -> Merge "1"; empty when redirecting to a file
	Target Expr   // file target, nil for a stream merge
}

// ExprStatement wraps a bare expression used as a pipeline element.
type ExprStatement struct {
	span
	Expr Expr
}

func (*ExprStatement) pipeElem() {}
func (*ExprStatement) stmt()     {}

// Assignment: lhs op rhs (= += -= *= /= %= ??=).
type Assignment struct {
	span
	LHS Expr
	Op  string
	RHS Statement // pipeline or expression statement
}

func (*Assignment) stmt() {}

// Block is a control-flow statement whose bodies hold nested statements the
// effects lane must recurse into (if/for/while/foreach/switch/try/trap/
// function/do). Keyword names the construct. Bodies are every nested block.
// Conditions holds any pipeline/expression conditions for completeness.
type Block struct {
	span
	Keyword    string
	Name       string      // function name / label, when applicable
	Conditions []Statement // conditions and headers (recursed too)
	Bodies     []*ScriptBlockExpr
}

func (*Block) stmt() {}

// UnknownStatement marks a run of tokens the parser could not structure.
type UnknownStatement struct {
	span
	Reason string
	Text   string
}

func (*UnknownStatement) stmt()     {}
func (*UnknownStatement) pipeElem() {}
