// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

// Expr is any expression node.
type Expr interface {
	Node
	expr()
}

// StringLit is a string literal or bareword. When Static is true, Value holds
// the fully-resolved literal text. For expandable strings with embedded
// variables or $( ) the Static flag is false and Parts holds the segments
// (literal runs and embedded expressions) so the effects lane can still read
// the literal skeleton (e.g. a path prefix before a $var).
type StringLit struct {
	span
	Kind   StringKind
	Value  string // resolved literal text when Static
	Static bool
	Parts  []StringPart // for expandable strings
	Bare   bool         // was an unquoted bareword
}

func (*StringLit) expr()    {}
func (*StringLit) cmdElem() {} // a bare string can appear directly as a command element

// StringPart is one segment of an expandable string: either a literal run
// (Lit non-empty, Expr nil) or an embedded expression ($var or $(...)).
type StringPart struct {
	Lit  string
	Expr Expr
}

// Number is a numeric literal; Text is the exact source (incl. any kb/mb
// multiplier or hex/0x form). Value is the parsed magnitude when resolvable.
type Number struct {
	span
	Text  string
	Value float64
	Int   bool
}

func (*Number) expr() {}

// Variable is $name / ${name} / $scope:name / @name (splatting).
type Variable struct {
	span
	Name  string
	Scope string // env, global, script, local, using, variable, or a drive
	Splat bool   // @name
}

func (*Variable) expr()    {}
func (*Variable) cmdElem() {}

// ScriptBlockExpr is a { ... } block: a nested script that may itself be
// re-parsed / executed (passed to Invoke-Command, & { }, [scriptblock], etc.).
type ScriptBlockExpr struct {
	span
	Params     []*Variable
	Statements []Statement
}

func (*ScriptBlockExpr) expr() {}

// SubExpr is $( ... ): a sub-expression whose statements produce a value.
type SubExpr struct {
	span
	Statements []Statement
}

func (*SubExpr) expr()    {}
func (*SubExpr) cmdElem() {}

// ArrayExpr is @( ... ): an array sub-expression.
type ArrayExpr struct {
	span
	Statements []Statement
}

func (*ArrayExpr) expr()    {}
func (*ArrayExpr) cmdElem() {}

// ArrayLit is a comma list a,b,c used in expression context.
type ArrayLit struct {
	span
	Elements []Expr
}

func (*ArrayLit) expr() {}

// Hashtable is @{ k = v; ... }. Keys/Values are parallel; a key or value that
// is non-literal keeps its Expr with Static=false upstream.
type Hashtable struct {
	span
	Keys   []Expr
	Values []Expr
}

func (*Hashtable) expr()    {}
func (*Hashtable) cmdElem() {}

// Paren is ( ... ): a parenthesised pipeline/expression.
type Paren struct {
	span
	Inner Statement
}

func (*Paren) expr()    {}
func (*Paren) cmdElem() {}

// Member is a property/field access: Target.Name or Target::Name. Static is
// true and Name set when the member name is a literal; otherwise Reason is set.
type Member struct {
	span
	Target Expr
	Name   string
	Static bool // ::
	Reason string
}

func (*Member) expr() {}

// Invoke is a method call: Target.Name(args) or Target::Name(args).
type Invoke struct {
	span
	Target Expr
	Name   string
	Static bool // ::
	Args   []Expr
	Reason string
}

func (*Invoke) expr() {}

// Index is Target[index].
type Index struct {
	span
	Target Expr
	Index  Expr
}

func (*Index) expr() {}

// TypeExpr is a [type] literal / cast, e.g. [scriptblock], [int], [System.IO.File].
type TypeExpr struct {
	span
	Name string
	Args []Expr // attribute arguments, e.g. [ValidateScript({...})] — walked for nested commands
}

func (*TypeExpr) expr() {}

// Unary is a prefix/postfix unary expression (-not, !, -, +, ++, --, -bnot, -split, -join as unary).
type Unary struct {
	span
	Op      string
	Operand Expr
	Postfix bool
}

func (*Unary) expr() {}

// Binary is a binary expression with a PowerShell operator (arithmetic,
// comparison -eq/-lt..., logical -and/-or, string -f/-replace/-match, etc.).
type Binary struct {
	span
	Op  string
	LHS Expr
	RHS Expr
}

func (*Binary) expr() {}

// ExpandableWrap wraps an expression produced inside an expandable context.
// Used when the parser recovers a cast/convert like [type]$x.
type Convert struct {
	span
	Type    string
	Operand Expr
}

func (*Convert) expr() {}

// ErrorExpr marks an expression the parser could not resolve. It never drops
// the source text so callers can escalate.
type ErrorExpr struct {
	span
	Reason string
	Text   string
}

func (*ErrorExpr) expr()    {}
func (*ErrorExpr) cmdElem() {}
