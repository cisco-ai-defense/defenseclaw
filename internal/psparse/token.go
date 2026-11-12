// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package psparse is a parsing-only parser for the PowerShell language. It
// produces an AST that models the structure of a PowerShell script well
// enough to derive effects from it (which commands run, with which arguments,
// which redirections and pipelines, and which nested script text). It is not
// an evaluator and does not execute anything.
//
// The parser never panics and never drops input: any construct it cannot
// resolve statically is represented by an ErrorExpr or an UnknownStatement
// carrying a Reason code, so callers can escalate rather than silently miss.
package psparse

// TokenKind enumerates the lexical token categories the PowerShell lexer
// emits. The set follows System.Management.Automation.Language.TokenKind
// closely enough for parsing; purely cosmetic distinctions are collapsed.
type TokenKind int

const (
	TokEOF TokenKind = iota
	TokNewline
	TokSemi        // ;
	TokPipe        // |
	TokAmpAmp      // &&
	TokPipePipe    // ||
	TokAmp         // &  (background / call operator)
	TokDot         // .  (dot-source / member)
	TokComma       // ,
	TokLParen      // (
	TokRParen      // )
	TokLBrace      // {
	TokRBrace      // }
	TokLBracket    // [
	TokRBracket    // ]
	TokAtParen     // @(
	TokAtBrace     // @{
	TokDollarParen // $(
	TokStopParse   // --%
	TokRedir       // > >> 2> *> 2>&1 etc (text in Value)
	TokParameter   // -Name  (Value is the name without the dash)
	TokVariable    // $x ${x} $env:x $global:x etc
	TokNumber      // 1 0x1F 1kb 1.5 1e3
	TokString      // quoted string (single/double/here-string); see StringKind
	TokGeneric     // a bareword / command name / operator word (-eq, -join, etc.)
	TokOperator    // assignment/comparison/arithmetic operator symbols
	TokLabel       // :label
	TokComment     // # ... or <# ... #>
	TokError       // a lexing error; Value holds a reason code
)

// StringKind distinguishes the five PowerShell string literal forms.
type StringKind int

const (
	StrNone       StringKind = iota
	StrSingle                // '...'            literal, '' escapes a quote
	StrDouble                // "..."            expandable
	StrHereSingle            // @'\n...\n'@      literal here-string
	StrHereDouble            // @"\n...\n"@      expandable here-string
	StrBare                  // bareword used as a string argument / command name
)

// Token is one lexical token with its source span.
type Token struct {
	Kind     TokenKind
	Value    string
	Raw      string
	Start    int
	End      int
	Str      StringKind
	HasColon bool
	ColonArg string
	Splat    bool
	VarName  string
	VarScope string
}
