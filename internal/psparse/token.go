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
//
// Static is an allowlist over host-call shapes. A powershell / pwsh / cmd
// invocation yields a Static nested script only when its argv is one of the
// tested shapes in host_shapes.go (whole-word host options from a fixed list,
// then one -Command or -EncodedCommand switch, or cmd's /c /k /r); each shape
// has pwsh 7.7 differential rows. Anything else is NotStatic with a reason
// code, and a newly found spelling is a corpus row, never a new special case.
//
// Cost of failing closed on child-process argv. psparse does not model how a
// native host (powershell, pwsh, cmd) receives its command line, so a nested
// script is reported Static only when its resolved text is certain to be what
// the child runs. The price is deliberate over-reporting of opaque scripts:
// under DialectUnknown or Windows PowerShell 5.1 a -Command / cmd /c payload
// with a double quote, or any host word that contains whitespace and ends in a
// backslash (for example the ordinary quoted directory 'C:\Program Files\'),
// is ps_legacy_quoting; a host command of "-" or a "-File -" is ps_stdin; a
// padded, empty or unrecognised host switch is ps_host_option; a cmd line
// hidden in a splat or a fused switch is ps_cmd_argv. Callers see these as
// non-static and treat the script as opaque code (the effects lane maps every
// non-static nested script to opaque_code). Pass DialectPwsh7 when the host is
// known to be pwsh 7 to keep the text of the quoting shapes.
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
