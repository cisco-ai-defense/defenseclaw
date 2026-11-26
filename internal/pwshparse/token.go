// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
//
// Portions of this package are a Go port of the PowerShell parser from
// https://github.com/PowerShell/PowerShell (MIT, Copyright (c) Microsoft
// Corporation); see THIRD_PARTY_LICENSES.txt.

package pwshparse

import (
	"strings"
	"unicode/utf16"
)

// RedirectionStream mirrors System.Management.Automation.Language.RedirectionStream.
type RedirectionStream int

const (
	StreamAll         RedirectionStream = 0
	StreamOutput      RedirectionStream = 1
	StreamError       RedirectionStream = 2
	StreamWarning     RedirectionStream = 3
	StreamVerbose     RedirectionStream = 4
	StreamDebug       RedirectionStream = 5
	StreamInformation RedirectionStream = 6
)

var streamNames = [...]string{"All", "Output", "Error", "Warning", "Verbose", "Debug", "Information"}

func (s RedirectionStream) String() string {
	if s >= 0 && int(s) < len(streamNames) {
		return streamNames[s]
	}
	return "Unknown"
}

// Token is one lexical token. Extents are UTF-16 offsets into the source.
type Token struct {
	Kind  TokenKind
	Flags TokenFlags
	Start int
	End   int

	// Value is the string value of string tokens, the parameter name of a
	// parameter token, the label text of a label token.
	Value string
	// Path is the variable path of a variable token.
	Path *VariablePath
	// Num is the value of a number token.
	Num *NumberValue
	// UsedColon is set for a parameter token written as -name:.
	UsedColon bool
	// x holds the fields only expandable strings, unscanned sub-expressions and redirections use.
	x *tokExtra
	// class: 0 plain, 1 string, 2 number, 3 parameter, 4 variable, 5 label
	class uint8
}

// tokExtra is the rarely used part of a Token.
type tokExtra struct {
	// Nested are the tokens inside an expandable string.
	Nested []*Token
	// Redirection payloads; redirKind: 0 none, 1 input, 2 merging, 3 file.
	FromStream, ToStream RedirectionStream
	Append               bool
	redirKind            uint8
	// skipped is the offset map of an unscanned sub-expression token.
	skipped *bitSet
}

func (t *Token) extra() *tokExtra {
	if t.x == nil {
		t.x = &tokExtra{}
	}
	return t.x
}

func (t *Token) nested() []*Token {
	if t.x == nil {
		return nil
	}
	return t.x.Nested
}

func (t *Token) redir() uint8 {
	if t.x == nil {
		return 0
	}
	return t.x.redirKind
}

func (t *Token) fromStream() RedirectionStream {
	if t.x == nil {
		return 0
	}
	return t.x.FromStream
}

func (t *Token) toStream() RedirectionStream {
	if t.x == nil {
		return 0
	}
	return t.x.ToStream
}

func (t *Token) appendMode() bool { return t.x != nil && t.x.Append }

const (
	tcPlain uint8 = iota
	tcString
	tcNumber
	tcParameter
	tcVariable
	tcLabel
)

func (t *Token) hasError() bool { return t.Flags&tfTokenInError != 0 }

func (t *Token) isStringToken() bool { return t.class == tcString }

// NumberValue is a number literal's value. Type is the .NET static type name
// (Int32, Int64, UInt64, Double, Decimal, BigInteger, ...); Text is the
// invariant-culture string of the value.
type NumberValue struct {
	Type string
	Text string
}

// bitSet is a minimal System.Collections.BitArray.
type bitSet struct{ bits []bool }

func newBitSet(n int) *bitSet { return &bitSet{bits: make([]bool, n)} }
func (b *bitSet) get(i int) bool {
	return b != nil && i >= 0 && i < len(b.bits) && b.bits[i]
}
func (b *bitSet) set(i int, v bool) {
	if i >= len(b.bits) {
		nb := make([]bool, i+1)
		copy(nb, b.bits)
		b.bits = nb
	}
	b.bits[i] = v
}
func (b *bitSet) length() int {
	if b == nil {
		return 0
	}
	return len(b.bits)
}

func (k TokenKind) hasTrait(f TokenFlags) bool { return staticTokenFlags[k]&f != 0 }
func (k TokenKind) binaryPrecedence() int {
	return int(staticTokenFlags[k] & tfBinaryPrecedenceMask)
}

// String returns the .NET enum name.
func (k TokenKind) String() string { return tokenKindNames[k] }

// Text is TokenKind.Text() in the reference.
func (k TokenKind) Text() string { return tokenText[k] }

// flagsString renders TokenFlags the way .NET's [Flags] enum ToString does:
// names of set flags, lowest value first, comma separated; None when empty.
func (f TokenFlags) String() string {
	if f == 0 {
		return "None"
	}
	// The binary-precedence values overlap (0x1,0x2,0x5,0x7,0x9,0xa,0xc,0xd,0xf):
	// .NET prints the largest-valued names that are fully contained first, from
	// the highest value down, then reverses to ascending order.
	rem := uint32(f)
	var names []string
	for i := len(flagNameTable) - 1; i >= 0; i-- {
		e := flagNameTable[i]
		if e.v != 0 && rem&e.v == e.v {
			names = append(names, e.name)
			rem &^= e.v
		}
	}
	if rem != 0 {
		return utf16Itoa(int(rem))
	}
	for i, j := 0, len(names)-1; i < j; i, j = i+1, j-1 {
		names[i], names[j] = names[j], names[i]
	}
	return strings.Join(names, ", ")
}

func utf16Itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

type flagName struct {
	v    uint32
	name string
}

// flagNameTable lists TokenFlags members in ascending value order.
var flagNameTable = []flagName{
	{0x1, "BinaryPrecedenceLogical"}, {0x2, "BinaryPrecedenceBitwise"}, {0x5, "BinaryPrecedenceComparison"},
	{0x7, "BinaryPrecedenceCoalesce"}, {0x9, "BinaryPrecedenceAdd"}, {0xa, "BinaryPrecedenceMultiply"},
	{0xc, "BinaryPrecedenceFormat"}, {0xd, "BinaryPrecedenceRange"}, {0xf, "BinaryPrecedenceMask"},
	{0x10, "Keyword"}, {0x20, "ScriptBlockBlockName"}, {0x100, "BinaryOperator"}, {0x200, "UnaryOperator"},
	{0x400, "CaseSensitiveOperator"}, {0x800, "TernaryOperator"}, {0x1000, "SpecialOperator"},
	{0x2000, "AssignmentOperator"}, {0x8000, "ParseModeInvariant"}, {0x10000, "TokenInError"},
	{0x20000, "DisallowedInRestrictedMode"}, {0x40000, "PrefixOrPostfixOperator"}, {0x80000, "CommandName"},
	{0x100000, "MemberName"}, {0x200000, "TypeName"}, {0x400000, "AttributeName"}, {0x800000, "CanConstantFold"},
	{0x1000000, "StatementDoesntSupportAttributes"},
}

// VariablePath mirrors System.Management.Automation.VariablePath.
type VariablePath struct {
	UserPath string
}

// u16 helpers: the parser indexes UTF-16 code units.

func toUTF16(s string) []char {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return utf16.Encode([]rune(s))
		}
	}
	out := make([]char, len(s))
	for i := 0; i < len(s); i++ {
		out[i] = char(s[i])
	}
	return out
}

func fromUTF16(c []char) string {
	for _, x := range c {
		if x >= 0x80 {
			return string(utf16.Decode(c))
		}
	}
	var sb strings.Builder
	sb.Grow(len(c))
	for _, x := range c {
		sb.WriteByte(byte(x))
	}
	return sb.String()
}
