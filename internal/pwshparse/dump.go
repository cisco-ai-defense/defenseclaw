// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
//
// Portions of this package are a Go port of the PowerShell parser from
// https://github.com/PowerShell/PowerShell (MIT, Copyright (c) Microsoft
// Corporation); see THIRD_PARTY_LICENSES.txt.

package pwshparse

import (
	"strconv"
	"strings"
)

// Dump renders the normalised pre-order dump the reference oracle prints
// (scripts/pwshoracle/PwshOracle.cs): one compact JSON object per script with
// the AST in pre-order with depth, the token stream and the parse errors.

// propNull marks a property whose value is null in the reference.
const propNull = "\x00null"

// dumpProps lists, per AST type, the properties the oracle dumps, in its order.
var dumpProps = map[string][]string{
	"NamedBlockAst":                     {"BlockKind", "Unnamed"},
	"CommandAst":                        {"InvocationOperator", "DefiningKeyword"},
	"CommandParameterAst":               {"ParameterName"},
	"StringConstantExpressionAst":       {"StringConstantType", "Value"},
	"ExpandableStringExpressionAst":     {"StringConstantType", "Value"},
	"ConstantExpressionAst":             {"StaticType", "Value"},
	"VariableExpressionAst":             {"VariablePath", "Splatted"},
	"BinaryExpressionAst":               {"Operator"},
	"UnaryExpressionAst":                {"TokenKind"},
	"AssignmentStatementAst":            {"Operator"},
	"MemberExpressionAst":               {"Static", "NullConditional"},
	"InvokeMemberExpressionAst":         {"Static", "NullConditional"},
	"BaseCtorInvokeMemberExpressionAst": {"Static", "NullConditional"},
	"FileRedirectionAst":                {"FromStream", "Append"},
	"MergingRedirectionAst":             {"FromStream", "ToStream"},
	"TypeExpressionAst":                 {"TypeName"},
	"TypeConstraintAst":                 {"TypeName"},
	"ConvertExpressionAst":              {"StaticType"},
	"AttributeAst":                      {"TypeName"},
	"FunctionDefinitionAst":             {"Name", "IsFilter", "IsWorkflow"},
	"NamedAttributeArgumentAst":         {"ArgumentName", "ExpressionOmitted"},
	"PipelineAst":                       {"Background"},
	"PipelineChainAst":                  {"Operator"},
	"UsingStatementAst":                 {"UsingStatementKind"},
	"DataStatementAst":                  {"Variable"},
	"CatchClauseAst":                    {"IsCatchAll"},
	"ForEachStatementAst":               {"Flags"},
	"SwitchStatementAst":                {"Flags"},
}

func jsonEsc(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString("\\\"")
		case '\\':
			sb.WriteString("\\\\")
		case '\n':
			sb.WriteString("\\n")
		case '\r':
			sb.WriteString("\\r")
		case '\t':
			sb.WriteString("\\t")
		default:
			if r < 0x20 {
				sb.WriteString("\\u")
				sb.WriteString(hex4(int(r)))
			} else if r >= 0x10000 {
				r -= 0x10000
				sb.WriteString("\\u")
				sb.WriteString(hex4(0xD800 + int(r>>10)))
				sb.WriteString("\\u")
				sb.WriteString(hex4(0xDC00 + int(r&0x3ff)))
			} else if r >= 0xD800 && r <= 0xDFFF {
				sb.WriteString("\\u")
				sb.WriteString(hex4(int(r)))
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
}

func hex4(v int) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[(v>>12)&15], digits[(v>>8)&15], digits[(v>>4)&15], digits[v&15]})
}

func jsonOpt(sb *strings.Builder, s string) {
	if s == propNull {
		sb.WriteString("null")
		return
	}
	jsonEsc(sb, s)
}

// Dump returns the oracle-format JSON line for the parse result.
func (r *Result) Dump(index int) string {
	var sb strings.Builder
	sb.WriteString(`{"i":`)
	sb.WriteString(strconv.Itoa(index))
	sb.WriteString(`,"ast":[`)
	first := true
	var walk func(n *Node, depth int)
	walk = func(n *Node, depth int) {
		if !first {
			sb.WriteByte(',')
		}
		first = false
		sb.WriteByte('[')
		sb.WriteString(strconv.Itoa(depth))
		sb.WriteByte(',')
		jsonEsc(&sb, n.Type)
		sb.WriteByte(',')
		sb.WriteString(strconv.Itoa(n.Start))
		sb.WriteByte(',')
		sb.WriteString(strconv.Itoa(n.End))
		sb.WriteString(",{")
		pf := true
		if n.Type == "CommandAst" {
			jsonEsc(&sb, "CommandName")
			sb.WriteByte(':')
			if len(n.Kids) > 0 && n.Kids[0].isStringConst() {
				jsonEsc(&sb, n.Kids[0].Str)
			} else {
				sb.WriteString("null")
			}
			pf = false
		}
		for _, name := range dumpProps[n.Type] {
			v, ok := n.getProp(name)
			if !ok {
				continue
			}
			if !pf {
				sb.WriteByte(',')
			}
			pf = false
			jsonEsc(&sb, name)
			sb.WriteByte(':')
			jsonOpt(&sb, v)
		}
		sb.WriteString("}]")
		for _, k := range n.Kids {
			walk(k, depth+1)
		}
	}
	if r.Root != nil {
		walk(r.Root, 0)
	}
	sb.WriteString(`],"tok":[`)
	for i, t := range r.Tokens {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('[')
		jsonEsc(&sb, t.Kind.String())
		sb.WriteByte(',')
		jsonEsc(&sb, t.Flags.String())
		sb.WriteByte(',')
		sb.WriteString(strconv.Itoa(t.Start))
		sb.WriteByte(',')
		sb.WriteString(strconv.Itoa(t.End))
		sb.WriteByte(',')
		switch t.class {
		case tcString, tcParameter, tcLabel:
			jsonEsc(&sb, t.Value)
		case tcVariable:
			jsonEsc(&sb, t.Path.UserPath)
		case tcNumber:
			if t.Num == nil {
				sb.WriteString("null")
			} else {
				jsonEsc(&sb, t.Num.Text)
			}
		default:
			sb.WriteString("null")
		}
		sb.WriteByte(']')
	}
	sb.WriteString(`],"err":[`)
	for i, e := range r.Errors {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('[')
		jsonEsc(&sb, e.ErrorID)
		sb.WriteByte(',')
		sb.WriteString(strconv.Itoa(e.Start))
		sb.WriteByte(',')
		sb.WriteString(strconv.Itoa(e.End))
		sb.WriteByte(']')
	}
	sb.WriteString("]}")
	return sb.String()
}
