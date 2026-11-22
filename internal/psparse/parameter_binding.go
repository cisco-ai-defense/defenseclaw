// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"strings"
	"unicode/utf8"
)

// Parameter binding: how PowerShell binds a parameter word of a command to
// one of the command's parameters. Readers that compare parameter names as
// literal text miss spellings PowerShell accepts (rel-1-0-10:GAP-0849): a
// unique prefix of a name or an alias (-ty for -Type), an en dash, em dash or
// horizontal bar in place of the hyphen, any letter case, and -Name:value with
// the value attached after a colon (or, with an empty attached value, in the
// next word). ParameterWord reads the word, and a ParameterTable (the
// parameter list of one command, as data) binds the name. A prefix that names
// more than one parameter does not bind: PowerShell refuses it, and a reader
// must treat it as an unknown parameter (the unknown tier, never an allow).

// ParameterWord reads word as PowerShell reads a parameter token: a dash
// (hyphen-minus, en dash, em dash or horizontal bar) and then a letter, an
// underscore or '?'. name is the parameter name in lower case, without the
// dash and without a colon part. With -Name:value, colon is true and value is
// the text after the first colon (empty when the value is the next word).
// ok is false for any other word: a value, a negative number, a bare dash.
func ParameterWord(word string) (name, value string, colon, ok bool) {
	first, size := utf8.DecodeRuneInString(word)
	if size == 0 || !isDash(first) {
		return "", "", false, false
	}
	rest := word[size:]
	start, _ := utf8.DecodeRuneInString(rest)
	if rest == "" || !isNameStart(start) {
		return "", "", false, false
	}
	name, value, colon = strings.Cut(rest, ":")
	return strings.ToLower(name), value, colon, true
}

// Binding is the parameter a name bound to: its canonical name in lower case
// and whether it is a switch (it takes no value word).
type Binding struct {
	Name   string
	Switch bool
}

// ParameterTable is the parameter list of one command: each parameter's
// names (the canonical name first, then its aliases) in lower case.
type ParameterTable struct {
	params []tableParameter
}

type tableParameter struct {
	names    []string
	isSwitch bool
}

// commonParameterSpec is the PowerShell common parameters and their aliases,
// which every advanced command accepts. They take part in prefix matching
// like the command's own parameters, so -v of New-Item names both Value and
// Verbose and binds to neither.
const commonParameterSpec = "verbose,vb! debug,db! erroraction,ea warningaction,wa informationaction,infa " +
	"progressaction,proga errorvariable,ev warningvariable,wv informationvariable,iv outvariable,ov " +
	"outbuffer,ob pipelinevariable,pv"

// NewParameterTable builds the table of a command from spec, its own
// parameters as space-separated fields: a canonical name and its aliases
// joined by commas, with a trailing "!" for a switch. The common parameters
// are added. The spec is data: a new spelling is a table change, not code.
func NewParameterTable(spec string) *ParameterTable {
	table := &ParameterTable{}
	for _, field := range strings.Fields(spec + " " + commonParameterSpec) {
		var param tableParameter
		field, param.isSwitch = strings.CutSuffix(field, "!")
		param.names = strings.Split(strings.ToLower(field), ",")
		table.params = append(table.params, param)
	}
	return table
}

// Bind binds a parameter name (as ParameterWord returns it) as PowerShell
// does: an exact name or alias of one parameter first, else a prefix of the
// names and aliases of exactly one parameter. ok is false for a name that
// names no parameter or, as a prefix, more than one (ambiguous): a reader
// treats either as an unknown parameter.
func (t *ParameterTable) Bind(name string) (Binding, bool) {
	name = strings.ToLower(name)
	if t == nil || name == "" {
		return Binding{}, false
	}
	match := -1
	for i, param := range t.params {
		for _, candidate := range param.names {
			if candidate == name {
				return param.binding(), true
			}
			if !strings.HasPrefix(candidate, name) || match == i {
				continue
			}
			if match >= 0 {
				match = -2
			} else if match == -1 {
				match = i
			}
		}
	}
	if match < 0 {
		return Binding{}, false
	}
	return t.params[match].binding(), true
}

// BindWord is ParameterWord and Bind together. isParameter reports a word
// PowerShell reads as a parameter token; known reports that its name binds.
func (t *ParameterTable) BindWord(word string) (binding Binding, value string, colon, isParameter, known bool) {
	name, value, colon, isParameter := ParameterWord(word)
	if !isParameter {
		return Binding{}, "", false, false, false
	}
	binding, known = t.Bind(name)
	return binding, value, colon, true, known
}

func (p tableParameter) binding() Binding {
	return Binding{Name: p.names[0], Switch: p.isSwitch}
}

// NewItemParameters are the parameters of New-Item (FileSystem provider,
// Windows PowerShell 5.1 and PowerShell 7; checked natively for the
// rel-1-0-10:GAP-0849 review) and the common parameters. Target is an alias
// of Value and Type an alias of ItemType.
var NewItemParameters = NewParameterTable("path name itemtype,type value,target credential force! " +
	"whatif,wi! confirm,cf! usetransaction,usetx!")
