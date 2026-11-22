// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import "strings"

// HostCommandChildText is the -Command script of a powershell or pwsh call
// whose one non-literal word is a double-quoted -Command value that expands
// only $HOME and $env:NAME: powershell -c "Copy-Item $HOME\.ssh\id_rsa x".
// The parent expands those to the values the child reads them as (the child
// has the same profile home and inherits the environment), so the body as
// written is the script the child runs. ExtractNestedScripts leaves such a
// call not static (ReasonNonLiteral), and the script went unread
// (rel-1-0-10:GAP-1226). Any other expansion, an escape, an embedded quote, a
// colon form, a stop-parsing token or a word after the value gives no text.
func HostCommandChildText(c *Command) (string, bool) {
	if c == nil {
		return "", false
	}
	for i, el := range c.Elements {
		p, isParam := el.(*Parameter)
		if !isParam {
			if text, static := LiteralString(elementExpr(el)); !static || strings.HasPrefix(text, "--%") {
				return "", false
			}
			continue
		}
		if p.HasColon {
			return "", false
		}
		canon, _, known := resolvePSParam(strings.ToLower(p.Name))
		if !known {
			return "", false
		}
		if canon != "command" {
			continue
		}
		if i != len(c.Elements)-2 {
			return "", false
		}
		return childReadableString(elementExpr(c.Elements[i+1]))
	}
	return "", false
}

func elementExpr(el CommandElement) Expr {
	switch v := el.(type) {
	case *Arg:
		return v.Value
	case Expr:
		return v
	}
	return nil
}

// childReadableString is the body of a double-quoted string whose only
// expansions are $HOME and $env:NAME.
func childReadableString(e Expr) (string, bool) {
	s, ok := e.(*StringLit)
	if !ok || s.Static || s.Fused || s.Kind != StrDouble {
		return "", false
	}
	body := trimRuneDelims(s.Raw)
	if strings.ContainsRune(body, '`') || strings.ContainsFunc(body, isDoubleQuote) || strings.TrimSpace(body) == "" {
		return "", false
	}
	for i := 0; i < len(body); i++ {
		if body[i] != '$' {
			continue
		}
		rest := strings.ToLower(body[i+1:])
		switch {
		case strings.HasPrefix(rest, "home") && (len(rest) == 4 || !childNameByte(rest[4])):
			i += 4
		case strings.HasPrefix(rest, "env:"):
			n := 4
			for n < len(rest) && childNameByte(rest[n]) {
				n++
			}
			if n == 4 {
				return "", false
			}
			i += n
		default:
			return "", false
		}
	}
	return body, true
}

// childNameByte is a byte that continues a variable name ($HOME: and
// $HOME? are other names, so they do not end it either).
func childNameByte(c byte) bool {
	return c == '_' || c == ':' || c == '?' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
