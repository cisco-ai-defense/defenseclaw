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

package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
)

// A held bridge call's ask names the exact call the owner sees (GAP-0840):
// its Rule carries a digest of the method, tool, reference and the judged
// arguments, so the store joins only identical pending calls, and the
// Summary carries a short, redacted preview of the arguments. Before, the
// ask was keyed on the tool alone: a second held call of the same tool with
// other arguments joined the first ask, and approving what the owner saw
// released both.

const (
	// substrateMCPAskPreviewMax bounds the argument preview in an ask's
	// summary (bytes), substrateMCPAskPreviewValue one value in it.
	substrateMCPAskPreviewMax   = 240
	substrateMCPAskPreviewValue = 48
)

// substrateMCPAskRule is the ask Rule of a held call: the sha256 of its
// method, tool, reference and judged readings, each length-prefixed so no
// two different calls share an encoding.
func substrateMCPAskRule(method, tool string, c substrateMCPJudgedCall) string {
	h := sha256.New()
	field := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	field([]byte(method))
	field([]byte(tool))
	field([]byte(c.ref))
	for _, a := range c.args {
		field(a)
	}
	field(c.params)
	return asks.MCPCallRule(hex.EncodeToString(h.Sum(nil)))
}

// substrateMCPAskSummary is what the owner reads before deciding: the
// server, the tool and a preview of the arguments (the tools/call
// arguments, or the whole params of another judged method).
func substrateMCPAskSummary(target, tool string, c substrateMCPJudgedCall) string {
	s := "laptop MCP call " + target + "." + tool
	raw := c.params
	if raw == nil && len(c.args) > 0 {
		raw = c.args[0]
	}
	if p := substrateMCPArgsPreview(raw); p != "" {
		s += " (" + p + ")"
	}
	return s
}

// substrateMCPArgsPreview renders the top level of an arguments object as
// key=value pairs in key order, bounded. A value under a secret-named key
// or carrying a known credential prefix shows only its length; a nested
// object or array shows only its size, so nothing below the top level is
// printed.
func substrateMCPArgsPreview(raw json.RawMessage) string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return ""
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return ""
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return "arguments " + substrateMCPPreviewValue("", v)
	}
	if len(obj) == 0 {
		return "no arguments"
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	for i, k := range keys {
		part := substrateMCPPreviewText(k, 32) + "=" + substrateMCPPreviewValue(k, obj[k])
		if i > 0 {
			part = ", " + part
		}
		if b.Len()+len(part) > substrateMCPAskPreviewMax {
			b.WriteString(", +" + strconv.Itoa(len(keys)-i) + " more")
			break
		}
		b.WriteString(part)
	}
	return b.String()
}

func substrateMCPPreviewValue(key string, v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(x)
	case json.Number:
		return substrateMCPPreviewText(x.String(), substrateMCPAskPreviewValue)
	case string:
		if (key != "" && substrateMCPAskSecretKey(key)) || redaction.AssertNoCredentials(x) != nil {
			return "<hidden len=" + strconv.Itoa(len(x)) + ">"
		}
		return strconv.Quote(substrateMCPPreviewText(x, substrateMCPAskPreviewValue))
	case map[string]any:
		return "{" + strconv.Itoa(len(x)) + " keys}"
	case []any:
		return "[" + strconv.Itoa(len(x)) + " items]"
	}
	return "?"
}

// substrateMCPAskSecretKey is a key whose value an ask never shows: the
// secret-named keys of the tool value lineage, and the request
// authentication keys.
func substrateMCPAskSecretKey(key string) bool {
	switch strings.ToLower(strings.ReplaceAll(key, "-", "_")) {
	case "authorization", "auth", "cookie", "bearer", "apikey", "session", "session_id":
		return true
	}
	return toolValueLineageSensitiveJSONKey(key)
}

// substrateMCPPreviewText cuts s to at most n bytes on a rune boundary and
// drops control characters, so a summary stays one readable line.
func substrateMCPPreviewText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
