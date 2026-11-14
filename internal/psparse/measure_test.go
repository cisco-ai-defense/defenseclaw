// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestMeasureHostStatic reads a case-v1 jsonl (payload.command) from
// PSPARSE_MEASURE_FILE and reports how many host invocations stay Static, by
// reason, and the most common rejected shapes. Run it on two trees to compare.
func TestMeasureHostStatic(t *testing.T) {
	path := os.Getenv("PSPARSE_MEASURE_FILE")
	if path == "" {
		t.Skip("PSPARSE_MEASURE_FILE unset")
	}
	cmds, err := measureCommands(path)
	if err != nil {
		t.Fatal(err)
	}
	var total, static int
	reasons := map[string]int{}
	shapes := map[string]int{}
	for _, cmdText := range cmds {
		sc, _ := Parse(cmdText, Options{Dialect: DialectUnknown})
		for _, n := range ExtractNestedScripts(sc) {
			if n.Kind != KindPowerShellCommand && n.Kind != KindEncodedCommand && n.Kind != KindCmdC {
				continue
			}
			total++
			if n.Static {
				static++
				continue
			}
			reasons[n.Reason]++
			if c, ok := n.Source.(*Command); ok {
				reasons["  cause:"+measureCause(c)]++
			}
			if c, ok := n.Source.(*Command); ok {
				shapes[measureSig(c)]++
			}
		}
	}
	t.Logf("commands=%d host_calls=%d static=%d (%.1f%%)", len(cmds), total, static, 100*float64(static)/float64(max(total, 1)))
	for r, n := range reasons {
		t.Logf("  not-static reason %-18s %d", r, n)
	}
	type kv struct {
		k string
		v int
	}
	var top []kv
	for k, v := range shapes {
		top = append(top, kv{k, v})
	}
	for i := 1; i < len(top); i++ {
		for j := i; j > 0 && top[j].v > top[j-1].v; j-- {
			top[j], top[j-1] = top[j-1], top[j]
		}
	}
	for i, e := range top {
		if i >= 30 {
			break
		}
		t.Logf("  rejected shape %5d  %s", e.v, e.k)
	}
}

// measureSig is a coarse signature of a host call: the host and its leading
// switch words (other words become <w>), without any payload text.
func measureSig(c *Command) string {
	name, _ := LiteralString(c.Name)
	sig := strings.ToLower(baseName(name))
	n := 0
	for _, w := range hostWords(c) {
		if n >= 6 {
			sig += " ..."
			break
		}
		switch {
		case !w.static:
			sig += " <dyn>"
		case strings.HasPrefix(w.text, "-") || strings.HasPrefix(w.text, "/"):
			sig += " " + strings.ToLower(strings.Fields(w.text + " x")[0])
		default:
			sig += " <w>"
		}
		n++
	}
	return sig
}

func measureCommands(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var row struct {
			Payload struct {
				Command string `json:"command"`
			} `json:"payload"`
		}
		if err := json.Unmarshal(line, &row); err == nil && row.Payload.Command != "" {
			out = append(out, row.Payload.Command)
		}
	}
	return out, nil
}

// measureCause names why a host call's words are not all certain, for the
// cost report: a number literal, a fused (compound) word, a glued neighbour, a
// quoted/whitespace cmd payload word, or something else (a variable, ...).
func measureCause(c *Command) string {
	causes := map[string]bool{}
	prevEnd := -1
	for _, el := range c.Elements {
		s0, s1 := el.Span()
		if prevEnd >= 0 && s0 == prevEnd {
			causes["glued"] = true
		}
		prevEnd = s1
		var v Expr
		switch e := el.(type) {
		case *Arg:
			v = e.Value
		case Expr:
			v = e
		}
		switch x := v.(type) {
		case *Number:
			causes["number"] = true
		case *StringLit:
			if x.Fused {
				causes["fused"] = true
			}
			if !x.Static {
				causes["dynamic"] = true
			}
			if x.Static && strings.ContainsAny(x.Value, " \t\"'") {
				causes["quoted-or-spaced-word"] = true
			}
		case nil:
		default:
			causes["expr"] = true
		}
	}
	out := ""
	for _, k := range []string{"number", "fused", "glued", "quoted-or-spaced-word", "dynamic", "expr"} {
		if causes[k] {
			out += k + ","
		}
	}
	if out == "" {
		out = "other"
	}
	return out
}
