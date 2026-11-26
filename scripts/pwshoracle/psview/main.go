// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Command psview prints the reading view of internal/psparse for every script
// of a base64 file (one script per line), as JSONL, in the same shape that
// scripts/pwshoracle/oracle_view.py builds from the real parser's output.
// Test-only tooling for the PowerShell differential oracle.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"unicode/utf16"

	"github.com/defenseclaw/defenseclaw/internal/psparse"
)

type elem []any

type cmdView struct {
	S    int    `json:"s"`
	Op   string `json:"op"`
	Name elem   `json:"name"`
	El   []elem `json:"el"`
	Rd   []elem `json:"rd"`
	Stop string `json:"stop,omitempty"`
}

type view struct {
	I     int       `json:"i"`
	Cmds  []cmdView `json:"cmds"`
	SBs   int       `json:"sbs"`
	Pipes []int     `json:"pipes"`
	Diag  []string  `json:"diag"`
}

var strKinds = map[psparse.StringKind]string{
	psparse.StrSingle: "sq", psparse.StrDouble: "dq", psparse.StrHereSingle: "hsq",
	psparse.StrHereDouble: "hdq", psparse.StrBare: "bare",
}

func exprView(e psparse.Expr) elem {
	switch v := e.(type) {
	case nil:
		return elem{"none", nil, false}
	case *psparse.StringLit:
		k := strKinds[v.Kind]
		if v.Bare && k == "" {
			k = "bare"
		}
		if (k == "dq" || k == "hdq") && !v.Static {
			k += "x"
		}
		return elem{k, v.Value, v.Static}
	case *psparse.Number:
		return elem{"num", v.Text, true}
	case *psparse.Variable:
		return elem{"var", v.Name, false}
	}
	return elem{"other:" + reflect.TypeOf(e).Elem().Name(), nil, false}
}

func main() {
	in, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	dialect := psparse.DialectPwsh7
	if len(os.Args) > 3 && os.Args[3] == "51" {
		dialect = psparse.DialectWindowsPS51
	}
	out, _ := os.Create(os.Args[2])
	w := bufio.NewWriterSize(out, 1<<20)
	defer w.Flush()
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 1<<28)
	i := -1
	for sc.Scan() {
		i++
		raw, err := base64.StdEncoding.DecodeString(sc.Text())
		if err != nil || len(sc.Text()) == 0 {
			fmt.Fprintf(w, "{\"i\":%d,\"empty\":true}\n", i)
			continue
		}
		src := string(raw)
		// byte offset -> UTF-16 offset
		o16 := make([]int, len(src)+1)
		n := 0
		for bi, r := range src {
			o16[bi] = n
			if r >= 0x10000 {
				n += 2
			} else {
				n++
			}
		}
		o16[len(src)] = n
		for bi := 1; bi < len(src); bi++ { // continuation bytes inherit the lead's offset
			if o16[bi] == 0 && bi > 0 {
				o16[bi] = o16[bi-1]
			}
		}
		v := view{I: i, Cmds: []cmdView{}, Pipes: []int{}, Diag: []string{}}
		func() {
			defer func() {
				if r := recover(); r != nil {
					v.Diag = append(v.Diag, fmt.Sprintf("PANIC:%v", r))
				}
			}()
			var s *psparse.Script
			if os.Getenv("PSVIEW_FRONTEND") == "pwshparse" {
				if fs, ok := psparse.FromPwshparse(src, psparse.Options{Dialect: dialect}); ok {
					s = fs
				}
			}
			if s == nil {
				s, _ = psparse.Parse(src, psparse.Options{Dialect: dialect})
			}
			if s == nil {
				return
			}
			for _, d := range s.Diagnostics {
				v.Diag = append(v.Diag, d.Reason)
			}
			psparse.WalkCommands(s, func(c *psparse.Command) {
				st, _ := c.Span()
				if st > len(src) {
					st = len(src)
				}
				cv := cmdView{S: o16[st], Op: c.InvokeOp, Name: exprView(c.Name), El: []elem{}, Rd: []elem{}, Stop: c.StopParsing}
				for _, el := range c.Elements {
					switch e := el.(type) {
					case *psparse.Parameter:
						cv.El = append(cv.El, elem{"param", e.Name, e.HasColon, exprView(e.Colon)})
					case *psparse.Arg:
						cv.El = append(cv.El, exprView(e.Value))
					case psparse.Expr:
						cv.El = append(cv.El, exprView(e))
					}
				}
				for _, r := range c.Redirs {
					cv.Rd = append(cv.Rd, elem{r.Op, r.Merge, exprView(r.Target)})
				}
				v.Cmds = append(v.Cmds, cv)
			})
			sort.SliceStable(v.Cmds, func(a, b int) bool { return v.Cmds[a].S < v.Cmds[b].S })
			countNodes(reflect.ValueOf(s), &v, map[uintptr]bool{})
		}()
		b, _ := json.Marshal(v)
		w.Write(b)
		w.WriteByte('\n')
	}
	_ = utf16.IsSurrogate
}

var sbType = reflect.TypeOf(&psparse.ScriptBlockExpr{})
var plType = reflect.TypeOf(&psparse.Pipeline{})

func countNodes(rv reflect.Value, v *view, seen map[uintptr]bool) {
	switch rv.Kind() {
	case reflect.Interface:
		if !rv.IsNil() {
			countNodes(rv.Elem(), v, seen)
		}
	case reflect.Pointer:
		if rv.IsNil() || seen[rv.Pointer()] {
			return
		}
		seen[rv.Pointer()] = true
		if b, ok := rv.Interface().(*psparse.Block); ok {
			// block bodies (if/loop/try/function) are not script-block expressions
			for _, c := range b.Conditions {
				countNodes(reflect.ValueOf(c), v, seen)
			}
			for _, bd := range b.Bodies {
				if bd != nil {
					for _, st := range bd.Statements {
						countNodes(reflect.ValueOf(st), v, seen)
					}
				}
			}
			return
		}
		if rv.Type() == sbType {
			v.SBs++
		}
		if rv.Type() == plType {
			v.Pipes = append(v.Pipes, len(rv.Interface().(*psparse.Pipeline).Elements))
		}
		countNodes(rv.Elem(), v, seen)
	case reflect.Struct:
		for f := 0; f < rv.NumField(); f++ {
			if rv.Type().Field(f).IsExported() {
				countNodes(rv.Field(f), v, seen)
			}
		}
	case reflect.Slice:
		for k := 0; k < rv.Len(); k++ {
			countNodes(rv.Index(k), v, seen)
		}
	}
}
