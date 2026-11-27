// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package pwshparse

import (
	"bufio"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Differential test against the recorded output of Microsoft's real parser
// (pwsh 7.6.6) over the public PowerShell rows (scripts/pwshoracle/fixture).
// Set PWSHORACLE_OUT=<dir> to write report.txt with the agreement per element
// class and the first differing rows of each class. PWSHORACLE_MIN=<pct>
// turns the agreement of every class on the valid-script rows into a gate.

const oracleFixtureDir = "../../scripts/pwshoracle/fixture"

type oNode struct {
	depth int
	typ   string
	s, e  int
	props map[string]any
}

type oRow struct {
	ast  []oNode
	tok  []string
	errs []string
}

func decodeRow(line []byte) (*oRow, error) {
	var raw struct {
		AST [][]any `json:"ast"`
		Tok [][]any `json:"tok"`
		Err [][]any `json:"err"`
	}
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, err
	}
	r := &oRow{}
	for _, a := range raw.AST {
		n := oNode{depth: int(a[0].(float64)), typ: a[1].(string), s: int(a[2].(float64)), e: int(a[3].(float64))}
		if m, ok := a[4].(map[string]any); ok {
			n.props = m
		}
		r.ast = append(r.ast, n)
	}
	for _, t := range raw.Tok {
		b, _ := json.Marshal(t)
		r.tok = append(r.tok, string(b))
	}
	for _, e := range raw.Err {
		b, _ := json.Marshal(e)
		r.errs = append(r.errs, string(b))
	}
	return r, nil
}

func prop(n oNode, k string) string {
	v, ok := n.props[k]
	if !ok {
		return "-"
	}
	if v == nil {
		return "null"
	}
	return fmt.Sprint(v)
}

var oracleClasses = []string{"cmd", "cmdelem", "param", "strkind", "strval", "scriptblock", "pipeline", "redirection", "ast", "tok", "errid", "errflag", "tree"}

// classSigs derives, per element class, the ordered signature list of the row.
func classSigs(r *oRow) map[string][]string {
	out := map[string][]string{}
	add := func(c, s string) { out[c] = append(out[c], s) }
	for i, n := range r.ast {
		span := fmt.Sprintf("%d-%d", n.s, n.e)
		switch n.typ {
		case "CommandAst":
			add("cmd", span+"|"+prop(n, "CommandName")+"|"+prop(n, "InvocationOperator"))
			for j := i + 1; j < len(r.ast) && r.ast[j].depth > n.depth; j++ {
				if r.ast[j].depth == n.depth+1 {
					add("cmdelem", span+"|"+r.ast[j].typ+fmt.Sprintf(" %d-%d", r.ast[j].s, r.ast[j].e))
				}
			}
		case "CommandParameterAst":
			add("param", span+"|"+prop(n, "ParameterName"))
		case "StringConstantExpressionAst", "ExpandableStringExpressionAst":
			add("strkind", n.typ+"|"+span+"|"+prop(n, "StringConstantType"))
			add("strval", n.typ+"|"+span+"|"+prop(n, "Value"))
		case "ScriptBlockAst", "ScriptBlockExpressionAst":
			add("scriptblock", n.typ+"|"+span)
		case "PipelineAst", "PipelineChainAst":
			add("pipeline", n.typ+"|"+span+"|"+prop(n, "Background")+prop(n, "Operator")+prop(n, "IsBackground"))
		case "FileRedirectionAst", "MergingRedirectionAst":
			add("redirection", n.typ+"|"+span+"|"+prop(n, "FromStream")+"|"+prop(n, "ToStream")+"|"+prop(n, "Append"))
		}
		var ps []string
		for k, v := range n.props {
			if k == "StaticType" {
				continue
			}
			ps = append(ps, fmt.Sprintf("%s=%v", k, v))
		}
		sort.Strings(ps)
		add("ast", fmt.Sprintf("%d|%s|%s|%s", n.depth, n.typ, span, strings.Join(ps, ",")))
	}
	out["tok"] = r.tok
	out["errid"] = r.errs
	if len(r.errs) > 0 {
		add("errflag", "error")
	} else {
		add("errflag", "ok")
	}
	return out
}

func readGz(t *testing.T, name string) *bufio.Scanner { return readGzB(t, name) }

func readGzB(t testing.TB, name string) *bufio.Scanner {
	f, err := os.Open(filepath.Join(oracleFixtureDir, name))
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 1<<20), 1<<28)
	return sc
}

type rowRes struct {
	valid   bool
	failed  map[string]string // class -> first difference
	panicd  string
	timeout bool
	// declined: the port flagged the row Unsupported (nesting beyond the depth budget, dynamic keyword,
	// configuration); the consumer falls back to the legacy reader, so it is not a verdict disagreement.
	declined bool
	// oracleVoid: the reference produced no AST (it failed on the row); nothing to compare.
	oracleVoid bool
	us         int64
}

func firstDiff(want, got []string) string {
	n := len(want)
	if len(got) < n {
		n = len(got)
	}
	for i := 0; i < n; i++ {
		if want[i] != got[i] {
			return fmt.Sprintf("#%d want %s | got %s", i, trunc(want[i]), trunc(got[i]))
		}
	}
	if len(want) != len(got) {
		return fmt.Sprintf("len want %d got %d", len(want), len(got))
	}
	return ""
}

func trunc(s string) string {
	if len(s) > 160 {
		return s[:160] + "..."
	}
	return s
}

func compareRow(script string, idx int, want *oRow) (res rowRes) {
	res.valid = len(want.errs) == 0
	res.oracleVoid = len(want.ast) == 0
	res.failed = map[string]string{}
	done := make(chan struct{})
	var got *oRow
	var dumpErr error
	start := time.Now()
	go func() {
		defer close(done)
		defer func() {
			if x := recover(); x != nil {
				res.panicd = fmt.Sprint(x)
			}
		}()
		r := Parse(script)
		res.declined = r.Unsupported
		got, dumpErr = decodeRow([]byte(r.Dump(idx)))
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		res.timeout = true
		return
	}
	res.us = time.Since(start).Microseconds()
	if res.panicd != "" {
		return
	}
	if dumpErr != nil {
		res.failed["ast"] = "dump decode: " + dumpErr.Error()
		return
	}
	ws, gs := classSigs(want), classSigs(got)
	for _, c := range oracleClasses {
		if c == "tree" {
			continue
		}
		if d := firstDiff(ws[c], gs[c]); d != "" {
			res.failed[c] = d
		}
	}
	// ParseTree (no token stream) must give the same tree and errors as Parse
	if tr, err := decodeRow([]byte(ParseTree(script).Dump(idx))); err != nil {
		res.failed["tree"] = err.Error()
	} else if d := firstDiff(gs["ast"], classSigs(tr)["ast"]); d != "" {
		res.failed["tree"] = "ast " + d
	} else if d := firstDiff(gs["errid"], classSigs(tr)["errid"]); d != "" {
		res.failed["tree"] = "err " + d
	}
	return
}

func TestOracleDifferential(t *testing.T) {
	ob := readGz(t, "pub.b64.gz")
	var scripts []string
	for ob.Scan() {
		b, err := base64.StdEncoding.DecodeString(ob.Text())
		if err != nil {
			t.Fatal(err)
		}
		scripts = append(scripts, string(b))
	}
	oo := readGz(t, "pub.oracle.jsonl.gz")
	var wants []*oRow
	for oo.Scan() {
		r, err := decodeRow(append([]byte(nil), oo.Bytes()...))
		if err != nil {
			t.Fatal(err)
		}
		wants = append(wants, r)
	}
	if len(scripts) != len(wants) {
		t.Fatalf("rows %d != oracle rows %d", len(scripts), len(wants))
	}
	ids := []string{}
	if f, err := os.Open(filepath.Join(oracleFixtureDir, "pub.ids")); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			ids = append(ids, strings.Fields(sc.Text())[0])
		}
		f.Close()
	}
	runOracle(t, scripts, wants, ids, false)
}

// TestOraclePrivate runs the same comparison over the private real-trace rows. The rows never leave
// the box: PWSHORACLE_PRIV_B64 and PWSHORACLE_PRIV_ORACLE name plain files there, and the report holds
// counts only (no row ids, no script text).
func TestOraclePrivate(t *testing.T) {
	bp, op := os.Getenv("PWSHORACLE_PRIV_B64"), os.Getenv("PWSHORACLE_PRIV_ORACLE")
	if bp == "" || op == "" {
		t.Skip("PWSHORACLE_PRIV_B64/PWSHORACLE_PRIV_ORACLE not set")
	}
	var scripts []string
	var wants []*oRow
	readLines := func(path string, f func(line []byte)) {
		fh, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer fh.Close()
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 1<<28)
		for sc.Scan() {
			f(sc.Bytes())
		}
	}
	readLines(bp, func(l []byte) {
		b, err := base64.StdEncoding.DecodeString(string(l))
		if err != nil {
			t.Fatal(err)
		}
		scripts = append(scripts, string(b))
	})
	readLines(op, func(l []byte) {
		r, err := decodeRow(append([]byte(nil), l...))
		if err != nil {
			t.Fatal(err)
		}
		wants = append(wants, r)
	})
	if len(scripts) != len(wants) {
		t.Fatalf("private rows %d != oracle rows %d", len(scripts), len(wants))
	}
	runOracle(t, scripts, wants, nil, true)
}

// runOracle compares every row and reports; private=true suppresses everything that identifies a row.
func runOracle(t *testing.T, scripts []string, wants []*oRow, ids []string, private bool) {
	limit := len(scripts)
	if s := os.Getenv("PWSHORACLE_LIMIT"); s != "" {
		fmt.Sscan(s, &limit)
		if limit > len(scripts) {
			limit = len(scripts)
		}
	}
	results := make([]rowRes, limit)
	var wg sync.WaitGroup
	jobs := make(chan int, 256)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = compareRow(scripts[i], i, wants[i])
			}
		}()
	}
	for i := 0; i < limit; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	id := func(i int) string {
		if i < len(ids) {
			return ids[i]
		}
		return fmt.Sprint(i)
	}

	var rep strings.Builder
	panics, timeouts, valid, declined, voids := 0, 0, 0, 0, 0
	counted := 0
	for _, r := range results {
		if r.declined {
			declined++
		}
		if r.oracleVoid {
			voids++
		}
		if r.declined || r.oracleVoid {
			continue
		}
		counted++
		if r.panicd != "" {
			panics++
		}
		if r.timeout {
			timeouts++
		}
		if r.valid {
			valid++
		}
	}
	fmt.Fprintf(&rep, "rows %d; compared %d (valid-by-oracle %d); declined by port (Unsupported) %d; oracle-void %d; panics %d, timeouts %d\n", limit, counted, valid, declined, voids, panics, timeouts)
	fmt.Fprintf(&rep, "%-12s %9s %9s   %9s %9s\n", "class", "all-ok", "all-%", "valid-ok", "valid-%")
	minPct := 0.0
	if s := os.Getenv("PWSHORACLE_MIN"); s != "" {
		fmt.Sscan(s, &minPct)
	}
	for _, c := range oracleClasses {
		okAll, okValid := 0, 0
		for _, r := range results {
			if r.panicd != "" || r.timeout || r.declined || r.oracleVoid {
				continue
			}
			if _, bad := r.failed[c]; !bad {
				okAll++
				if r.valid {
					okValid++
				}
			}
		}
		pa, pv := 100*float64(okAll)/float64(counted), 100*float64(okValid)/float64(valid)
		fmt.Fprintf(&rep, "%-12s %9d %8.2f%%   %9d %8.2f%%\n", c, okAll, pa, okValid, pv)
		if minPct > 0 && pv < minPct && c != "errid" && c != "tok" && c != "ast" {
			t.Errorf("class %s agreement on valid rows %.2f%% < %.2f%%", c, pv, minPct)
		}
	}
	// samples: the first 25 differing rows of each class (valid rows first)
	for _, c := range oracleClasses {
		if private {
			break
		}
		fmt.Fprintf(&rep, "\n== %s: first differing rows (valid first)\n", c)
		n := 0
		for pass := 0; pass < 2 && n < 25; pass++ {
			for i, r := range results {
				if n >= 25 {
					break
				}
				if d, bad := r.failed[c]; bad && r.valid == (pass == 0) && !r.declined && !r.oracleVoid {
					fmt.Fprintf(&rep, "%s %s valid=%v: %s\n", id(i), fmt.Sprint(i), r.valid, d)
					n++
				}
			}
		}
	}
	for i, r := range results {
		if private {
			break
		}
		if r.panicd != "" {
			fmt.Fprintf(&rep, "PANIC row %d %s: %s\n", i, id(i), r.panicd)
		}
		if r.timeout {
			fmt.Fprintf(&rep, "TIMEOUT row %d %s\n", i, id(i))
		}
	}
	// error-id tally: ids the real parser reports that the port does not (missing) and vice versa (extra)
	{
		missing, extra := map[string]int{}, map[string]int{}
		for i := 0; i < limit; i++ {
			if results[i].panicd != "" || results[i].timeout || results[i].failed["errid"] == "" {
				continue
			}
			got, _ := decodeRow([]byte(Parse(scripts[i]).Dump(i)))
			cw, cg := map[string]int{}, map[string]int{}
			for _, e := range wants[i].errs {
				cw[strings.SplitN(e, "\"", 3)[1]]++
			}
			for _, e := range got.errs {
				cg[strings.SplitN(e, "\"", 3)[1]]++
			}
			for k, v := range cw {
				if v > cg[k] {
					missing[k] += v - cg[k]
				}
			}
			for k, v := range cg {
				if v > cw[k] {
					extra[k] += v - cw[k]
				}
			}
		}
		fmt.Fprintf(&rep, "\n== error ids missing in port: %v\n== error ids extra in port: %v\n", missing, extra)
	}
	if dir := os.Getenv("PWSHORACLE_OUT"); dir != "" {
		name := "report.txt"
		if private {
			name = "report-private.txt"
		}
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(dir, name), []byte(rep.String()), 0o644)
	}
	if dir := os.Getenv("PWSHORACLE_OUT"); dir != "" && !private {
		// differing row index list per class for the fix loop
		for _, c := range oracleClasses {
			var sb strings.Builder
			for i, r := range results {
				if d, bad := r.failed[c]; bad && !r.declined && !r.oracleVoid {
					fmt.Fprintf(&sb, "%d\t%s\t%v\t%s\n", i, id(i), r.valid, strings.ReplaceAll(d, "\n", " "))
				}
			}
			os.WriteFile(filepath.Join(dir, "diff-"+c+".tsv"), []byte(sb.String()), 0o644)
		}
	}
	t.Logf("\n%s", strings.SplitN(rep.String(), "\n== ", 2)[0])
	if panics > 0 || timeouts > 0 {
		t.Errorf("panics %d timeouts %d", panics, timeouts)
	}
}

// TestOracleRow prints the oracle and the port AST of the rows named in
// PWSHORACLE_ROWS (comma separated indices) for the fix loop.
func TestOracleRow(t *testing.T) {
	spec := os.Getenv("PWSHORACLE_ROWS")
	if spec == "" {
		t.Skip("PWSHORACLE_ROWS not set")
	}
	ob := readGz(t, "pub.b64.gz")
	var scripts []string
	for ob.Scan() {
		b, _ := base64.StdEncoding.DecodeString(ob.Text())
		scripts = append(scripts, string(b))
	}
	oo := readGz(t, "pub.oracle.jsonl.gz")
	var wants []*oRow
	for oo.Scan() {
		r, _ := decodeRow(append([]byte(nil), oo.Bytes()...))
		wants = append(wants, r)
	}
	for _, f := range strings.Split(spec, ",") {
		var i int
		fmt.Sscan(f, &i)
		s := scripts[i]
		if len(s) > 400 {
			s = s[:400] + "..."
		}
		fmt.Printf("=== row %d: %q\n", i, s)
		got, _ := decodeRow([]byte(Parse(scripts[i]).Dump(i)))
		fmt.Println("--- want ast")
		for _, n := range wants[i].ast {
			fmt.Printf("%s%s %d-%d %v\n", strings.Repeat(" ", n.depth), n.typ, n.s, n.e, n.props)
		}
		fmt.Println("--- got ast")
		for _, n := range got.ast {
			fmt.Printf("%s%s %d-%d %v\n", strings.Repeat(" ", n.depth), n.typ, n.s, n.e, n.props)
		}
		fmt.Println("--- want errs", wants[i].errs, "got errs", got.errs)
	}
}
