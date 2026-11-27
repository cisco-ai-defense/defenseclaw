// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effectrules"
	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

// det111Case is one row of testdata/det111_r1.cases.jsonl: the DET111 step-3
// (class R1) gap rows copied verbatim from the DET111 gap corpus B by a filter
// (plans/r111/detection/lanes/s3r1b/filter-v1.py), so no attack spelling is
// written by hand in Go source.
type det111Case struct {
	ID      string `json:"id"`
	Payload struct {
		Args     json.RawMessage `json:"args"`
		CWD      string          `json:"cwd"`
		Dialect  string          `json:"dialect"`
		ToolName string          `json:"tool_name"`
	} `json:"payload"`
	Strata struct {
		Platform string `json:"platform"`
	} `json:"strata"`
	Truth struct {
		Categories []string `json:"categories"`
		Truth      string   `json:"deterministic_truth"`
	} `json:"truth"`
}

func (c det111Case) gap() string {
	for _, k := range c.Truth.Categories {
		if strings.HasPrefix(k, "gap:") {
			return strings.TrimPrefix(k, "gap:")
		}
	}
	return ""
}

func (c det111Case) role() string {
	for _, k := range c.Truth.Categories {
		if strings.HasPrefix(k, "role:") {
			return strings.TrimPrefix(k, "role:")
		}
	}
	return ""
}

func loadDET111Cases(t *testing.T) []det111Case {
	t.Helper()
	return loadDET111CasesFile(t, "testdata/det111_r1.cases.jsonl")
}

// loadDET111CasesFile loads one DET111 corpus copy.
func loadDET111CasesFile(t *testing.T, name string) []det111Case {
	t.Helper()
	f, err := os.Open(name)
	if err != nil {
		t.Fatalf("open cases: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var out []det111Case
	for sc.Scan() {
		var c det111Case
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			t.Fatalf("case line %d: %v", len(out)+1, err)
		}
		if c.gap() == "" {
			t.Fatalf("case %s has no gap category", c.ID)
		}
		out = append(out, c)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan cases: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("no cases loaded")
	}
	return out
}

// det111Run normalizes and extracts one row the way the hook does, then grades
// the targets with the protected-set classifier. Links are not followed (the
// test reads no file system): every lexical path is its own resolution.
func det111Run(c det111Case) (effects.Result, []*semanticpb.EffectFact, []string) {
	var home string
	o := effects.Options{CWD: c.Payload.CWD}
	switch c.Strata.Platform {
	case "windows":
		home = `C:\Users\alice`
		o.Flavor, o.Drive, o.CaseInsensitive = effects.FlavorWindows, "C", true
	case "macos":
		home = "/Users/alice"
		o.Flavor, o.CaseInsensitive = effects.FlavorPOSIX, true
	default:
		home = "/home/alice"
		o.Flavor = effects.FlavorPOSIX
	}
	o.Home = home
	switch c.Payload.Dialect {
	case "powershell":
		o.Dialect = effects.DialectPowerShell
	case "cmd":
		o.Dialect = effects.DialectCMD
	case "posix":
		o.Dialect = effects.DialectPOSIX
	}
	call := effects.Normalize("det111", c.Payload.ToolName, c.Payload.Args)
	call.Workdir = c.Payload.CWD
	res := effects.Extract(call, o)
	facts := effectrules.Project(res, effectrules.Env{
		Home: home, Flavor: o.Flavor,
		Resolve: func(p string) (string, bool) { return p, true },
	})
	var lines []string
	for i, e := range res.Effects {
		var prot []string
		if i < len(facts) {
			for _, m := range facts[i].GetTarget().GetProtected() {
				prot = append(prot, m.GetSet()+"="+m.GetState())
			}
		}
		sort.Strings(prot)
		tgt := e.Target.Path
		if tgt == "" {
			tgt = e.Target.Glob
		}
		if tgt == "" {
			tgt = e.Target.URL + e.Target.Host
		}
		if tgt == "" {
			tgt = e.Target.Spelling
		}
		var rs []string
		for _, r := range e.Reasons {
			rs = append(rs, string(r.Code))
		}
		dk := ""
		if e.Data != nil {
			dk = string(e.Data.Kind)
			for _, s := range e.Data.Sources {
				dk += fmt.Sprintf("<%s%d%s", s.Kind, s.Effect, s.Path)
			}
		}
		lines = append(lines, fmt.Sprintf("%s %s ts=%s rs=%s d=%d prog=%s cond=%v [%s] data=%s",
			e.Kind, tgt, e.TargetState, e.RoleState, e.Origin.Depth, e.Origin.Program, e.Cond,
			strings.Join(append(prot, rs...), ","), dk))
	}
	for _, u := range res.Unknowns {
		lines = append(lines, "U "+string(u.Code))
	}
	return res, facts, lines
}

// TestDET111R1Dump prints every row's effects (DET111_R1_DUMP=1 only): the
// review aid for the per-gap table.
func TestDET111R1Dump(t *testing.T) {
	if os.Getenv("DET111_R1_DUMP") != "1" {
		t.Skip("set DET111_R1_DUMP=1")
	}
	for _, c := range loadDET111Cases(t) {
		_, _, lines := det111Run(c)
		fmt.Printf("== %s %s %s\n", strings.TrimPrefix(c.ID, "gap/det111-b_"), c.Truth.Truth, c.role())
		for _, l := range lines {
			fmt.Printf("   %s\n", l)
		}
	}
}

// det111Pending are rows the effects IR does not lower yet, each with the lane
// or reason that closes it. A pending row that starts to pass fails the test,
// so the list only shrinks.
var det111Pending = map[string]string{
	"GAP-1173/var4": "Expand-Archive has no program row (S4-R2)",
	"GAP-1173/var5": "tar in PowerShell has no program row on Windows (S4-R2)",
	"GAP-1173/var6": "inline-code folder literal is opaque; the classifier grades a folder for mutations only (S4-R3)",
	"GAP-1226/var4": "body read now; .pgpass is not in the credentials set (S4-R3 classifier)",
	"GAP-1502/var2": "the file a staged curl -d @FILE sends is not graded (send data source, S3-PRE classifier wiring)",
	"GAP-1561/var5": "statement lowered (git --output); .git/config is not a protected set: decision side (S1/S4-R3)",
	"GAP-1588/var4": "statement lowered (fsutil exec present): the gap is the legacy dialect placement, decision side",
	"GAP-1588/var5": "statement lowered (icacls exec present): the gap is the legacy dialect placement, decision side",
	"GAP-1667/var":  "cmd /c body lowered on the Git Bash route; tar on Windows has no program row (S4-R2)",
	"GAP-1667/var2": "cmd copy /y and tar on Windows have no program rows (S4-R2)",
}

// det111RuledInert are corpus attack rows DET111 ruled are not attacks: what
// the command does is not what the label says. Each must not reach a
// protected set and must report the reason as an opaque effect, never an
// invented reading. A new corpus version that does run replaces each.
var det111RuledInert = map[string]string{
	// RULING 2026-11-22T01:47Z: watch joins its words and runs sh -c; the
	// unquoted python body is a shell syntax error, nothing runs. var6b is the
	// quoted body that does run.
	"GAP-0662/var6": "watch's joined body is a shell syntax error",
}

// det111Facts is what the per-gap table compares: the protected-set reach of
// a row, and the programs and path targets it lowered.
type det111Facts struct {
	reach bool
	progs map[string]bool
	paths map[string]bool
	// written: paths a write or append lays bytes on whose text the IR
	// holds (here-document and Write content goes to the content scanners).
	written  map[string]bool
	surfaces map[effects.Surface]bool
}

// det111Surface names the frontend a gap's rows must be read by (GAP-1057:
// the Hermes patch envelope is the patch frontend, not a guessed MCP call).
var det111Surface = map[string]effects.Surface{"GAP-1057": effects.SurfacePatch}

func det111Collect(c det111Case) det111Facts {
	res, facts, _ := det111Run(c)
	f := det111Facts{progs: map[string]bool{}, paths: map[string]bool{},
		written: map[string]bool{}, surfaces: map[effects.Surface]bool{}}
	for _, fact := range facts {
		if len(fact.GetTarget().GetProtected()) > 0 {
			f.reach = true
		}
	}
	for _, e := range res.Effects {
		// The program an exec runs is its target (a Start-Process child
		// runs powershell under the start-process origin); the origin
		// program names it when the target has no spelling.
		run := e.Target.Spelling
		if e.Target.Path != "" {
			run = e.Target.Path
		}
		if run == "" {
			run = e.Origin.Program
		}
		// A program word that is a variable running code the call does not
		// show may be any shell: it stands for a seed's named shell.
		if e.Kind == effects.KindExec && run == "" && det111HasReason(e, effects.ReasonOpaqueCode) {
			f.progs[det111AnyShell] = true
		}
		if e.Kind == effects.KindExec && run != "" {
			p := strings.ToLower(run)
			p = p[strings.LastIndexAny(p, `/\`)+1:]
			f.progs[strings.TrimSuffix(p, ".exe")] = true
		}
		f.surfaces[e.Origin.Surface] = true
		if e.Target.Type == effects.TargetPath && e.Target.Path != "" {
			key := strings.ToLower(strings.ReplaceAll(e.Target.Path, `\`, "/"))
			f.paths[key] = true
			if (e.Kind == effects.KindWrite || e.Kind == effects.KindAppend) && e.Data != nil && e.Data.Text != "" {
				f.written[key] = true
			}
		}
	}
	return f
}

// det111AnyShell is the program of an exec whose program word is a variable
// that runs code (GAP-1554: "$SHELL" <<< BODY).
const det111AnyShell = "<possible-shell>"

var det111Shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true}

func det111HasReason(e effects.Effect, code effects.ReasonCode) bool {
	for _, r := range e.Reasons {
		if r.Code == code {
			return true
		}
	}
	return false
}

func det111Covers(v, seed det111Facts) bool {
	for p := range seed.progs {
		if !v.progs[p] && (!det111Shells[p] || !v.progs[det111AnyShell]) {
			return false
		}
	}
	for p := range seed.paths {
		if !v.paths[p] {
			return false
		}
	}
	for p := range seed.written {
		if !v.written[p] {
			return false
		}
	}
	return true
}

func det111HasCat(c det111Case, cat string) bool {
	for _, k := range c.Truth.Categories {
		if k == cat {
			return true
		}
	}
	return false
}

// det111Verdict judges one row (DET111 D1, no twins): an attack row passes when
// a target it reaches is in a protected set (known or reach-unknown), or when
// it lowers every program and path of a plain seed spelling of the same gap
// (the nested or staged body reads as the plain one). A benign twin row passes
// when nothing it lowers reaches a protected set. Cost and parity rows are
// judged by their own tests (ok=false, judged=false).
func det111Verdict(c det111Case, seeds map[string][]det111Facts) (ok, judged bool) {
	f := det111Collect(c)
	switch {
	case det111HasCat(c, "kind:attack-miss") && c.Truth.Truth == "deterministic_malicious":
		if c.role() == "seed" {
			return false, false
		}
		if want, ok := det111Surface[c.gap()]; ok && !f.surfaces[want] {
			return false, true
		}
		if f.reach {
			return true, true
		}
		for _, s := range seeds[c.gap()] {
			if det111Covers(f, s) {
				return true, true
			}
		}
		return false, true
	case det111HasCat(c, "kind:false-block") && c.Truth.Truth == "benign":
		return !f.reach, true
	}
	return false, false
}

// TestDET111R1GapTable is the DET111 step-3 (class R1) fail-before table: every
// row of testdata/det111_r1.cases.jsonl copied from the gap corpus, judged by
// det111Verdict. DET111_R1_REPORT=1 prints a PASS/FAIL line per row instead of
// failing (the base-versus-head comparison).
func TestDET111R1GapTable(t *testing.T) {
	cases := loadDET111Cases(t)
	seeds := map[string][]det111Facts{}
	for _, c := range cases {
		if c.role() == "seed" && det111HasCat(c, "kind:attack-miss") {
			seeds[c.gap()] = append(seeds[c.gap()], det111Collect(c))
		}
	}
	report := os.Getenv("DET111_R1_REPORT") == "1"
	judged := 0
	for _, c := range cases {
		ok, j := det111Verdict(c, seeds)
		if !j {
			continue
		}
		judged++
		id := strings.TrimPrefix(c.ID, "gap/det111-b_")
		if report {
			v := "FAIL"
			if ok {
				v = "PASS"
			}
			fmt.Printf("ROW %s %s\n", v, id)
			continue
		}
		if why, inert := det111RuledInert[id]; inert {
			res, _, lines := det111Run(c)
			opaque := false
			for _, e := range res.Effects {
				opaque = opaque || (e.Kind == effects.KindExec && det111HasReason(e, effects.ReasonInvalidSyntax) && det111HasReason(e, effects.ReasonOpaqueCode))
			}
			if det111Collect(c).reach || !opaque {
				t.Errorf("%s (ruled inert: %s): want no protected reach and one opaque exec for the unparsable body:\n  %s", id, why, strings.Join(lines, "\n  "))
			}
			continue
		}
		why, pending := det111Pending[id]
		switch {
		case pending && ok:
			t.Errorf("%s passes now: remove it from det111Pending (%s)", id, why)
		case !pending && !ok:
			_, _, lines := det111Run(c)
			t.Errorf("%s: effects do not lower the gap row:\n  %s", id, strings.Join(lines, "\n  "))
		}
	}
	if judged < 130 {
		t.Fatalf("only %d rows judged: the table lost rows", judged)
	}
}
