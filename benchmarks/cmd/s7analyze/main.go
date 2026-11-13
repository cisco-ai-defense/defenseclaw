// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7analyze re-derives the effect-lane unknown-tier decision for each benign
// call and buckets the new benign alerts by the deciding protected match's
// basis, the effect reason codes and the command family. Pure: it calls only
// internal/effects and internal/effectrules, no gateway boot. It emits no raw
// command text; examples carry the program, kind, target basename (the
// directory is redacted) and the reason codes.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/effectrules"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

type ev struct {
	ToolName string          `json:"tool_name"`
	Args     json.RawMessage `json:"args"`
	Command  string          `json:"command"`
	CWD      string          `json:"cwd"`
	Dialect  string          `json:"dialect"`
}
type payload struct {
	ev
	Events []ev `json:"events"`
}
type kase struct {
	ID      string  `json:"id"`
	Payload payload `json:"payload"`
	Truth   struct {
		Disp string `json:"expected_disposition"`
		Src  string `json:"source_truth"`
	} `json:"truth"`
}

var mutating = map[string]bool{"write": true, "append": true, "delete": true, "link": true, "permission_change": true}

func str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func call(e ev) (effects.Call, effects.Options, bool) {
	home := "/home/bench"
	cwd := e.CWD
	if cwd == "" {
		cwd = home + "/work"
	} else if strings.HasPrefix(cwd, "/home/") {
		parts := strings.SplitN(strings.TrimPrefix(cwd, "/home/"), "/", 2)
		home = "/home/" + parts[0]
	}
	flavor, dialect := effects.FlavorPOSIX, effects.DialectNone
	switch e.Dialect {
	case "powershell":
		flavor, dialect = effects.FlavorWindows, effects.DialectPowerShell
	case "cmd":
		flavor, dialect = effects.FlavorWindows, effects.DialectCMD
	case "posix":
		dialect = effects.DialectPOSIX
	}
	opts := effects.Options{Flavor: flavor, Dialect: dialect, Home: home, CWD: cwd}
	cmd := e.Command
	var args map[string]any
	_ = json.Unmarshal(e.Args, &args)
	if cmd == "" && args != nil {
		cmd = str(args, "command", "cmd", "script", "code", "input")
	}
	if cmd != "" {
		return effects.Call{Surface: effects.SurfaceShell, Tool: e.ToolName, Command: cmd}, opts, true
	}
	if len(e.Args) > 0 {
		return effects.Normalize("claudecode", e.ToolName, e.Args), opts, true
	}
	return effects.Call{}, opts, false
}

func lexical(p string) (string, bool) { return p, true }

// decide mirrors classifyEffects: returns whether the call would alert in the
// unknown tier (touches a protected set, not restricted-eligible), plus the
// deciding match basis, reason codes, program and target basename.
func decide(res effects.Result, facts []*semanticpb.EffectFact) (touch, restricted bool, basis, reasons, prog, base string) {
	fully := len(res.Unknowns) == 0
	prio := map[string]int{"exact": 0, "tree": 1, "protected_dir": 2, "wrong_dir": 3, "dir": 4, "glob": 5, "unresolved": 6, "dynamic": 7}
	bestP := 99
	for _, f := range facts {
		t := f.GetTarget()
		if t.GetType() != "path" || len(t.GetProtected()) == 0 {
			continue
		}
		kind := f.GetKind()
		mut := mutating[kind]
		unknownEff := f.GetTargetState() != "known" || f.GetRoleState() != "known" || kind == "opaque"
		cred := false
		for _, m := range t.GetProtected() {
			if m.GetSet() == effectrules.SetCredentials {
				cred = true
			}
		}
		relevant := mut || unknownEff || (kind == "read" && cred)
		if !relevant {
			continue
		}
		touch = true
		if prog == "" {
			prog = f.GetOrigin().GetProgram()
			if prog == "" {
				prog = "(" + f.GetOrigin().GetSurface() + ")"
			}
			base = redactBase(t.GetPath(), t.GetGlob())
			rs := make([]string, 0, len(f.GetReasons()))
			for _, r := range f.GetReasons() {
				rs = append(rs, r)
			}
			reasons = strings.Join(rs, ",")
		}
		for _, m := range t.GetProtected() {
			if p, ok := prio[m.GetReason()]; ok && p < bestP {
				bestP = p
				basis = m.GetReason()
			}
		}
		// restricted eligibility
		if mut && fully && f.GetTargetState() == "known" && f.GetRoleState() == "known" && len(f.GetReasons()) == 0 &&
			effectrules.RestrictedBlockCommand(f.GetOrigin().GetProgram(), effects.Surface(f.GetOrigin().GetSurface())) &&
			effectrules.CanonicalAbsolute(t.GetPath(), effects.Flavor(t.GetFlavor())) {
			for _, m := range t.GetProtected() {
				if m.GetState() == "known" && m.GetReason() == "exact" && m.GetSet() != effectrules.SetOutsideHome {
					restricted = true
				}
			}
		}
	}
	return
}

func redactBase(p, glob string) string {
	if p == "" {
		if glob != "" {
			return "<glob>"
		}
		return "<dynamic>"
	}
	return "<dir>/" + path.Base(strings.ReplaceAll(p, "\\", "/"))
}

func main() {
	corpus := flag.String("corpus", "", "")
	decisions := flag.String("decisions", "", "decision jsonl to read today's action")
	flag.Parse()
	today := map[string]bool{}
	if *decisions != "" {
		df, _ := os.Open(*decisions)
		sc := bufio.NewScanner(df)
		sc.Buffer(make([]byte, 1<<20), 64<<20)
		for sc.Scan() {
			var r struct {
				Case      string `json:"case"`
				Action    string `json:"action"`
				RawAction string `json:"raw_action"`
			}
			if json.Unmarshal(sc.Bytes(), &r) == nil {
				if r.Action == "block" || r.Action == "alert" || r.Action == "confirm" || r.RawAction == "block" || r.RawAction == "alert" {
					today[r.Case] = true
				}
			}
		}
		df.Close()
	}
	f, _ := os.Open(*corpus)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<20), 64<<20)
	type bucket struct {
		n      int
		byProg map[string]int
		ex     []string
	}
	buckets := map[string]*bucket{}
	get := func(k string) *bucket {
		if buckets[k] == nil {
			buckets[k] = &bucket{byProg: map[string]int{}}
		}
		return buckets[k]
	}
	var benign, benignAlert int
	for sc.Scan() {
		var c kase
		if json.Unmarshal(sc.Bytes(), &c) != nil {
			continue
		}
		if c.Truth.Src == "malicious" || c.Truth.Src == "sensitive" || c.Truth.Disp == "block" {
			continue // only benign
		}
		benign++
		evs := c.Payload.Events
		if len(evs) == 0 {
			evs = []ev{c.Payload.ev}
		}
		var alerted bool
		var basis, reasons, prog, base string
		for _, e := range evs {
			cl, opts, ok := call(e)
			if !ok {
				continue
			}
			res := effects.Extract(cl, opts)
			facts := effectrules.Project(res, effectrules.Env{Home: opts.Home, Flavor: opts.Flavor, Resolve: lexical})
			touch, restricted, b, rr, pg, ba := decide(res, facts)
			if touch && !restricted {
				alerted = true
				if basis == "" {
					basis, reasons, prog, base = b, rr, pg, ba
				}
			}
		}
		if !alerted || today[c.ID] {
			continue // only NEW benign alerts
		}
		benignAlert++
		key := basis
		if key == "" {
			key = "(none)"
		}
		b := get(key)
		b.n++
		b.byProg[prog]++
		if len(b.ex) < 10 {
			b.ex = append(b.ex, fmt.Sprintf("prog=%s kind-target=%s reasons=[%s]", prog, base, reasons))
		}
	}
	fmt.Printf("benign=%d new_benign_alerts=%d\n", benign, benignAlert)
	keys := make([]string, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return buckets[keys[i]].n > buckets[keys[j]].n })
	for _, k := range keys {
		b := buckets[k]
		var progs []string
		for p, n := range b.byProg {
			progs = append(progs, fmt.Sprintf("%s:%d", p, n))
		}
		sort.Slice(progs, func(i, j int) bool { return progs[i] < progs[j] })
		fmt.Printf("\n== basis=%s  n=%d\n  programs: %s\n", k, b.n, strings.Join(progs, " "))
		for _, e := range b.ex {
			fmt.Println("  ex:", e)
		}
	}
}
