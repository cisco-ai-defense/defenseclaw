// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Command s7flowreplay measures Secret flow tracking (internal/flow) over a
// case-v1 corpus WITHOUT the gateway. It groups the calls into sessions by
// strata.trajectory_id (ordered by sequence_index then call_index), replays
// the effects of each call into one flow.State per session, and reports the
// rate of sink hits it would fire.
//
// Because the corpora carry no tool results, the value-hash lane cannot be
// exercised; this measures the FILE-LABEL and session-context lanes only (the
// owner's interim measure until the s7-corpus lane publishes whole sessions
// with tool results). Paths in the examples are already redacted by the corpus
// normalizer.
//
// Usage:
//
//	s7flowreplay -corpus <file.jsonl> [-mode default|strict] [-examples 8] [-json]
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/flow"
)

type caseRow struct {
	Payload struct {
		ToolName string          `json:"tool_name"`
		Command  string          `json:"command"`
		Args     json.RawMessage `json:"args"`
		Dialect  string          `json:"dialect"`
		CWD      string          `json:"cwd"`
		Events   []struct {
			ToolName string          `json:"tool_name"`
			Command  string          `json:"command"`
			Args     json.RawMessage `json:"args"`
			Dialect  string          `json:"dialect"`
		} `json:"events"`
	} `json:"payload"`
	Surface string `json:"surface"`
	Strata  struct {
		TrajectoryID  string `json:"trajectory_id"`
		SequenceIndex *int   `json:"sequence_index"`
		CallIndex     *int   `json:"call_index"`
		Provider      string `json:"provider"`
		Platform      string `json:"platform"`
	} `json:"strata"`
}

type call struct {
	tool, command, dialect, cwd, provider, platform string
	args                                            json.RawMessage
}

func flavorFor(dialect, platform string) effects.Flavor {
	if dialect == "powershell" || dialect == "cmd" || platform == "windows" {
		return effects.FlavorWindows
	}
	return effects.FlavorPOSIX
}

func dialectFor(dialect string) effects.Dialect {
	switch dialect {
	case "powershell":
		return effects.DialectPowerShell
	case "cmd":
		return effects.DialectCMD
	case "posix":
		return effects.DialectPOSIX
	}
	return effects.DialectNone
}

func homeFor(platform string) string {
	switch platform {
	case "macos":
		return "/Users/alice"
	case "windows":
		return `C:\Users\alice`
	}
	return "/home/alice"
}

func buildCall(c call) (effects.Call, effects.Options, bool) {
	opts := effects.Options{
		Flavor: flavorFor(c.dialect, c.platform), Dialect: dialectFor(c.dialect),
		Home: homeFor(c.platform), CWD: c.cwd,
	}
	switch {
	case strings.TrimSpace(c.command) != "":
		return effects.Call{Surface: effects.SurfaceShell, Tool: c.tool, Command: c.command}, opts, true
	case len(c.args) > 0:
		return effects.Normalize(c.provider, c.tool, c.args), opts, true
	}
	return effects.Call{}, opts, false
}

func main() {
	corpus := flag.String("corpus", "", "case-v1 jsonl corpus")
	modeName := flag.String("mode", "default", "default|strict (the pack; a managed install follows its pack)")
	examples := flag.Int("examples", 8, "redacted examples to print per hit kind")
	asJSON := flag.Bool("json", false, "print the report as JSON")
	explainCtx := flag.Int("explain-ctx", 0, "print up to N session_context hits with the sink effect's data shape (no paths or values)")
	synth := flag.Bool("synth-results", false, "after a call that reads a labeled credential file, feed the session a synthetic secret value as that call's result (the best case: the connector delivers every result and every value is indexable)")
	flag.Parse()
	if *corpus == "" {
		fmt.Fprintln(os.Stderr, "need -corpus")
		os.Exit(2)
	}

	sf := config.DefaultConfig().Guardrail.SecretFlow
	cfg := flow.Config{
		Credentials:          sf.CredentialsEnabled(),
		ExtraPathGlobs:       sf.LabelSets.ExtraPathGlobs,
		ExtraSecretPatterns:  sf.LabelSets.ExtraSecretPatterns,
		Reencodings:          sf.Reencodings,
		MaxLabeledPaths:      sf.Memory.MaxLabeledPaths,
		MaxValueDigests:      sf.Memory.MaxValueDigests,
		DestinationAllowlist: sf.DestinationAllowlist,
		SinkDefault:          flow.Action(sf.SinkActionFor(false)),
		SinkStrict:           flow.Action(sf.SinkActionFor(true)),
	}
	switch *modeName {
	case "strict":
		cfg.Strict = true
	}

	f, err := os.Open(*corpus)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()

	// sessions keyed by trajectory id; a case with no trajectory id is its own
	// session. Stateful cases carry their own ordered event window.
	type sessionCalls struct {
		calls []call
		order []int // sequence/call index per call, for stable ordering
	}
	sessions := map[string]*sessionCalls{}
	var soloSessions [][]call
	anon := 0

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var r caseRow
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		plat, prov := r.Strata.Platform, r.Strata.Provider
		if r.Surface == "stateful" && len(r.Payload.Events) > 0 {
			var cs []call
			for _, e := range r.Payload.Events {
				cs = append(cs, call{tool: e.ToolName, command: e.Command, args: e.Args, dialect: e.Dialect, cwd: r.Payload.CWD, provider: prov, platform: plat})
			}
			soloSessions = append(soloSessions, cs)
			continue
		}
		cl := call{tool: r.Payload.ToolName, command: r.Payload.Command, args: r.Payload.Args, dialect: r.Payload.Dialect, cwd: r.Payload.CWD, provider: prov, platform: plat}
		tid := r.Strata.TrajectoryID
		if tid == "" {
			soloSessions = append(soloSessions, []call{cl})
			anon++
			continue
		}
		s := sessions[tid]
		if s == nil {
			s = &sessionCalls{}
			sessions[tid] = s
		}
		idx := 0
		if r.Strata.SequenceIndex != nil {
			idx = *r.Strata.SequenceIndex
		} else if r.Strata.CallIndex != nil {
			idx = *r.Strata.CallIndex
		}
		s.calls = append(s.calls, cl)
		s.order = append(s.order, idx)
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "scan:", err)
	}

	type example struct {
		Kind, Program, Host, Sets, Source string
	}
	var (
		totalSessions, totalCalls, hitSessions, totalHits int
		byKind                                            = map[string]int{}
		bySet                                             = map[string]int{}
		exByKind                                          = map[string][]example{}
	)

	replay := func(calls []call) {
		totalSessions++
		st := flow.NewState(cfg.MaxLabeledPaths, cfg.MaxValueDigests)
		sessionHit := false
		synthN := 0
		for _, c := range calls {
			ec, opts, ok := buildCall(c)
			if !ok {
				continue
			}
			totalCalls++
			res := effects.Extract(ec, opts)
			out := st.Step(res, c.command, cfg)
			if *synth {
				for i := range res.Effects {
					e := &res.Effects[i]
					if e.Kind != effects.KindRead {
						continue
					}
					if _, _, ok := cfg.LabelForTarget(e.Target); ok {
						synthN++
						st.AddResultValues([]byte(fmt.Sprintf("API_KEY=synthetic_%d_0123456789abcdefghijklmnop\n", synthN)), "synthetic", cfg)
						break
					}
				}
			}
			if out.Action == flow.ActionAllow || len(out.Hits) == 0 {
				continue
			}
			sessionHit = true
			for _, h := range out.Hits {
				if *explainCtx > 0 && h.Kind == flow.HitSessionContext && h.EffectIndex >= 1 && h.EffectIndex <= len(res.Effects) {
					*explainCtx--
					se := res.Effects[h.EffectIndex-1]
					dk, srcs := "", ""
					if se.Data != nil {
						dk = string(se.Data.Kind)
						for _, s := range se.Data.Sources {
							srcs += string(s.Kind) + ","
						}
					}
					rs := ""
					for _, r := range se.Reasons {
						rs += string(r.Code) + ","
					}
					fmt.Fprintf(os.Stderr, "CTX prog=%s kind=%s target=%s data=%q sources=%q digests=%d state=%s/%s reasons=%s\n", h.Program, se.Kind, se.Target.Type, dk, srcs, st.ValueDigests(), se.TargetState, se.RoleState, rs)
				}
				totalHits++
				byKind[string(h.Kind)]++
				for _, s := range h.Sets {
					bySet[s]++
				}
				if len(exByKind[string(h.Kind)]) < *examples {
					exByKind[string(h.Kind)] = append(exByKind[string(h.Kind)], example{
						Kind: string(h.Kind), Program: h.Program, Host: h.Host,
						Sets: strings.Join(h.Sets, ","), Source: h.Source,
					})
				}
			}
		}
		if sessionHit {
			hitSessions++
		}
	}

	// Replay trajectory sessions (ordered) and solo sessions.
	tids := make([]string, 0, len(sessions))
	for tid := range sessions {
		tids = append(tids, tid)
	}
	sort.Strings(tids)
	for _, tid := range tids {
		s := sessions[tid]
		order := append([]int(nil), s.order...)
		idxs := make([]int, len(s.calls))
		for i := range idxs {
			idxs[i] = i
		}
		sort.SliceStable(idxs, func(a, b int) bool { return order[idxs[a]] < order[idxs[b]] })
		ordered := make([]call, len(s.calls))
		for i, j := range idxs {
			ordered[i] = s.calls[j]
		}
		replay(ordered)
	}
	for _, cs := range soloSessions {
		replay(cs)
	}

	per1000 := 0.0
	if totalCalls > 0 {
		per1000 = float64(totalHits) * 1000 / float64(totalCalls)
	}
	perSession := 0.0
	if totalSessions > 0 {
		perSession = float64(hitSessions) * 100 / float64(totalSessions)
	}

	report := map[string]any{
		"corpus": *corpus, "mode": *modeName,
		"sessions": totalSessions, "calls": totalCalls,
		"hit_sessions": hitSessions, "hits": totalHits,
		"hits_per_1000_calls": per1000, "pct_sessions_with_hit": perSession,
		"by_kind": byKind, "by_set": bySet, "examples": exByKind,
	}
	if *asJSON {
		b, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(b))
		return
	}
	fmt.Printf("corpus=%s mode=%s\n", *corpus, *modeName)
	fmt.Printf("sessions=%d calls=%d hit_sessions=%d hits=%d\n", totalSessions, totalCalls, hitSessions, totalHits)
	fmt.Printf("hits per 1000 calls = %.3f ; sessions with a hit = %.3f%%\n", per1000, perSession)
	fmt.Printf("by kind: %v\n", byKind)
	fmt.Printf("by set:  %v\n", bySet)
	for kind, exs := range exByKind {
		fmt.Printf("examples [%s]:\n", kind)
		for _, e := range exs {
			fmt.Printf("  %s -> %s  sets=%s src=%s\n", e.Program, e.Host, e.Sets, e.Source)
		}
	}
}
