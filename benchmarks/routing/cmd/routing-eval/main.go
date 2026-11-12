// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Command routing-eval measures router classifiers (keyword rules, vLLM SR
// container, System One decision model, and the R1 hybrid) on the S12
// labelled set and the adversarial route-flip set. See ../../README.md.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/benchmarks/routing/routingeval"
	"github.com/defenseclaw/defenseclaw/internal/routing"
)

type options struct {
	data, out, classifiers                 string
	srEndpoint                             string
	srTimeoutMs                            int
	s1Endpoint, s1Model, s1KeyEnv, s1Label string
	s1Timeout                              time.Duration
	s1Budget                               time.Duration
	extraBudgets                           string
	minConfidence, target                  float64
	concurrency                            int
	emitSRConfig                           string
	limit                                  int
	narrowPrefixes                         string
}

func main() {
	var o options
	flag.StringVar(&o.data, "data", "benchmarks/routing/data", "data directory (eval.jsonl, adversarial.jsonl, routing-reference.yaml, profiles.yaml, prices.yaml)")
	flag.StringVar(&o.out, "out", "", "output directory (results.json, results.md, predictions.jsonl)")
	flag.StringVar(&o.classifiers, "classifiers", "keyword", "comma list: keyword,vllm_sr,systemone (hybrid is derived when keyword and systemone both run)")
	flag.StringVar(&o.srEndpoint, "sr-endpoint", "http://127.0.0.1:18480", "vLLM SR classifier API")
	flag.IntVar(&o.srTimeoutMs, "sr-timeout-ms", 50, "per-request SR timeout (the 1.0.9 proxy default is 50 ms)")
	flag.StringVar(&o.s1Endpoint, "systemone-endpoint", "http://127.0.0.1:18791/v1/systemone", "System One protocol endpoint")
	flag.StringVar(&o.s1Model, "systemone-model", "systemone-standin", "model name sent in each System One request")
	flag.StringVar(&o.s1Label, "systemone-label", "", "free-text label of the System One backend for the report")
	flag.StringVar(&o.s1KeyEnv, "systemone-key-env", "DEFENSECLAW_DECISION_MODEL_KEY", "env var holding the bearer token (unset = no token)")
	flag.DurationVar(&o.s1Timeout, "systemone-timeout", 15*time.Second, "measurement timeout per System One call")
	flag.DurationVar(&o.s1Budget, "systemone-budget", 300*time.Millisecond, "R1 route budget: slower answers fall back to rules in the hybrid")
	flag.StringVar(&o.extraBudgets, "hybrid-extra-budgets", "1s", "comma list of further System One budgets to score as hybrid@<budget> (sensitivity)")
	flag.Float64Var(&o.minConfidence, "min-confidence", 0.6, "routing.min_confidence for the hybrid")
	flag.Float64Var(&o.target, "quality-target", 0.95, "quality target for the cost metric (share of strong-model quality)")
	flag.IntVar(&o.concurrency, "concurrency", 8, "parallel requests for remote classifiers")
	flag.StringVar(&o.emitSRConfig, "emit-sr-config", "", "write the vLLM SR config for routing-reference.yaml (internal/routing.Translate) to this directory and exit")
	flag.StringVar(&o.narrowPrefixes, "narrow-prefixes", strings.Join(routingeval.DefaultNarrowPrefixes, ","), "guardrail rule-ID prefixes whose findings narrow a route to local aliases")
	flag.IntVar(&o.limit, "limit", 0, "use only the first N eval items (smoke runs)")
	flag.Parse()
	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "routing-eval:", err)
		os.Exit(1)
	}
}

func run(o options) error {
	rc, err := routingeval.LoadRouting(filepath.Join(o.data, "routing-reference.yaml"))
	if err != nil {
		return err
	}
	if o.emitSRConfig != "" {
		path, err := routing.TranslateAndWrite(routingeval.TranslateInput(rc), o.emitSRConfig)
		if err != nil {
			return err
		}
		fmt.Println(path)
		return nil
	}
	if o.out == "" {
		return fmt.Errorf("-out is required")
	}
	eval, err := routingeval.LoadItems(filepath.Join(o.data, "eval.jsonl"))
	if err != nil {
		return err
	}
	if o.limit > 0 && o.limit < len(eval) {
		eval = eval[:o.limit]
	}
	adv, err := routingeval.LoadItems(filepath.Join(o.data, "adversarial.jsonl"))
	if err != nil {
		return err
	}
	baseIDs := map[string]bool{}
	for _, it := range eval {
		baseIDs[it.ID] = true
	}
	advKept := adv[:0]
	for _, it := range adv {
		if baseIDs[it.BaseID] {
			advKept = append(advKept, it)
		}
	}
	adv = advKept
	profs, err := routingeval.LoadProfiles(filepath.Join(o.data, "profiles.yaml"))
	if err != nil {
		return err
	}
	prices, err := routingeval.LoadPrices(filepath.Join(o.data, "prices.yaml"))
	if err != nil {
		return err
	}
	aliases := routingeval.CategoryAliases(rc)
	need := []string{"strong", "fast", profs.RequestAlias}
	for _, a := range aliases {
		need = append(need, a)
	}
	for _, p := range profs.Profiles {
		need = append(need, p.AllowedAliases...)
	}
	if err := prices.Check(need...); err != nil {
		return err
	}

	var cls []routingeval.Classifier
	var s1 *routingeval.SystemOne
	for _, name := range strings.Split(o.classifiers, ",") {
		switch strings.TrimSpace(name) {
		case "keyword", "rules":
			k, err := routingeval.NewKeyword("keyword", rc)
			if err != nil {
				return err
			}
			cls = append(cls, k)
		case "vllm_sr":
			sr := routingeval.NewVLLMSR(o.srEndpoint, o.srTimeoutMs, rc)
			for _, it := range eval[:min(5, len(eval))] { // warm the container's connections
				_ = sr.Classify(context.Background(), it)
			}
			cls = append(cls, sr)
		case "systemone":
			s1 = routingeval.NewSystemOne(o.s1Endpoint, o.s1Model, os.Getenv(o.s1KeyEnv), o.s1Timeout, aliases)
			cls = append(cls, s1)
		case "":
		default:
			return fmt.Errorf("unknown classifier %q", name)
		}
	}

	all := append(append([]routingeval.Item(nil), eval...), adv...)
	ctx := context.Background()

	// Guardrail narrowing signal, once per item.
	g := routingeval.Guardrail{}
	for _, p := range strings.Split(o.narrowPrefixes, ",") {
		if p = strings.TrimSpace(p); p != "" {
			g.NarrowPrefixes = append(g.NarrowPrefixes, p)
		}
	}
	signal := make(map[string]bool, len(all))
	ruleHits := map[string][2]int{}
	isEval := map[string]bool{}
	for _, it := range eval {
		isEval[it.ID] = true
	}
	for _, it := range all {
		s, ids, err := g.Sensitive(ctx, it)
		if err != nil {
			return fmt.Errorf("guardrail: %w", err)
		}
		signal[it.ID] = s
		if !isEval[it.ID] {
			continue
		}
		seen := map[string]bool{}
		for _, id := range ids {
			if seen[id] {
				continue
			}
			seen[id] = true
			v := ruleHits[id]
			if it.ExpectedCategory == "sensitive" {
				v[0]++
			} else {
				v[1]++
			}
			ruleHits[id] = v
		}
	}

	preds := map[string]map[string]routingeval.Prediction{}
	for _, c := range cls {
		start := time.Now()
		preds[c.Name()] = classifyAll(ctx, c, all, o.concurrency)
		fmt.Fprintf(os.Stderr, "%s: %d items in %s\n", c.Name(), len(all), time.Since(start).Round(time.Millisecond))
	}
	if kp, ok := preds["keyword"]; ok {
		if sp, ok := preds["systemone"]; ok {
			preds["hybrid"] = hybrid(kp, sp, o.s1Budget, o.minConfidence)
			for _, b := range strings.Split(o.extraBudgets, ",") {
				if d, err := time.ParseDuration(strings.TrimSpace(b)); err == nil && d > 0 {
					preds["hybrid@"+d.String()] = hybrid(kp, sp, d, o.minConfidence)
				}
			}
		}
	}

	rep := routingeval.Report{
		Generated:      time.Now().UTC().Format(time.RFC3339),
		EvalN:          len(eval),
		AdversarialN:   len(adv),
		PricesVersion:  prices.Version,
		PricesNote:     prices.Note,
		SystemOne:      systemOneLabel(o.s1Label, s1),
		Budget:         o.s1Budget.String(),
		MinConfidence:  o.minConfidence,
		Target:         o.target,
		Classifiers:    map[string]routingeval.ClassifierReport{},
		GuardrailRules: ruleHits,
		NarrowPrefixes: g.NarrowPrefixes,
	}
	guardHits := 0
	for _, it := range eval {
		if it.ExpectedCategory == "sensitive" && signal[it.ID] {
			guardHits++
		}
	}
	rep.GuardrailSensitiveRecall = ratioOf(guardHits, countCat(eval, "sensitive"))
	guardFP := 0
	for _, it := range eval {
		if it.ExpectedCategory != "sensitive" && signal[it.ID] {
			guardFP++
		}
	}
	rep.GuardrailFalseNarrowing = ratioOf(guardFP, len(eval)-countCat(eval, "sensitive"))

	names := make([]string, 0, len(preds))
	for n := range preds {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		rep.Classifiers[n] = routingeval.Evaluate(n, eval, adv, preds[n], signal, profs, prices, o.target)
	}
	if kp, ok := preds["keyword"]; ok {
		if sp, ok := preds["vllm_sr"]; ok {
			agree := func(items []routingeval.Item) (float64, int) {
				same, both := 0, 0
				for _, it := range items {
					a, b := kp[it.ID], sp[it.ID]
					if a.Err != "" || b.Err != "" {
						continue
					}
					both++
					if a.Category == b.Category && a.Alias == b.Alias {
						same++
					}
				}
				return ratioOf(same, both), both
			}
			ag := &routingeval.Agreement{}
			ag.Eval, ag.EvalN = agree(eval)
			ag.Adversarial, ag.AdvN = agree(adv)
			rep.KeywordVsSR = ag
		}
	}

	if err := os.MkdirAll(o.out, 0o755); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(o.out, "results.json"), rep); err != nil {
		return err
	}
	if err := writePredictions(filepath.Join(o.out, "predictions.jsonl"), all, names, preds, signal, profs); err != nil {
		return err
	}
	md := routingeval.Markdown(rep, names)
	if err := os.WriteFile(filepath.Join(o.out, "results.md"), []byte(md), 0o644); err != nil {
		return err
	}
	fmt.Print(md)
	return nil
}

func classifyAll(ctx context.Context, c routingeval.Classifier, items []routingeval.Item, conc int) map[string]routingeval.Prediction {
	if conc < 1 {
		conc = 1
	}
	if _, local := c.(*routingeval.Keyword); local {
		conc = 1 // in-process: measure single-thread latency
	}
	out := make(map[string]routingeval.Prediction, len(items))
	var mu sync.Mutex
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for _, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(it routingeval.Item) {
			defer wg.Done()
			defer func() { <-sem }()
			p := c.Classify(ctx, it)
			mu.Lock()
			out[it.ID] = p
			mu.Unlock()
		}(it)
	}
	wg.Wait()
	return out
}

// hybrid is R1: rules always; the System One answer replaces the rules
// answer only when it arrived within the budget with at least min_confidence.
func hybrid(rules, s1 map[string]routingeval.Prediction, budget time.Duration, minConf float64) map[string]routingeval.Prediction {
	out := make(map[string]routingeval.Prediction, len(rules))
	for id, r := range rules {
		s := s1[id]
		wait := s.LatencyUS
		if b := budget.Microseconds(); wait > b {
			wait = b
		}
		p := r
		if s.Err == "" && s.LatencyUS <= budget.Microseconds() && s.Confidence >= minConf {
			p = s
		}
		p.LatencyUS = r.LatencyUS + wait
		out[id] = p
	}
	return out
}

func countCat(items []routingeval.Item, c string) int {
	n := 0
	for _, it := range items {
		if it.ExpectedCategory == c {
			n++
		}
	}
	return n
}

func ratioOf(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

// writePredictions writes one line per item and classifier, without prompt text.
func writePredictions(path string, items []routingeval.Item, names []string, preds map[string]map[string]routingeval.Prediction, signal map[string]bool, profs routingeval.Profiles) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	def := profs.Profiles["default"]
	for _, it := range items {
		for _, n := range names {
			p := preds[n][it.ID]
			fin := routingeval.Route(p, signal[it.ID], def, profs)
			if err := enc.Encode(map[string]any{
				"id": it.ID, "classifier": n, "expected_category": it.ExpectedCategory,
				"category": p.Category, "alias": p.Alias, "confidence": p.Confidence,
				"latency_us": p.LatencyUS, "error": p.Err, "guardrail_sensitive": signal[it.ID],
				"final_alias_default_profile": fin.Alias, "filtered_by": fin.FilteredBy,
				"base_id": it.BaseID, "gadget_family": it.GadgetFamily,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// systemOneLabel names the System One backend in the report: the operator
// label, else the backend model the endpoint reported.
func systemOneLabel(label string, s1 *routingeval.SystemOne) string {
	if s1 == nil {
		return label
	}
	if b := s1.Backend(); b != "" {
		if label == "" {
			return "backend " + b
		}
		return label + " (backend " + b + ")"
	}
	if label == "" {
		return "unlabelled endpoint"
	}
	return label
}
