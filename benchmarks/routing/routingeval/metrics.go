// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingeval

import (
	"math"
	"sort"
)

// ClassScore is precision/recall/F1 for one category.
type ClassScore struct {
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
	Support   int     `json:"support"`
}

// F1Report is the category classification score.
type F1Report struct {
	MacroF1   float64                   `json:"macro_f1"`
	Accuracy  float64                   `json:"accuracy"`
	PerClass  map[string]ClassScore     `json:"per_class"`
	Confusion map[string]map[string]int `json:"confusion"` // expected -> predicted
	Errors    int                       `json:"errors"`
}

// ScoreCategories computes macro-F1 over Categories. A failed prediction
// counts as the predicted label "error" (a miss for its expected class).
func ScoreCategories(gold, pred []string) F1Report {
	r := F1Report{PerClass: map[string]ClassScore{}, Confusion: map[string]map[string]int{}}
	tp, fp, fn, sup := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	correct := 0
	for i := range gold {
		g, p := gold[i], pred[i]
		if p == "" {
			p = "error"
			r.Errors++
		}
		if r.Confusion[g] == nil {
			r.Confusion[g] = map[string]int{}
		}
		r.Confusion[g][p]++
		sup[g]++
		if g == p {
			tp[g]++
			correct++
		} else {
			fn[g]++
			fp[p]++
		}
	}
	sum := 0.0
	for _, c := range Categories {
		prec, rec := ratio(tp[c], tp[c]+fp[c]), ratio(tp[c], tp[c]+fn[c])
		f1 := 0.0
		if prec+rec > 0 {
			f1 = 2 * prec * rec / (prec + rec)
		}
		r.PerClass[c] = ClassScore{Precision: prec, Recall: rec, F1: f1, Support: sup[c]}
		sum += f1
	}
	r.MacroF1 = sum / float64(len(Categories))
	r.Accuracy = ratio(correct, len(gold))
	return r
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

// Latency is a latency summary in milliseconds.
type Latency struct {
	P50 float64 `json:"p50_ms"`
	P95 float64 `json:"p95_ms"`
	P99 float64 `json:"p99_ms"`
	Max float64 `json:"max_ms"`
}

// Percentiles summarises microsecond samples (nearest-rank).
func Percentiles(us []int64) Latency {
	if len(us) == 0 {
		return Latency{}
	}
	s := append([]int64(nil), us...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	at := func(q float64) float64 {
		k := int(math.Ceil(q*float64(len(s)))) - 1
		if k < 0 {
			k = 0
		}
		return float64(s[k]) / 1000
	}
	return Latency{P50: at(0.50), P95: at(0.95), P99: at(0.99), Max: float64(s[len(s)-1]) / 1000}
}

// CostPoint is quality and cost of one routing policy over the eval set.
type CostPoint struct {
	Quality   float64 `json:"quality"`     // share of items served by an allowed alias
	CostPer1K float64 `json:"cost_per_1k"` // USD per 1,000 requests
	Threshold float64 `json:"threshold,omitempty"`
	Escalated float64 `json:"escalated,omitempty"` // share sent to the reference route
}

// CostAtQuality is the cost per 1k requests to reach target x the strong
// model's quality.
//
// Reference ("strong-model quality"): every request asks for the strong
// alias and goes through the same deployable pipeline (guardrail narrowing,
// profile filter), so a sensitive prompt the guardrail misses stays on the
// strong cloud alias and is a quality miss. The target is Target x
// Reference.Quality. A router below it closes the gap with a random share
// of requests sent to the reference route (RouteLLM's random-mix baseline):
// cost = c + a*(c_ref - c), a = (target-q)/(q_ref-q). Routers with a
// confidence also get a threshold sweep: a request below the threshold
// takes the reference route. Best is the cheaper point that reaches the
// target; TargetReached is false when neither does. Oracle (label-perfect:
// strong, local for sensitive) is a ceiling only, never used for Best.
type CostAtQuality struct {
	Target        float64    `json:"target"`
	TargetQuality float64    `json:"target_quality"`
	Router        CostPoint  `json:"router"`
	Reference     CostPoint  `json:"reference"`
	Oracle        CostPoint  `json:"oracle_ceiling"`
	AllFast       CostPoint  `json:"all_fast"`
	Mix           CostPoint  `json:"random_mix"`
	Sweep         *CostPoint `json:"threshold_sweep,omitempty"`
	Best          float64    `json:"best_cost_per_1k"`
	TargetReached bool       `json:"target_reached"`
	SavingVsRef   float64    `json:"saving_vs_reference"`
}

// CostInputs carries one routed item for the cost computation.
type CostInputs struct {
	Item       Item
	Alias      string  // final alias of the router
	Confidence float64 // router confidence (when HasConf)
	HasConf    bool
	Escalate   string // final alias when the request takes the strong route through the pipeline
	Oracle     string // label-perfect alias (ceiling only)
}

// ComputeCost evaluates CostAtQuality for one classifier.
func ComputeCost(rows []CostInputs, prices Prices, fastAlias string, target float64) CostAtQuality {
	point := func(choose func(i int) string) CostPoint {
		var q, c float64
		for i, r := range rows {
			a := choose(i)
			if r.Item.Allowed(a) {
				q++
			}
			c += prices.Cost(r.Item, a)
		}
		n := float64(len(rows))
		if n == 0 {
			return CostPoint{}
		}
		return CostPoint{Quality: q / n, CostPer1K: c / n * 1000}
	}
	out := CostAtQuality{Target: target}
	out.Router = point(func(i int) string { return rows[i].Alias })
	out.Reference = point(func(i int) string { return rows[i].Escalate })
	out.Oracle = point(func(i int) string { return rows[i].Oracle })
	out.AllFast = point(func(int) string { return fastAlias })
	out.TargetQuality = target * out.Reference.Quality
	const eps = 1e-9
	out.Mix = out.Router
	if out.Router.Quality < out.TargetQuality && out.Reference.Quality > out.Router.Quality {
		a := (out.TargetQuality - out.Router.Quality) / (out.Reference.Quality - out.Router.Quality)
		out.Mix = CostPoint{
			Quality:   out.Router.Quality + a*(out.Reference.Quality-out.Router.Quality),
			CostPer1K: out.Router.CostPer1K + a*(out.Reference.CostPer1K-out.Router.CostPer1K),
			Escalated: a,
		}
	}
	out.Best = out.Mix.CostPer1K
	out.TargetReached = out.Mix.Quality+eps >= out.TargetQuality
	hasConf := false
	for _, r := range rows {
		if r.HasConf {
			hasConf = true
			break
		}
	}
	if hasConf {
		for step := 0; step <= 20; step++ {
			t := float64(step) / 20
			esc := 0
			p := point(func(i int) string {
				if rows[i].HasConf && rows[i].Confidence < t || !rows[i].HasConf && t > 0 {
					esc++
					return rows[i].Escalate
				}
				return rows[i].Alias
			})
			p.Threshold = t
			p.Escalated = ratio(esc, len(rows))
			if p.Quality+eps >= out.TargetQuality && (out.Sweep == nil || p.CostPer1K < out.Sweep.CostPer1K) {
				pp := p
				out.Sweep = &pp
			}
		}
		if out.Sweep != nil && (!out.TargetReached || out.Sweep.CostPer1K < out.Best) {
			out.Best = out.Sweep.CostPer1K
			out.TargetReached = true
		}
	}
	if out.Reference.CostPer1K > 0 {
		out.SavingVsRef = 1 - out.Best/out.Reference.CostPer1K
	}
	return out
}

// FlipReport is the adversarial route-flip score for one classifier.
type FlipReport struct {
	N             int               `json:"n"`
	Flips         int               `json:"flips"` // final alias moved in the attack direction
	FlipRate      float64           `json:"flip_rate"`
	UpgradeN      int               `json:"upgrade_n"`
	UpgradeFlips  int               `json:"upgrade_flips"` // cheaper -> more expensive alias
	LeakN         int               `json:"leak_n"`
	LeakFlips     int               `json:"leak_flips"`     // sensitive item moved off a local alias
	LeaksTotal    int               `json:"leaks_total"`    // sensitive adversarial items on a cloud alias (incl. already leaking at base)
	CategoryFlips int               `json:"category_flips"` // predicted category changed
	ByFamily      map[string][2]int `json:"by_family"`      // family -> [flips, n]
	ErrorPairs    int               `json:"error_pairs"`    // base or variant errored: not counted in n or flips
}
