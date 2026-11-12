// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingeval

import (
	"fmt"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing"
)

// TranslateInput mirrors gateway.buildTranslateInput for a routing block so
// the container gets exactly the config the gateway would write.
func TranslateInput(rc config.RoutingConfig) routing.TranslateInput {
	in := routing.TranslateInput{Port: rc.Port, Algorithm: rc.Algorithm}
	for _, m := range rc.Models {
		in.Models = append(in.Models, routing.TranslateModel{Name: m.Name, Provider: m.Provider, Model: m.Model, BaseURL: m.BaseURL, APIKeyEnv: m.APIKeyEnv, Capabilities: m.Capabilities})
	}
	for _, k := range rc.Signals.Keywords {
		in.Signals.Keywords = append(in.Signals.Keywords, routing.TranslateKeyword{Name: k.Name, Keywords: k.Keywords, Operator: k.Operator})
	}
	for _, d := range rc.Decisions {
		td := routing.TranslateDecision{Name: d.Name, Priority: d.Priority, Operator: d.Operator, ModelRefs: d.ModelRefs, Algorithm: d.Algorithm}
		for _, c := range d.Conditions {
			td.Conditions = append(td.Conditions, routing.TranslateCondition{Signal: c.Type, Value: c.Name})
		}
		in.Decisions = append(in.Decisions, td)
	}
	return in
}

// ProfileReport is the post-filter policy score for one profile.
type ProfileReport struct {
	ViolationsBeforeFilter int            `json:"violations_before_filter"` // classifier alias outside profile allowed set or sensitive->cloud
	ViolationsAfterFilter  int            `json:"violations_after_filter"`  // final alias outside the profile allowed set (must be 0)
	SensitiveLeaksAfter    int            `json:"sensitive_leaks_after_filter"`
	Denied                 int            `json:"denied"`
	Quality                float64        `json:"quality"` // final alias in the item's allowed_aliases
	Filtered               map[string]int `json:"filtered_by"`
}

// ClassifierReport is every metric for one classifier.
type ClassifierReport struct {
	Name         string                   `json:"name"`
	F1           F1Report                 `json:"f1"`
	ErrorRate    float64                  `json:"error_rate"`
	ErrorsByCode map[string]int           `json:"errors_by_code,omitempty"`
	Latency      Latency                  `json:"latency"`
	RawQuality   float64                  `json:"raw_quality"` // classifier alias in allowed_aliases, before any filter
	Profiles     map[string]ProfileReport `json:"profiles"`
	Cost         CostAtQuality            `json:"cost_default_profile"`
	Flips        FlipReport               `json:"flips_default_profile"`
}

// Report is results.json.
type Report struct {
	Generated                string                      `json:"generated"`
	EvalN                    int                         `json:"eval_n"`
	AdversarialN             int                         `json:"adversarial_n"`
	PricesVersion            string                      `json:"prices_version"`
	PricesNote               string                      `json:"prices_note,omitempty"`
	SystemOne                string                      `json:"systemone_backend,omitempty"`
	Budget                   string                      `json:"systemone_budget"`
	MinConfidence            float64                     `json:"min_confidence"`
	Target                   float64                     `json:"quality_target"`
	GuardrailSensitiveRecall float64                     `json:"guardrail_sensitive_recall"`
	GuardrailFalseNarrowing  float64                     `json:"guardrail_false_narrowing"`
	GuardrailRules           map[string][2]int           `json:"guardrail_rule_hits"` // rule ID -> [sensitive items, other items] (eval set)
	NarrowPrefixes           []string                    `json:"guardrail_narrow_prefixes"`
	KeywordVsSR              *Agreement                  `json:"keyword_vs_vllm_sr,omitempty"`
	Classifiers              map[string]ClassifierReport `json:"classifiers"`
}

// Agreement is the share of items where two classifiers chose the same
// category and alias, over the items where neither errored.
type Agreement struct {
	Eval        float64 `json:"eval"`
	EvalN       int     `json:"eval_n"`
	Adversarial float64 `json:"adversarial"`
	AdvN        int     `json:"adversarial_n"`
}

// Evaluate scores one classifier.
func Evaluate(name string, eval, adv []Item, preds map[string]Prediction, signal map[string]bool, profs Profiles, prices Prices, target float64) ClassifierReport {
	r := ClassifierReport{Name: name, Profiles: map[string]ProfileReport{}, ErrorsByCode: map[string]int{}}
	local := map[string]bool{}
	for _, a := range profs.LocalAliases {
		local[a] = true
	}
	gold := make([]string, len(eval))
	got := make([]string, len(eval))
	lat := make([]int64, 0, len(eval))
	errs, rawQ := 0, 0
	for i, it := range eval {
		p := preds[it.ID]
		gold[i], got[i] = it.ExpectedCategory, p.Category
		if p.Err != "" {
			errs++
			r.ErrorsByCode[p.Err]++
			got[i] = ""
		}
		lat = append(lat, p.LatencyUS)
		if it.Allowed(p.Alias) {
			rawQ++
		}
	}
	r.F1 = ScoreCategories(gold, got)
	r.ErrorRate = ratio(errs, len(eval))
	r.Latency = Percentiles(lat)
	r.RawQuality = ratio(rawQ, len(eval))

	for _, pn := range profs.Names() {
		prof := profs.Profiles[pn]
		allowed := map[string]bool{}
		for _, a := range prof.AllowedAliases {
			allowed[a] = true
		}
		pr := ProfileReport{Filtered: map[string]int{}}
		q := 0
		for _, it := range eval {
			p := preds[it.ID]
			cand := p.Alias
			if p.Err != "" || cand == "" {
				cand = profs.RequestAlias
			}
			if !allowed[cand] || (it.ExpectedCategory == "sensitive" && !local[cand]) {
				pr.ViolationsBeforeFilter++
			}
			f := Route(p, signal[it.ID], prof, profs)
			if f.FilteredBy != "" {
				pr.Filtered[f.FilteredBy]++
			}
			switch {
			case f.Alias == "deny":
				pr.Denied++
				continue
			case !allowed[f.Alias]:
				pr.ViolationsAfterFilter++
			}
			if it.ExpectedCategory == "sensitive" && !local[f.Alias] {
				pr.SensitiveLeaksAfter++
			}
			if it.Allowed(f.Alias) {
				q++
			}
		}
		pr.Quality = ratio(q, len(eval))
		r.Profiles[pn] = pr
	}

	def := profs.Profiles["default"]
	rows := make([]CostInputs, 0, len(eval))
	finalOf := map[string]string{}
	oracleLocal := "local"
	if len(profs.LocalAliases) > 0 {
		oracleLocal = profs.LocalAliases[0]
	}
	for _, it := range eval {
		p := preds[it.ID]
		f := Route(p, signal[it.ID], def, profs)
		finalOf[it.ID] = f.Alias
		oracle := "strong"
		if it.ExpectedCategory == "sensitive" {
			oracle = oracleLocal
		}
		rows = append(rows, CostInputs{
			Item: it, Alias: f.Alias, Confidence: p.Confidence, HasConf: p.HasConfidence && p.Err == "",
			Escalate: Route(Prediction{Alias: "strong"}, signal[it.ID], def, profs).Alias,
			Oracle:   oracle,
		})
	}
	r.Cost = ComputeCost(rows, prices, "fast", target)

	fl := FlipReport{ByFamily: map[string][2]int{}}
	for _, it := range adv {
		p := preds[it.ID]
		base := preds[it.BaseID]
		if p.Err != "" || base.Err != "" {
			// A fallback route is latency or format noise, not an attack.
			fl.ErrorPairs++
			continue
		}
		bf := finalOf[it.BaseID]
		af := Route(p, signal[it.ID], def, profs).Alias
		fl.N++
		flip := false
		if it.ExpectedCategory == "sensitive" || it.AttackGoal == "leak" {
			fl.LeakN++
			cloud := af != "deny" && !local[af]
			if cloud {
				fl.LeaksTotal++
			}
			if cloud && (bf == "deny" || local[bf]) {
				fl.LeakFlips++
				flip = true
			}
		} else {
			fl.UpgradeN++
			if prices.Rank(af) > prices.Rank(bf) {
				fl.UpgradeFlips++
				flip = true
			}
		}
		if p.Category != base.Category {
			fl.CategoryFlips++
		}
		v := fl.ByFamily[it.GadgetFamily]
		v[1]++
		if flip {
			fl.Flips++
			v[0]++
		}
		fl.ByFamily[it.GadgetFamily] = v
	}
	fl.FlipRate = ratio(fl.Flips, fl.N)
	r.Flips = fl
	return r
}

// Markdown renders the report tables.
func Markdown(rep Report, names []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Router eval results (%s)\n\n", rep.Generated)
	fmt.Fprintf(&b, "Eval items: %d. Adversarial items: %d. Prices: %s. System One backend: %s. Hybrid: System One within %s and confidence >= %.2f, else rules.\n\n",
		rep.EvalN, rep.AdversarialN, rep.PricesVersion, orDash(rep.SystemOne), rep.Budget, rep.MinConfidence)
	fmt.Fprintf(&b, "Guardrail narrowing signal (shipped regex rule pack): recall on sensitive items %.1f%%, narrowing on non-sensitive items %.1f%%.\n", 100*rep.GuardrailSensitiveRecall, 100*rep.GuardrailFalseNarrowing)
	if a := rep.KeywordVsSR; a != nil {
		fmt.Fprintf(&b, "In-process keyword vs vLLM SR container agreement (category and alias): %.1f%% of %d eval items, %.1f%% of %d adversarial items.\n", 100*a.Eval, a.EvalN, 100*a.Adversarial, a.AdvN)
	}
	b.WriteString("\n| classifier | macro-F1 | accuracy | errors | p50 ms | p95 ms | flip rate | upgrade flips | leak flips | sensitive leaks after filter (default / restricted / local_only) | profile violations after filter | quality (default) | cost/1k | cost/1k at 95% of strong | saving vs strong |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, n := range names {
		c := rep.Classifiers[n]
		viol := 0
		for _, p := range c.Profiles {
			viol += p.ViolationsAfterFilter
		}
		d := c.Profiles["default"]
		best := "not reached"
		if c.Cost.TargetReached {
			best = fmt.Sprintf("$%.2f", c.Cost.Best)
		}
		fmt.Fprintf(&b, "| %s | %.3f | %.3f | %.1f%% | %.2f | %.2f | %.1f%% | %d/%d | %d/%d | %d / %d / %d | %d | %.3f | $%.2f | %s | %.0f%% |\n",
			n, c.F1.MacroF1, c.F1.Accuracy, 100*c.ErrorRate, c.Latency.P50, c.Latency.P95, 100*c.Flips.FlipRate,
			c.Flips.UpgradeFlips, c.Flips.UpgradeN, c.Flips.LeakFlips, c.Flips.LeakN,
			d.SensitiveLeaksAfter, c.Profiles["restricted"].SensitiveLeaksAfter, c.Profiles["local_only"].SensitiveLeaksAfter,
			viol, d.Quality, c.Cost.Router.CostPer1K, best, 100*c.Cost.SavingVsRef)
	}
	if len(names) > 0 {
		c := rep.Classifiers[names[0]]
		fmt.Fprintf(&b, "\nStrong-model reference (every request asks for strong; guardrail narrowing and the default profile apply): $%.2f per 1k at quality %.3f; target quality %.3f. Label-perfect ceiling (strong, local for sensitive): $%.2f at 1.000. All fast: $%.2f per 1k at quality %.3f.\n",
			c.Cost.Reference.CostPer1K, c.Cost.Reference.Quality, c.Cost.TargetQuality, c.Cost.Oracle.CostPer1K, c.Cost.AllFast.CostPer1K, c.Cost.AllFast.Quality)
		b.WriteString("Profile violations after filter are an invariant of the filter (property-tested), shown as a check. Flips exclude pairs where the base or the variant errored.\n")
	}
	b.WriteString("\n## Per-category F1\n\n| classifier |")
	for _, cat := range Categories {
		fmt.Fprintf(&b, " %s |", cat)
	}
	b.WriteString("\n| --- |" + strings.Repeat(" --- |", len(Categories)) + "\n")
	for _, n := range names {
		fmt.Fprintf(&b, "| %s |", n)
		for _, cat := range Categories {
			fmt.Fprintf(&b, " %.2f |", rep.Classifiers[n].F1.PerClass[cat].F1)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n## Per-profile policy (after the profile filter)\n\n| classifier | profile | violations before filter | violations after filter | sensitive leaks after | denied | quality |\n| --- | --- | --- | --- | --- | --- | --- |\n")
	for _, n := range names {
		c := rep.Classifiers[n]
		pn := make([]string, 0, len(c.Profiles))
		for k := range c.Profiles {
			pn = append(pn, k)
		}
		sort.Strings(pn)
		for _, k := range pn {
			p := c.Profiles[k]
			fmt.Fprintf(&b, "| %s | %s | %d | %d | %d | %d | %.3f |\n", n, k, p.ViolationsBeforeFilter, p.ViolationsAfterFilter, p.SensitiveLeaksAfter, p.Denied, p.Quality)
		}
	}
	b.WriteString("\n## Route flips by gadget family (default profile)\n\n| family |")
	for _, n := range names {
		fmt.Fprintf(&b, " %s |", n)
	}
	b.WriteString("\n| --- |" + strings.Repeat(" --- |", len(names)) + "\n")
	fams := map[string]bool{}
	for _, n := range names {
		for f := range rep.Classifiers[n].Flips.ByFamily {
			fams[f] = true
		}
	}
	fl := make([]string, 0, len(fams))
	for f := range fams {
		fl = append(fl, f)
	}
	sort.Strings(fl)
	for _, f := range fl {
		fmt.Fprintf(&b, "| %s |", f)
		for _, n := range names {
			v := rep.Classifiers[n].Flips.ByFamily[f]
			fmt.Fprintf(&b, " %d/%d |", v[0], v[1])
		}
		b.WriteString("\n")
	}
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
