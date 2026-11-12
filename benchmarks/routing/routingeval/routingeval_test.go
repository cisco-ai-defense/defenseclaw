// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingeval

import (
	"context"
	"math"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestScoreCategoriesMacroF1(t *testing.T) {
	gold := []string{"coding", "coding", "chat", "chat"}
	pred := []string{"coding", "chat", "chat", ""}
	r := ScoreCategories(gold, pred)
	if r.Errors != 1 || r.Accuracy != 0.5 {
		t.Fatalf("errors=%d accuracy=%v", r.Errors, r.Accuracy)
	}
	// coding P=1 R=.5 F1=2/3; chat P=.5 R=.5 F1=.5; five absent classes 0.
	want := (2.0/3 + 0.5) / float64(len(Categories))
	if math.Abs(r.MacroF1-want) > 1e-9 {
		t.Fatalf("macro-F1 %v want %v", r.MacroF1, want)
	}
}

func TestRouteNarrowsNeverWidens(t *testing.T) {
	profs := Profiles{LocalAliases: []string{"local"}, RequestAlias: "strong", Profiles: map[string]Profile{
		"default":    {AllowedAliases: []string{"local", "fast", "mid", "strong"}, DefaultAlias: "fast"},
		"restricted": {AllowedAliases: []string{"local", "fast", "mid"}, DefaultAlias: "mid"},
		"cloud_only": {AllowedAliases: []string{"fast"}, DefaultAlias: "fast"},
	}}
	cases := []struct {
		pred      Prediction
		sensitive bool
		profile   string
		want      string
	}{
		{Prediction{Alias: "strong"}, false, "default", "strong"},
		{Prediction{Alias: "strong"}, false, "restricted", "mid"},
		{Prediction{Alias: "strong"}, true, "default", "local"},
		{Prediction{Err: "timeout"}, false, "default", "strong"},
		{Prediction{Err: "timeout"}, false, "restricted", "mid"},
		{Prediction{Alias: "fast"}, true, "cloud_only", "deny"},
		{Prediction{Alias: "local"}, false, "cloud_only", "fast"},
	}
	for i, c := range cases {
		got := Route(c.pred, c.sensitive, profs.Profiles[c.profile], profs).Alias
		if got != c.want {
			t.Errorf("case %d: got %q want %q", i, got, c.want)
		}
	}
}

func TestKeywordMatchesSRSemantics(t *testing.T) {
	rc := config.RoutingConfig{
		Signals: config.RoutingSignalConfig{Keywords: []config.RoutingKeywordSignal{
			{Name: "code", Keywords: []string{"debug"}, Operator: "OR"},
		}},
		Decisions: []config.RoutingDecisionRule{
			{Name: "coding", Priority: 10, Conditions: []config.RoutingCondition{{Type: "keyword", Name: "code"}}, ModelRefs: []string{"mid"}},
			{Name: "chat", Priority: 1, ModelRefs: []string{"fast"}},
		},
	}
	k, err := NewKeyword("keyword", rc)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]Message{
		"coding": {{Role: "user", Content: "please DEBUG this"}},
		"chat":   {{Role: "user", Content: "debugging is fun"}}, // word boundary
	}
	cases2 := []Message{{Role: "system", Content: "debug"}, {Role: "user", Content: "hello"}} // only last user turn
	for want, msgs := range cases {
		if got := k.Classify(context.Background(), Item{Messages: msgs}).Category; got != want {
			t.Errorf("%v: got %q want %q", msgs, got, want)
		}
	}
	if got := k.Classify(context.Background(), Item{Messages: cases2}).Category; got != "chat" {
		t.Errorf("system turn classified: %q", got)
	}
}

func TestCostRandomMix(t *testing.T) {
	prices := Prices{Aliases: map[string]Price{"fast": {OutputPerMTok: 1}, "strong": {OutputPerMTok: 10}, "local": {}}, OutputTokens: map[string]int{"chat": 1_000_000}}
	mk := func(alias string) CostInputs {
		return CostInputs{Item: Item{ExpectedCategory: "chat", AllowedAliases: []string{"strong"}}, Alias: alias, Escalate: "strong", Oracle: "strong"}
	}
	// Half right: quality .5; the reference (all strong) has quality 1.
	c := ComputeCost([]CostInputs{mk("fast"), mk("strong")}, prices, "fast", 0.95)
	if !c.TargetReached || math.Abs(c.Mix.Quality-0.95) > 1e-9 || math.Abs(c.Mix.Escalated-0.9) > 1e-9 {
		t.Fatalf("mix %+v", c)
	}
	// A sensitive miss the reference cannot fix lowers the target with it.
	sens := CostInputs{Item: Item{ExpectedCategory: "sensitive", AllowedAliases: []string{"local"}}, Alias: "fast", Escalate: "strong", Oracle: "local"}
	c = ComputeCost([]CostInputs{mk("strong"), sens}, prices, "fast", 0.95)
	if c.Reference.Quality != 0.5 || math.Abs(c.TargetQuality-0.475) > 1e-9 || c.Oracle.Quality != 1 {
		t.Fatalf("reference %+v target %v oracle %+v", c.Reference, c.TargetQuality, c.Oracle)
	}
}

// The filter's contract: whatever the classifier says, the final alias is
// in the profile's allowed set (or deny), and a narrowing signal never ends
// on a non-local alias.
func TestRouteInvariantProperty(t *testing.T) {
	aliases := []string{"", "local", "fast", "mid", "strong", "bogus"}
	profs := Profiles{LocalAliases: []string{"local"}, RequestAlias: "strong", Profiles: map[string]Profile{
		"default":    {AllowedAliases: []string{"local", "fast", "mid", "strong"}, DefaultAlias: "fast"},
		"restricted": {AllowedAliases: []string{"local", "fast", "mid"}, DefaultAlias: "mid"},
		"local_only": {AllowedAliases: []string{"local"}, DefaultAlias: "local"},
		"cloud_only": {AllowedAliases: []string{"fast", "mid"}, DefaultAlias: "strong"},
	}}
	for name, prof := range profs.Profiles {
		allowed := map[string]bool{}
		for _, a := range prof.AllowedAliases {
			allowed[a] = true
		}
		for _, a := range aliases {
			for _, errStr := range []string{"", "timeout"} {
				for _, sig := range []bool{false, true} {
					f := Route(Prediction{Alias: a, Err: errStr}, sig, prof, profs)
					if f.Alias != "deny" && !allowed[f.Alias] {
						t.Fatalf("%s alias=%q err=%q sig=%v: final %q outside allowed set", name, a, errStr, sig, f.Alias)
					}
					if sig && f.Alias != "deny" && f.Alias != "local" {
						t.Fatalf("%s alias=%q sig: final %q not local", name, a, f.Alias)
					}
				}
			}
		}
	}
}

func TestValidProbsMatchesDecisionModelChecks(t *testing.T) {
	cases := []struct {
		probs map[string]float64
		ok    bool
	}{
		{map[string]float64{"chat": 0.7, "coding": 0.3}, true},
		{map[string]float64{"chat": 0.7, "coding": 0.2}, false}, // sums to 0.9
		{map[string]float64{"coding": 1}, false},                // choice missing
		{map[string]float64{"chat": 1.5, "coding": -0.5}, false},
		{map[string]float64{"chat": math.NaN()}, false},
	}
	for i, c := range cases {
		if got := validProbs(c.probs, "chat"); got != c.ok {
			t.Errorf("case %d: got %v want %v", i, got, c.ok)
		}
	}
}

func TestShippedDataLoads(t *testing.T) {
	dir := filepath.Join("..", "data")
	rc, err := LoadRouting(filepath.Join(dir, "routing-reference.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if got := CategoryAliases(rc); got["sensitive"] != "local" || len(got) != len(Categories) {
		t.Fatalf("category aliases %v", got)
	}
	items, err := LoadItems(filepath.Join(dir, "eval.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) < 500 {
		t.Fatalf("eval set has %d items, want >= 500", len(items))
	}
	for _, it := range items {
		if it.ExpectedCategory == "sensitive" && (len(it.AllowedAliases) != 1 || it.AllowedAliases[0] != "local") {
			t.Fatalf("%s: sensitive item allowed %v", it.ID, it.AllowedAliases)
		}
	}
	if _, err := LoadItems(filepath.Join(dir, "adversarial.jsonl")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProfiles(filepath.Join(dir, "profiles.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrices(filepath.Join(dir, "prices.yaml")); err != nil {
		t.Fatal(err)
	}
}
