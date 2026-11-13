// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package routingeval measures semantic-router classifiers against a
// labelled prompt set and an adversarial route-flip set (S12, 1.0.10).
package routingeval

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"gopkg.in/yaml.v3"
)

// Categories is the closed label set the router eval uses.
var Categories = []string{"coding", "reasoning", "chat", "summarize", "sensitive", "tool_heavy", "cheap_fast"}

// Message is one chat turn of an eval item.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Item is one labelled prompt (eval set) or one adversarial variant of a
// labelled prompt (route-flip set, BaseID set).
type Item struct {
	ID               string    `json:"id"`
	Messages         []Message `json:"messages"`
	ExpectedCategory string    `json:"expected_category"`
	AllowedAliases   []string  `json:"allowed_aliases"`

	BaseID       string `json:"base_id,omitempty"`
	GadgetFamily string `json:"gadget_family,omitempty"`
	AttackGoal   string `json:"attack_goal,omitempty"`
}

// LastUser returns the last user message, the text the 1.0.9 router
// classifies (system, assistant and tool turns are not classified).
func (it Item) LastUser() string {
	for i := len(it.Messages) - 1; i >= 0; i-- {
		if it.Messages[i].Role == "user" {
			return it.Messages[i].Content
		}
	}
	return ""
}

// AllText joins every message, the text the guardrail inspects.
func (it Item) AllText() string {
	parts := make([]string, 0, len(it.Messages))
	for _, m := range it.Messages {
		parts = append(parts, m.Content)
	}
	return strings.Join(parts, "\n")
}

// Allowed reports whether alias is in the item's allowed set.
func (it Item) Allowed(alias string) bool {
	for _, a := range it.AllowedAliases {
		if a == alias {
			return true
		}
	}
	return false
}

// LoadItems reads a JSONL file and checks every label.
func LoadItems(path string) ([]Item, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Item
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		var it Item
		if err := json.Unmarshal([]byte(text), &it); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		if it.ID == "" || seen[it.ID] {
			return nil, fmt.Errorf("%s:%d: empty or duplicate id %q", path, line, it.ID)
		}
		seen[it.ID] = true
		if !isCategory(it.ExpectedCategory) {
			return nil, fmt.Errorf("%s:%d: unknown expected_category %q", path, line, it.ExpectedCategory)
		}
		if len(it.AllowedAliases) == 0 {
			return nil, fmt.Errorf("%s:%d: empty allowed_aliases", path, line)
		}
		if len(it.Messages) == 0 {
			return nil, fmt.Errorf("%s:%d: no messages", path, line)
		}
		out = append(out, it)
	}
	return out, sc.Err()
}

func isCategory(c string) bool {
	for _, k := range Categories {
		if k == c {
			return true
		}
	}
	return false
}

// RoutingFile is the `routing:` block of a config.yaml.
type RoutingFile struct {
	Routing config.RoutingConfig `yaml:"routing"`
}

// LoadRouting reads and validates a routing block with the 1.0.9 validator.
func LoadRouting(path string) (config.RoutingConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return config.RoutingConfig{}, err
	}
	var rf RoutingFile
	if err := yaml.Unmarshal(raw, &rf); err != nil {
		return config.RoutingConfig{}, err
	}
	if err := rf.Routing.Validate(); err != nil {
		return config.RoutingConfig{}, fmt.Errorf("routing config: %w", err)
	}
	return rf.Routing, nil
}

// CategoryAliases maps each decision name to its first model ref.
func CategoryAliases(r config.RoutingConfig) map[string]string {
	out := map[string]string{}
	for _, d := range r.Decisions {
		if len(d.ModelRefs) > 0 {
			out[d.Name] = d.ModelRefs[0]
		}
	}
	return out
}

// Profile is the eval stand-in for guardrail.profiles.<name>.routing
// (allowed_aliases + default_alias); the filter narrows, never widens.
type Profile struct {
	AllowedAliases []string `yaml:"allowed_aliases"`
	DefaultAlias   string   `yaml:"default_alias"`
}

// Profiles is profiles.yaml.
type Profiles struct {
	Profiles     map[string]Profile `yaml:"profiles"`
	LocalAliases []string           `yaml:"local_aliases"`
	// RequestAlias stands for the model the agent asked for; a classifier
	// failure falls back to it (D3: original provider), then the profile.
	RequestAlias string `yaml:"request_alias"`
}

// Names returns the profile names in a stable order.
func (p Profiles) Names() []string {
	out := make([]string, 0, len(p.Profiles))
	for k := range p.Profiles {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Price is one alias price row (USD per million tokens).
type Price struct {
	InputPerMTok  float64 `yaml:"input_per_mtok"`
	OutputPerMTok float64 `yaml:"output_per_mtok"`
}

// Prices is the price table plus the per-category output token estimate.
type Prices struct {
	Version      string           `yaml:"version"`
	Note         string           `yaml:"note"`
	Aliases      map[string]Price `yaml:"aliases"`
	OutputTokens map[string]int   `yaml:"output_tokens"`
	CharsPerTok  float64          `yaml:"chars_per_token"`
}

// Cost is the estimated USD cost of serving it with alias.
func (p Prices) Cost(it Item, alias string) float64 {
	pr, ok := p.Aliases[alias]
	if !ok {
		return 0
	}
	cpt := p.CharsPerTok
	if cpt <= 0 {
		cpt = 4
	}
	in := float64(len(it.AllText())) / cpt
	out := float64(p.OutputTokens[it.ExpectedCategory])
	return (in*pr.InputPerMTok + out*pr.OutputPerMTok) / 1e6
}

// Check fails when an alias has no price row, so a renamed or mistyped
// alias can never be priced at $0 silently.
func (p Prices) Check(aliases ...string) error {
	for _, a := range aliases {
		if _, ok := p.Aliases[a]; !ok {
			return fmt.Errorf("price table %s has no row for alias %q", p.Version, a)
		}
	}
	return nil
}

// Rank orders aliases by output price (cheapest first) for flip direction.
func (p Prices) Rank(alias string) float64 {
	pr, ok := p.Aliases[alias]
	if !ok {
		return -1
	}
	return pr.OutputPerMTok + pr.InputPerMTok/1000
}

func loadYAML(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(raw, v)
}

// LoadProfiles reads profiles.yaml.
func LoadProfiles(path string) (Profiles, error) {
	var p Profiles
	if err := loadYAML(path, &p); err != nil {
		return p, err
	}
	if len(p.Profiles) == 0 {
		return p, fmt.Errorf("%s: no profiles", path)
	}
	return p, nil
}

// LoadPrices reads the price table.
func LoadPrices(path string) (Prices, error) {
	var p Prices
	if err := loadYAML(path, &p); err != nil {
		return p, err
	}
	if len(p.Aliases) == 0 {
		return p, fmt.Errorf("%s: no aliases", path)
	}
	return p, nil
}
