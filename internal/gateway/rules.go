// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
)

// PatternRule is a single detection rule with a compiled regex, severity,
// and confidence score. All runtime tool inspection uses these rules.
type PatternRule struct {
	ID         string
	Pattern    *regexp.Regexp
	Expression string
	// ToolCallOnly keeps a rule's regex out of prompt, result, and artifact
	// text scans. Expressions are always confined to the trusted dispatcher,
	// which decides between Expression and Pattern for one owner.
	ToolCallOnly bool
	Title        string
	Severity     string
	Confidence   float64
	Tags         []string
}

// RuleFinding is a structured finding produced by scanning tool args or content.
type RuleFinding struct {
	RuleID     string   `json:"rule_id"`
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`
	Confidence float64  `json:"confidence"`
	Evidence   string   `json:"evidence,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	// ToolCapabilityClass is set for tool-call inspection findings
	// from the invoked tool's name (via guardrail.ClassifyToolName).
	// Empty for content-only matches; the emission pipeline then
	// falls back to a rule-id-based capability (CapabilityForRuleID).
	ToolCapabilityClass string `json:"tool_capability_class,omitempty"`
	enforcement         findingEnforcement
}

type findingEnforcement uint8

const (
	// findingEnforcementInherit preserves the enforcement behavior of every
	// finding produced before trusted semantic dispatch existed.
	findingEnforcementInherit findingEnforcement = iota
	findingEnforcementAllowed
	findingEnforcementDetectionOnly
)

func (f RuleFinding) contributesToEnforcement() bool {
	return f.enforcement != findingEnforcementDetectionOnly
}

// ---------------------------------------------------------------------------
// Scan engine — runs the generated default catalog against input
// ---------------------------------------------------------------------------

// ruleCategoriesMu guards reads and writes to allRuleCategories.
// ApplyRulePackOverrides writes at startup; ScanAllRules reads on every request.
var ruleCategoriesMu sync.RWMutex

// ruleCategory is one named group of detection rules.
type ruleCategory struct {
	Name  string
	Rules []PatternRule
}

// allRuleCategories groups all rule slices for iteration. Seeded from the
// compiled-in defaults; a rule pack can override individual categories by
// name via ApplyRulePackOverrides without removing the others.
//
// In single-connector mode this is the one active rule set (the connector's
// pack, or the compiled-in defaults). In multi-connector mode it is the
// fallback used by ScanAllRulesForConnector when a connector has no
// dedicated set registered.
var allRuleGeneration = mustCompileRulePackGeneration(defaultRuleCategories)

// allRuleCategories remains a package-private compatibility view for the
// existing lifecycle tests. Production publication and reads use the
// immutable generation pointer. Both are replaced under ruleCategoriesMu.
var allRuleCategories = allRuleGeneration.categories

// connectorRuleCategories holds a per-connector compiled rule set so each
// connector scans against its own EffectiveRulePackDir at runtime — the same
// behavior single-connector installs get, lifted to N connectors. Populated
// at boot by ApplyConnectorRulePackOverrides (one entry per connector that
// resolved a pack). A connector with no entry falls back to
// allRuleCategories, so this map is purely additive and leaves the
// single-connector path untouched. Guarded by ruleCategoriesMu.
var connectorRuleCategories = map[string][]ruleCategory{}
var connectorRuleGenerations = map[string]*compiledRulePackCategories{}

func canonicalConnectorRulePackKey(connector string) string {
	return strings.ToLower(strings.TrimSpace(connector))
}

// maxRegexCompileTime caps how long a single user-supplied regex may take to
// compile, guarding against ReDoS-style patterns in rule pack YAML files.
const maxRegexCompileTime = 2 * time.Second

var (
	errRegexPatternSize    = errors.New("pattern exceeds size limit")
	errRegexPatternSyntax  = errors.New("pattern syntax is invalid")
	errRegexCompileTimeout = errors.New("pattern compilation timed out")
)

func compileRegexSafe(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > 2048 {
		return nil, errRegexPatternSize
	}
	type result struct {
		re  *regexp.Regexp
		err error
	}
	ch := make(chan result, 1)
	go func() {
		re, err := regexp.Compile(pattern)
		ch <- result{re, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, errRegexPatternSyntax
		}
		return r.re, nil
	case <-time.After(maxRegexCompileTime):
		return nil, errRegexCompileTimeout
	}
}

// ApplyRulePackOverrides merges rule-pack rule files into the compiled-in
// defaults. For each rules/*.yaml in the pack, the category named by
// `category:` replaces the same-named compiled-in category. Categories not
// mentioned by the pack keep their compiled-in defaults, so a partial or
// corrupt deployment cannot silently drop whole detection categories — the
// previous implementation wholesale-replaced allRuleCategories, which meant
// one valid rules/commands.yaml on disk would delete every other default
// category.
//
// Unknown category names (not in the compiled-in set) are appended so rule
// packs can add new categories without modifying Go source.
//
// This function is idempotent: it always starts from defaultRuleCategories,
// so repeated calls (config reload, tests) converge on the same state.
func ApplyRulePackOverrides(rp *guardrail.RulePack) error {
	compiled, err := compileRulePackCategories(rp)
	if err != nil {
		return err
	}
	publishRulePackOverrides(compiled)
	return nil
}

type compiledRulePackCategories struct {
	categories    []ruleCategory
	semanticRules []compiledSemanticRule
	overridden    int
	added         int
}

const (
	maxGenerationSemanticRules      = 256
	maxGenerationSemanticStaticCost = uint64(32_000_000)
)

func compileRulePackCategories(rp *guardrail.RulePack) (*compiledRulePackCategories, error) {
	compiler, err := semantic.NewCompiler()
	if err != nil {
		return nil, errors.New("semantic rule compiler is unavailable")
	}
	merged, overridden, added, err := mergeRulePackCategories(rp, compiler)
	if err != nil {
		return nil, err
	}
	compiled, err := compileRulePackGenerationWithCompiler(merged, compiler)
	if err != nil {
		return nil, err
	}
	compiled.overridden = overridden
	compiled.added = added
	return compiled, nil
}

func mustCompileRulePackGeneration(categories []ruleCategory) *compiledRulePackCategories {
	compiled, err := compileRulePackGeneration(categories)
	if err != nil {
		panic(fmt.Sprintf("compile generated guardrail catalog: %v", err))
	}
	return compiled
}

func compileRulePackGeneration(categories []ruleCategory) (*compiledRulePackCategories, error) {
	compiler, err := semantic.NewCompiler()
	if err != nil {
		return nil, errors.New("semantic rule compiler is unavailable")
	}
	return compileRulePackGenerationWithCompiler(categories, compiler)
}

func compileRulePackGenerationWithCompiler(
	categories []ruleCategory,
	compiler *semantic.Compiler,
) (*compiledRulePackCategories, error) {
	if compiler == nil {
		return nil, errors.New("semantic rule compiler is unavailable")
	}
	ownedCategories := cloneRuleCategories(categories)
	compiled := &compiledRulePackCategories{categories: ownedCategories}
	claimed := make(map[string]string)
	var staticCost uint64
	for _, category := range ownedCategories {
		for _, rule := range category.Rules {
			expression := strings.TrimSpace(rule.Expression)
			if rule.Expression != expression {
				return nil, fmt.Errorf(
					"semantic rule %q expression has outer whitespace",
					rule.ID,
				)
			}
			if expression == "" {
				continue
			}
			program, code := compiler.Compile(expression)
			if code != semantic.CompileOK {
				return nil, fmt.Errorf("semantic rule %q failed admission (%s)", rule.ID, code)
			}
			if len(compiled.semanticRules) >= maxGenerationSemanticRules {
				return nil, errors.New("effective semantic rule count exceeds limit")
			}
			staticCost += program.StaticCost()
			if staticCost > maxGenerationSemanticStaticCost {
				return nil, errors.New("effective semantic rule cost exceeds limit")
			}
			owner := semanticOwnerForRule(rule.ID)
			for _, claimedID := range owner.claimedIDs(true) {
				if previous, exists := claimed[claimedID]; exists && previous != rule.ID {
					return nil, fmt.Errorf(
						"semantic rule %q conflicts with owner %q on %q",
						rule.ID,
						previous,
						claimedID,
					)
				}
				claimed[claimedID] = rule.ID
			}
			compiled.semanticRules = append(compiled.semanticRules, compiledSemanticRule{
				rule:    rule,
				program: program,
				owner:   owner,
			})
		}
	}
	return compiled, nil
}

func cloneRuleCategories(categories []ruleCategory) []ruleCategory {
	cloned := make([]ruleCategory, len(categories))
	for categoryIndex, category := range categories {
		cloned[categoryIndex] = ruleCategory{
			Name:  category.Name,
			Rules: make([]PatternRule, len(category.Rules)),
		}
		for ruleIndex, rule := range category.Rules {
			cloned[categoryIndex].Rules[ruleIndex] = rule
			if rule.Pattern != nil {
				cloned[categoryIndex].Rules[ruleIndex].Pattern = rule.Pattern.Copy()
			}
			cloned[categoryIndex].Rules[ruleIndex].Tags = append(
				[]string(nil),
				rule.Tags...,
			)
		}
	}
	return cloned
}

func publishRulePackOverrides(compiled *compiledRulePackCategories) {
	if compiled == nil {
		return
	}
	ruleCategoriesMu.Lock()
	allRuleGeneration = compiled
	allRuleCategories = compiled.categories
	ruleCategoriesMu.Unlock()
	fmt.Fprintf(os.Stderr, "[guardrail] rule pack merged: %d categories overridden, %d added, %d defaults retained\n",
		compiled.overridden, compiled.added, len(defaultRuleCategories)-compiled.overridden)
}

// ApplyConnectorRulePackOverrides registers a connector-scoped rule set built
// from that connector's effective rule pack. This is the multi-connector
// analogue of ApplyRulePackOverrides: instead of mutating the single process
// global, it stores the merged set keyed by connector so each connector's
// hook lane scans against its own pack (closing the "primary wins" gap).
//
// Called once per connector at boot. A nil/empty pack still registers an
// entry equal to the compiled-in defaults so the connector is explicitly
// pinned to a known set rather than inheriting whatever the primary happened
// to install. Connectors with no entry fall back to allRuleCategories via
// ScanAllRulesForConnector. Empty connector names are ignored.
func ApplyConnectorRulePackOverrides(connector string, rp *guardrail.RulePack) error {
	connector = canonicalConnectorRulePackKey(connector)
	if connector == "" {
		return nil
	}

	compiled, err := compileRulePackCategories(rp)
	if err != nil {
		return fmt.Errorf("connector %s rule pack activation: %w", connector, err)
	}
	publishConnectorRulePackOverrides(connector, compiled)
	return nil
}

func publishConnectorRulePackOverrides(connector string, compiled *compiledRulePackCategories) {
	connector = canonicalConnectorRulePackKey(connector)
	if connector == "" || compiled == nil {
		return
	}
	ruleCategoriesMu.Lock()
	connectorRuleGenerations[connector] = compiled
	connectorRuleCategories[connector] = compiled.categories
	ruleCategoriesMu.Unlock()
	fmt.Fprintf(os.Stderr, "[guardrail] connector %s rule set: %d categories overridden, %d added, %d defaults retained\n",
		connector, compiled.overridden, compiled.added, len(defaultRuleCategories)-compiled.overridden)
}

// publishConnectorRulePackGeneration replaces the manual connector portion of
// the current generation under one lock. Dynamically protected connectors are
// left intact unless they also appeared in the previous manual connector set.
func publishConnectorRulePackGeneration(
	previousManual []string,
	next map[string]*compiledRulePackCategories,
) {
	canonicalNext := make(map[string]*compiledRulePackCategories, len(next))
	for rawName, compiled := range next {
		name := canonicalConnectorRulePackKey(rawName)
		if name == "" || compiled == nil {
			continue
		}
		canonicalNext[name] = compiled
	}

	ruleCategoriesMu.Lock()
	for _, rawName := range previousManual {
		name := canonicalConnectorRulePackKey(rawName)
		if name == "" {
			continue
		}
		if _, retained := canonicalNext[name]; !retained {
			delete(connectorRuleGenerations, name)
			delete(connectorRuleCategories, name)
		}
	}
	for name, compiled := range canonicalNext {
		connectorRuleGenerations[name] = compiled
		connectorRuleCategories[name] = compiled.categories
	}
	ruleCategoriesMu.Unlock()
}

// RemoveConnectorRulePackOverrides removes connector-scoped runtime state
// after a connector is cleanly torn down. A later scan for that connector
// falls back to the current generated global defaults instead of retaining a
// stale override from an earlier activation.
func RemoveConnectorRulePackOverrides(connector string) {
	connector = canonicalConnectorRulePackKey(connector)
	if connector == "" {
		return
	}
	ruleCategoriesMu.Lock()
	delete(connectorRuleGenerations, connector)
	delete(connectorRuleCategories, connector)
	ruleCategoriesMu.Unlock()
}

// mergeRulePackCategories builds a full rule-category slice by merging the
// rule-pack's rule files onto the compiled-in defaults. It is pure — it never
// touches package globals — so both the single-connector global path
// (ApplyRulePackOverrides) and the per-connector store
// (ApplyConnectorRulePackOverrides) share identical merge semantics. A nil
// pack or one with no rule files yields a copy of defaultRuleCategories.
func mergeRulePackCategories(
	rp *guardrail.RulePack,
	compiler *semantic.Compiler,
) (merged []ruleCategory, overridden, added int, err error) {
	merged = make([]ruleCategory, len(defaultRuleCategories))
	copy(merged, defaultRuleCategories)
	if rp == nil || len(rp.RuleFiles) == 0 {
		return merged, 0, 0, nil
	}

	idx := make(map[string]int, len(merged))
	for i, c := range merged {
		idx[c.Name] = i
	}

	for fileIndex, rf := range rp.RuleFiles {
		if rf == nil || rf.Category == "" {
			continue
		}
		var compiled []PatternRule
		for ruleIndex, r := range rf.Rules {
			expression := strings.TrimSpace(r.Expression)
			if r.Expression != expression {
				return nil, 0, 0, fmt.Errorf(
					"rule-pack category entry %d rule %d semantic expression has outer whitespace",
					fileIndex,
					ruleIndex,
				)
			}
			if expression != "" {
				if compiler == nil {
					return nil, 0, 0, errors.New("semantic rule compiler is unavailable")
				}
				if _, code := compiler.Compile(expression); code != semantic.CompileOK {
					return nil, 0, 0, fmt.Errorf(
						"rule-pack category entry %d rule %d contains an invalid semantic expression (%s)",
						fileIndex,
						ruleIndex,
						code,
					)
				}
			}
			re, err := compileRegexSafe(r.Pattern)
			if err != nil {
				return nil, 0, 0, fmt.Errorf(
					"rule-pack category entry %d rule %d contains an invalid regular expression: %w",
					fileIndex,
					ruleIndex,
					err,
				)
			}
			if r.Enabled != nil && !*r.Enabled {
				continue
			}
			compiled = append(compiled, PatternRule{
				ID:           r.ID,
				Pattern:      re,
				Expression:   r.Expression,
				ToolCallOnly: r.ToolCallOnly,
				Title:        r.Title,
				Severity:     r.Severity,
				Confidence:   r.Confidence,
				Tags:         append([]string(nil), r.Tags...),
			})
		}
		if len(compiled) == 0 {
			continue
		}
		if i, ok := idx[rf.Category]; ok {
			merged[i].Rules = compiled
			overridden++
		} else {
			merged = append(merged, ruleCategory{Name: rf.Category, Rules: compiled})
			idx[rf.Category] = len(merged) - 1
			added++
		}
	}
	return merged, overridden, added, nil
}

// severityRank maps severity strings to numeric ranks for comparison.
var severityRank = map[string]int{
	"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
}

// knownExecTools lists tool names that are known execution tools. When the
// tool name matches, confidence for command rules is boosted. When it does
// NOT match, command rules still run — just at reduced confidence.
var knownExecTools = map[string]bool{
	"shell": true, "system.run": true, "exec": true, "bash": true,
	"terminal": true, "run_command": true, "execute": true, "subprocess": true,
}

// knownFileTools lists tool names that are known file operation tools.
var knownFileTools = map[string]bool{
	"read_file": true, "write_file": true, "edit_file": true,
	"delete_file": true, "move_file": true, "create_file": true,
}

// knownReadTools and knownWriteTools allow operation-aware handling for
// cognitive file detections (read is less risky than write/delete).
var knownReadTools = map[string]bool{
	"read_file": true, "cat_file": true, "open_file": true, "view_file": true,
}

var knownWriteTools = map[string]bool{
	"write_file": true, "edit_file": true, "delete_file": true, "move_file": true,
	"create_file": true, "append_file": true,
}

// adjustConfidence adjusts a finding's confidence based on tool name context.
// A shell command pattern in a tool named "shell" is higher confidence than
// the same pattern in a tool named "search_docs".
func adjustConfidence(toolName string, f RuleFinding) RuleFinding {
	tool := strings.ToLower(toolName)

	switch {
	// Command rules: boost if exec tool, reduce if not
	case hasTag(f.Tags, "execution") || hasTag(f.Tags, "reverse-shell") || hasTag(f.Tags, "destructive"):
		if knownExecTools[tool] {
			f.Confidence = clampConfidence(f.Confidence * 1.05)
		} else if !knownFileTools[tool] {
			f.Confidence = clampConfidence(f.Confidence * 0.8)
		}

	// Path rules: boost if file tool
	case hasTag(f.Tags, "file-sensitive") || hasTag(f.Tags, "system-file"):
		if knownFileTools[tool] {
			f.Confidence = clampConfidence(f.Confidence * 1.05)
		} else if !knownExecTools[tool] {
			f.Confidence = clampConfidence(f.Confidence * 0.85)
		}

	// Cognitive tampering: treat write/delete as high risk, reads as lower-risk.
	case hasTag(f.Tags, "cognitive-tampering"):
		if knownWriteTools[tool] {
			f.Confidence = clampConfidence(f.Confidence * 1.10)
		} else if knownReadTools[tool] {
			f.Confidence = clampConfidence(f.Confidence * 0.65)
			switch f.Severity {
			case "CRITICAL":
				f.Severity = "HIGH"
			case "HIGH":
				f.Severity = "MEDIUM"
			}
		}

		// Credential patterns always stay high regardless of tool.
		// C2 and trust-exploit are tool-agnostic; cognitive rules are adjusted above.
	}

	return f
}

// ScanAllRules runs every rule category against the input text and returns
// structured findings. Tool name is used only for confidence adjustment,
// never for gating which rules run.
//
// The input is scanned twice: once raw and once after shell normalization
// (stripping quotes, backslashes, empty string concatenation, and
// variable-like constructions). This defeats path obfuscation tricks
// like /etc/sha""dow, /etc/sha\dow, ${P}/shadow, and /etc/shad?w.
func ScanAllRules(text string, toolName string) []RuleFinding {
	// managed_enterprise: local regex detection is disabled — Cisco AI
	// Defense is authoritative. Return no findings so any residual call
	// site (router lane, misc callers) cannot produce a local block.
	if ManagedEnterpriseActive() {
		return nil
	}
	generation := snapshotRulePackGeneration("")
	return scanRuleGeneration(generation, text, toolName, ruleScanOptions{})
}

// ScanAllRulesForConnector scans against the named connector's registered
// rule set (its EffectiveRulePackDir, installed at boot via
// ApplyConnectorRulePackOverrides). When the connector has no dedicated set
// — single-connector installs, the OpenClaw generic inspect endpoint, or a
// connector that never resolved a pack — it falls back to the process-global
// allRuleCategories, so the single-connector path is byte-for-byte unchanged.
func ScanAllRulesForConnector(connector, text, toolName string) []RuleFinding {
	// managed_enterprise: local regex detection is disabled — Cisco AI
	// Defense is authoritative. See ScanAllRules.
	if ManagedEnterpriseActive() {
		return nil
	}
	generation := snapshotRulePackGeneration(connector)
	return scanRuleGeneration(generation, text, toolName, ruleScanOptions{})
}

// scanContentRulesForConnector applies the content-only rule boundary used by
// connector prompts and tool results. Concrete actions (commands, paths,
// cognitive-file mutations, and C2 operations) belong to the trusted tool-call
// dispatcher, where ActionFacts can prove what will execute. Scanning those
// categories against prose or returned bytes turns source, tests, and command
// output into false actions. Trust, secret, and PII rules remain fully eligible
// for untrusted output. In the much narrower physically verified fixture/rule
// scope, matches remain visible as LOW detection-only telemetry; repository
// enforcement is owned by CodeGuard instead of generating a HIGH/CRITICAL hook
// alert every time an operator reads a security test corpus.
func scanContentRulesForConnector(
	connector, text, toolName string,
	scope ruleContentScope,
) []RuleFinding {
	return scanContentRuleCategoryForConnector(connector, text, toolName, scope, "")
}

// scanContentRuleCategoryForConnector applies the same content boundary as
// scanContentRulesForConnector while restricting evaluation to one declared
// rule-pack category. An empty category preserves the all-content-category
// behavior above. Keeping the filter in the scan options means custom rule IDs
// and tags cannot accidentally enter a category-specific decision.
func scanContentRuleCategoryForConnector(
	connector, text, toolName string,
	scope ruleContentScope,
	category string,
) []RuleFinding {
	if ManagedEnterpriseActive() {
		return nil
	}
	if scope == ruleContentScopeSource {
		text = neutralizeKnownFixtureDataLiterals(text)
	}
	findings := scanRuleGeneration(
		snapshotRulePackGeneration(connector),
		text,
		toolName,
		ruleScanOptions{contentScope: scope, onlyCategory: category},
	)
	if scope == ruleContentScopeSource {
		// Physically verified test, fixture, and bundled rule sources are useful
		// telemetry, but their contents are not an action by the agent. Keeping
		// literal attack strings or sample credentials at HIGH/CRITICAL created
		// an alert for every source review. CodeGuard remains the enforcement
		// owner for credentials committed to repository files, while symlinked,
		// mixed, ordinary-source, process, and external output never enter this
		// narrow scope and retain their original severity.
		for i := range findings {
			findings[i].Severity = "LOW"
			findings[i].enforcement = findingEnforcementDetectionOnly
		}
	}
	return findings
}

type ruleContentScope uint8

const (
	ruleContentScopeAll ruleContentScope = iota
	ruleContentScopeSource
	ruleContentScopeUntrusted
)

type ruleScanOptions struct {
	includeToolCallOnly bool
	excludeTrustExploit bool
	excludedRuleIDs     map[string]struct{}
	contentScope        ruleContentScope
	onlyCategory        string
}

func (o ruleScanOptions) allows(ruleID string, toolCallOnly bool) bool {
	if toolCallOnly && !o.includeToolCallOnly {
		return false
	}
	_, excluded := o.excludedRuleIDs[ruleID]
	return !excluded
}

func (o ruleScanOptions) allowsCategory(category string) bool {
	if o.onlyCategory != "" && category != o.onlyCategory {
		return false
	}
	if o.excludeTrustExploit && category == "trust-exploit" {
		return false
	}
	if o.contentScope == ruleContentScopeAll {
		return true
	}
	switch category {
	case "command", "sensitive-path", "cognitive-file", "c2":
		return false
	case "trust-exploit":
		// Source-scope matches are retained and downgraded after matching rather
		// than suppressed here, so telemetry still records the literal.
		return o.contentScope == ruleContentScopeUntrusted ||
			o.contentScope == ruleContentScopeSource
	case "secret", "enterprise-data":
		return true
	default:
		return true
	}
}

// neutralizeKnownFixtureDataLiterals removes only canonical public examples.
// It deliberately does not suppress an entire detector category: a fixture can
// still contain a real credential or PII value, and a fixture-looking path can
// be redirected to live data by a symlink.
func neutralizeKnownFixtureDataLiterals(text string) string {
	for _, literal := range []string{
		"AKIA" + "IOSFODNN7EXAMPLE",
		"123" + "-45-6789",
	} {
		text = strings.ReplaceAll(text, literal, strings.Repeat("x", len(literal)))
	}
	return text
}

func snapshotRulePackGeneration(connector string) *compiledRulePackCategories {
	connector = canonicalConnectorRulePackKey(connector)
	ruleCategoriesMu.RLock()
	generation := allRuleGeneration
	categories := allRuleCategories
	if connector != "" {
		if connectorCategories, ok := connectorRuleCategories[connector]; ok {
			categories = connectorCategories
			generation = connectorRuleGenerations[connector]
		}
	}
	legacyView := generation == nil ||
		!sameRuleCategoryView(generation.categories, categories)
	ruleCategoriesMu.RUnlock()
	if legacyView {
		// Compatibility for package tests that temporarily replace the legacy
		// category view directly. Production publication always takes the
		// immutable-generation path above.
		compiled, err := compileRulePackGeneration(categories)
		if err == nil {
			return compiled
		}
		return &compiledRulePackCategories{categories: categories}
	}
	return generation
}

func sameRuleCategoryView(a, b []ruleCategory) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	return &a[0] == &b[0]
}

func scanRuleGeneration(
	generation *compiledRulePackCategories,
	text string,
	toolName string,
	options ruleScanOptions,
) []RuleFinding {
	if generation == nil {
		return nil
	}
	return scanRuleCategoriesWithOptions(generation.categories, text, toolName, options)
}

// scanRuleCategories runs every rule in cats against text, scanning both the
// raw input and a shell-normalized copy to defeat obfuscation. It is the
// shared core of ScanAllRules / ScanAllRulesForConnector — the only
// difference between those entry points is which category set they select.
func scanRuleCategories(cats []ruleCategory, text string, toolName string) []RuleFinding {
	return scanRuleCategoriesWithOptions(cats, text, toolName, ruleScanOptions{})
}

func scanRuleCategoriesWithOptions(
	cats []ruleCategory,
	text string,
	toolName string,
	options ruleScanOptions,
) []RuleFinding {
	var findings []RuleFinding
	// The hard-coded Windows recognizers cover only command and sensitive-path
	// actions, both of which are intentionally absent from content scans.
	if options.contentScope == ruleContentScopeAll {
		findings = windowsCommandFindingsWithOptions(text, toolName, options)
	}
	seen := make(map[string]bool)
	for i := range findings {
		findings[i] = adjustConfidence(toolName, findings[i])
		seen[findings[i].RuleID] = true
	}

	// Scan raw text first
	for _, cat := range cats {
		if !options.allowsCategory(cat.Name) {
			continue
		}
		for _, rule := range cat.Rules {
			if !options.allows(rule.ID, rule.ToolCallOnly) {
				continue
			}
			loc := firstAcceptedRuleMatch(rule, text)
			if loc == nil {
				continue
			}

			evidence := text[loc[0]:minInt(loc[1], loc[0]+80)]

			f := RuleFinding{
				RuleID:     rule.ID,
				Title:      rule.Title,
				Severity:   rule.Severity,
				Confidence: rule.Confidence,
				Evidence:   sanitizeEvidence(evidence),
				Tags:       rule.Tags,
			}

			f = adjustConfidence(toolName, f)
			findings = append(findings, f)
			seen[rule.ID] = true
		}
	}

	// Scan normalized text to catch shell obfuscation
	normalized := normalizeShell(text)
	if normalized != text {
		for _, cat := range cats {
			if !options.allowsCategory(cat.Name) {
				continue
			}
			for _, rule := range cat.Rules {
				if !options.allows(rule.ID, rule.ToolCallOnly) {
					continue
				}
				if seen[rule.ID] {
					continue // already found on raw pass
				}
				loc := firstAcceptedRuleMatch(rule, normalized)
				if loc == nil {
					continue
				}

				evidence := normalized[loc[0]:minInt(loc[1], loc[0]+80)]

				f := RuleFinding{
					RuleID:     rule.ID,
					Title:      rule.Title + " (obfuscated)",
					Severity:   rule.Severity,
					Confidence: rule.Confidence * 0.9, // slightly lower for normalized match
					Evidence:   sanitizeEvidence(evidence),
					Tags:       rule.Tags,
				}

				f = adjustConfidence(toolName, f)
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// normalizeShell strips common shell obfuscation tricks so that regex rules
// can match the effective path/command. This catches:
//   - Empty string concatenation: sha""dow → shadow
//   - Backslash escapes: sha\dow → shadow
//   - Single-char globs: shad?w → shadXw (replaced with wildcard char)
//   - Variable-like patterns: ${VAR}/path → /path
var shellNormalizeReplacer = strings.NewReplacer(
	`""`, "", // empty double-quote pairs
	`''`, "", // empty single-quote pairs
	`\`, "", // stray backslashes
)

var shellVarPattern = regexp.MustCompile(`\$\{?\w+\}?`)
var shellGlobPattern = regexp.MustCompile(`\?`)

func normalizeShell(s string) string {
	n := shellNormalizeReplacer.Replace(s)
	// Expand globs: replace ? with each common character so /etc/shad?w → /etc/shadow
	n = shellGlobPattern.ReplaceAllString(n, "o")
	// Strip variable references: ${P}/shadow → /shadow, $HOME/.ssh → /.ssh
	n = shellVarPattern.ReplaceAllString(n, "")
	return n
}

// HighestSeverity returns the highest severity string from a list of findings.
func HighestSeverity(findings []RuleFinding) string {
	best := "NONE"
	bestRank := 0
	for _, f := range findings {
		r := severityRank[f.Severity]
		if r > bestRank {
			bestRank = r
			best = f.Severity
		}
	}
	return best
}

// HighestConfidence returns the highest confidence from findings at the given severity.
func HighestConfidence(findings []RuleFinding, severity string) float64 {
	best := 0.0
	for _, f := range findings {
		if f.Severity == severity && f.Confidence > best {
			best = f.Confidence
		}
	}
	return best
}

// FindingStrings converts structured findings to simple strings for the
// existing ToolInspectVerdict.Findings field (backward compatibility).
func FindingStrings(findings []RuleFinding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.RuleID+":"+f.Title)
	}
	return out
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

func clampConfidence(c float64) float64 {
	if c > 1.0 {
		return 1.0
	}
	if c < 0.0 {
		return 0.0
	}
	return c
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// sanitizeEvidence truncates and strips control characters from evidence.
func sanitizeEvidence(s string) string {
	if len(s) > 80 {
		s = s[:80] + "..."
	}
	// Strip newlines and tabs
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\t", " ")
	return s
}
