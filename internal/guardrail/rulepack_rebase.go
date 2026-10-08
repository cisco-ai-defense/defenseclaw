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

package guardrail

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	policyassets "github.com/defenseclaw/defenseclaw/policies"
)

// The 0.8.10 default action files are the baseline for preserving operator
// field edits during v9 migration. The 0.8.x releases shipped these same
// rules. Only fields unchanged from this baseline take their 1.0 values.
//
//go:embed legacy08/*.yaml
var legacy08RuleFiles embed.FS

var legacy08FileNames = map[string]string{
	"command":        "commands.yaml",
	"c2":             "c2.yaml",
	"cognitive-file": "cognitive.yaml",
	"sensitive-path": "sensitive-paths.yaml",
}

// actionRuleCategories judge a concrete action: a command, a path, a change
// to an agent's own files, a network destination. The engine blocks such an
// action only with a semantic proof (the rule's expression, or a built-in
// owner of a shipped rule's ID); a pattern alone selects candidates and
// records a match on a tool call, but never blocks one.
var actionRuleCategories = map[string]bool{"command": true, "sensitive-path": true, "cognitive-file": true, "c2": true}

// default08RuleIDs are the action rules of the 0.8.x default pack (0.8.0 to
// 0.8.10 shipped the same ones), none with an expression. A copy of that
// pack without one of them had the rule removed by its operator. Keep until
// the config_version 8 migration is dropped (1.1.0).
var default08RuleIDs = map[string][]string{
	"command": {"CMD-REVSHELL-BASH", "CMD-REVSHELL-DEVTCP", "CMD-REVSHELL-NC", "CMD-REVSHELL-PYTHON", "CMD-PIPE-CURL",
		"CMD-PIPE-WGET", "CMD-PIPE-BASE64", "CMD-EVAL", "CMD-BASH-C", "CMD-PYTHON-C", "CMD-PERL-E", "CMD-RUBY-E",
		"CMD-RM-RF", "CMD-MKFS", "CMD-DD-IF", "CMD-CHMOD-WORLD", "CMD-CHOWN-ROOT", "CMD-SUDO", "CMD-ETC-WRITE",
		"CMD-CRONTAB", "CMD-SYSTEMCTL", "CMD-NETCAT-LISTEN", "CMD-CURL-UPLOAD", "CMD-WGET-POST", "CMD-SOCAT-EXEC",
		"CMD-ENV-DUMP"},
	"c2": {"C2-WEBHOOK-SITE", "C2-NGROK", "C2-PIPEDREAM", "C2-REQUESTBIN", "C2-HOOKBIN", "C2-BURP", "C2-INTERACTSH",
		"C2-OAST", "C2-CANARY", "C2-PASTEBIN", "C2-METADATA-AWS", "C2-METADATA-GCP", "C2-METADATA-AZURE",
		"C2-METADATA-HEX", "C2-METADATA-DECIMAL", "C2-METADATA-OCTAL", "C2-DNS-TUNNEL", "C2-DNS-EXFIL"},
	"cognitive-file": {"COG-SOUL", "COG-IDENTITY", "COG-MEMORY", "COG-CLAUDE-MD", "COG-TOOLS-MD", "COG-AGENTS-MD",
		"COG-OPENCLAW-JSON", "COG-GATEWAY-JSON"},
	"sensitive-path": {"PATH-SSH-DIR", "PATH-SSH-KEY", "PATH-AWS-CREDS", "PATH-AWS-CONFIG", "PATH-KUBE", "PATH-DOCKER",
		"PATH-GNUPG", "PATH-NPMRC", "PATH-PYPIRC", "PATH-GIT-CREDS", "PATH-NETRC", "PATH-ENV-FILE", "PATH-ETC-PASSWD",
		"PATH-ETC-SHADOW", "PATH-ETC-SUDOERS", "PATH-PROC-ENVIRON", "PATH-HISTORY"},
}

// shippedRules indexes the action rules of the packs this build ships.
type shippedRules struct {
	// withExpression and patternOnly map a category to the rule IDs some
	// shipped pack gives an expression, or ships without one (those have a
	// built-in owner and need none).
	withExpression map[string]map[string]bool
	patternOnly    map[string]map[string]bool
	// defaultFiles is the shipped default pack's rule file per category.
	defaultFiles map[string][]byte
}

var shippedRuleIndex = sync.OnceValues(func() (*shippedRules, error) {
	files, err := policyassets.Files()
	if err != nil {
		return nil, err
	}
	index := &shippedRules{
		withExpression: map[string]map[string]bool{},
		patternOnly:    map[string]map[string]bool{},
		defaultFiles:   map[string][]byte{},
	}
	for _, file := range files {
		parts := strings.Split(file.Path, "/")
		if len(parts) != 4 || parts[0] != "guardrail" || parts[2] != "rules" || path.Ext(parts[3]) != ".yaml" {
			continue
		}
		var rules RulesFileYAML
		if err := yaml.Unmarshal(file.Data, &rules); err != nil {
			return nil, fmt.Errorf("shipped rule file %s: %w", file.Path, err)
		}
		if !actionRuleCategories[rules.Category] {
			continue
		}
		for _, rule := range rules.Rules {
			set := index.patternOnly
			if strings.TrimSpace(rule.Expression) != "" {
				set = index.withExpression
			}
			if set[rules.Category] == nil {
				set[rules.Category] = map[string]bool{}
			}
			set[rules.Category][rule.ID] = true
		}
		if parts[1] == "default" {
			index.defaultFiles[rules.Category] = file.Data
		}
	}
	return index, nil
})

// actionRuleGap classifies an enabled action rule without an expression: a
// stale 0.8.x copy of a built-in rule (the shipped packs give that ID an
// expression, or no longer ship it), or one of the operator's own, which
// records matches and cannot block (GAP-0360).
func (s *shippedRules) actionRuleGap(category string, rule RuleDefYAML) (stale, alertOnly bool) {
	if !actionRuleCategories[category] || strings.TrimSpace(rule.Expression) != "" ||
		(rule.Enabled != nil && !*rule.Enabled) || s.patternOnly[category][rule.ID] {
		return false, false
	}
	if s.withExpression[category][rule.ID] || slices.Contains(default08RuleIDs[category], rule.ID) {
		return true, false
	}
	return false, true
}

// actionRuleGaps counts the pack's stale and alert-only action rules.
func (rp *RulePack) actionRuleGaps() (stale, alertOnly int) {
	index, err := shippedRuleIndex()
	if err != nil || rp == nil {
		return 0, 0
	}
	for _, ruleFile := range rp.RuleFiles {
		if ruleFile == nil {
			continue
		}
		for _, rule := range ruleFile.Rules {
			isStale, isAlertOnly := index.actionRuleGap(ruleFile.Category, rule)
			if isStale {
				stale++
			}
			if isAlertOnly {
				alertOnly++
			}
		}
	}
	return stale, alertOnly
}

// RulePackRebase is the 1.0 copy of a custom pack whose action rule files
// are 0.8.x copies of the default pack's: in 1.0 those rules enforced
// nothing (GAP-0360). Each such file is rebuilt on the shipped default's,
// keeping the operator's own rules and the built-in rules they turned off.
type RulePackRebase struct {
	// Files holds every file of the rebased pack (slash-separated relative path).
	Files map[string][]byte
	// Digest is the FilesDigest of the rebased pack (hex).
	Digest string
	// Updated counts the built-in rules replaced by their 1.0 versions.
	Updated int
	// Carried names the operator's own rules carried into the 1.0 files,
	// Expressed those of them given an expression (a literal pattern, as an
	// argument of the command), AlertOnly those that still have none, and
	// Disabled the built-in rules the copy had removed.
	Carried, Expressed, AlertOnly, Disabled []string
}

// PlanRulePackRebase returns the rebased copy of the custom pack in dir, or
// nil when none of its action rule files is a stale 0.8.x copy.
func PlanRulePackRebase(dir string) (*RulePackRebase, error) {
	index, err := shippedRuleIndex()
	if err != nil {
		return nil, err
	}
	files, err := readRulePackTree(dir)
	if err != nil {
		return nil, err
	}
	plan := &RulePackRebase{Files: files}
	rebased := false
	for _, rel := range slices.Sorted(maps.Keys(files)) {
		if path.Dir(rel) != "rules" || path.Ext(rel) != ".yaml" || rel == "rules/local-patterns.yaml" {
			continue
		}
		var parsed RulesFileYAML
		if yaml.Unmarshal(files[rel], &parsed) != nil {
			continue // LoadRulePack reports it
		}
		shipped, ok := index.defaultFiles[parsed.Category]
		if !ok || !slices.ContainsFunc(parsed.Rules, func(rule RuleDefYAML) bool {
			stale, _ := index.actionRuleGap(parsed.Category, rule)
			return stale
		}) {
			continue
		}
		data, err := rebaseRuleFile(shipped, files[rel], parsed.Category, plan)
		if err != nil {
			return nil, fmt.Errorf("rebase %s: %w", rel, err)
		}
		files[rel] = data
		rebased = true
	}
	if !rebased {
		return nil, nil
	}
	staging, err := os.MkdirTemp("", "defenseclaw-rebase-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(staging)
	for rel, data := range files {
		target := filepath.Join(staging, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(target, data, 0o600); err != nil {
			return nil, err
		}
	}
	pack, err := LoadRulePack(staging)
	if err != nil {
		return nil, fmt.Errorf("the rebased pack does not load: %w", err)
	}
	plan.Digest = pack.FilesDigest()
	return plan, nil
}

// readRulePackTree reads every regular file under dir, within the loader's limits.
func readRulePackTree(dir string) (map[string][]byte, error) {
	files := map[string][]byte{}
	var total int64
	err := filepath.WalkDir(dir, func(full string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !entry.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, full)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if total += info.Size(); total > maxRulePackAggregateBytes || len(files) >= maxRulePackInventoryEntries {
			return errors.New("the rule pack is larger than a rule pack may be")
		}
		data, err := os.ReadFile(full)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = data
		return nil
	})
	return files, err
}

// rebaseRuleFile rebuilds a 0.8.x copy of an action rule file on the shipped
// default's: the built-in rules become their 1.0 versions (kept off when the
// copy turned them off or removed them) and the operator's own rules follow.
func rebaseRuleFile(shipped, custom []byte, category string, plan *RulePackRebase) ([]byte, error) {
	var base, old yaml.Node
	if err := yaml.Unmarshal(shipped, &base); err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(custom, &old); err != nil {
		return nil, err
	}
	baseRules, oldRules := yamlRulesSequence(&base), yamlRulesSequence(&old)
	if baseRules == nil || oldRules == nil {
		return nil, errors.New("no rules list")
	}
	legacyName, ok := legacy08FileNames[category]
	if !ok {
		return nil, fmt.Errorf("no 0.8.x baseline for category %s", category)
	}
	legacyBytes, err := legacy08RuleFiles.ReadFile("legacy08/" + legacyName)
	if err != nil {
		return nil, err
	}
	var legacy yaml.Node
	if err := yaml.Unmarshal(legacyBytes, &legacy); err != nil {
		return nil, err
	}
	legacyRules := map[string]*yaml.Node{}
	for _, item := range yamlRulesSequence(&legacy).Content {
		legacyRules[yamlScalarField(item, "id")] = item
	}
	builtin := map[string]*yaml.Node{}
	for _, item := range baseRules.Content {
		if id := yamlScalarField(item, "id"); id != "" {
			builtin[id] = item
		}
	}
	present := map[string]bool{}
	for _, item := range oldRules.Content {
		id := yamlScalarField(item, "id")
		present[id] = true
		switch {
		case builtin[id] != nil:
			plan.Updated++
			preserveRuleEdits(builtin[id], item, legacyRules[id])
		case slices.Contains(default08RuleIDs[category], id):
			plan.Updated++ // a 0.8.x rule 1.0 no longer ships
		default:
			plan.Carried = append(plan.Carried, id)
			if strings.TrimSpace(yamlScalarField(item, "expression")) == "" {
				if literal := literalPattern(yamlScalarField(item, "pattern")); category == "command" && literal != "" {
					setYAMLScalarField(item, "expression", "f.commands.exists(c, '"+literal+"' in c.argv)", "!!str")
					plan.Expressed = append(plan.Expressed, id)
				} else if yamlScalarField(item, "enabled") != "false" {
					plan.AlertOnly = append(plan.AlertOnly, id)
				}
			}
			baseRules.Content = append(baseRules.Content, item)
		}
	}
	for _, id := range default08RuleIDs[category] {
		if node := builtin[id]; node != nil && !present[id] {
			setYAMLScalarField(node, "enabled", "false", "!!bool")
			plan.Disabled = append(plan.Disabled, id)
		}
	}
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(&base); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// preserveRuleEdits applies only fields the operator changed against the
// shipped 0.8.x rule. Fields added in 1.0, including semantic expressions,
// remain on the new rule unless the operator explicitly supplied a value.
func preserveRuleEdits(current, custom, legacy *yaml.Node) {
	if legacy == nil {
		legacy = &yaml.Node{Kind: yaml.MappingNode}
	}
	keys := map[string]bool{}
	for i := 0; i+1 < len(custom.Content); i += 2 {
		keys[custom.Content[i].Value] = true
	}
	for i := 0; i+1 < len(legacy.Content); i += 2 {
		keys[legacy.Content[i].Value] = true
	}
	for key := range keys {
		if key == "id" {
			continue
		}
		oldValue, oldOK := yamlField(custom, key)
		baseValue, baseOK := yamlField(legacy, key)
		if yamlValuesEqual(oldValue, oldOK, baseValue, baseOK) {
			continue
		}
		if !oldOK {
			removeYAMLField(current, key)
			continue
		}
		setYAMLField(current, key, oldValue)
	}
}

func yamlField(mapping *yaml.Node, key string) (*yaml.Node, bool) {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil, false
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1], true
		}
	}
	return nil, false
}

func yamlValuesEqual(a *yaml.Node, aOK bool, b *yaml.Node, bOK bool) bool {
	if aOK != bOK {
		return false
	}
	if !aOK {
		return true
	}
	var av, bv any
	if a.Decode(&av) != nil || b.Decode(&bv) != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}

func setYAMLField(mapping *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			mapping.Content[i+1] = value
			return
		}
	}
	mapping.Content = append(mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
}

func removeYAMLField(mapping *yaml.Node, key string) {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			mapping.Content = append(mapping.Content[:i], mapping.Content[i+2:]...)
			return
		}
	}
}

// literalPattern is the text a pattern matches when it is a plain literal
// (optionally between \b word boundaries) that a CEL string holds as is,
// else "".
func literalPattern(pattern string) string {
	literal := strings.TrimSuffix(strings.TrimPrefix(pattern, `\b`), `\b`)
	if literal == "" || len(literal) > 256 || strings.ContainsAny(literal, `.^$*+?()[]{}|\'"`+" \t\r\n") {
		return ""
	}
	return literal
}

func yamlRulesSequence(document *yaml.Node) *yaml.Node {
	root := document
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(root.Content); index += 2 {
		if root.Content[index].Value == "rules" && root.Content[index+1].Kind == yaml.SequenceNode {
			return root.Content[index+1]
		}
	}
	return nil
}

func yamlScalarField(mapping *yaml.Node, key string) string {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return ""
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key && mapping.Content[index+1].Kind == yaml.ScalarNode {
			return mapping.Content[index+1].Value
		}
	}
	return ""
}

func setYAMLScalarField(mapping *yaml.Node, key, value, tag string) {
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			mapping.Content[index+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value}
			return
		}
	}
	// After the id, where a reader looks first.
	at := min(2, len(mapping.Content))
	mapping.Content = slices.Insert(mapping.Content, at,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value})
}
