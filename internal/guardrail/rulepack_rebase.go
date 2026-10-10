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
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"sync"
	"unicode"

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

// shippedRules indexes the rules of the packs this build ships.
type shippedRules struct {
	// withExpression and patternOnly map a category to the rule IDs some
	// shipped pack gives an expression, or ships without one (those have a
	// built-in owner, or are content rules, and need none).
	withExpression map[string]map[string]bool
	patternOnly    map[string]map[string]bool
	// builtin holds every shipped rule ID, of any category.
	builtin map[string]bool
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
		builtin:        map[string]bool{},
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
		for _, rule := range rules.Rules {
			index.builtin[rule.ID] = true
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

// ruleGap classifies an enabled rule without an expression. The engine blocks
// a tool call only with a semantic proof (the rule's expression, or a
// built-in owner of a shipped rule's ID); a pattern alone records a match on
// a tool call but never blocks one, where 0.8.x blocked it. A stale rule is a
// 0.8.x copy of a built-in command, path, agent-file or C2 rule (the shipped
// packs give that ID an expression, or no longer ship it) (GAP-0360); an
// alert-only rule is one of the operator's own, in any category (GAP-1225).
func (s *shippedRules) ruleGap(category string, rule RuleDefYAML) (stale, alertOnly bool) {
	if strings.TrimSpace(rule.Expression) != "" || (rule.Enabled != nil && !*rule.Enabled) ||
		s.patternOnly[category][rule.ID] {
		return false, false
	}
	if _, legacy := legacy08FileNames[category]; legacy &&
		(s.withExpression[category][rule.ID] || slices.Contains(default08RuleIDs[category], rule.ID)) {
		return true, false
	}
	return false, !s.builtin[rule.ID]
}

// ruleGaps counts the pack's stale and alert-only rules.
func (rp *RulePack) ruleGaps() (stale, alertOnly int) {
	index, err := shippedRuleIndex()
	if err != nil || rp == nil {
		return 0, 0
	}
	for _, ruleFile := range rp.RuleFiles {
		if ruleFile == nil {
			continue
		}
		for _, rule := range ruleFile.Rules {
			isStale, isAlertOnly := index.ruleGap(ruleFile.Category, rule)
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

// RulePackRebase is the 1.0 copy of a 0.8.x custom pack. A 0.8.x rule blocked
// a tool call with its pattern alone; in 1.0 only an expression can. An
// action rule file that is a 0.8.x copy of the default pack's enforced
// nothing (GAP-0360): it is rebuilt on the shipped default's, keeping the
// operator's own rules and the built-in rules they turned off. The
// operator's own rules in any file get an expression where one can be
// derived; the others are named (GAP-1225).
type RulePackRebase struct {
	// Files holds every file of the rebased pack (slash-separated relative
	// path); nil when no file changed and the pack is pinned as it is.
	Files map[string][]byte
	// Digest is the FilesDigest of the rebased pack (hex).
	Digest string
	// Updated counts the built-in rules replaced by their 1.0 versions.
	Updated int
	// Carried names the operator's own rules carried into rebuilt files,
	// Expressed the operator's own rules, and the built-in rules whose
	// pattern they changed, given an expression (a literal pattern, see
	// literalRuleExpression), AlertOnly the enabled ones that still have
	// none and only record a tool call's match, and Disabled the built-in
	// rules the copy had removed.
	Carried, Expressed, AlertOnly, Disabled []string
	// WholeArgument names the Expressed rules that match only a command
	// argument equal to their literal: the full form of the others did not
	// fit the pack's semantic cost budget (semantic_catalog_cost_limit).
	WholeArgument []string
	// Merged says, per rule file folded into another of its category, what
	// was done ("rules/b.yaml (category \"acme\") merged into rules/a.yaml;
	// 2 rule(s) kept"): 1.0 refuses two files of one category (GAP-1339).
	Merged []string
	// Linked names each link of the pack and its target ("rules/custom.yaml
	// -> shared/custom.yaml"): 1.0 refuses a link in a pack, so the copy
	// holds the file it points to in its place (GAP-1346).
	Linked []string
	// mergedAway holds the files Merged folded into another.
	mergedAway map[string]bool
	// literals counts the literal rules met so far, in order; from the
	// wholeArgumentFrom-th on (0: none) they get the whole-argument form.
	literals, wholeArgumentFrom int
}

// PlanRulePackRebase returns the 1.0 copy of the custom pack in dir, a plan
// without Files when it only names rules that stay detection-only for tool
// calls, or nil when the pack needs neither.
func PlanRulePackRebase(dir string) (*RulePackRebase, error) {
	plan, err := planRulePackRebase(dir, -1)
	var packErr *RulePackError
	if err == nil || !errors.As(err, &packErr) || packErr.Code != "semantic_catalog_cost_limit" {
		return plan, err
	}
	// The full literal forms do not fit the pack's semantic cost budget:
	// give it to as many literal rules as fit, in the order they are met,
	// and the others the whole-argument form (named in WholeArgument).
	// Fewer full forms cost less, so the most that fit is bisected.
	narrow, err := planRulePackRebase(dir, 0)
	if err != nil {
		return nil, err
	}
	best, low, high := narrow, 0, narrow.literals
	for low < high {
		mid := (low + high + 1) / 2
		candidate, err := planRulePackRebase(dir, mid)
		if err != nil {
			high = mid - 1
			continue
		}
		best, low = candidate, mid
	}
	return best, nil
}

func planRulePackRebase(dir string, fullLiterals int) (*RulePackRebase, error) {
	index, err := shippedRuleIndex()
	if err != nil {
		return nil, err
	}
	files, linked, err := readRulePackTree(dir)
	if err != nil {
		return nil, err
	}
	plan := &RulePackRebase{Files: files, Linked: linked}
	if fullLiterals >= 0 {
		plan.wholeArgumentFrom = fullLiterals + 1
	}
	if err := mergeDuplicateCategories(files, plan); err != nil {
		return nil, err
	}
	changed := len(plan.Merged) > 0 || len(linked) > 0
	for _, rel := range slices.Sorted(maps.Keys(files)) {
		if path.Dir(rel) != "rules" || path.Ext(rel) != ".yaml" || rel == "rules/local-patterns.yaml" {
			continue
		}
		var parsed RulesFileYAML
		if yaml.Unmarshal(files[rel], &parsed) != nil {
			continue // LoadRulePack reports it
		}
		has := func(stale bool) bool {
			return slices.ContainsFunc(parsed.Rules, func(rule RuleDefYAML) bool {
				isStale, isOwn := index.ruleGap(parsed.Category, rule)
				return isStale && stale || isOwn && !stale
			})
		}
		var data []byte
		var err error
		if shipped, ok := index.defaultFiles[parsed.Category]; ok && has(true) {
			data, err = rebaseRuleFile(shipped, files[rel], parsed.Category, plan)
		} else if has(false) {
			data, err = expressOwnRules(files[rel], parsed.Category, index, plan)
		}
		if err != nil {
			return nil, fmt.Errorf("rebase %s: %w", rel, err)
		}
		if data != nil {
			files[rel] = data
			changed = true
		}
	}
	if !changed {
		if len(plan.AlertOnly) == 0 {
			return nil, nil
		}
		plan.Files = nil
		return plan, nil
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

// RebaseLoadedRulePack applies the 0.8.x rebase to a validated loaded pack
// without changing its source directory. The caller must check the source
// pack's digest pin before using the returned pack.
func RebaseLoadedRulePack(dir string, source *RulePack) (*RulePack, error) {
	plan, err := PlanRulePackRebase(dir)
	if err != nil {
		return nil, err
	}
	if plan == nil || plan.Files == nil {
		return source, nil
	}
	currentDigest, err := RulePackDigest(dir)
	if err != nil {
		return nil, err
	}
	if currentDigest != source.FilesDigest() {
		return nil, fmt.Errorf("source rule pack changed while rebasing in memory")
	}
	// The loader records each rule file under the pack's resolved folder.
	absDir, err := filepath.EvalSymlinks(dir)
	if err == nil {
		absDir, err = filepath.Abs(absDir)
	}
	if err != nil {
		return nil, err
	}
	rebased := *source
	rebased.RuleFiles = make([]*RulesFileYAML, 0, len(source.RuleFiles))
	for _, original := range source.RuleFiles {
		rel, err := filepath.Rel(absDir, original.SourcePath)
		if err != nil {
			return nil, err
		}
		rel = filepath.ToSlash(rel)
		data, ok := plan.Files[rel]
		if !ok && plan.mergedAway[rel] {
			continue // its rules are in the file of its category
		}
		if !ok {
			return nil, fmt.Errorf("rebased rule pack is missing %s", rel)
		}
		var parsed RulesFileYAML
		if err := decodeStrictYAML(data, rel, &parsed); err != nil {
			return nil, err
		}
		parsed.SourcePath = original.SourcePath
		rebased.RuleFiles = append(rebased.RuleFiles, &parsed)
	}
	rebased.filesDigest = plan.Digest
	if err := rebased.Validate(); err != nil {
		return nil, err
	}
	return &rebased, nil
}

// mergeDuplicateCategories folds the rule files of a 0.8.x pack that share a
// category into the first of them, in file-name order: 0.8.x took such a pack
// (its gateway enforced only the last file of a category), 1.0 refuses it
// (duplicate_category), and the category is what the 1.0 engine keys its
// rules on (GAP-1339). Categories match trimmed and case-folded. The rules
// move as YAML nodes, every field and comment kept; a moved rule whose ID the
// file already has is dropped when it is the same rule and otherwise renamed
// with the stem of the file it came from. A merge that can not be done safely
// fails with the edit that makes the pack load.
func mergeDuplicateCategories(files map[string][]byte, plan *RulePackRebase) error {
	type ruleFile struct {
		rel, category string
		version       int
		document      yaml.Node
	}
	groups := map[string][]*ruleFile{}
	var order []string
	for _, rel := range slices.Sorted(maps.Keys(files)) {
		if path.Dir(rel) != "rules" || path.Ext(rel) != ".yaml" || rel == "rules/local-patterns.yaml" {
			continue
		}
		var header struct {
			Version  int    `yaml:"version"`
			Category string `yaml:"category"`
		}
		file := &ruleFile{rel: rel}
		if yaml.Unmarshal(files[rel], &header) != nil || yaml.Unmarshal(files[rel], &file.document) != nil {
			continue // LoadRulePack reports it
		}
		key := strings.ToLower(strings.TrimSpace(header.Category))
		if key == "" {
			continue
		}
		file.category, file.version = strings.TrimSpace(header.Category), header.Version
		if groups[key] == nil {
			order = append(order, key)
		}
		groups[key] = append(groups[key], file)
	}
	for _, key := range order {
		group := groups[key]
		if len(group) < 2 {
			continue
		}
		target := group[0]
		targetRules := yamlRulesSequence(&target.document)
		ids := map[string]*yaml.Node{}
		if targetRules != nil {
			for _, item := range targetRules.Content {
				ids[yamlScalarField(item, "id")] = item
			}
		}
		for _, file := range group[1:] {
			unsafe := func(reason string) error {
				return fmt.Errorf("%s (category %q) can not be merged into %s, %s. Categories must be unique in "+
					"1.0: move the rules of %s into %s and delete %s, then run the upgrade again",
					file.rel, file.category, target.rel, reason, file.rel, target.rel, file.rel)
			}
			rules := yamlRulesSequence(&file.document)
			switch {
			case targetRules == nil || rules == nil:
				return unsafe("as one of them has no rules list")
			case file.version != target.version:
				return unsafe(fmt.Sprintf("as their versions differ (%d and %d)", file.version, target.version))
			case len(targetRules.Content)+len(rules.Content) > maxRulesPerFile:
				return unsafe(fmt.Sprintf("which would then have more than %d rules", maxRulesPerFile))
			}
			if root := yamlDocumentRoot(&file.document); root.Kind == yaml.MappingNode {
				for index := 0; index+1 < len(root.Content); index += 2 {
					switch name := root.Content[index].Value; name {
					case "version", "category", "rules":
					default:
						return unsafe(fmt.Sprintf("as it also sets %q", name))
					}
				}
			}
			kept, same := 0, 0
			var renamed []string
			for _, item := range rules.Content {
				id := yamlScalarField(item, "id")
				if existing := ids[id]; existing != nil && id != "" {
					if yamlValuesEqual(item, true, existing, true) {
						same++
						continue
					}
					stem := strings.TrimSuffix(path.Base(file.rel), ".yaml")
					fresh := id + "-" + stem
					for suffix := 2; ids[fresh] != nil; suffix++ {
						fresh = fmt.Sprintf("%s-%s-%d", id, stem, suffix)
					}
					setYAMLScalarField(item, "id", fresh, "!!str")
					renamed = append(renamed, id+" is now "+fresh)
					id = fresh
				}
				ids[id] = item
				targetRules.Content = append(targetRules.Content, item)
				kept++
			}
			line := fmt.Sprintf("%s (category %q) merged into %s; %d rule(s) kept", file.rel, file.category, target.rel, kept)
			if same > 0 {
				line += fmt.Sprintf(", %d identical one(s) were already there", same)
			}
			if len(renamed) > 0 {
				line += fmt.Sprintf(" (renamed, as %s has the ID: %s)", target.rel, strings.Join(renamed, ", "))
			}
			plan.Merged = append(plan.Merged, line)
			if plan.mergedAway == nil {
				plan.mergedAway = map[string]bool{}
			}
			plan.mergedAway[file.rel] = true
			delete(files, file.rel)
		}
		data, err := encodeRuleFile(&target.document)
		if err != nil {
			return fmt.Errorf("merge into %s: %w", target.rel, err)
		}
		files[target.rel] = data
	}
	return nil
}

// readRulePackTree reads the files of the pack in dir, within the loader's
// limits, the way the 0.8.x loader read them: through links (GAP-1346). 1.0
// refuses a link in a pack, so the 1.0 copy holds the file a link points to
// in its place, and leaves out a YAML file outside the 1.0 layout that only a
// link reaches. A link that does not resolve, leads out of the pack or loops
// fails the rebase: its copy would miss rules 0.8.x enforced. linked names
// each link and its target.
func readRulePackTree(dir string) (files map[string][]byte, linked []string, err error) {
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, nil, err
	}
	type treeFile struct {
		real    string
		data    []byte
		viaLink bool
	}
	tree := map[string]treeFile{}
	var targets []string
	var total int64
	entries := 0
	read := func(rel, real string, viaLink bool) error {
		handle, err := openRulePackFile(real)
		if err != nil {
			return fmt.Errorf("read %s: %w", rel, err)
		}
		defer handle.Close()
		if info, err := handle.Stat(); err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("read %s: not a regular file", rel)
		}
		data, err := io.ReadAll(io.LimitReader(handle, maxRulePackAggregateBytes-total+1))
		if err != nil {
			return fmt.Errorf("read %s: %w", rel, err)
		}
		if total += int64(len(data)); total > maxRulePackAggregateBytes {
			return errors.New("the rule pack is larger than a rule pack may be")
		}
		tree[rel] = treeFile{real: real, data: data, viaLink: viaLink}
		return nil
	}
	var walk func(real, rel string, ancestors []string, viaLink bool) error
	walk = func(real, rel string, ancestors []string, viaLink bool) error {
		list, err := os.ReadDir(real)
		if err != nil {
			return err
		}
		for _, entry := range list {
			if entries++; entries > maxRulePackInventoryEntries {
				return errors.New("the rule pack is larger than a rule pack may be")
			}
			full, name := filepath.Join(real, entry.Name()), path.Join(rel, entry.Name())
			mode := entry.Type()
			switch {
			case mode.IsDir():
				if err := walk(full, name, append(ancestors[:len(ancestors):len(ancestors)], full), viaLink); err != nil {
					return err
				}
				continue
			case mode.IsRegular():
				if err := read(name, full, viaLink); err != nil {
					return err
				}
				continue
			case mode&(fs.ModeSymlink|fs.ModeIrregular) == 0:
				continue // a socket, pipe or device is no rule file
			}
			// A link (or a Windows junction).
			target, err := filepath.EvalSymlinks(full)
			if err != nil {
				return fmt.Errorf("%s is a link that does not resolve (its target is missing, or the links loop): "+
					"point it at the file, or remove it, then run the upgrade again", name)
			}
			inside, ok := pathWithin(root, target)
			if !ok {
				return fmt.Errorf("%s links to %s, outside the rule pack %s, and 1.0 reads no file outside a pack: "+
					"replace the link with the file it points to, then run the upgrade again", name, target, root)
			}
			info, err := os.Stat(target)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			linked = append(linked, name+" -> "+inside)
			targets = append(targets, target)
			switch {
			case info.IsDir():
				if slices.Contains(ancestors, target) {
					return fmt.Errorf("%s links to %s, a folder it is in (a loop): remove the link, then run the "+
						"upgrade again", name, inside)
				}
				err = walk(target, name, append(ancestors[:len(ancestors):len(ancestors)], target), true)
			case info.Mode().IsRegular():
				err = read(name, target, true)
			default:
				err = fmt.Errorf("%s links to %s, which is not a file or a folder", name, inside)
			}
			if err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root, "", []string{root}, false); err != nil {
		return nil, nil, err
	}
	files = make(map[string][]byte, len(tree))
	for rel, file := range tree {
		extension := strings.ToLower(path.Ext(rel))
		stray := (extension == ".yaml" || extension == ".yml") && !isRecognizedRulePackYAML(rel)
		if stray && !file.viaLink && slices.ContainsFunc(targets, func(target string) bool {
			_, ok := pathWithin(target, file.real)
			return ok
		}) {
			continue // the copy holds it where the link was
		}
		files[rel] = file.data
	}
	return files, linked, nil
}

// pathWithin returns target relative to root (slash-separated) when target
// is root or below it.
func pathWithin(root, target string) (string, bool) {
	rel, err := filepath.Rel(root, target)
	if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(rel), true
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
			if preserveRuleEdits(builtin[id], item, legacyRules[id]) {
				// The operator's own 0.8.x regex blocked on its own; derive
				// its expression or name it as alert-only (GAP-1314).
				expressOwnRule(builtin[id], plan)
			}
		case slices.Contains(default08RuleIDs[category], id):
			plan.Updated++ // a 0.8.x rule 1.0 no longer ships
		default:
			plan.Carried = append(plan.Carried, id)
			expressOwnRule(item, plan)
			baseRules.Content = append(baseRules.Content, item)
		}
	}
	for _, id := range default08RuleIDs[category] {
		if node := builtin[id]; node != nil && !present[id] {
			setYAMLScalarField(node, "enabled", "false", "!!bool")
			plan.Disabled = append(plan.Disabled, id)
		}
	}
	return encodeRuleFile(&base)
}

// expressOwnRules gives the operator's own rules in a rule file that is not
// a 0.8.x copy of a default one their expression (expressOwnRule). It
// returns nil when no rule got one, so the file is kept byte for byte.
func expressOwnRules(custom []byte, category string, index *shippedRules, plan *RulePackRebase) ([]byte, error) {
	var document yaml.Node
	if err := yaml.Unmarshal(custom, &document); err != nil {
		return nil, err
	}
	rules := yamlRulesSequence(&document)
	if rules == nil {
		return nil, errors.New("no rules list")
	}
	expressed := false
	for _, item := range rules.Content {
		var rule RuleDefYAML
		if item.Decode(&rule) != nil {
			continue // LoadRulePack reports it
		}
		if _, own := index.ruleGap(category, rule); own && expressOwnRule(item, plan) {
			expressed = true
		}
	}
	if !expressed {
		return nil, nil
	}
	return encodeRuleFile(&document)
}

// expressOwnRule gives one of the operator's own enabled rules without an
// expression the one its pattern implies when that pattern is a literal
// (literalRuleExpression), which blocks as the 0.8.x pattern did. A rule
// with any other pattern keeps only its pattern and is named in AlertOnly:
// in 1.0 it records a tool call's match and never blocks.
func expressOwnRule(item *yaml.Node, plan *RulePackRebase) bool {
	if strings.TrimSpace(yamlScalarField(item, "expression")) != "" || yamlRuleDisabled(item) {
		return false
	}
	id := yamlScalarField(item, "id")
	if literal, before, after := literalPattern(yamlScalarField(item, "pattern")); literal != "" {
		plan.literals++
		full := plan.wholeArgumentFrom == 0 || plan.literals < plan.wholeArgumentFrom
		if !full {
			plan.WholeArgument = append(plan.WholeArgument, id)
		}
		setYAMLScalarField(item, "expression", literalRuleExpression(literal, before, after, full), "!!str")
		plan.Expressed = append(plan.Expressed, id)
		return true
	}
	plan.AlertOnly = append(plan.AlertOnly, id)
	return false
}

func yamlRuleDisabled(item *yaml.Node) bool {
	value, ok := yamlField(item, "enabled")
	var enabled bool
	return ok && value.Decode(&enabled) == nil && !enabled
}

func encodeRuleFile(document *yaml.Node) ([]byte, error) {
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(document); err != nil {
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
// It reports whether the operator changed the pattern without giving an
// expression: the rule then has no expression and needs one of its own.
func preserveRuleEdits(current, custom, legacy *yaml.Node) (ownPattern bool) {
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
	// A changed 0.8.x regex cannot inherit the new semantic expression:
	// that expression can enforce independently of the operator's pattern.
	customPattern, customHasPattern := yamlField(custom, "pattern")
	legacyPattern, legacyHasPattern := yamlField(legacy, "pattern")
	_, customHasExpression := yamlField(custom, "expression")
	if !yamlValuesEqual(customPattern, customHasPattern, legacyPattern, legacyHasPattern) && !customHasExpression {
		removeYAMLField(current, "expression")
		ownPattern = true
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
	return ownPattern
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

// literalPattern is the text a pattern matches when it is a case-sensitive
// literal (escaped metacharacters such as \. included, optionally after
// and before \b word boundaries, reported in before and after) that a CEL
// string holds as is, else "". The literal has no quote, backslash, space
// or unprintable character, so it goes into a CEL string unescaped.
func literalPattern(pattern string) (literal string, before, after bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return "", false, false
	}
	parts := []*syntax.Regexp{re}
	if re.Op == syntax.OpConcat {
		parts = re.Sub
	}
	if len(parts) > 1 && parts[0].Op == syntax.OpWordBoundary {
		parts, before = parts[1:], true
	}
	if len(parts) > 1 && parts[len(parts)-1].Op == syntax.OpWordBoundary {
		parts, after = parts[:len(parts)-1], true
	}
	if len(parts) != 1 || parts[0].Op != syntax.OpLiteral || parts[0].Flags&syntax.FoldCase != 0 {
		return "", false, false
	}
	literal = string(parts[0].Rune)
	if literal == "" || len(literal) > 256 || strings.ContainsAny(literal, `\'"`) ||
		strings.ContainsFunc(literal, func(r rune) bool { return unicode.IsSpace(r) || !unicode.IsPrint(r) }) {
		return "", false, false
	}
	return literal, before, after
}

// literalRuleExpression is the expression of a carried literal rule. 0.8.x
// ran a rule's pattern over the text of a tool call's arguments
// (internal/gateway/rules.go scanRuleCategories at tag 0.8.9), so a plain
// literal matched anywhere in it. The full form keeps that as far as the 1.0
// facts tell: a command argument that starts or ends with the literal (so
// is, or names a file such as literal.txt), or a file path or network host
// of the call that contains it. A \b word boundary meant a word boundary in
// 0.8.x (Go's ASCII \b) and still does: an argument must then start (\b
// before), end (\b after) or be (both) the literal, and a path or host must
// hold it as a word. A literal inside a longer argument that is neither a
// path nor a URL (echo xLITERALy) is not matched; the rule's pattern still
// records it. The whole-argument form (full false) matches only a command
// argument equal to the literal.
func literalRuleExpression(literal string, before, after, full bool) string {
	quoted := "'" + literal + "'"
	if !full {
		return "f.commands.exists(c, " + quoted + " in c.argv)"
	}
	if !before && !after {
		return "f.commands.exists(c, c.argv.exists(a, a.startsWith(" + quoted + ") || a.endsWith(" + quoted + "))) || " +
			"f.paths.exists(p, p.value.contains(" + quoted + ")) || f.network.exists(n, n.host.contains(" + quoted + "))"
	}
	argument := "f.commands.exists(c, " + quoted + " in c.argv)"
	switch {
	case before && !after:
		argument = "f.commands.exists(c, c.argv.exists(a, a.startsWith(" + quoted + ")))"
	case after && !before:
		argument = "f.commands.exists(c, c.argv.exists(a, a.endsWith(" + quoted + ")))"
	}
	word := regexp.QuoteMeta(literal)
	if before {
		word = `\b` + word
	}
	if after {
		word += `\b`
	}
	// A raw CEL string keeps the backslashes; the literal has no quote.
	word = "r'" + word + "'"
	return argument + " || f.paths.exists(p, p.value.matches(" + word + ")) || f.network.exists(n, n.host.matches(" + word + "))"
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
