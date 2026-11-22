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
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// gap0433PackCopy copies the shipped pack named tier to a temporary
// directory and returns the directory.
func gap0433PackCopy(t *testing.T, tier string) string {
	t.Helper()
	source := filepath.Join(guardrailPoliciesRoot(t), tier)
	target := filepath.Join(t.TempDir(), tier)
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.MkdirAll(filepath.Join(target, rel), 0o700)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(target, rel), data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return target
}

// gap0433AddKeyWord makes the pack in dir name word as a credential key: the
// rule's pattern finds it and its key vocabulary holds it.
func gap0433AddKeyWord(t *testing.T, dir, word string) {
	t.Helper()
	path := filepath.Join(dir, "rules", "secrets.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	start := strings.Index(text, "  - id: SEC-SECRET-ASSIGN\n")
	if start < 0 {
		t.Fatal("the pack has no SEC-SECRET-ASSIGN")
	}
	end := strings.Index(text[start+1:], "\n  - id: ")
	if end < 0 {
		end = len(text) - start - 1
	}
	rule := text[start : start+1+end]
	changed := strings.Replace(rule, "|credential)s?", "|credential|"+word+")s?", 1)
	if changed == rule {
		t.Fatal("the SEC-SECRET-ASSIGN pattern does not end its key words with credential")
	}
	if strings.Contains(changed, "    keys:\n      words: [") {
		changed = strings.Replace(changed, "    keys:\n      words: [", "    keys:\n      words: ["+word+", ", 1)
	} else {
		changed = strings.TrimRight(changed, "\n") + "\n    keys:\n      words: [password, passwd, pwd, passphrase, secret, token, apikey, privatekey, encryptionkey, signingkey, credential, " + word + "]\n"
	}
	if err := os.WriteFile(path, []byte(text[:start]+changed+text[start+1+end:]), 0o600); err != nil {
		t.Fatal(err)
	}
}

// gap0433Scan is the SEC-SECRET-ASSIGN finding of text under the pack in dir.
func gap0433Scan(t *testing.T, dir, text string) bool {
	t.Helper()
	rp, err := guardrail.LoadRulePack(dir)
	if err != nil {
		t.Fatalf("load %s: %v", dir, err)
	}
	compiled, err := compileRulePackCategories(rp)
	if err != nil {
		t.Fatalf("compile %s: %v", dir, err)
	}
	return slices.ContainsFunc(scanRuleCategories(compiled.categories, text, "write_file"), func(finding RuleFinding) bool {
		return finding.RuleID == secretAssignmentRuleID
	})
}

// TestGAP0433PackKeyWordChangesTheVerdict: SEC-SECRET-ASSIGN's key words are
// rule pack data. A pack that adds a key word (pin) to the rule finds a
// random value assigned to it; the shipped pack does not. At 1.0.10 the
// words were a Go map, so a pack could widen the pattern and the precision
// stage still refused the key.
func TestGAP0433PackKeyWordChangesTheVerdict(t *testing.T) {
	const assignment = `db_pin = "Qw7xZp9LmK2vRt4sYh6N"`
	shipped := gap0433PackCopy(t, "default")
	if gap0433Scan(t, shipped, assignment) {
		t.Fatalf("the shipped default pack flags %q", assignment)
	}
	widened := gap0433PackCopy(t, "default")
	gap0433AddKeyWord(t, widened, "pin")
	if !gap0433Scan(t, widened, assignment) {
		t.Fatalf("a pack whose SEC-SECRET-ASSIGN names the key word pin does not flag %q", assignment)
	}
	// The words the pack keeps still decide; a setting around one still
	// does not hold a credential.
	if !gap0433Scan(t, widened, `api_key = "Qw7xZp9LmK2vRt4sYh6N"`) {
		t.Fatal("the widened pack lost the api_key assignment")
	}
	if gap0433Scan(t, widened, `pin_count = "Qw7xZp9LmK2vRt4sYh6N"`) {
		t.Fatal("the widened pack flags pin_count, a setting")
	}
}

// TestGAP0433KeysAreReadOnlyByTheAssignmentRule: a keys block on another
// rule, or one with a word that is not a lower case word, refuses the pack.
func TestGAP0433KeysAreReadOnlyByTheAssignmentRule(t *testing.T) {
	for _, test := range []struct {
		name, from, to string
	}{
		{"other rule", "  - id: SEC-AWS-KEY\n", "  - id: SEC-AWS-KEY\n    keys:\n      words: [pin]\n"},
		{"upper case word", "      words: [password,", "      words: [PIN, password,"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := gap0433PackCopy(t, "default")
			path := filepath.Join(dir, "rules", "secrets.yaml")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := strings.Replace(string(data), test.from, test.to, 1)
			if changed == string(data) {
				t.Fatalf("pack text %q not found", test.from)
			}
			if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := guardrail.LoadRulePack(dir); err == nil {
				t.Fatal("the pack loaded")
			}
		})
	}
}
