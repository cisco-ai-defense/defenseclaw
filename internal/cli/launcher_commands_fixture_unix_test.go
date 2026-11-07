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

//go:build linux || darwin

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// launcherCommandsFixture is what docs-site/scripts/test-docs-claims.ts reads
// as the commands a managed user can and cannot run: the offered table of
// launcher.go, and the commands of the gateway's own tree it refuses. Run the
// test with DEFENSECLAW_UPDATE_LAUNCHER_REFUSAL=1 to rewrite the file after the
// table or the tree changes on purpose, then update the pages the docs gate
// names.
const launcherCommandsFixture = "testdata/launcher_commands.json"

type launcherCommandsDoc struct {
	Offered []string `json:"offered"`
	Refused []string `json:"refused"`
}

func launcherCommandsFromCode() launcherCommandsDoc {
	doc := launcherCommandsDoc{Offered: []string{}, Refused: []string{}}
	firstWords := map[string]bool{}
	for _, offer := range launcherOffered {
		doc.Offered = append(doc.Offered, offer.Name)
		firstWords[offer.Name] = true
		for _, match := range offer.Match {
			firstWords[match[0]] = true
		}
	}
	refused := map[string]bool{}
	for _, command := range rootCmd.Commands() {
		name := command.Name()
		if command.Hidden || name == "help" || name == "completion" || firstWords[name] {
			continue
		}
		refused[name] = true
	}
	for _, name := range launcherRefusedByName {
		refused[name] = true
	}
	for name := range refused {
		doc.Refused = append(doc.Refused, name)
	}
	slices.Sort(doc.Refused)
	return doc
}

func TestLauncherCommandsFixture(t *testing.T) {
	doc := launcherCommandsFromCode()
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("DEFENSECLAW_UPDATE_LAUNCHER_REFUSAL") == "1" {
		if err := os.WriteFile(launcherCommandsFixture, buffer.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(filepath.Clean(launcherCommandsFixture))
	if err != nil {
		t.Fatalf("read %s: %v", launcherCommandsFixture, err)
	}
	if !bytes.Equal(want, buffer.Bytes()) {
		t.Fatalf("the commands the launcher offers or refuses changed: %s holds\n%s\nthe code gives\n%s\nrewrite it with DEFENSECLAW_UPDATE_LAUNCHER_REFUSAL=1 and update the docs pages (npm run test:docs-claims in docs-site)", launcherCommandsFixture, want, buffer.Bytes())
	}
}

// Every command the table offers runs, and every command the fixture lists as
// refused is refused.
func TestLauncherOfferedTableAgreesWithLauncherOffers(t *testing.T) {
	for _, offer := range launcherOffered {
		args := [][]string{{offer.Name}}
		if offer.Name == "guardrail profile explain" {
			args = [][]string{{"guardrail", "profile", "explain"}}
		}
		for _, match := range offer.Match {
			args = append(args, match)
		}
		for _, a := range args {
			if !launcherOffers(a) {
				t.Errorf("launcherOffers(%v) = false for the offered %q", a, offer.Name)
			}
		}
	}
	for _, name := range launcherCommandsFromCode().Refused {
		if launcherOffers([]string{name}) {
			t.Errorf("launcherOffers([%q]) = true for a command listed as refused", name)
		}
	}
}
