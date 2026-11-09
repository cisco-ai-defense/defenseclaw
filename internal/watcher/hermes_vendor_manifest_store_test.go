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

package watcher

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The uninstall command computes the same digest to tell the last write of the
// gateway in a data directory it left from a file of the same structure the
// account edited or created (cli/tests/test_uninstall_moved_hermes_records.py,
// test_the_seal_is_the_one_the_gateway_writes, pins the same value).
func TestHermesAnswersSealIsTheDigestUninstallComputes(t *testing.T) {
	answers := map[string]hermesStoredAnswer{
		strings.Repeat("b", 64): {Entrypoints: []string{"plugins/a/__init__.py", "plugins/é/x.py"}, Seen: 1789012345678901234},
		strings.Repeat("a", 64): {Entrypoints: []string{}, Seen: 7},
	}
	const want = "ca761783fb55bdc977ddc51de8c6221df60de69801ff8ce3f7cb5eb5c9c75490"
	if got := hermesAnswersSeal(answers); got != want {
		t.Fatalf("seal = %s, want %s", got, want)
	}
}

func TestHermesAnswerStoreFileCarriesTheSealOfItsAnswersAndStillLoads(t *testing.T) {
	dir := t.TempDir()
	store := newHermesAnswerStore(dir)
	digest := strings.Repeat("c", 64)
	if err := store.remember(digest, []string{"plugins/a/__init__.py"}); err != nil {
		t.Fatal(err)
	}
	if err := store.remember(strings.Repeat("d", 64), nil); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, hermesStoreFileName))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Answers map[string]hermesStoredAnswer `json:"answers"`
		Sealed  string                        `json:"sealed"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Answers) != 2 || file.Sealed != hermesAnswersSeal(file.Answers) {
		t.Fatalf("file %s: sealed %q does not match its %d answers", data, file.Sealed, len(file.Answers))
	}

	got, ok := newHermesAnswerStore(dir).recall(digest)
	if !ok || !slices.Equal(got, []string{"plugins/a/__init__.py"}) {
		t.Fatalf("recall after reload = %v, %v", got, ok)
	}
}

// A change to the answers changes the seal, so a file edited after the write
// no longer carries the digest of what it holds.
func TestHermesAnswersSealChangesWithAnyAnswer(t *testing.T) {
	base := map[string]hermesStoredAnswer{"k": {Entrypoints: []string{"a", "b"}, Seen: 1}}
	for name, other := range map[string]map[string]hermesStoredAnswer{
		"entrypoint": {"k": {Entrypoints: []string{"a", "c"}, Seen: 1}},
		"seen":       {"k": {Entrypoints: []string{"a", "b"}, Seen: 2}},
		"key":        {"j": {Entrypoints: []string{"a", "b"}, Seen: 1}},
		"split":      {"k": {Entrypoints: []string{"ab"}, Seen: 1}},
		"extra":      {"k": {Entrypoints: []string{"a", "b"}, Seen: 1}, "l": {Entrypoints: []string{}, Seen: 1}},
	} {
		if hermesAnswersSeal(other) == hermesAnswersSeal(base) {
			t.Errorf("%s: seal did not change", name)
		}
	}
}
