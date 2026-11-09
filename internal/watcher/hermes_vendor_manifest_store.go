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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"
)

// hermesStoreFileName is the file, in the data directory, that keeps the last
// answer of the plugin scanner for each set of manifests.
const hermesStoreFileName = "hermes-plugin-entrypoints.json"

// hermesStoreMaxEntries bounds the manifests kept; the oldest is dropped.
const hermesStoreMaxEntries = 256

// hermesManifestDigest is the digest of the names and bytes of manifests, the
// key under which the scanner answer for them is kept.
func hermesManifestDigest(manifests map[string][]byte) string {
	names := make([]string, 0, len(manifests))
	for name := range manifests {
		names = append(names, name)
	}
	sort.Strings(names)
	digest := sha256.New()
	for _, name := range names {
		fmt.Fprintf(digest, "%s\x00%d\x00", name, len(manifests[name]))
		_, _ = digest.Write(manifests[name])
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// hermesStoredAnswer is one answer of the plugin scanner.
type hermesStoredAnswer struct {
	Entrypoints []string `json:"entrypoints"`
	Seen        int64    `json:"seen"`
}

// hermesAnswerStore keeps the last successful answer of the plugin scanner
// for each manifest digest, in memory and, when path is set, in a file that
// outlives the process. It is read only while the scanner cannot answer: a
// scanner that answers is always believed over the store, so the store never
// decides what a scan reports; it only says what the scanner last said about
// these exact manifest bytes.
type hermesAnswerStore struct {
	mu      sync.Mutex
	path    string
	loaded  bool
	answers map[string]hermesStoredAnswer
}

func newHermesAnswerStore(dataDir string) *hermesAnswerStore {
	store := &hermesAnswerStore{answers: map[string]hermesStoredAnswer{}}
	if dataDir != "" {
		store.path = filepath.Join(dataDir, hermesStoreFileName)
	}
	return store
}

// load reads the file once. A missing or unreadable file is an empty store.
// The caller holds mu.
func (s *hermesAnswerStore) load() {
	if s.loaded {
		return
	}
	s.loaded = true
	if s.path == "" {
		return
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	// Each record is read on its own, the way the scanner reply is: a record
	// with no entrypoints list, a null list, a null element or a field of the
	// wrong type is damaged, not an empty answer, and is dropped alone, so its
	// manifests are unknown while the records of other digests still apply.
	// Only an explicit empty list is an answer.
	var file struct {
		Answers map[string]json.RawMessage `json:"answers"`
	}
	if json.Unmarshal(data, &file) != nil {
		return
	}
	damaged := 0
	for digest, raw := range file.Answers {
		var record struct {
			Entrypoints *[]*string `json:"entrypoints"`
			Seen        int64      `json:"seen"`
		}
		if json.Unmarshal(raw, &record) != nil || record.Entrypoints == nil {
			damaged++
			continue
		}
		entrypoints := make([]string, 0, len(*record.Entrypoints))
		intact := true
		for _, entrypoint := range *record.Entrypoints {
			if entrypoint == nil {
				intact = false
				break
			}
			entrypoints = append(entrypoints, *entrypoint)
		}
		if !intact {
			damaged++
			continue
		}
		s.answers[digest] = hermesStoredAnswer{Entrypoints: entrypoints, Seen: record.Seen}
	}
	if damaged > 0 {
		fmt.Fprintf(os.Stderr, "[watcher] hermes plugin scanner store: %d damaged record(s) ignored\n", damaged)
	}
}

// recall returns the last successful answer for digest.
func (s *hermesAnswerStore) recall(digest string) ([]string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	answer, ok := s.answers[digest]
	if !ok {
		return nil, false
	}
	return slices.Clone(answer.Entrypoints), true
}

// remember keeps entrypoints as the answer for digest, and writes the file
// when the answer is new or changed.
func (s *hermesAnswerStore) remember(digest string, entrypoints []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	if entrypoints == nil {
		entrypoints = []string{}
	}
	if known, ok := s.answers[digest]; ok && slices.Equal(known.Entrypoints, entrypoints) {
		// An answer given again is the most recent, so the bound drops the
		// manifests unseen for longest. The file is rewritten for this only when
		// the bound is reached, the one time recency decides what is kept.
		known.Seen = time.Now().UnixNano()
		s.answers[digest] = known
		if len(s.answers) < hermesStoreMaxEntries {
			return nil
		}
		return s.writeLocked()
	}
	s.answers[digest] = hermesStoredAnswer{Entrypoints: slices.Clone(entrypoints), Seen: time.Now().UnixNano()}
	for len(s.answers) > hermesStoreMaxEntries {
		oldest := ""
		for key, answer := range s.answers {
			if oldest == "" || answer.Seen < s.answers[oldest].Seen {
				oldest = key
			}
		}
		delete(s.answers, oldest)
	}
	return s.writeLocked()
}

// writeLocked writes the answers to the file, if the store has one. The
// caller holds mu.
func (s *hermesAnswerStore) writeLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := json.Marshal(map[string]any{"answers": s.answers, "sealed": hermesAnswersSeal(s.answers)})
	if err != nil {
		return err
	}
	return writeFileAtomic0600(s.path, data)
}

// hermesAnswersSeal is the digest of the answers a write puts in the file,
// kept in the file beside them as "sealed". It lets a reader that finds the
// file in a data directory the gateway no longer uses tell the last write of
// the gateway from a file of the same shape that the account edited or
// created since: such a file does not carry the digest of the answers it
// holds. It is computed from the answers, not from their JSON text, so it
// does not depend on how either side encodes them; the uninstall command
// computes the same digest (cli/defenseclaw/commands/cmd_uninstall.py,
// _plugin_answers_seal). Each field is length-prefixed and the keys are in
// byte order.
func hermesAnswersSeal(answers map[string]hermesStoredAnswer) string {
	keys := make([]string, 0, len(answers))
	for key := range answers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	digest := sha256.New()
	_, _ = digest.Write([]byte("defenseclaw-hermes-plugin-answers-v1\n"))
	for _, key := range keys {
		answer := answers[key]
		fmt.Fprintf(digest, "%d:%s%d:%d:", len(key), key, answer.Seen, len(answer.Entrypoints))
		for _, entrypoint := range answer.Entrypoints {
			fmt.Fprintf(digest, "%d:%s", len(entrypoint), entrypoint)
		}
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// writeFileAtomic0600 replaces path with data through a temporary file in the
// same folder, so a reader sees the old file or the new one.
func writeFileAtomic0600(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, err = tmp.Write(data)
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Chmod(name, 0o600)
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		if rmErr := os.Remove(name); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			return errors.Join(err, rmErr)
		}
	}
	return err
}
