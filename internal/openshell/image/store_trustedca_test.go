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

// The image store refuses Windows hosts (lock_windows.go), as in image_test.go.

//go:build !windows

package image

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

// recordFields102 are the record fields DefenseClaw 1.0.2 reads from
// images.json; its decoder refuses any other (DisallowUnknownFields).
var recordFields102 = map[string]bool{
	"tag": true, "image_id": true, "content_hash": true, "connector": true, "harness_version": true, "hook_contract": true,
	"base_image": true, "uid": true, "gid": true, "ingress_port": true, "defenseclaw_version": true, "fail_mode": true,
	"owner": true, "microvm": true, "built_at": true, "binaries": true, "network_binaries": true, "hook_fire_verified": true,
	"hook_fire_verified_at": true, "microvm_verified": true, "microvm_problem": true, "microvm_inconclusive": true,
}

// GAP-0071, GAP-0075: a downgrade to 1.0.2 opens the image store a 1.0.3
// build with trusted CAs wrote. images.json keeps the 1.0.2 record fields;
// the trusted CAs are in images-trusted-cas.json beside it, each bundle
// once, and the file goes when no record has any.
func TestStoreKeepsTrustedCAsBesideImagesJSON(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	pem := string(openshelltest.NewCA(t, "Corp Root CA").PEM)
	withCA := Record{Tag: "defenseclaw-sandbox-claudecode:aaaa", ContentHash: "aaaa", Connector: "claudecode", TrustedCAs: pem}
	sameCA := Record{Tag: "defenseclaw-sandbox-codex:bbbb", ContentHash: "bbbb", Connector: "codex", TrustedCAs: pem}
	plain := Record{Tag: "defenseclaw-sandbox-copilot:cccc", ContentHash: "cccc", Connector: "copilot"}
	for _, r := range []Record{withCA, sameCA, plain} {
		if err := s.Put(r); err != nil {
			t.Fatal(err)
		}
	}

	raw, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Images []map[string]json.RawMessage `json:"images"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Images) != 3 {
		t.Fatalf("images.json: %v %d records", err, len(doc.Images))
	}
	for _, r := range doc.Images {
		for k := range r {
			if !recordFields102[k] {
				t.Errorf("images.json record field %q: DefenseClaw 1.0.2 refuses it", k)
			}
		}
	}

	side := filepath.Join(dir, "sandboxes", trustedCAsFile)
	var cas trustedCAsDoc
	if data, err := os.ReadFile(side); err != nil || json.Unmarshal(data, &cas) != nil {
		t.Fatalf("%s: %v", side, err)
	}
	if fi, _ := os.Stat(side); fi == nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%s mode: %v", side, fi)
	}
	if len(cas.Bundles) != 1 || len(cas.Images) != 2 || cas.Images[withCA.Tag] != pemDigest(pem) || cas.Bundles[pemDigest(pem)] != pem {
		t.Fatalf("%s: %+v", side, cas)
	}
	for _, want := range []Record{withCA, sameCA, plain} {
		got, ok, err := s.Get(want.Tag)
		if err != nil || !ok || got.TrustedCAs != want.TrustedCAs {
			t.Fatalf("Get(%s) = %v %v, trusted CAs %q", want.Tag, ok, err, got.TrustedCAs)
		}
	}
	// update keeps them.
	if _, err := s.update(withCA.Tag, func(r *Record) error { r.HookFireVerified = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.Get(withCA.Tag); got.TrustedCAs != pem || !got.HookFireVerified {
		t.Fatalf("after update: %+v", got)
	}

	// A record the file names no bundle for has none: its image is built
	// again rather than run without them.
	if err := os.WriteFile(side, []byte(`{"version":1,"bundles":{},"images":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _, err := s.Get(withCA.Tag); err != nil || got.TrustedCAs != "" {
		t.Fatalf("no bundle named: %q %v", got.TrustedCAs, err)
	}

	// A malformed file stops the store, as a malformed images.json does.
	for name, data := range map[string]string{
		"unknown field":   `{"version":1,"bundles":{},"images":{},"extra":1}`,
		"version":         `{"version":2,"bundles":{},"images":{}}`,
		"digest mismatch": `{"version":1,"bundles":{"sha256:00":` + mustJSON(t, pem) + `},"images":{"` + withCA.Tag + `":"sha256:00"}}`,
		"missing bundle":  `{"version":1,"bundles":{},"images":{"` + withCA.Tag + `":"` + pemDigest(pem) + `"}}`,
	} {
		if err := os.WriteFile(side, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.List(); err == nil || !strings.Contains(err.Error(), trustedCAsFile) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Put writes it again; with no record left that has CAs it goes.
	if err := os.Remove(side); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(withCA); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(withCA.Tag, sameCA.Tag); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(side); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s after the last CA record: %v", side, err)
	}
	if rs, err := s.List(); err != nil || len(rs) != 1 || rs[0].Tag != plain.Tag {
		t.Fatalf("left: %v %v", rs, err)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
