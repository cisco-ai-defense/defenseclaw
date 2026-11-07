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

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

const approvedSourceConfigA = "config_version: 9\nguardrail:\n  mode: action\n"
const approvedSourceConfigB = "config_version: 9\nguardrail:\n  mode: observe\n"

// approvedSourceFolder stages an install state folder as the upgrade
// transaction leaves it after an ensure of config A: the approved copy, and a
// deployment record that names its digest next to values the refresh must not
// touch.
func approvedSourceFolder(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	record := `{"schema_version":1,"installed":true,"profile":"standalone","hashes":{"gateway":"` + strings.Repeat("a", 64) +
		`"},"managed_hooks_activation":{"state":"activated","target_count":3},"note":"a<b&c","approved_policy_sources":{"config":"` +
		configwrite.SHA256Hex([]byte(approvedSourceConfigA)) + `","manifest":"` + strings.Repeat("c", 64) + `"}}`
	for name, body := range map[string]string{managedDeploymentRecordFile: record, managedApprovedConfigFile: approvedSourceConfigA} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func readApprovedSourceFolder(t *testing.T, dir string) (copyBody string, record map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, managedApprovedConfigFile))
	if err != nil {
		t.Fatal(err)
	}
	recordRaw, err := os.ReadFile(filepath.Join(dir, managedDeploymentRecordFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(recordRaw, &record); err != nil {
		t.Fatalf("deployment record is not JSON after the refresh: %v", err)
	}
	return string(raw), record
}

func approvedConfigDigest(record map[string]any) string {
	sources, _ := record["approved_policy_sources"].(map[string]any)
	digest, _ := sources["config"].(string)
	return digest
}

// A then B: the approved source is B, the config the last ensure applied, and
// every other value of the deployment record keeps its value.
func TestRefreshManagedApprovedConfigSourceFollowsTheLastApprovedConfig(t *testing.T) {
	dir := approvedSourceFolder(t)
	if err := refreshManagedApprovedConfigSource(dir, []byte(approvedSourceConfigB)); err != nil {
		t.Fatal(err)
	}
	body, record := readApprovedSourceFolder(t, dir)
	if body != approvedSourceConfigB || approvedConfigDigest(record) != configwrite.SHA256Hex([]byte(approvedSourceConfigB)) {
		t.Fatalf("approved copy %q, record %v: want config B and its digest", body, record)
	}
	sources := record["approved_policy_sources"].(map[string]any)
	if sources["manifest"] != strings.Repeat("c", 64) {
		t.Fatalf("the approved manifest digest changed: %v", sources)
	}
	activation, _ := record["managed_hooks_activation"].(map[string]any)
	if record["installed"] != true || record["profile"] != "standalone" || record["note"] != "a<b&c" ||
		activation["state"] != "activated" || activation["target_count"] != float64(3) {
		t.Fatalf("other deployment record values changed: %v", record)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, managedDeploymentRecordFile))
	if strings.Contains(string(raw), `\u003c`) {
		t.Fatalf("deployment record text was HTML-escaped: %s", raw)
	}

	// Then back to A: a later ensure of an older config is the latest approval.
	if err := refreshManagedApprovedConfigSource(dir, []byte(approvedSourceConfigA)); err != nil {
		t.Fatal(err)
	}
	if body, record = readApprovedSourceFolder(t, dir); body != approvedSourceConfigA ||
		approvedConfigDigest(record) != configwrite.SHA256Hex([]byte(approvedSourceConfigA)) {
		t.Fatalf("approved copy %q, record %v: want config A again", body, record)
	}
}

// Benign twins: the config the record already names changes nothing, and a
// deployment that never published an approved source gets one, as the upgrade
// transaction gives it.
func TestRefreshManagedApprovedConfigSourceLeavesCurrentAndFillsMissingSources(t *testing.T) {
	dir := approvedSourceFolder(t)
	writes := 0
	restore := writeManagedApprovedSourceFile
	t.Cleanup(func() { writeManagedApprovedSourceFile = restore })
	writeManagedApprovedSourceFile = func(path string, data []byte, sibling string) error {
		writes++
		return restore(path, data, sibling)
	}
	if err := refreshManagedApprovedConfigSource(dir, []byte(approvedSourceConfigA)); err != nil {
		t.Fatal(err)
	}
	if writes != 0 {
		t.Fatalf("the current approved source was rewritten (%d writes)", writes)
	}

	bare := t.TempDir()
	if err := os.WriteFile(filepath.Join(bare, managedDeploymentRecordFile), []byte(`{"schema_version":1,"installed":true,"profile":"standalone"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := refreshManagedApprovedConfigSource(bare, []byte(approvedSourceConfigB)); err != nil {
		t.Fatal(err)
	}
	body, record := readApprovedSourceFolder(t, bare)
	if body != approvedSourceConfigB || approvedConfigDigest(record) != configwrite.SHA256Hex([]byte(approvedSourceConfigB)) {
		t.Fatalf("a deployment without an approved source: copy %q, record %v", body, record)
	}
}

// A failed ensure leaves both unchanged: the record cannot be written, so the
// approved copy goes back, and a copy that did not exist goes away.
func TestRefreshManagedApprovedConfigSourceKeepsBothWhenTheRecordCannotBeWritten(t *testing.T) {
	dir := approvedSourceFolder(t)
	rawBefore, _ := os.ReadFile(filepath.Join(dir, managedDeploymentRecordFile))
	restore := writeManagedApprovedSourceFile
	t.Cleanup(func() { writeManagedApprovedSourceFile = restore })
	writeManagedApprovedSourceFile = func(path string, data []byte, sibling string) error {
		if filepath.Base(path) == managedDeploymentRecordFile {
			return errors.New("access denied")
		}
		return restore(path, data, sibling)
	}
	if err := refreshManagedApprovedConfigSource(dir, []byte(approvedSourceConfigB)); err == nil {
		t.Fatal("a record that could not be written was reported as written")
	}
	body, _ := readApprovedSourceFolder(t, dir)
	rawAfter, _ := os.ReadFile(filepath.Join(dir, managedDeploymentRecordFile))
	if body != approvedSourceConfigA || string(rawAfter) != string(rawBefore) {
		t.Fatalf("a failed refresh changed the approved source: copy %q, record %s", body, rawAfter)
	}

	fresh := t.TempDir()
	if err := os.WriteFile(filepath.Join(fresh, managedDeploymentRecordFile), []byte(`{"installed":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := refreshManagedApprovedConfigSource(fresh, []byte(approvedSourceConfigB)); err == nil {
		t.Fatal("a record that could not be written was reported as written")
	}
	if _, err := os.Stat(filepath.Join(fresh, managedApprovedConfigFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an approved copy was left without its record: %v", err)
	}
}

// A record the refresh cannot read as a standalone one, or a path that is not
// a regular file, changes nothing: the ensure falls back to the upgrade
// transaction.
func TestRefreshManagedApprovedConfigSourceRefusesWhatItCannotBind(t *testing.T) {
	for name, record := range map[string]string{
		"secure client profile": `{"installed":true,"profile":"secure_client"}`,
		"not an object":         `[]`,
		"bad digest":            `{"installed":true,"approved_policy_sources":{"config":"zz"}}`,
		"unknown source":        `{"installed":true,"approved_policy_sources":{"other":"` + strings.Repeat("a", 64) + `"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, managedDeploymentRecordFile)
			if err := os.WriteFile(path, []byte(record), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := refreshManagedApprovedConfigSource(dir, []byte(approvedSourceConfigB)); err == nil {
				t.Fatal("the refresh accepted a record it cannot bind")
			}
			after, _ := os.ReadFile(path)
			if string(after) != record {
				t.Fatalf("the record changed: %s", after)
			}
			if _, err := os.Stat(filepath.Join(dir, managedApprovedConfigFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("an approved copy was written: %v", err)
			}
		})
	}
	if err := refreshManagedApprovedConfigSource("", []byte(approvedSourceConfigB)); err == nil {
		t.Fatal("an unknown install state folder was accepted")
	}
	if err := refreshManagedApprovedConfigSource(t.TempDir(), []byte(approvedSourceConfigB)); err == nil {
		t.Fatal("a missing deployment record was accepted")
	}

	linked := approvedSourceFolder(t)
	target := filepath.Join(t.TempDir(), "elsewhere.yaml")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(linked, managedApprovedConfigFile)
	if err := os.Remove(copyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, copyPath); err != nil {
		t.Skip("cannot create a link here:", err)
	}
	if err := refreshManagedApprovedConfigSource(linked, []byte(approvedSourceConfigB)); err == nil {
		t.Fatal("an approved copy that is a link was written through")
	}
	if got, _ := os.ReadFile(target); string(got) != "x" {
		t.Fatalf("the link target was written: %q", got)
	}
}
