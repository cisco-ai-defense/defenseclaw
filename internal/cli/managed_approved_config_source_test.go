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
	"context"
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
	if err := refreshManagedApprovedConfigSource(dir, approvedConfigAt(t, approvedSourceConfigB), []byte(approvedSourceConfigB)); err != nil {
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
	if err := refreshManagedApprovedConfigSource(dir, approvedConfigAt(t, approvedSourceConfigA), []byte(approvedSourceConfigA)); err != nil {
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
		if filepath.Base(path) != managedApprovedProofFile { // the proof is the one write a current source may still get
			writes++
		}
		return restore(path, data, sibling)
	}
	if err := refreshManagedApprovedConfigSource(dir, approvedConfigAt(t, approvedSourceConfigA), []byte(approvedSourceConfigA)); err != nil {
		t.Fatal(err)
	}
	if writes != 0 {
		t.Fatalf("the current approved source was rewritten (%d writes)", writes)
	}

	bare := t.TempDir()
	if err := os.WriteFile(filepath.Join(bare, managedDeploymentRecordFile), []byte(`{"schema_version":1,"installed":true,"profile":"standalone"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := refreshManagedApprovedConfigSource(bare, approvedConfigAt(t, approvedSourceConfigB), []byte(approvedSourceConfigB)); err != nil {
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
	if err := refreshManagedApprovedConfigSource(dir, approvedConfigAt(t, approvedSourceConfigB), []byte(approvedSourceConfigB)); err == nil {
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
	if err := refreshManagedApprovedConfigSource(fresh, approvedConfigAt(t, approvedSourceConfigB), []byte(approvedSourceConfigB)); err == nil {
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
		"null record":           `null`,
		"null source record":    `{"installed":true,"profile":"standalone","approved_policy_sources":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, managedDeploymentRecordFile)
			if err := os.WriteFile(path, []byte(record), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := refreshManagedApprovedConfigSource(dir, approvedConfigAt(t, approvedSourceConfigB), []byte(approvedSourceConfigB)); err == nil {
				t.Fatal("the refresh accepted a record it cannot bind")
			}
			if changed, err := healManagedApprovedConfigSource(dir, approvedConfigAt(t, approvedSourceConfigB), []byte(approvedSourceConfigB)); err == nil || changed {
				t.Fatalf("the heal accepted a record it cannot bind: changed=%v err=%v", changed, err)
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
	if err := refreshManagedApprovedConfigSource("", approvedConfigAt(t, approvedSourceConfigB), []byte(approvedSourceConfigB)); err == nil {
		t.Fatal("an unknown install state folder was accepted")
	}
	if err := refreshManagedApprovedConfigSource(t.TempDir(), approvedConfigAt(t, approvedSourceConfigB), []byte(approvedSourceConfigB)); err == nil {
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
	if err := refreshManagedApprovedConfigSource(linked, approvedConfigAt(t, approvedSourceConfigB), []byte(approvedSourceConfigB)); err == nil {
		t.Fatal("an approved copy that is a link was written through")
	}
	if got, _ := os.ReadFile(target); string(got) != "x" {
		t.Fatalf("the link target was written: %q", got)
	}
}

// approvedRepairRestores is what Setup /repair does with the approved config
// source over a config.yaml the generation record calls a hand edit
// (Get-DefenseClawApprovedPolicySource): the copy is restored only when its
// digest is the one deployment.json records.
func approvedRepairRestores(t *testing.T, dir string) string {
	t.Helper()
	body, record := readApprovedSourceFolder(t, dir)
	if approvedConfigDigest(record) != configwrite.SHA256Hex([]byte(body)) {
		t.Fatal("Repair would refuse a copy its record does not name")
	}
	return body
}

// A then B (the older build records A and leaves it), a binary-only upgrade
// and a compliant ensure of the same B, then a hand edit and a Repair: the
// heal at the end of that compliant ensure makes B the approved source, so
// Repair restores B, not A.
func TestHealManagedApprovedConfigSourceReplacesAnOlderApprovedConfigBeforeRepair(t *testing.T) {
	dir := approvedSourceFolder(t) // the older build approved A; B is installed
	if got := approvedRepairRestores(t, dir); got != approvedSourceConfigA {
		t.Fatalf("setup: the stale source is %q", got)
	}
	changed, err := healManagedApprovedConfigSource(dir, approvedConfigAt(t, approvedSourceConfigB), []byte(approvedSourceConfigB))
	if err != nil || !changed {
		t.Fatalf("heal: changed=%v err=%v", changed, err)
	}
	if got := approvedRepairRestores(t, dir); got != approvedSourceConfigB {
		t.Fatalf("Repair after a hand edit restores %q, want the installed config B", got)
	}
	_, record := readApprovedSourceFolder(t, dir)
	if sources := record["approved_policy_sources"].(map[string]any); sources["manifest"] != strings.Repeat("c", 64) {
		t.Fatalf("the approved manifest digest changed: %v", sources)
	}
}

// Benign twins: a current source is not rewritten, a deployment that records no
// approved config source (or has no record at all) is left exactly as it is.
func TestHealManagedApprovedConfigSourceLeavesWhatItDoesNotOwn(t *testing.T) {
	writes := 0
	restore := writeManagedApprovedSourceFile
	t.Cleanup(func() { writeManagedApprovedSourceFile = restore })
	writeManagedApprovedSourceFile = func(path string, data []byte, sibling string) error {
		if filepath.Base(path) != managedApprovedProofFile { // the proof is the one write a current source may still get
			writes++
		}
		return restore(path, data, sibling)
	}

	dir := approvedSourceFolder(t)
	if changed, err := healManagedApprovedConfigSource(dir, approvedConfigAt(t, approvedSourceConfigA), []byte(approvedSourceConfigA)); err != nil || changed || writes != 0 {
		t.Fatalf("a current source was rewritten: changed=%v err=%v writes=%d", changed, err, writes)
	}

	none := t.TempDir()
	record := `{"installed":true,"profile":"standalone","hashes":{}}`
	if err := os.WriteFile(filepath.Join(none, managedDeploymentRecordFile), []byte(record), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := healManagedApprovedConfigSource(none, approvedConfigAt(t, approvedSourceConfigB), []byte(approvedSourceConfigB)); err != nil || changed || writes != 0 {
		t.Fatalf("a deployment without an approved source was changed: changed=%v err=%v writes=%d", changed, err, writes)
	}
	if after, _ := os.ReadFile(filepath.Join(none, managedDeploymentRecordFile)); string(after) != record {
		t.Fatalf("the record changed: %s", after)
	}
	if _, err := os.Stat(filepath.Join(none, managedApprovedConfigFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an approved copy was created: %v", err)
	}

	if changed, err := healManagedApprovedConfigSource(t.TempDir(), approvedConfigAt(t, approvedSourceConfigB), []byte(approvedSourceConfigB)); err != nil || changed {
		t.Fatalf("a folder without a deployment record: changed=%v err=%v", changed, err)
	}
	if _, err := healManagedApprovedConfigSource("", approvedConfigAt(t, approvedSourceConfigB), []byte(approvedSourceConfigB)); err == nil {
		t.Fatal("an unknown install state folder was accepted")
	}
}

// stageConfigGeneration writes the config.generation.json a writer leaves for
// recordedBody, with the given actor.
func stageConfigGeneration(t *testing.T, configPath, recordedBody, actor string) {
	t.Helper()
	previous, _ := configwrite.ReadGenerationState(configPath) // a writer advances the counter by one
	record := map[string]any{
		"generation": previous.Generation + 1, "config_sha256": configwrite.SHA256Hex([]byte(recordedBody)), "actor": actor, "written_at": "2026-11-07T00:00:00Z",
	}
	if previous.ConfigSHA256 != "" { // the digest a writer finds in the record it replaces
		record["previous_config_sha256"] = previous.ConfigSHA256
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configwrite.GenerationPath(configPath), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// approvedConfigAt stages a config.yaml holding body that config.generation.json
// records as a lifecycle write, and returns its path: the config a lifecycle
// run has just applied.
func approvedConfigAt(t *testing.T, body string) string {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	stageConfigGeneration(t, configPath, body, "lifecycle")
	return configPath
}

// lockProbe is the lifecycle lock of a heal: it counts how often it was taken.
type lockProbe struct {
	acquired, released int
	err                error
}

func (p *lockProbe) acquire() (func(), error) {
	if p.err != nil {
		return nil, p.err
	}
	p.acquired++
	return func() { p.released++ }, nil
}

// A stale source (the older build approved A, B is installed) is replaced
// only by bytes the generation record binds to a lifecycle write, as the
// verify of the run accepted them. An edit after the verify, a hand-edit
// record, a missing record and a link in place of config.yaml all leave A and
// fail the heal, so the run cannot report success while A stays restorable.
func TestHealManagedApprovedConfigSourcePublishesOnlyWhatTheGenerationBinds(t *testing.T) {
	for _, tc := range []struct {
		name, installed, recorded, actor string
		noRecord, link                   bool
		wantCopy                         string
		wantErr                          bool
	}{
		{name: "config the lifecycle recorded", installed: approvedSourceConfigB, recorded: approvedSourceConfigB, actor: "lifecycle", wantCopy: approvedSourceConfigB},
		{name: "edited after the verify", installed: approvedSourceConfigB + "# edit\n", recorded: approvedSourceConfigB, actor: "lifecycle", wantCopy: approvedSourceConfigA, wantErr: true},
		{name: "recorded as a hand edit", installed: approvedSourceConfigB, recorded: approvedSourceConfigB, actor: configwrite.ActorUnattributedHandEdit, wantCopy: approvedSourceConfigA, wantErr: true},
		{name: "no generation record", installed: approvedSourceConfigB, noRecord: true, wantCopy: approvedSourceConfigA, wantErr: true},
		{name: "config.yaml is a link", installed: approvedSourceConfigB, recorded: approvedSourceConfigB, actor: "lifecycle", link: true, wantCopy: approvedSourceConfigA, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := approvedSourceFolder(t)
			configPath := filepath.Join(t.TempDir(), "config.yaml")
			if tc.link {
				target := filepath.Join(t.TempDir(), "elsewhere.yaml")
				if err := os.WriteFile(target, []byte(tc.installed), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, configPath); err != nil {
					t.Skip("cannot create a link here:", err)
				}
			} else if err := os.WriteFile(configPath, []byte(tc.installed), 0o600); err != nil {
				t.Fatal(err)
			}
			if !tc.noRecord {
				stageConfigGeneration(t, configPath, tc.recorded, tc.actor)
			}
			lock := &lockProbe{}
			changed, err := healManagedApprovedConfigSourceBound(dir, configPath, lock.acquire)
			if (err != nil) != tc.wantErr || changed == tc.wantErr {
				t.Fatalf("heal: changed=%v err=%v, want error %v", changed, err, tc.wantErr)
			}
			if lock.acquired != lock.released {
				t.Fatalf("the lock was taken %d times and released %d times", lock.acquired, lock.released)
			}
			if got := approvedRepairRestores(t, dir); got != tc.wantCopy {
				t.Fatalf("Repair restores %q, want %q", got, tc.wantCopy)
			}
		})
	}
}

// Benign twins: a source that already is the installed config needs no lock
// and no generation record, and does not fail a run whose config is a hand
// edit or has no record; a lock another run holds fails only a heal that has
// something to write.
func TestHealManagedApprovedConfigSourceLeavesACurrentSourceAlone(t *testing.T) {
	dir := approvedSourceFolder(t)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(approvedSourceConfigA), 0o600); err != nil {
		t.Fatal(err)
	}
	busy := &lockProbe{err: errManagedApprovedSourceBusy}
	for _, actor := range []string{"", configwrite.ActorUnattributedHandEdit} {
		if actor != "" {
			stageConfigGeneration(t, configPath, approvedSourceConfigA, actor)
		}
		if changed, err := healManagedApprovedConfigSourceBound(dir, configPath, busy.acquire); err != nil || changed {
			t.Fatalf("a current source (record actor %q): changed=%v err=%v", actor, changed, err)
		}
	}

	stale := approvedSourceFolder(t)
	if err := os.WriteFile(configPath, []byte(approvedSourceConfigB), 0o600); err != nil {
		t.Fatal(err)
	}
	stageConfigGeneration(t, configPath, approvedSourceConfigB, "lifecycle")
	if changed, err := healManagedApprovedConfigSourceBound(stale, configPath, busy.acquire); !errors.Is(err, errManagedApprovedSourceBusy) || changed {
		t.Fatalf("a busy lock: changed=%v err=%v", changed, err)
	}
	if got := approvedRepairRestores(t, stale); got != approvedSourceConfigA {
		t.Fatalf("a busy lock changed the source to %q", got)
	}
}

// A transient failure to write the deployment record is an error the caller
// fails the run with, and it leaves A in place, digest-valid: that is why the
// run must fail instead of warning (a later hand edit and Repair would restore
// A after an apparently successful ensure).
func TestHealManagedApprovedConfigSourceReportsARecordThatCannotBeWritten(t *testing.T) {
	dir := approvedSourceFolder(t)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(approvedSourceConfigB), 0o600); err != nil {
		t.Fatal(err)
	}
	stageConfigGeneration(t, configPath, approvedSourceConfigB, "lifecycle")
	restore := writeManagedApprovedSourceFile
	t.Cleanup(func() { writeManagedApprovedSourceFile = restore })
	writeManagedApprovedSourceFile = func(path string, data []byte, sibling string) error {
		if filepath.Base(path) == managedDeploymentRecordFile {
			return errors.New("access denied")
		}
		return restore(path, data, sibling)
	}
	if changed, err := healManagedApprovedConfigSourceBound(dir, configPath, (&lockProbe{}).acquire); err == nil || changed {
		t.Fatalf("an unwritable record: changed=%v err=%v", changed, err)
	}
	if got := approvedRepairRestores(t, dir); got != approvedSourceConfigA {
		t.Fatalf("the failed heal left %q", got)
	}
}

// Direct upgrade, then Repair before any ensure: installed B, approved copy
// and digest A (what an older build left). A binary-only upgrade publishes no
// config and carries the digest forward; the check every upgrade, repair and
// ensure ends with is what makes B the approved source before a hand edit and
// a Repair.
func TestHealManagedApprovedConfigSourceAfterABinaryOnlyUpgradeBeforeRepair(t *testing.T) {
	dir := approvedSourceFolder(t)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(approvedSourceConfigB), 0o600); err != nil {
		t.Fatal(err)
	}
	stageConfigGeneration(t, configPath, approvedSourceConfigB, "lifecycle")
	if got := approvedRepairRestores(t, dir); got != approvedSourceConfigA {
		t.Fatalf("setup: the carried source is %q", got)
	}
	if changed, err := healManagedApprovedConfigSourceBound(dir, configPath, (&lockProbe{}).acquire); err != nil || !changed {
		t.Fatalf("heal after the upgrade: changed=%v err=%v", changed, err)
	}
	// The hand edit and the guardian record come after.
	if err := os.WriteFile(configPath, []byte(approvedSourceConfigB+"# edit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stageConfigGeneration(t, configPath, approvedSourceConfigB+"# edit\n", configwrite.ActorUnattributedHandEdit)
	if got := approvedRepairRestores(t, dir); got != approvedSourceConfigB {
		t.Fatalf("Repair after the hand edit restores %q, want B", got)
	}
}

// handEditAfter stages what a hand edit of the installed config leaves: the
// edited bytes, and the guardian record that calls them a hand edit. There is
// no record of the lifecycle config it replaced.
func handEditAfter(t *testing.T, configPath, lifecycleBody string) {
	t.Helper()
	edited := lifecycleBody + "# hand edit\n"
	if err := os.WriteFile(configPath, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	stageConfigGeneration(t, configPath, edited, configwrite.ActorUnattributedHandEdit)
}

// The first Repair of this release over state an earlier release left: B is
// the installed lifecycle config, the approved copy and its digest still name
// A. The installer restores the digest-valid copy before any later check can
// run, so Repair has to stop first. It does, until a lifecycle run of this
// release has proven the copy: the proof comes from the ensure, upgrade,
// install or repair that heals the source, and then Repair restores B.
func TestRepairOverAHandEditStopsOnAnApprovedSourceNothingProves(t *testing.T) {
	dir := approvedSourceFolder(t) // an earlier release: installed B, approved A, no proof
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(approvedSourceConfigB), 0o600); err != nil {
		t.Fatal(err)
	}
	stageConfigGeneration(t, configPath, approvedSourceConfigB, "lifecycle")
	handEditAfter(t, configPath, approvedSourceConfigB)

	if err := unprovenApprovedConfigSourceForHandEdit(dir, configPath); err == nil {
		t.Fatal("Repair would restore the approved copy A over the hand edit of the installed B")
	}
	if got := approvedRepairRestores(t, dir); got != approvedSourceConfigA {
		t.Fatalf("the refusal changed the approved source to %q", got)
	}

	// The same state after a run of this release: the heal of that run
	// made B the approved source and proved it before the hand edit.
	healed := approvedSourceFolder(t)
	cleanPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cleanPath, []byte(approvedSourceConfigB), 0o600); err != nil {
		t.Fatal(err)
	}
	stageConfigGeneration(t, cleanPath, approvedSourceConfigB, "lifecycle")
	if changed, err := healManagedApprovedConfigSourceBound(healed, cleanPath, (&lockProbe{}).acquire); err != nil || !changed {
		t.Fatalf("heal: changed=%v err=%v", changed, err)
	}
	handEditAfter(t, cleanPath, approvedSourceConfigB)
	if err := unprovenApprovedConfigSourceForHandEdit(healed, cleanPath); err != nil {
		t.Fatalf("Repair refused a proven approved source: %v", err)
	}
	if got := approvedRepairRestores(t, healed); got != approvedSourceConfigB {
		t.Fatalf("Repair restores %q, want B", got)
	}
}

// Benign twins: Repair is not held up when nothing would be restored over a
// hand edit (a lifecycle record, no record at all), and a deployment whose
// approved copy already is the installed config needs one ensure, not a new
// config, to become repairable.
func TestRepairOverAHandEditLeavesWhatDoesNotRestoreTheApprovedSource(t *testing.T) {
	dir := approvedSourceFolder(t)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(approvedSourceConfigB), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unprovenApprovedConfigSourceForHandEdit(dir, configPath); err != nil {
		t.Fatalf("no generation record: %v", err)
	}
	stageConfigGeneration(t, configPath, approvedSourceConfigB, "lifecycle")
	if err := unprovenApprovedConfigSourceForHandEdit(dir, configPath); err != nil {
		t.Fatalf("a config the lifecycle recorded: %v", err)
	}

	// Approved copy A is the installed config (nothing was ever applied in
	// place): the first heal of this release proves it without rewriting the
	// copy, and a Repair over a later hand edit then restores A.
	current := approvedSourceFolder(t)
	currentPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(currentPath, []byte(approvedSourceConfigA), 0o600); err != nil {
		t.Fatal(err)
	}
	stageConfigGeneration(t, currentPath, approvedSourceConfigA, "lifecycle")
	handEditAfter(t, currentPath, approvedSourceConfigA)
	if err := unprovenApprovedConfigSourceForHandEdit(current, currentPath); err == nil {
		t.Fatal("an unproven copy was restored before any lifecycle run of this release")
	}
	stageConfigGeneration(t, currentPath, approvedSourceConfigA, "lifecycle")
	if err := os.WriteFile(currentPath, []byte(approvedSourceConfigA), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := healManagedApprovedConfigSourceBound(current, currentPath, (&lockProbe{}).acquire); err != nil || changed {
		t.Fatalf("proof of a current copy: changed=%v err=%v", changed, err)
	}
	handEditAfter(t, currentPath, approvedSourceConfigA)
	if err := unprovenApprovedConfigSourceForHandEdit(current, currentPath); err != nil {
		t.Fatalf("Repair refused a copy that is the proven installed config: %v", err)
	}
	if got := approvedRepairRestores(t, current); got != approvedSourceConfigA {
		t.Fatalf("Repair restores %q, want A", got)
	}
}

// The proof names the digest of the copy it proves, so a copy or record that
// anything else changed is unproven again, and a proof that cannot be written
// leaves copy and record as they were.
func TestApprovedConfigSourceProofFollowsTheCopy(t *testing.T) {
	dir := approvedSourceFolder(t)
	proofPath := filepath.Join(dir, managedApprovedProofFile)
	if err := refreshManagedApprovedConfigSource(dir, approvedConfigAt(t, approvedSourceConfigB), []byte(approvedSourceConfigB)); err != nil {
		t.Fatal(err)
	}
	if approvedConfigProofGap(dir, handEditRecord(2, approvedSourceConfigB)) != "" {
		t.Fatal("a copy the ensure published is not proven")
	}
	// An earlier release publishes another config (copy and digest), or only
	// the copy changes: neither matches the proof.
	other := approvedSourceConfigA + "# other\n"
	if err := os.WriteFile(filepath.Join(dir, managedApprovedConfigFile), []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}
	if approvedConfigProofGap(dir, handEditRecord(2, approvedSourceConfigB)) == "" {
		t.Fatal("a copy changed after the proof is proven")
	}
	recordRaw, _ := os.ReadFile(filepath.Join(dir, managedDeploymentRecordFile))
	republished := strings.ReplaceAll(string(recordRaw), configwrite.SHA256Hex([]byte(approvedSourceConfigB)), configwrite.SHA256Hex([]byte(other)))
	if err := os.WriteFile(filepath.Join(dir, managedDeploymentRecordFile), []byte(republished), 0o600); err != nil {
		t.Fatal(err)
	}
	if approvedConfigProofGap(dir, handEditRecord(2, approvedSourceConfigB)) == "" {
		t.Fatal("a copy and digest republished without the proof are proven")
	}
	if err := os.Remove(proofPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proofPath, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if approvedConfigProofGap(dir, handEditRecord(2, approvedSourceConfigB)) == "" {
		t.Fatal("an unreadable proof is proven")
	}

	failing := approvedSourceFolder(t)
	rawBefore, _ := os.ReadFile(filepath.Join(failing, managedDeploymentRecordFile))
	restore := writeManagedApprovedSourceFile
	t.Cleanup(func() { writeManagedApprovedSourceFile = restore })
	writeManagedApprovedSourceFile = func(path string, data []byte, sibling string) error {
		if filepath.Base(path) == managedApprovedProofFile {
			return errors.New("access denied")
		}
		return restore(path, data, sibling)
	}
	if err := refreshManagedApprovedConfigSource(failing, approvedConfigAt(t, approvedSourceConfigB), []byte(approvedSourceConfigB)); err == nil {
		t.Fatal("a proof that could not be written was reported as written")
	}
	body, _ := readApprovedSourceFolder(t, failing)
	rawAfter, _ := os.ReadFile(filepath.Join(failing, managedDeploymentRecordFile))
	if body != approvedSourceConfigA || string(rawAfter) != string(rawBefore) {
		t.Fatalf("a failed proof left copy %q, record %s", body, rawAfter)
	}
	if _, err := os.Stat(filepath.Join(failing, managedApprovedProofFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a proof was left: %v", err)
	}
}

// The proof names the config generation that recorded the config as applied,
// and a hand edit may restore the copy only when it is recorded directly after
// that generation: a config recorded in between, by a build that never wrote
// the proof, leaves a larger gap and the proof stale (GAP-0779).
func TestApprovedConfigSourceProofIsBoundToTheLifecycleGeneration(t *testing.T) {
	dir := approvedSourceFolder(t)
	configPath := approvedConfigAt(t, approvedSourceConfigB) // generation 1
	if err := refreshManagedApprovedConfigSource(dir, configPath, []byte(approvedSourceConfigB)); err != nil {
		t.Fatal(err)
	}
	for generation, want := range map[uint64]bool{0: false, 1: false, 2: true, 3: false, 9: false} {
		if got := approvedConfigProofGap(dir, handEditRecord(generation, approvedSourceConfigB)) == ""; got != want {
			t.Fatalf("hand edit recorded as generation %d after a proof of generation 1: proven=%v, want %v", generation, got, want)
		}
	}
	// A proof an earlier build wrote without a generation proves nothing.
	proofPath := filepath.Join(dir, managedApprovedProofFile)
	if err := os.WriteFile(proofPath, []byte(`{"config_sha256":"`+configwrite.SHA256Hex([]byte(approvedSourceConfigB))+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if approvedConfigProofGap(dir, handEditRecord(2, approvedSourceConfigB)) == "" {
		t.Fatal("a proof without a generation is proven")
	}
}

// The reviewed variant: this release proved A, then an earlier signed build
// of the same version ran an explicit Upgrade whose in-place ensure applied B
// (it records installed B and its generation and knows nothing of the approved
// source or the proof). The approved copy, its digest and the proof still name
// A and match each other, so only the generation tells the proof is stale: the
// hand edit of B follows that later generation, and Repair must stop instead of
// restoring A. A heal of this release over B proves B again and then Repair
// restores B; the benign twin is a hand edit that directly follows the proof.
func TestRepairOverAHandEditStopsWhenALaterBuildAppliedAnotherConfig(t *testing.T) {
	dir := approvedSourceFolder(t) // approved A
	configPath := approvedConfigAt(t, approvedSourceConfigA)
	if err := refreshManagedApprovedConfigSource(dir, configPath, []byte(approvedSourceConfigA)); err != nil {
		t.Fatal(err)
	}
	// Benign twin: a hand edit of A directly after the proof restores A.
	handEditAfter(t, configPath, approvedSourceConfigA)
	if err := unprovenApprovedConfigSourceForHandEdit(dir, configPath); err != nil {
		t.Fatalf("a hand edit directly after the proof refused: %v", err)
	}
	if got := approvedRepairRestores(t, dir); got != approvedSourceConfigA {
		t.Fatalf("Repair restores %q, want A", got)
	}

	// The older build applies B in place: config.yaml and its generation
	// record, nothing else.
	if err := os.WriteFile(configPath, []byte(approvedSourceConfigB), 0o600); err != nil {
		t.Fatal(err)
	}
	stageConfigGeneration(t, configPath, approvedSourceConfigB, "lifecycle")
	handEditAfter(t, configPath, approvedSourceConfigB)
	if err := unprovenApprovedConfigSourceForHandEdit(dir, configPath); err == nil {
		t.Fatal("Repair would restore the approved copy A over a hand edit of the later config B")
	}
	if got := approvedRepairRestores(t, dir); got != approvedSourceConfigA {
		t.Fatalf("the refusal changed the approved source to %q", got)
	}

	// A lifecycle run of this release heals the source over B and proves it.
	if err := os.WriteFile(configPath, []byte(approvedSourceConfigB), 0o600); err != nil {
		t.Fatal(err)
	}
	stageConfigGeneration(t, configPath, approvedSourceConfigB, "lifecycle")
	if changed, err := healManagedApprovedConfigSourceBound(dir, configPath, (&lockProbe{}).acquire); err != nil || !changed {
		t.Fatalf("heal: changed=%v err=%v", changed, err)
	}
	handEditAfter(t, configPath, approvedSourceConfigB)
	if err := unprovenApprovedConfigSourceForHandEdit(dir, configPath); err != nil {
		t.Fatalf("Repair refused the healed and proven source: %v", err)
	}
	if got := approvedRepairRestores(t, dir); got != approvedSourceConfigB {
		t.Fatalf("Repair restores %q, want B", got)
	}
}

// A proof that cannot be written for a copy that already is the installed
// config does not fail the run (the next Repair over a hand edit stops and
// names the ensure), and neither does a config the generation record does not
// bind; a stale copy still fails it.
func TestHealManagedApprovedConfigSourceProofIsBestEffort(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(approvedSourceConfigA), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, setup := range map[string]func(){
		"hand-edit record": func() {
			stageConfigGeneration(t, configPath, approvedSourceConfigA, configwrite.ActorUnattributedHandEdit)
		},
		"no record": func() { _ = os.Remove(configwrite.GenerationPath(configPath)) },
		"lock held": func() { stageConfigGeneration(t, configPath, approvedSourceConfigA, "lifecycle") },
	} {
		t.Run(name, func(t *testing.T) {
			dir := approvedSourceFolder(t)
			setup()
			lock := &lockProbe{}
			if name == "lock held" {
				lock.err = errManagedApprovedSourceBusy
			}
			if changed, err := healManagedApprovedConfigSourceBound(dir, configPath, lock.acquire); err != nil || changed {
				t.Fatalf("changed=%v err=%v", changed, err)
			}
			if approvedConfigProofGap(dir, handEditRecord(2, approvedSourceConfigA)) == "" {
				t.Fatal("a copy nothing bound was proven")
			}
		})
	}
}

// handEditRecord is the generation record a hand edit of the config that
// previousBody names leaves: the next number, a hand-edit actor and the digest
// of the record it replaced.
func handEditRecord(generation uint64, previousBody string) configwrite.GenerationState {
	return configwrite.GenerationState{
		Generation:           generation,
		Actor:                configwrite.ActorUnattributedHandEdit,
		PreviousConfigSHA256: configwrite.SHA256Hex([]byte(previousBody)),
	}
}

// The number alone does not tie a hand edit to the proof: the hand edit must
// also have replaced the config the proof covers.
func TestApprovedConfigSourceProofNamesTheConfigTheHandEditReplaced(t *testing.T) {
	dir := approvedSourceFolder(t)
	if err := refreshManagedApprovedConfigSource(dir, approvedConfigAt(t, approvedSourceConfigB), []byte(approvedSourceConfigB)); err != nil {
		t.Fatal(err)
	}
	digest := configwrite.SHA256Hex([]byte(approvedSourceConfigB))
	for name, tc := range map[string]struct {
		previous string
		want     bool
	}{
		"the covered config":           {digest, true},
		"the covered config, prefixed": {"sha256:" + strings.ToUpper(digest), true},
		"another config":               {configwrite.SHA256Hex([]byte(approvedSourceConfigA)), false},
		"no predecessor":               {"", false},
	} {
		record := handEditRecord(2, approvedSourceConfigB)
		record.PreviousConfigSHA256 = tc.previous
		if got := approvedConfigProofGap(dir, record) == ""; got != tc.want {
			t.Fatalf("%s: proven=%v, want %v", name, got, tc.want)
		}
	}
}

// The reviewed reset variant (round 5): this release proved A at generation 1,
// then config.generation.json was lost and an earlier signed build applied B in
// place (the record restarts at 1 with the reset marker), then B was hand
// edited and the guardian recorded it as generation 2. The numbers read as
// directly after the proof, but the edit replaced B, not A, so Repair must
// stop instead of restoring A. Real writers throughout. Benign twin: the same
// sequence without the lost record restores A.
func TestRepairOverAHandEditStopsWhenTheGenerationRecordRestartedAfterTheProof(t *testing.T) {
	ctx := context.Background()
	handEdit := func(t *testing.T, configPath, body string) {
		t.Helper()
		if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		recorded, err := configwrite.RecordUnrecorded(ctx, configPath, []byte(body), configwrite.Options{
			Actor: configwrite.ActorUnattributedHandEdit, Reason: "edited outside the lifecycle",
		})
		if err != nil || !recorded {
			t.Fatalf("hand edit record: recorded=%t err=%v", recorded, err)
		}
	}
	prove := func(t *testing.T) (dir, configPath string) {
		t.Helper()
		dir = approvedSourceFolder(t)
		configPath = filepath.Join(t.TempDir(), "config.yaml")
		if _, err := configwrite.ReplaceDocument(ctx, configPath, []byte(approvedSourceConfigA), configwrite.Options{Actor: configwrite.ActorLifecycle, Reason: "ensure"}); err != nil {
			t.Fatal(err)
		}
		if err := refreshManagedApprovedConfigSource(dir, configPath, []byte(approvedSourceConfigA)); err != nil {
			t.Fatal(err)
		}
		return dir, configPath
	}

	// Benign twin: the hand edit directly follows the proof.
	dir, configPath := prove(t)
	handEdit(t, configPath, approvedSourceConfigA+"# edit\n")
	if err := unprovenApprovedConfigSourceForHandEdit(dir, configPath); err != nil {
		t.Fatalf("a hand edit directly after the proof refused: %v", err)
	}

	// The record is lost, the earlier build applies B, B is hand edited.
	dir, configPath = prove(t)
	if err := os.Remove(configwrite.GenerationPath(configPath)); err != nil {
		t.Fatal(err)
	}
	applied, err := configwrite.ReplaceDocument(ctx, configPath, []byte(approvedSourceConfigB), configwrite.Options{
		Actor: configwrite.ActorLifecycle, Reason: "earlier build in-place ensure",
		ExpectSHA256: configwrite.SHA256Hex([]byte(approvedSourceConfigA)),
	})
	if err != nil || applied.Generation != 1 {
		t.Fatalf("the restarted record: generation=%d err=%v", applied.Generation, err)
	}
	handEdit(t, configPath, approvedSourceConfigB+"# edit\n")
	if state, err := configwrite.ReadGenerationState(configPath); err != nil || state.Generation != 2 {
		t.Fatalf("hand edit record: %+v err=%v", state, err)
	}
	if err := unprovenApprovedConfigSourceForHandEdit(dir, configPath); err == nil {
		t.Fatal("Repair would restore the approved copy A over a hand edit of the later config B")
	}
	if got := approvedRepairRestores(t, dir); got != approvedSourceConfigA {
		t.Fatalf("the refusal changed the approved source to %q", got)
	}

	// A record that is lost right before the hand edit leaves no predecessor.
	dir, configPath = prove(t)
	if err := os.Remove(configwrite.GenerationPath(configPath)); err != nil {
		t.Fatal(err)
	}
	handEdit(t, configPath, approvedSourceConfigA+"# edit\n")
	if err := unprovenApprovedConfigSourceForHandEdit(dir, configPath); err == nil {
		t.Fatal("Repair trusted a proof after the record it names was lost")
	}
}

// GAP-0854: the refusal names the check that failed, so an administrator sees
// whether the proof is missing, names another config, or fell behind the
// config generations, and each state still refuses (nothing is restored).
func TestApprovedConfigProofGapNamesTheFailedCheck(t *testing.T) {
	digestA := configwrite.SHA256Hex([]byte(approvedSourceConfigA))
	digestB := configwrite.SHA256Hex([]byte(approvedSourceConfigB))
	for _, tc := range []struct {
		name     string
		setup    func(t *testing.T, dir string)
		handEdit configwrite.GenerationState
		want     string
	}{
		{"proven", func(t *testing.T, dir string) { mustWriteProof(t, dir, digestA, 4) }, handEditRecord(5, approvedSourceConfigA), ""},
		{"no proof", func(*testing.T, string) {}, handEditRecord(2, approvedSourceConfigA), "no lifecycle run of this release has proven"},
		{"proof of another config", func(t *testing.T, dir string) { mustWriteProof(t, dir, digestB, 4) }, handEditRecord(5, approvedSourceConfigA), "another config than the approved copy"},
		{"generations recorded after the proof", func(t *testing.T, dir string) { mustWriteProof(t, dir, digestA, 4) }, handEditRecord(7, approvedSourceConfigA), "2 config generations were recorded after the proof"},
		{"proof ahead of the hand edit", func(t *testing.T, dir string) { mustWriteProof(t, dir, digestA, 9) }, handEditRecord(5, approvedSourceConfigA), "later config generation"},
		{"hand edit replaced another config", func(t *testing.T, dir string) { mustWriteProof(t, dir, digestA, 4) }, handEditRecord(5, approvedSourceConfigB), "other than the approved copy"},
		{"approved copy missing", func(t *testing.T, dir string) {
			mustWriteProof(t, dir, digestA, 4)
			if err := os.Remove(filepath.Join(dir, managedApprovedConfigFile)); err != nil {
				t.Fatal(err)
			}
		}, handEditRecord(5, approvedSourceConfigA), "approved-config.yaml is missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := approvedSourceFolder(t)
			tc.setup(t, dir)
			got := approvedConfigProofGap(dir, tc.handEdit)
			if tc.want == "" && got != "" || !strings.Contains(got, tc.want) {
				t.Fatalf("gap = %q, want %q", got, tc.want)
			}
		})
	}

	// The message Repair prints carries the reason next to the next step.
	dir := approvedSourceFolder(t)
	configPath := approvedConfigAt(t, approvedSourceConfigA)
	handEditAfter(t, configPath, approvedSourceConfigA)
	err := unprovenApprovedConfigSourceForHandEdit(dir, configPath)
	if err == nil || !strings.Contains(err.Error(), "no lifecycle run of this release has proven") ||
		!strings.Contains(err.Error(), "nothing proves that the approved config source") {
		t.Fatalf("refusal = %v", err)
	}
}

func mustWriteProof(t *testing.T, dir, digest string, generation uint64) {
	t.Helper()
	if err := writeManagedApprovedProof(dir, digest, generation); err != nil {
		t.Fatal(err)
	}
}

// GAP-0854: a single hand edit is repairable after every way a lifecycle run
// leaves the config: an ensure that applied it, an ensure that changed nothing,
// and a Repair that put the approved copy back (which records one more
// generation for the same bytes). Each run ends with the same heal, so the
// proof follows the generation, and the one hand edit after it directly
// follows the proof. A hand edit that follows a run that never healed is
// refused, and the refusal says how many generations the proof is behind.
func TestApprovedConfigProofFollowsEveryLifecycleExit(t *testing.T) {
	dir := approvedSourceFolder(t) // copy and digest name A, as the transaction published them
	configPath := approvedConfigAt(t, approvedSourceConfigA)
	lock := &lockProbe{}
	heal := func(t *testing.T, wantChanged bool) {
		t.Helper()
		if changed, err := healManagedApprovedConfigSourceBound(dir, configPath, lock.acquire); err != nil || changed != wantChanged {
			t.Fatalf("heal: changed=%v err=%v, want changed=%v", changed, err, wantChanged)
		}
	}
	repairable := func(t *testing.T, label string) {
		t.Helper()
		handEditAfter(t, configPath, approvedSourceConfigA)
		if err := unprovenApprovedConfigSourceForHandEdit(dir, configPath); err != nil {
			t.Fatalf("%s: a single hand edit is refused: %v", label, err)
		}
		// The repair puts the approved copy back and records it again.
		if err := os.WriteFile(configPath, []byte(approvedSourceConfigA), 0o600); err != nil {
			t.Fatal(err)
		}
		stageConfigGeneration(t, configPath, approvedSourceConfigA, "lifecycle")
	}

	// A transaction (restart ensure, upgrade) published copy and digest; the
	// heal at its exit proves them, taking the lock once.
	heal(t, false)
	if lock.acquired != 1 {
		t.Fatalf("the first heal took the lock %d times", lock.acquired)
	}
	// A no-op ensure: nothing to prove, no lock.
	heal(t, false)
	if lock.acquired != 1 {
		t.Fatalf("a no-op ensure took the lock again (%d)", lock.acquired)
	}
	repairable(t, "after an ensure")

	// The repair restored the copy under a newer generation. Without the heal
	// at the end of that repair the next single hand edit is refused, and the
	// refusal names the gap.
	handEditAfter(t, configPath, approvedSourceConfigA)
	err := unprovenApprovedConfigSourceForHandEdit(dir, configPath)
	if err == nil || !strings.Contains(err.Error(), "config generations were recorded after the proof") {
		t.Fatalf("a hand edit after an unhealed repair: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(approvedSourceConfigA), 0o600); err != nil {
		t.Fatal(err)
	}
	stageConfigGeneration(t, configPath, approvedSourceConfigA, "lifecycle")

	// The heal at the end of the repair moves the proof to the new generation.
	heal(t, false)
	repairable(t, "after a repair")
	heal(t, false)
	repairable(t, "after a repair and a no-op ensure")
}
