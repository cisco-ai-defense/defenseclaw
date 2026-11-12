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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// The approved config source of a managed standalone Windows deployment is
// install\approved-config.yaml, bound by sha256 to deployment.json
// approved_policy_sources.config. Setup /repair puts it back over a config.yaml
// the generation record calls a hand edit, so it has to be the last config a
// lifecycle run approved: the upgrade transaction publishes it
// (Publish-DefenseClawApprovedPolicySources) and the in-place config-only
// ensure publishes it here, so no ensure path leaves an older approved config
// for a repair to restore (GAP-0779).
//
// A config.yaml the generation record calls a hand edit does not show by itself
// which lifecycle config it replaced, so the approved copy alone cannot prove
// it is that config: an earlier release applied a config in place and left the copy
// at an older one, with a matching digest. approved-config.current.json is
// the proof. A lifecycle run writes it, next to the copy, only for a copy that
// is the config the run applied; it names the digest of that copy and the
// config generation that recorded the config as applied. A copy or a
// deployment record changed by anything else no longer matches the digest, and
// a config applied after the proof (by a build that knows nothing of the
// proof, or any other writer) moved the generation on, so the hand edit that
// follows it is recorded more than one generation after the proof. Repair over
// a hand edit puts the copy back only when copy, record and proof agree and
// the hand edit directly follows the proven generation
// (approvedConfigProofGap). Setup /repair checks that in Go before it
// starts the installer; the installer checks the same rule itself
// (Assert-DefenseClawApprovedConfigProven), so a direct run of
// install-enterprise.ps1 stops at the same point before it changes anything.
const (
	managedApprovedConfigFile     = "approved-config.yaml"
	managedApprovedProofFile      = "approved-config.current.json"
	managedDeploymentRecordFile   = "deployment.json"
	managedApprovedSourcesKey     = "approved_policy_sources"
	managedApprovedConfigKey      = "config"
	managedApprovedRecordMaxBytes = 4 << 20
)

// writeManagedApprovedSourceFile writes one of the two files; a seam for tests.
var writeManagedApprovedSourceFile = writeFileKeepingDACL

// refreshManagedApprovedConfigSource makes installed, the config.yaml a
// lifecycle run just applied, the approved config source of the deployment
// whose protected install state folder is installDir: the approved copy and
// the digest deployment.json records for it change together, or neither does.
// The copy is replaced first and deployment.json second; a failure of the
// second puts the copy back, and a crash between the two leaves a copy whose
// digest the record does not name, which Repair refuses (it never restores
// bytes it cannot bind) until the next ensure publishes both again. Every
// other field of deployment.json, and the approved manifest digest, keep their
// values. Both files keep deployment.json access control.
func refreshManagedApprovedConfigSource(installDir, configPath string, installed []byte) error {
	_, err := publishManagedApprovedConfigSource(installDir, configPath, installed, approvedPublishAlways)
	return err
}

// healManagedApprovedConfigSource is the refresh for a lifecycle run that
// ended compliant without publishing a config of its own: a binary-only
// upgrade carries the earlier digest forward, so the stale approved copy an
// older build left would survive it and a Repair after a hand edit would put
// it back (GAP-0779). installed is the config the run accepted. It acts only
// on a deployment that already records an approved config source and changes
// nothing when the copy and the record already match installed; a deployment
// that records none, or has no deployment record, is left as it is (Repair
// refuses it and names the next step). It reports whether it changed anything.
func healManagedApprovedConfigSource(installDir, configPath string, installed []byte) (bool, error) {
	result, err := publishManagedApprovedConfigSource(installDir, configPath, installed, approvedPublishIfRecorded)
	return result == approvedSourceChanged, err
}

// approvedPublishMode says when publishManagedApprovedConfigSource writes.
type approvedPublishMode int

const (
	// approvedPublishAlways publishes installed, filling a missing source.
	approvedPublishAlways approvedPublishMode = iota
	// approvedPublishIfRecorded publishes only over a recorded source.
	approvedPublishIfRecorded
	// approvedPublishCheck is approvedPublishIfRecorded without the writes:
	// it reports what a heal would write.
	approvedPublishCheck
)

// approvedPublishResult says what publishManagedApprovedConfigSource wrote, or
// in check mode would write.
type approvedPublishResult int

const (
	// approvedSourceCurrent: copy, record and proof already name installed.
	approvedSourceCurrent approvedPublishResult = iota
	// approvedProofMissing: copy and record already name installed; only the
	// proof of it was missing or named another copy.
	approvedProofMissing
	// approvedSourceChanged: the copy and the record change.
	approvedSourceChanged
)

// errManagedApprovedSourceBusy is a lifecycle lock another run holds.
var errManagedApprovedSourceBusy = errors.New("another DefenseClaw lifecycle run holds lifecycle.lock")

// readManagedConfigBoundToGeneration reads the installed config.yaml only
// when it is exactly the config its generation record names and that record
// is not a hand edit: the bytes a lifecycle run applied and a verify
// accepted. Anything else (a link in place of the file, an edit made between
// the verify and this read, an unreadable or missing record) is an error, so
// bytes nobody approved never become the source Repair restores (GAP-0779).
func readManagedConfigBoundToGeneration(configPath string) ([]byte, error) {
	info, err := os.Lstat(configPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", configPath)
	}
	raw, err := readBoundedConfigFile(configPath, managedApprovedRecordMaxBytes)
	if err != nil {
		return nil, err
	}
	if _, err := managedConfigGenerationOf(configPath, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// managedConfigGenerationOf is the generation that config.generation.json next
// to configPath records for installed, the config bytes a lifecycle run
// applied. It is an error when the record cannot be read, calls the bytes a
// hand edit or names other bytes. The approved config proof binds to this
// generation.
func managedConfigGenerationOf(configPath string, installed []byte) (uint64, error) {
	state, err := configwrite.ReadGenerationState(configPath)
	switch {
	case err != nil:
		return 0, fmt.Errorf("the config generation record cannot be read: %w", err)
	case configwrite.IsHandEditActor(state.Actor):
		return 0, errors.New("the config generation record calls config.yaml a hand edit")
	case !strings.EqualFold(strings.TrimPrefix(state.ConfigSHA256, "sha256:"), configwrite.SHA256Hex(installed)):
		return 0, errors.New("config.yaml is not the config its generation record names")
	}
	return state.Generation, nil
}

// healManagedApprovedConfigSourceBound is the one check every lifecycle exit
// shares (ensure, upgrade, repair): when the deployment records an approved
// config source that differs from the installed config.yaml, the installed
// config becomes the source under acquire lock, but only bytes the generation
// record binds to a lifecycle write (readManagedConfigBoundToGeneration). A
// source that is already current is not touched and needs no lock. A failure
// leaves the source as it was and is returned for the caller to fail the run:
// a run must not report success while a stale source stays restorable.
// acquire reports a lock another run holds as errManagedApprovedSourceBusy.
func healManagedApprovedConfigSourceBound(installDir, configPath string, acquire func() (func(), error)) (bool, error) {
	peek, err := readBoundedConfigFile(configPath, managedApprovedRecordMaxBytes)
	if err != nil {
		return false, fmt.Errorf("read the installed config: %w", err)
	}
	pending, err := publishManagedApprovedConfigSource(installDir, configPath, peek, approvedPublishCheck)
	if err != nil || pending == approvedSourceCurrent {
		return false, err
	}
	// A copy that already is the installed config only lacks its proof. That
	// is best effort: a run that cannot write it did nothing wrong, and a
	// Repair over a later hand edit then stops and names the next step
	// instead of restoring a copy nothing proves.
	proofOnly := pending == approvedProofMissing
	release, err := acquire()
	if err != nil {
		if proofOnly {
			return false, nil
		}
		return false, err
	}
	defer release()
	installed, err := readManagedConfigBoundToGeneration(configPath)
	if err != nil {
		if proofOnly {
			return false, nil
		}
		return false, fmt.Errorf("the installed config cannot be approved: %w", err)
	}
	changed, err := healManagedApprovedConfigSource(installDir, configPath, installed)
	if err != nil && proofOnly {
		return false, nil
	}
	return changed, err
}

// managedApprovedProof is approved-config.current.json: the digest of the
// approved copy a lifecycle run proved to be the config it applied, and the
// config generation that recorded that config as applied. Generation is a
// pointer so a proof an earlier build wrote without it names no generation.
type managedApprovedProof struct {
	ConfigSHA256 string  `json:"config_sha256"`
	Generation   *uint64 `json:"generation"`
}

// readManagedApprovedProof reads the proof file at path when it is a regular
// file that names a digest and a generation.
func readManagedApprovedProof(path string) (digest string, generation uint64, ok bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", 0, false
	}
	raw, err := readBoundedConfigFile(path, managedApprovedRecordMaxBytes)
	if err != nil {
		return "", 0, false
	}
	var proof managedApprovedProof
	if json.Unmarshal(raw, &proof) != nil || proof.Generation == nil {
		return "", 0, false
	}
	return proof.ConfigSHA256, *proof.Generation, true
}

// managedApprovedProofNames reports whether the proof file at path names
// digest at generation.
func managedApprovedProofNames(path, digest string, generation uint64) bool {
	provenDigest, provenGeneration, ok := readManagedApprovedProof(path)
	return ok && provenDigest == digest && provenGeneration == generation
}

// writeManagedApprovedProof records digest, the approved copy a lifecycle run
// applied at config generation generation, as the proven approved copy.
func writeManagedApprovedProof(installDir, digest string, generation uint64) error {
	raw, err := json.Marshal(managedApprovedProof{ConfigSHA256: digest, Generation: &generation})
	if err != nil {
		return err
	}
	return writeManagedApprovedSourceFile(filepath.Join(installDir, managedApprovedProofFile), raw,
		filepath.Join(installDir, managedDeploymentRecordFile))
}

// unprovenApprovedConfigSourceForHandEdit is the check Setup /repair makes
// before it changes anything. When config.yaml is recorded as a hand edit,
// the installer puts install\approved-config.yaml in its place, and the hand
// edit record names no lifecycle predecessor to compare the copy with. It
// returns nil when no approved copy would replace the config (the record is
// not a hand edit or cannot be read: the installer answers those itself), or
// when copy, deployment record and proof all name one digest and the hand edit
// directly follows the generation the proof names. Otherwise the copy is one
// nothing proves current (an earlier release applied a config in place without
// publishing it, or a build that knows nothing of the proof applied another
// config after it), and the error says which check failed.
func unprovenApprovedConfigSourceForHandEdit(installDir, configPath string) error {
	state, err := configwrite.ReadGenerationState(configPath)
	if err != nil || !configwrite.IsHandEditActor(state.Actor) {
		return nil
	}
	gap := approvedConfigProofGap(installDir, state)
	if gap == "" {
		return nil
	}
	return errors.New("config.yaml is recorded as a hand edit, and nothing proves that the approved config source " +
		"Repair would put back is the config the last lifecycle run applied (" + gap + ")")
}

// approvedConfigProofGap is "" when the approved copy, the digest
// deployment.json records for it and the proof file all name one config, and
// handEdit, the generation record that calls config.yaml a hand edit,
// directly follows the generation the proof names and replaced the very
// config the proof covers. Otherwise it names the first check that failed. Any
// config recorded in between (a lifecycle apply by a build that does not write
// the proof) makes the gap larger. The number alone is not enough: a
// generation record that was lost starts its counter over, so a later config
// written after the reset can carry the number that looks like the proof is
// current. The record links each generation to the config digest it replaced
// (previous_config_sha256); a hand edit that replaced another config, or a
// record with no readable predecessor, leaves the proof stale. The PowerShell
// installer makes the same check (Assert-DefenseClawApprovedConfigProven).
func approvedConfigProofGap(installDir string, handEdit configwrite.GenerationState) string {
	recordPath := filepath.Join(installDir, managedDeploymentRecordFile)
	copyPath := filepath.Join(installDir, managedApprovedConfigFile)
	for _, path := range []string{recordPath, copyPath} {
		if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
			return filepath.Base(path) + " is missing or not a regular file"
		}
	}
	rawRecord, err := readBoundedConfigFile(recordPath, managedApprovedRecordMaxBytes)
	if err != nil {
		return "the deployment record cannot be read"
	}
	var record struct {
		Sources map[string]string `json:"approved_policy_sources"`
	}
	if json.Unmarshal(rawRecord, &record) != nil {
		return "the deployment record cannot be read"
	}
	digest := record.Sources[managedApprovedConfigKey]
	if !managedConfigSHA256Pattern.MatchString(digest) {
		return "the deployment record names no approved config digest"
	}
	body, err := readBoundedConfigFile(copyPath, managedApprovedRecordMaxBytes)
	if err != nil || configwrite.SHA256Hex(body) != digest {
		return "the approved copy is not the config the deployment record names"
	}
	provenDigest, provenGeneration, ok := readManagedApprovedProof(filepath.Join(installDir, managedApprovedProofFile))
	switch {
	case !ok:
		return "no lifecycle run of this release has proven the approved copy"
	case provenDigest != digest:
		return "the proof names another config than the approved copy"
	case handEdit.Generation <= provenGeneration:
		return "the proof names a later config generation than the hand edit"
	case handEdit.Generation-provenGeneration != 1:
		return fmt.Sprintf("%d config generations were recorded after the proof", handEdit.Generation-provenGeneration-1)
	case !strings.EqualFold(strings.TrimPrefix(handEdit.PreviousConfigSHA256, "sha256:"), digest):
		return "the hand edit replaced a config other than the approved copy"
	}
	return ""
}

func publishManagedApprovedConfigSource(installDir, configPath string, installed []byte, mode approvedPublishMode) (approvedPublishResult, error) {
	onlyIfRecorded := mode != approvedPublishAlways
	if installDir == "" {
		return approvedSourceCurrent, errors.New("the install state folder is unknown")
	}
	recordPath := filepath.Join(installDir, managedDeploymentRecordFile)
	copyPath := filepath.Join(installDir, managedApprovedConfigFile)
	proofPath := filepath.Join(installDir, managedApprovedProofFile)
	for _, path := range []string{recordPath, copyPath, proofPath} {
		if info, statErr := os.Lstat(path); statErr == nil && !info.Mode().IsRegular() {
			return approvedSourceCurrent, fmt.Errorf("%s is not a regular file", path)
		} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return approvedSourceCurrent, statErr
		}
	}
	rawRecord, err := readBoundedConfigFile(recordPath, managedApprovedRecordMaxBytes)
	if err != nil {
		if onlyIfRecorded && errors.Is(err, os.ErrNotExist) {
			return approvedSourceCurrent, nil
		}
		return approvedSourceCurrent, fmt.Errorf("read the deployment record: %w", err)
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(rawRecord, &record); err != nil || record == nil {
		// JSON null decodes into a nil map without an error.
		return approvedSourceCurrent, errors.New("the deployment record is not a JSON object")
	}
	if profile, ok := record["profile"]; ok {
		var name string
		if err := json.Unmarshal(profile, &name); err != nil || name != "standalone" {
			return approvedSourceCurrent, errors.New("the deployment record is not the standalone profile")
		}
	}
	sources := map[string]string{}
	if raw, ok := record[managedApprovedSourcesKey]; ok {
		if err := json.Unmarshal(raw, &sources); err != nil || sources == nil {
			// JSON null decodes into a nil map without an error.
			return approvedSourceCurrent, errors.New("the deployment record has an invalid approved policy source record")
		}
		for name, digest := range sources {
			if (name != managedApprovedConfigKey && name != "manifest") || !managedConfigSHA256Pattern.MatchString(digest) {
				return approvedSourceCurrent, errors.New("the deployment record has an invalid approved policy source digest")
			}
		}
	}
	if onlyIfRecorded && sources[managedApprovedConfigKey] == "" {
		return approvedSourceCurrent, nil
	}
	digest := configwrite.SHA256Hex(installed)
	previousCopy, copyErr := readBoundedConfigFile(copyPath, managedApprovedRecordMaxBytes)
	copyExisted := copyErr == nil
	if copyErr != nil && !errors.Is(copyErr, os.ErrNotExist) {
		return approvedSourceCurrent, fmt.Errorf("read the approved config source: %w", copyErr)
	}
	copyCurrent := sources[managedApprovedConfigKey] == digest && copyExisted && bytes.Equal(previousCopy, installed)
	// The proof names the generation that recorded installed as applied.
	generation, generationErr := managedConfigGenerationOf(configPath, installed)
	proofCurrent := generationErr == nil && managedApprovedProofNames(proofPath, digest, generation)
	switch {
	case copyCurrent && proofCurrent:
		return approvedSourceCurrent, nil
	case mode == approvedPublishCheck && copyCurrent:
		return approvedProofMissing, nil
	case mode == approvedPublishCheck:
		return approvedSourceChanged, nil
	case generationErr != nil:
		return approvedSourceCurrent, fmt.Errorf("the config generation behind the approved config source cannot be bound: %w", generationErr)
	case copyCurrent:
		if err := writeManagedApprovedProof(installDir, digest, generation); err != nil {
			return approvedSourceCurrent, fmt.Errorf("write the approved config source proof: %w", err)
		}
		return approvedProofMissing, nil
	}
	sources[managedApprovedConfigKey] = digest
	encodedSources, err := json.Marshal(sources)
	if err != nil {
		return approvedSourceCurrent, err
	}
	record[managedApprovedSourcesKey] = encodedSources
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(record); err != nil {
		return approvedSourceCurrent, err
	}

	// putCopyBack undoes the copy write. The proof written last names digest,
	// so until it exists the new copy is unproven, never mistaken for proven.
	putCopyBack := func() error {
		if copyExisted {
			return writeManagedApprovedSourceFile(copyPath, previousCopy, recordPath)
		}
		return os.Remove(copyPath)
	}
	if err := writeManagedApprovedSourceFile(copyPath, installed, recordPath); err != nil {
		return approvedSourceCurrent, fmt.Errorf("write the approved config source: %w", err)
	}
	if err := writeManagedApprovedSourceFile(recordPath, out.Bytes(), recordPath); err != nil {
		if restoreErr := putCopyBack(); restoreErr != nil {
			return approvedSourceCurrent, fmt.Errorf("write the deployment record: %w; putting the approved config source back failed too: %v", err, restoreErr)
		}
		return approvedSourceCurrent, fmt.Errorf("write the deployment record: %w", err)
	}
	if err := writeManagedApprovedProof(installDir, digest, generation); err != nil {
		restoreErr := writeManagedApprovedSourceFile(recordPath, rawRecord, recordPath)
		if restoreErr == nil {
			restoreErr = putCopyBack()
		}
		if restoreErr != nil {
			return approvedSourceCurrent, fmt.Errorf("write the approved config source proof: %w; putting the approved config source back failed too: %v", err, restoreErr)
		}
		return approvedSourceCurrent, fmt.Errorf("write the approved config source proof: %w", err)
	}
	return approvedSourceChanged, nil
}
