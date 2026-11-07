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
const (
	managedApprovedConfigFile     = "approved-config.yaml"
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
func refreshManagedApprovedConfigSource(installDir string, installed []byte) error {
	_, err := publishManagedApprovedConfigSource(installDir, installed, false)
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
func healManagedApprovedConfigSource(installDir string, installed []byte) (bool, error) {
	return publishManagedApprovedConfigSource(installDir, installed, true)
}

func publishManagedApprovedConfigSource(installDir string, installed []byte, onlyIfRecorded bool) (bool, error) {
	if installDir == "" {
		return false, errors.New("the install state folder is unknown")
	}
	recordPath := filepath.Join(installDir, managedDeploymentRecordFile)
	copyPath := filepath.Join(installDir, managedApprovedConfigFile)
	for _, path := range []string{recordPath, copyPath} {
		if info, statErr := os.Lstat(path); statErr == nil && !info.Mode().IsRegular() {
			return false, fmt.Errorf("%s is not a regular file", path)
		} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return false, statErr
		}
	}
	rawRecord, err := readBoundedConfigFile(recordPath, managedApprovedRecordMaxBytes)
	if err != nil {
		if onlyIfRecorded && errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("read the deployment record: %w", err)
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(rawRecord, &record); err != nil || record == nil {
		// JSON null decodes into a nil map without an error.
		return false, errors.New("the deployment record is not a JSON object")
	}
	if profile, ok := record["profile"]; ok {
		var name string
		if err := json.Unmarshal(profile, &name); err != nil || name != "standalone" {
			return false, errors.New("the deployment record is not the standalone profile")
		}
	}
	sources := map[string]string{}
	if raw, ok := record[managedApprovedSourcesKey]; ok {
		if err := json.Unmarshal(raw, &sources); err != nil || sources == nil {
			// JSON null decodes into a nil map without an error.
			return false, errors.New("the deployment record has an invalid approved policy source record")
		}
		for name, digest := range sources {
			if (name != managedApprovedConfigKey && name != "manifest") || !managedConfigSHA256Pattern.MatchString(digest) {
				return false, errors.New("the deployment record has an invalid approved policy source digest")
			}
		}
	}
	if onlyIfRecorded && sources[managedApprovedConfigKey] == "" {
		return false, nil
	}
	digest := configwrite.SHA256Hex(installed)
	previousCopy, copyErr := readBoundedConfigFile(copyPath, managedApprovedRecordMaxBytes)
	copyExisted := copyErr == nil
	if copyErr != nil && !errors.Is(copyErr, os.ErrNotExist) {
		return false, fmt.Errorf("read the approved config source: %w", copyErr)
	}
	if sources[managedApprovedConfigKey] == digest && copyExisted && bytes.Equal(previousCopy, installed) {
		return false, nil
	}
	sources[managedApprovedConfigKey] = digest
	encodedSources, err := json.Marshal(sources)
	if err != nil {
		return false, err
	}
	record[managedApprovedSourcesKey] = encodedSources
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(record); err != nil {
		return false, err
	}

	if err := writeManagedApprovedSourceFile(copyPath, installed, recordPath); err != nil {
		return false, fmt.Errorf("write the approved config source: %w", err)
	}
	if err := writeManagedApprovedSourceFile(recordPath, out.Bytes(), recordPath); err != nil {
		var restoreErr error
		if copyExisted {
			restoreErr = writeManagedApprovedSourceFile(copyPath, previousCopy, recordPath)
		} else {
			restoreErr = os.Remove(copyPath)
		}
		if restoreErr != nil {
			return false, fmt.Errorf("write the deployment record: %w; putting the approved config source back failed too: %v", err, restoreErr)
		}
		return false, fmt.Errorf("write the deployment record: %w", err)
	}
	return true, nil
}
