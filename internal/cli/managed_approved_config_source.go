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
	if installDir == "" {
		return errors.New("the install state folder is unknown")
	}
	recordPath := filepath.Join(installDir, managedDeploymentRecordFile)
	copyPath := filepath.Join(installDir, managedApprovedConfigFile)
	for _, path := range []string{recordPath, copyPath} {
		if info, statErr := os.Lstat(path); statErr == nil && !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", path)
		} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
	}
	rawRecord, err := readBoundedConfigFile(recordPath, managedApprovedRecordMaxBytes)
	if err != nil {
		return fmt.Errorf("read the deployment record: %w", err)
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(rawRecord, &record); err != nil {
		return fmt.Errorf("the deployment record is not a JSON object: %w", err)
	}
	if profile, ok := record["profile"]; ok {
		var name string
		if err := json.Unmarshal(profile, &name); err != nil || name != "standalone" {
			return errors.New("the deployment record is not the standalone profile")
		}
	}
	sources := map[string]string{}
	if raw, ok := record[managedApprovedSourcesKey]; ok {
		if err := json.Unmarshal(raw, &sources); err != nil {
			return fmt.Errorf("the deployment record has an invalid approved policy source record: %w", err)
		}
		for name, digest := range sources {
			if (name != managedApprovedConfigKey && name != "manifest") || !managedConfigSHA256Pattern.MatchString(digest) {
				return errors.New("the deployment record has an invalid approved policy source digest")
			}
		}
	}
	digest := configwrite.SHA256Hex(installed)
	previousCopy, copyErr := readBoundedConfigFile(copyPath, managedApprovedRecordMaxBytes)
	copyExisted := copyErr == nil
	if copyErr != nil && !errors.Is(copyErr, os.ErrNotExist) {
		return fmt.Errorf("read the approved config source: %w", copyErr)
	}
	if sources[managedApprovedConfigKey] == digest && copyExisted && bytes.Equal(previousCopy, installed) {
		return nil
	}
	sources[managedApprovedConfigKey] = digest
	encodedSources, err := json.Marshal(sources)
	if err != nil {
		return err
	}
	record[managedApprovedSourcesKey] = encodedSources
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(record); err != nil {
		return err
	}

	if err := writeManagedApprovedSourceFile(copyPath, installed, recordPath); err != nil {
		return fmt.Errorf("write the approved config source: %w", err)
	}
	if err := writeManagedApprovedSourceFile(recordPath, out.Bytes(), recordPath); err != nil {
		var restoreErr error
		if copyExisted {
			restoreErr = writeManagedApprovedSourceFile(copyPath, previousCopy, recordPath)
		} else {
			restoreErr = os.Remove(copyPath)
		}
		if restoreErr != nil {
			return fmt.Errorf("write the deployment record: %w; putting the approved config source back failed too: %v", err, restoreErr)
		}
		return fmt.Errorf("write the deployment record: %w", err)
	}
	return nil
}
