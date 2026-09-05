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
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

type windowsManagedRotationFileIdentity struct {
	VolumeSerial  uint32 `json:"volume_serial"`
	FileIndexHigh uint32 `json:"file_index_high"`
	FileIndexLow  uint32 `json:"file_index_low"`
	NumberOfLinks uint32 `json:"number_of_links"`
	CanonicalPath string `json:"canonical_path,omitempty"`
}

type windowsManagedRotationSnapshot struct {
	Path          string                             `json:"path"`
	Present       bool                               `json:"present"`
	Digest        string                             `json:"digest,omitempty"`
	OwnerSID      string                             `json:"owner_sid,omitempty"`
	ProtectedDACL bool                               `json:"protected_dacl,omitempty"`
	Identity      windowsManagedRotationFileIdentity `json:"identity,omitempty"`
	Bytes         []byte                             `json:"-"`
}

type windowsManagedRotationSecretRecord struct {
	Target     enterpriseHookRotationTarget       `json:"target"`
	Artifact   windowsManagedRotationSnapshot     `json:"artifact"`
	PublishedB windowsManagedRotationFileIdentity `json:"published_b,omitempty"`
	Payloads   [][]byte                           `json:"payloads"`
}

func bindWindowsManagedRotationRestore(record windowsManagedRotationSecretRecord, target enterpriseHookRotationTarget) error {
	if record.Target != target {
		return fmt.Errorf("rotation snapshot target does not match the restore target")
	}
	expectedPath, err := connector.HookAPITokenFilePath(enterpriseHookRotationUserDataDir(target), target.Connector)
	if err != nil {
		return err
	}
	if record.Artifact.Path != expectedPath {
		return fmt.Errorf("rotation snapshot path does not match the target token path")
	}
	if !record.Artifact.Present {
		return nil
	}
	identity := record.Artifact.Identity
	if identity.VolumeSerial == 0 && identity.FileIndexHigh == 0 && identity.FileIndexLow == 0 {
		return fmt.Errorf("rotation snapshot is missing generation A file identity")
	}
	if strings.TrimSpace(identity.CanonicalPath) == "" {
		return fmt.Errorf("rotation snapshot is missing generation A canonical path")
	}
	return nil
}
