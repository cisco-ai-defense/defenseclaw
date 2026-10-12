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
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// managedConfigRecordMaxBytes bounds the config read for the record.
const managedConfigRecordMaxBytes = 8 << 20

// recordUnrecordedManagedConfig records a managed config.yaml that the caller
// has already loaded, but that config.generation.json does not record, as the
// next config generation with the actor hand-edit:unattributed. The gateway
// hot reloads such a content write (an administrator's editor, configuration
// management) within seconds and enforces it, yet the reported config
// generation stayed where it was, so status, the policy line and the audit
// trail named the previous config (GAP-0617). The Windows hook guardian runs
// as SYSTEM and calls it each cycle; the lifecycle's own writes are recorded
// under the writer lock, so they are never recorded twice. The generation
// still says hand-edit, so status keeps warning that the config was changed
// outside the lifecycle.
func recordUnrecordedManagedConfig(path string, w io.Writer) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	raw, err := readBoundedConfigFile(path, managedConfigRecordMaxBytes)
	if err != nil {
		return
	}
	if state, err := configwrite.ReadGenerationState(path); err == nil &&
		strings.EqualFold(strings.TrimPrefix(state.ConfigSHA256, "sha256:"), configwrite.SHA256Hex(raw)) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	recorded, err := configwrite.RecordUnrecorded(ctx, path, raw, configwrite.Options{
		Actor:  configwrite.ActorUnattributedHandEdit,
		Reason: "config.yaml edited outside the lifecycle; recorded by the hook guardian",
	})
	switch {
	case err != nil:
		fmt.Fprintf(w, "[hook-guardian] could not record the config generation of the edited config.yaml: %v\n", err)
	case recorded:
		if state, err := configwrite.ReadGenerationState(path); err == nil {
			fmt.Fprintf(w, "[hook-guardian] config.yaml was edited outside the lifecycle; recorded as config generation %d\n", state.Generation)
		}
	}
}

// readBoundedConfigFile reads path, refusing a file over limit bytes.
func readBoundedConfigFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return raw, nil
}
