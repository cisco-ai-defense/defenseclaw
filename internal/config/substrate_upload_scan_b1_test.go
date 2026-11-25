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

package config

import (
	"strings"
	"testing"
	"time"
)

func TestB1UploadScanDefaultsAndValidation(t *testing.T) {
	var u SubstrateUploadScanConfig
	if u.EffectiveMaxFileBytes() != 8<<20 || u.EffectiveTimeBudget() != 120*time.Second ||
		u.EffectiveSecretAction() != SubstrateUploadReplace || u.EffectivePlaceholderForm() != SubstratePlaceholderTok {
		t.Fatalf("defaults wrong: %d %s %s %s", u.EffectiveMaxFileBytes(), u.EffectiveTimeBudget(), u.EffectiveSecretAction(), u.EffectivePlaceholderForm())
	}
	for _, bad := range []SubstrateUploadScanConfig{
		{SecretAction: "drop"}, {PlaceholderForm: "x"}, {TimeBudget: "10ms"}, {MaxFileBytes: -1}, {MaxFileBytes: 65 << 20},
	} {
		s := SubstrateConfig{Launcher: SubstrateLauncherConfig{UploadScan: bad}}
		if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "launcher.upload_scan.") {
			t.Fatalf("%+v: err = %v", bad, err)
		}
	}
}
