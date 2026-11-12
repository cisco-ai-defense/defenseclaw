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
)

// TestSubstrateChainFailureModeManaged is GAP-0090 per D8: a managed
// enterprise install refuses extproc.chain.failure_mode open; auto and
// closed are accepted, and an OSS install accepts open.
func TestSubstrateChainFailureModeManaged(t *testing.T) {
	for _, tc := range []struct {
		mode    string
		managed bool
		ok      bool
	}{
		{"open", true, false},
		{"OPEN", true, false},
		{"auto", true, true},
		{"", true, true},
		{"closed", true, true},
		{"open", false, true},
		{"auto", false, true},
	} {
		s := validSubstrate()
		s.Extproc.Chain.FailureMode = tc.mode
		if err := s.Validate(); err != nil {
			t.Fatalf("%q: base validation: %v", tc.mode, err)
		}
		err := s.ValidateManaged(tc.managed)
		if (err == nil) != tc.ok {
			t.Errorf("managed=%v chain.failure_mode=%q: err %v", tc.managed, tc.mode, err)
		}
		if err != nil && !strings.Contains(err.Error(), "extproc.chain.failure_mode") {
			t.Errorf("error does not name the key: %v", err)
		}
	}
	var nilCfg *SubstrateConfig
	if err := nilCfg.ValidateManaged(true); err != nil {
		t.Fatal(err)
	}
}
