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

package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestLocalModelInfoClassificationJSONCompatibility pins the wire contract for
// the model classification block. It previously guarded the v7 envelope's
// AIDiscoveryModel; that payload is gone, and LocalModelInfo is the live type
// the API, the TUI, and the macOS app all decode.
//
// The explicit-zero case is the one worth a test. DiscoveryConfidence is a
// *float64 with omitempty precisely so that a genuine 0.0 survives the wire:
// omitempty drops a nil pointer but not a pointer to zero. A plain float64
// would make "the scanner scored this 0" indistinguishable from "the scanner
// never scored it", and the recommended-scope filter treats those differently.
func TestLocalModelInfoClassificationJSONCompatibility(t *testing.T) {
	t.Parallel()
	confidence := 0.95
	want := LocalModelInfo{
		ID:                  "Qwen3.5-4B-Q4_K_M",
		Status:              "installed",
		OwnerApplication:    "Meetily",
		Modality:            "generative",
		Relevance:           "primary",
		DiscoveryConfidence: &confidence,
	}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal local model: %v", err)
	}
	var got LocalModelInfo
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal local model: %v", err)
	}
	if got.OwnerApplication != want.OwnerApplication || got.Modality != want.Modality ||
		got.Relevance != want.Relevance || got.DiscoveryConfidence == nil ||
		*got.DiscoveryConfidence != *want.DiscoveryConfidence {
		t.Fatalf("classification metadata did not round trip: got=%+v want=%+v", got, want)
	}

	zero := 0.0
	raw, err = json.Marshal(LocalModelInfo{ID: "unknown", Status: "installed", DiscoveryConfidence: &zero})
	if err != nil {
		t.Fatalf("marshal explicit zero discovery confidence: %v", err)
	}
	if !strings.Contains(string(raw), `"discovery_confidence":0`) {
		t.Fatalf("explicit zero discovery confidence was omitted: %s", raw)
	}

	raw, err = json.Marshal(LocalModelInfo{ID: "unknown", Status: "installed"})
	if err != nil {
		t.Fatalf("marshal absent discovery confidence: %v", err)
	}
	if strings.Contains(string(raw), "discovery_confidence") {
		t.Fatalf("absent discovery confidence must not reach the wire: %s", raw)
	}
}
