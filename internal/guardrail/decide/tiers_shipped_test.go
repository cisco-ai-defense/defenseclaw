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

package decide

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestShippedTiersMatchBuiltin: each built-in pack's tiers.yaml is its tier's
// column of Builtin(), byte for byte, and passes ParseColumn. With
// DET111_WRITE_TIERS=1 the files are written from Builtin() instead.
func TestShippedTiersMatchBuiltin(t *testing.T) {
	root := filepath.Join("..", "..", "..", "policies", "guardrail")
	for _, tier := range []Tier{TierDefault, TierPermissive, TierStrict} {
		want, err := MarshalColumn(Builtin().ColumnOf(tier))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, tier.String(), "tiers.yaml")
		if os.Getenv("DET111_WRITE_TIERS") == "1" {
			if err := os.WriteFile(path, want, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s is not the %s column of decide.Builtin(); regenerate with DET111_WRITE_TIERS=1\n--- want\n%s", path, tier, want)
		}
		col, err := ParseColumn(got)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if col.Tier != tier {
			t.Fatalf("%s names tier %v", path, col.Tier)
		}
	}
}
