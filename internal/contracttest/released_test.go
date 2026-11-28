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

package contracttest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A management agent on this release's schemas still reads the documents of
// a cluster on the last release. Under schema_version 1 and
// management_contract 1 only an optional member may be added (the guide,
// "Versioning"), so the substrate-status and substrate-verify documents
// DefenseClaw 1.0.10 wrote, with their 12 checks and no bundle_state, must
// still pass the current schemas and their forward schemas.
//
// testdata/released/1.0.10/substrate-status.json is the tag's own fixture.
// substrate-verify.json was built by the 1.0.10 code (BuildVerify over the
// healthy cluster of its status tests), as the tag has no verify fixture.
func TestReleased1010SubstrateDocumentsStillValidate(t *testing.T) {
	s := Compile(t)
	for _, name := range []string{"substrate-status.schema.json", "substrate-verify.schema.json"} {
		file := filepath.Join("testdata", "released", "1.0.10", name[:len(name)-len(".schema.json")]+".json")
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			ProductVersion string `json:"product_version"`
			Checks         []struct {
				ID string `json:"id"`
			} `json:"checks"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if doc.ProductVersion != "1.0.10" || len(doc.Checks) != 12 {
			t.Fatalf("%s is not a 1.0.10 document: version %q, %d checks", file, doc.ProductVersion, len(doc.Checks))
		}
		for _, c := range doc.Checks {
			if c.ID == "bundle_state" {
				t.Fatalf("%s has bundle_state, which 1.0.10 did not write", file)
			}
		}
		t.Run(name, func(t *testing.T) {
			// Validate checks the raw schema and projects the document
			// through the forward schema too.
			s.Validate(t, name, data)
		})
	}
}
