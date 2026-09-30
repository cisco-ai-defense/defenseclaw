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

package profiles

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestSandboxDocProfileTable keeps the provider profile table of the
// contributor guide (docs/SANDBOX.md) a checked projection of the
// templates: one row per template, under the id it is imported as (with
// <ingress_port> and <region> for the listener port and the Bedrock
// region), naming the credential variable, how it is sent (bearer, or the
// header), and the first endpoint. A DefenseClaw row with no template fails
// too.
func TestSandboxDocProfileTable(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "..", "docs", "SANDBOX.md"))
	if err != nil {
		t.Fatal(err)
	}
	const header = "| Profile | Credential | Sent as | Endpoint |"
	rows := map[string][]string{}
	inTable := false
	for _, line := range strings.Split(string(raw), "\n") {
		if !inTable {
			inTable = strings.TrimSpace(line) == header
			continue
		}
		if !strings.HasPrefix(line, "|") {
			break
		}
		cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if len(cells) != 4 || strings.HasPrefix(cells[0], "---") {
			continue
		}
		rows[strings.Trim(cells[0], "`")] = cells
	}
	if len(rows) == 0 {
		t.Fatalf("docs/SANDBOX.md has no %q table", header)
	}

	// A region no fixed endpoint names, so only a Mantle host changes.
	const region = "eu-west-1"
	documented := map[string]bool{}
	for id, in := range goldenInputs() {
		in.BedrockRegion = region
		p, err := Render(id, in)
		if err != nil {
			t.Fatalf("Render %s: %v", id, err)
		}
		docID, port := p.ID, strconv.Itoa(int(p.Spec.Endpoints[0].Port))
		switch catalog[id] {
		case kindIngress:
			docID, port = IngressID+"-<ingress_port>", "<ingress_port>"
		case kindBedrock:
			docID = id + "-<region>"
		}
		row, ok := rows[docID]
		if !ok {
			t.Errorf("docs/SANDBOX.md: the provider profile table has no `%s` row (template %s)", docID, id)
			continue
		}
		documented[docID] = true
		cred := p.Spec.Credentials[0]
		if want := "`" + cred.EnvVars[0] + "`"; row[1] != want {
			t.Errorf("docs/SANDBOX.md: %s credential = %s, want %s", docID, row[1], want)
		}
		sentAs := "bearer"
		if cred.AuthStyle != "bearer" {
			sentAs = "`" + cred.HeaderName + "`"
		}
		if row[2] != sentAs {
			t.Errorf("docs/SANDBOX.md: %s is sent as %s, want %s", docID, row[2], sentAs)
		}
		host := strings.ReplaceAll(p.Spec.Endpoints[0].Host, region, "<region>")
		if want := "`" + host + ":" + port + "`"; !strings.Contains(row[3], want) {
			t.Errorf("docs/SANDBOX.md: %s endpoint %q does not name %s", docID, row[3], want)
		}
	}
	for id := range rows {
		if strings.HasPrefix(id, "defenseclaw-") && !documented[id] {
			t.Errorf("docs/SANDBOX.md: the provider profile table's `%s` row is no profile template", id)
		}
	}
}
