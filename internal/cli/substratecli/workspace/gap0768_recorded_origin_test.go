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

package workspace

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	gap0768Origin = "https://git.example.test/team/app.git"
	gap0768Fork   = "https://git.example.test/team/fork.git"
)

// RecordedOrigin reads the clone address or the uploaded folder's origin
// from this computer's records, the newer one when both exist.
func TestGAP0768RecordedOriginComesFromThisComputer(t *testing.T) {
	data := t.TempDir()
	if got := RecordedOrigin(data, "c1"); got != "" {
		t.Fatalf("no record: %q", got)
	}
	gap0768File(t, filepath.Join(data, "sandboxes", "c1", "copy", "copy.json"),
		`{"version":1,"name":"c1","remotes":{"origin":"https://git.example.test/team/app.git","up":"https://git.example.test/up/app.git"},"uploaded_at":"2026-11-20T00:00:00Z"}`)
	if got := RecordedOrigin(data, "c1"); got != gap0768Origin {
		t.Fatalf("upload record: %q", got)
	}
	rec := &hostRecord{Version: hostRecordVersion, Name: "c2", CloneURL: "https://git.example.test/team/cl.git"}
	if err := rec.save(data); err != nil {
		t.Fatal(err)
	}
	if got := RecordedOrigin(data, "c2"); got != "https://git.example.test/team/cl.git" {
		t.Fatalf("clone record: %q", got)
	}
}

func gap0768Mkdir(t *testing.T, d string) {
	t.Helper()
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
}

func gap0768File(t *testing.T, p, body string) {
	t.Helper()
	gap0768Mkdir(t, filepath.Dir(p))
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
