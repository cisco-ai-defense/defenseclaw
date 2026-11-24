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
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// Without a recorded origin there is nothing trusted to push to: refused
// before any network read, whatever the checkout's config says.
func TestGAP0768NoRecordedOriginIsRefused(t *testing.T) {
	s := rv4Setup(t)
	s.write("a.txt", "x\n")
	_, err := PrepareBranchPush(context.Background(), localExec, s.root, "a1", "", nil)
	var pe *BranchPushError
	if !errors.As(err, &pe) || pe.Kind != "no_origin" {
		t.Fatalf("got %v, want a no_origin refusal", err)
	}
}

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
