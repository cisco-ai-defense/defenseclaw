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

//go:build !windows

package sandboxcli

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
)

// On a managed computer the sandbox daemon builds the harness images in its
// own state directory. `image list` and the doctor read the user's DefenseClaw
// data directory, found no image there and said none was built after a run
// had built one (GAP-0548).
func TestManagedImagesAreTheDaemonsStore(t *testing.T) {
	ta := newTestApp(t, "")
	daemonDir := filepath.Join(ta.home, ".local", "state", "defenseclaw-sandbox")
	rec := image.Record{Tag: "defenseclaw/sandbox:claudecode-d05d9035569c7972-u1000", ImageID: "sha256:aa", Connector: "claudecode",
		HarnessVersion: "2.0.0", HookFireVerified: true, BuiltAt: time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)}
	if err := image.NewStore(daemonDir).Put(rec); err != nil {
		t.Fatal(err)
	}
	real := &builderImages{app: ta.App}

	// Elsewhere the images are the user's own data directory's.
	if got, err := real.List(); err != nil || len(got) != 0 {
		t.Fatalf("unmanaged list = %v, %v", got, err)
	}
	if got := ta.imageDataDir(); got != ta.dataDir() {
		t.Fatalf("unmanaged image dir = %s", got)
	}

	withManagedHost(t)
	if got := ta.imageDataDir(); got != daemonDir {
		t.Fatalf("managed image dir = %s, want %s", got, daemonDir)
	}
	got, err := real.List()
	if err != nil || len(got) != 1 || got[0].Tag != rec.Tag {
		t.Fatalf("managed list = %v, %v", got, err)
	}
	if ids := ta.storeImageIDs("claudecode"); len(ids) != 1 || ids[0] != "sha256:aa" {
		t.Fatalf("managed image ids = %v", ids)
	}
}
