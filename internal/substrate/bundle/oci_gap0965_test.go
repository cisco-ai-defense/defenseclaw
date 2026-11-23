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

package bundle

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"

	eb "github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// GAP-0965: anchors that are readable when the cluster key is taken, unreadable
// when the apply reads them and back to the same contents after must not leave
// the refusal stored under the good key: the digest is pulled again.
func TestGAP0965RefusalFromAnchorFlapIsRetried(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	reg := newTestRegistry(t, buildBundle(t, e.key, 3, policyYAML("paste.example.com")))
	c := reg.client(t, "")
	good := e.store.Anchors
	missing := filepath.Join(t.TempDir(), "missing.json")
	var calls atomic.Int32
	e.store.Anchors = func() (*eb.Anchors, error) {
		if calls.Add(1) == 2 {
			return LoadAnchorsFile(missing)
		}
		return good()
	}
	st := ociStage(reg.ref())
	rcs, _, err := e.store.SyncOCI(ctx, c, st)
	if err != nil || len(rcs) != 1 || rcs[0].Result != ResultRefused {
		t.Fatalf("pass 1: rcs=%+v err=%v, want one refusal", rcs, err)
	}
	if _, _, err = e.store.SyncOCI(ctx, c, st); err != nil {
		t.Fatal(err)
	}
	if r, _ := e.load(t); r.For("team-a") == nil {
		t.Fatalf("the refusal from the anchor flap was stored under the good key and never retried (manifest gets=%d)", reg.manifestGets.Load())
	}
}
