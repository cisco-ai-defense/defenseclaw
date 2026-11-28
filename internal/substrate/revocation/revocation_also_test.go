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

package revocation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RV1-03: a logout ends the ID token and the access token of a sign-in in
// one write; Also is never stored.
func TestPutAlsoEndsEveryTokenInOneWrite(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	out, err := st.Put(ctx, Entry{Person: alice, Token: "k-id", Also: []string{"k-acc", "k-id", ""}})
	if err != nil || out.Token != "k-id" || len(out.Also) != 0 {
		t.Fatalf("put: %+v %v", out, err)
	}
	snap := NewSnapshot(time.Minute)
	if err := snap.Pull(ctx, st); err != nil {
		t.Fatal(err)
	}
	iat := time.Now().Add(-time.Minute)
	for _, k := range []string{"k-id", "k-acc"} {
		if err := snap.Check(alice, k, iat); !errors.Is(err, ErrEnded) {
			t.Errorf("%s: %v", k, err)
		}
	}
	if _, seq := snap.Cursor(); seq != 2 {
		t.Errorf("seq %d, want 2 (one entry per key, the repeat dropped)", seq)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "revocations.json"))
	if strings.Contains(string(b), `"also"`) {
		t.Errorf("also was stored: %s", b)
	}
	if _, err := st.Put(ctx, Entry{Person: alice, NotBefore: Watermark(time.Now()), Also: []string{"k"}}); err == nil {
		t.Error("also on a person-wide entry was taken")
	}
}
