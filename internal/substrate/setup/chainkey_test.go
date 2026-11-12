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

package setup

import (
	"context"
	"strings"
	"testing"
)

type fakeSecrets struct{ m map[string]map[string][]byte }

func (f *fakeSecrets) SecretExists(_ context.Context, ns, name string) (bool, error) {
	_, ok := f.m[ns+"/"+name]
	return ok, nil
}
func (f *fakeSecrets) CreateSecret(_ context.Context, ns, name string, data map[string][]byte) error {
	f.m[ns+"/"+name] = data
	return nil
}

// A13: one chain key per release, created once and never replaced.
func TestEnsureChainKey(t *testing.T) {
	f := &fakeSecrets{m: map[string]map[string][]byte{}}
	plan := testPlan()
	r, err := EnsureChainKey(context.Background(), plan, f)
	if err != nil {
		t.Fatal(err)
	}
	key := string(f.m[plan.Namespace+"/"+ChainKeySecret]["key"])
	if len(key) != 64 || strings.Contains(strings.Join(r.Notes, " "), key) {
		t.Fatalf("key %d chars; notes %v", len(key), r.Notes)
	}
	if _, err := EnsureChainKey(context.Background(), plan, f); err != nil {
		t.Fatal(err)
	}
	if string(f.m[plan.Namespace+"/"+ChainKeySecret]["key"]) != key {
		t.Fatal("an existing chain key was replaced")
	}
}
