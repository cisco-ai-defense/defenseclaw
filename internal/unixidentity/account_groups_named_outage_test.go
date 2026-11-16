// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// GAP-0592: Open Directory answers "no such group" also while part of a
// bound directory does not answer, so an assignment group it named a moment
// ago was dropped from a successful answer and a looser profile could match.
// A name that resolved within namedGroupMemoryTTL keeps its gid (the uid
// membership check still decides whether the account is in it); a name that
// never resolved, or has not resolved for longer than the TTL, is gone; a
// failed lookup stays a failure.
func TestNamedGroupKnownBeforeKeepsItsGIDWhenTheDirectoryStopsNamingIt(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	memory := &namedGroupMemory{now: func() time.Time { return now }}
	answers := map[string]int{"dc-strict": 7000}
	fail := false
	lookup := memory.lookup(func(_ context.Context, name string) (int, bool, error) {
		if fail {
			return 0, false, errors.New("opendirectoryd did not answer")
		}
		gid, ok := answers[name]
		return gid, ok, nil
	})
	ctx := context.Background()
	if ids, err := namedGroupIDs(ctx, []string{"dc-strict", "dc-never"}, lookup); err != nil || !reflect.DeepEqual(ids, []int{7000}) {
		t.Fatalf("directory answering: %v, %v", ids, err)
	}

	delete(answers, "dc-strict")
	now = now.Add(time.Minute)
	if ids, err := namedGroupIDs(ctx, []string{"DC-STRICT", "dc-never"}, lookup); err != nil || !reflect.DeepEqual(ids, []int{7000}) {
		t.Fatalf("a group named a minute ago was dropped when the directory stopped naming it: %v, %v", ids, err)
	}

	fail = true
	if ids, err := namedGroupIDs(ctx, []string{"dc-strict"}, lookup); err == nil {
		t.Fatalf("a failed lookup answered %v from memory; want the failure", ids)
	}
	fail = false

	now = now.Add(namedGroupMemoryTTL)
	if ids, err := namedGroupIDs(ctx, []string{"dc-strict"}, lookup); err != nil || len(ids) != 0 {
		t.Fatalf("a group not named for longer than %s is still listed: %v, %v", namedGroupMemoryTTL, ids, err)
	}

	answers["dc-strict"] = 7001
	if ids, err := namedGroupIDs(ctx, []string{"dc-strict"}, lookup); err != nil || !reflect.DeepEqual(ids, []int{7001}) {
		t.Fatalf("a name the directory answers again: %v, %v", ids, err)
	}
}
