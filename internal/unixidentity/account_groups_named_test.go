// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"
)

func TestNamedGroupIDsChecksEveryAcceptedSelector(t *testing.T) {
	var names []string
	for i := range 200 {
		names = append(names, fmt.Sprintf("assignment-%03d", i))
	}
	names = append(names, "ASSIGNMENT-065", "assignment-150@domain.test", " ")
	var calls atomic.Int32
	ids, err := namedGroupIDs(context.Background(), names, func(ctx context.Context, name string) (int, bool, error) {
		calls.Add(1)
		if err := ctx.Err(); err != nil {
			return 0, false, err
		}
		var i int
		_, err := fmt.Sscanf(name, "assignment-%03d", &i)
		return i, i == 65 || i == 150, err
	})
	if err != nil || !reflect.DeepEqual(ids, []int{65, 150}) || calls.Load() != 200 {
		t.Fatalf("all accepted selectors: ids %v, calls %d, error %v", ids, calls.Load(), err)
	}
}

func TestNamedGroupIDsDeadlineFailsTheWholeAnswer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ids, err := namedGroupIDs(ctx, []string{"assignment-001"}, func(context.Context, string) (int, bool, error) {
		t.Fatal("lookup ran after its deadline")
		return 0, false, nil
	})
	if len(ids) != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("partial answer %v, %v", ids, err)
	}
}
