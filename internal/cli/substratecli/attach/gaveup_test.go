// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"errors"
	"testing"
)

// The end of a wait keeps its kind, so doctor can tell a starting agent
// from a broken route.
func TestGaveUpKeepsItsKind(t *testing.T) {
	for _, k := range []error{ErrStarting, ErrClusterFull} {
		var err error = &gaveUpError{kind: k, msg: "x"}
		if !errors.Is(err, k) || err.Error() != "x" {
			t.Errorf("%v: %v", k, err)
		}
	}
	if !(&RouteError{Kind: ErrAttachOff}).final() {
		t.Error("attach_unavailable does not change by waiting")
	}
}
