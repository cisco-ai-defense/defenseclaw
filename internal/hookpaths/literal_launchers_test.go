// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

func TestDirectLiteralProgramOperandsBareCopyNoPanic(t *testing.T) {
	for _, words := range [][]string{{"cp"}, {"gcp"}, {"cp", "a.txt"}} {
		if got := directLiteralProgramOperands(words, nil, t.TempDir(), t.TempDir(), false); got != nil {
			t.Errorf("%v: got %v, want no write", words, got)
		}
	}
}
