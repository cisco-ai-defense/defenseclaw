// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"testing"
)

type remediedAssetError struct{ remedy string }

func (e remediedAssetError) Error() string           { return "rule catalog over its limit" }
func (e remediedAssetError) CandidateRemedy() string { return e.remedy }

// A candidate whose valid pack reference composes a catalog over a limit is
// refused with the check's own remedy, not "fix the reference" (GAP-0965).
func TestCheckCandidateAssetsNamesTheCheckRemedy(t *testing.T) {
	previous := candidateAssetCheck
	t.Cleanup(func() { candidateAssetCheck = previous })
	for _, tc := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("global rule pack: %w", remediedAssetError{"select fewer rules, then retry"}), "select fewer rules, then retry"},
		{errors.New("rule pack is not a custom_packs entry"), "fix the reference, then retry"},
	} {
		RegisterCandidateAssetCheck(func(*Config) error { return tc.err })
		var semantic *V8SemanticError
		if err := CheckCandidateAssets(&Config{}); !errors.As(err, &semantic) || semantic.Action != tc.want {
			t.Fatalf("CheckCandidateAssets(%v) = %#v, want action %q", tc.err, err, tc.want)
		}
	}
}
