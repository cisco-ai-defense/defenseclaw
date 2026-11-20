// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
)

// GAP-0419: list --all's OWNER column tells an agent made outside the
// launcher from a person's.
func TestSubstrateListOwnerColumnGAP0419(t *testing.T) {
	for _, tc := range []struct {
		a    api.Actor
		want string
	}{
		{api.Actor{Owner: "eng1@example.com", Attribution: "person"}, "eng1@example.com"},
		{api.Actor{Attribution: "atespace", Foreign: true}, "not launcher (atespace only)"},
		{api.Actor{Foreign: true}, "not launcher (atespace only)"},
		{api.Actor{}, "-"},
	} {
		if got := substrateListOwner(tc.a); got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.a, got, tc.want)
		}
	}
}
