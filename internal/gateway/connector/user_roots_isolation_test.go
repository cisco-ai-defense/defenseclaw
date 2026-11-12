// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// A test that moves the home with HOME and USERPROFILE alone must not reach
// the real roaming profile, where Devin keeps its config (GAP-0887): the
// package TestMain moves %APPDATA% for the whole run.
func TestConnectorTestsRunOffTheRealRoamingProfile(t *testing.T) {
	testenv.AssertOffRealRoamingProfile(t)
}
