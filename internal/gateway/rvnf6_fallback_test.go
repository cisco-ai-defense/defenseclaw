// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import "testing"

// RVNF6's saved no-facts probe now shares the permanent 96-row matrix,
// including explicit no-copy expectations from the T6 ambiguity ruling.
func TestRVNF6FallbackParity(t *testing.T) { gapNF6ParityModes(t, false) }
