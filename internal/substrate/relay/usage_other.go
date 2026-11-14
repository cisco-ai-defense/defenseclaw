// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package relay

// processGroupUsage is not measured off Linux (actors run Linux): only the
// agent's output counts as progress there.
func processGroupUsage(int) (Usage, bool) { return Usage{}, false }
