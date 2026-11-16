// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build race

package hookpaths

// gap0055RaceBuild: a race build reads a spread of the GAP-0055 sweep through Resolve.
const gap0055RaceBuild = true
