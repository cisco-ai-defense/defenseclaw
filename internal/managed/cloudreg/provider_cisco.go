// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build cmid

package cloudreg

// This file is the OSS-side placeholder for the managed cloud
// credential provider registration. It is deliberately a stub: it must
// not import any private module so that `go build`, `go test`, and
// `go mod tidy` on the public repo succeed in a clean environment with
// no private-registry access.
//
// The managed release build (scripts/build-macos-bundle.sh, invoked by
// `make packaging-macos-bundle`) overwrites this file with the real
// implementation before running `go build -tags cmid`, then restores
// this stub on exit. See scripts/build-macos-bundle.sh for the overlay
// mechanics.
//
// If a managed binary is somehow shipped with this stub still in place,
// New() will return ErrNoProviderRegistered — the same fail-closed
// outcome as an OSS binary running in managed_enterprise mode.

func init() {
	// Intentionally empty. The release-time overlay replaces this file
	// with one whose init() registers the real provider factory.
}
