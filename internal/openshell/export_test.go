// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"io/fs"
	"testing"
)

// SetGatewayFileOwner makes owned judge which gateway files are the
// caller's for the rest of t: only root could make another user's file.
func SetGatewayFileOwner(t *testing.T, owned func(fs.FileInfo) bool) {
	prev := gatewayFileOwned
	gatewayFileOwned = owned
	t.Cleanup(func() { gatewayFileOwned = prev })
}

// SetProcessTranslated makes translated report whether a goos/goarch
// build runs under Rosetta, for the rest of t.
func SetProcessTranslated(t *testing.T, translated func(goos, goarch string) bool) {
	prev := processTranslated
	processTranslated = translated
	t.Cleanup(func() { processTranslated = prev })
}

// SetSSHShimBase makes NewSSHShim make its directories in dir for the
// rest of t.
func SetSSHShimBase(t *testing.T, dir string) {
	prev := sshShimBase
	sshShimBase = dir
	t.Cleanup(func() { sshShimBase = prev })
}

// SetSSHShimOwners makes owned judge the shim and its directory, and
// trusted the directories above it, for the rest of t.
func SetSSHShimOwners(t *testing.T, owned, trusted func(fs.FileInfo) bool) {
	prevOwned, prevTrusted := sshShimOwned, sshShimTrusted
	sshShimOwned, sshShimTrusted = owned, trusted
	t.Cleanup(func() { sshShimOwned, sshShimTrusted = prevOwned, prevTrusted })
}
