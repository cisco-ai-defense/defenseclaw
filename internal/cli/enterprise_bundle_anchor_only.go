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

package cli

import (
	"bytes"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// anchorOnlyChange is what a Windows standalone ensure with trust anchors
// and no bundle (Setup /ensure TRUSTANCHORS= without BUNDLE=) did to the
// installed anchor file: its bytes before the run (nil when there was none)
// and the bytes the run installed.
type anchorOnlyChange struct {
	path      string
	previous  []byte
	installed []byte
}

// settleAnchorOnlyEnsure keeps the result of such a run truthful. The
// lifecycle then finds the deployment compliant and reported noop:true with
// noop_reason "compliant" although the run had replaced the anchor file, so
// Intune showed a successful install while the new anchors revoked the
// confirmed bundle signer. A run that changed the file is not a no-op: it
// says what it installed in changes. The warning that names a confirmed
// signer the new anchors revoke or drop comes from the bundle summary
// (bundleCurrentSignerWarning). Byte-identical anchors stay a no-op.
func settleAnchorOnlyEnsure(result *enterprisestatus.Result, change *anchorOnlyChange) {
	if result == nil || change == nil || len(result.Errors) != 0 || bytes.Equal(change.previous, change.installed) {
		return
	}
	result.Noop, result.NoopReason = false, ""
	verb := "replaced the trust anchors in "
	if change.previous == nil {
		verb = "installed trust anchors in "
	}
	result.Changes = append(result.Changes, verb+change.path+"; the confirmed bundle keeps enforcing until a newer signed bundle replaces it")
}
