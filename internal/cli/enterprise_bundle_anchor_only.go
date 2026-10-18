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

// anchorOnlyConfirmedClause ends the change line when a confirmed bundle is
// current: new anchors do not re-check or remove it.
const anchorOnlyConfirmedClause = "; the confirmed bundle keeps enforcing until a newer signed bundle replaces it"

// anchorOnlyChange is what a Windows standalone ensure with trust anchors
// and no bundle (Setup /ensure TRUSTANCHORS= without BUNDLE=) did to the
// installed anchor file: whether a file was there, its bytes before the run
// (nil when there was none or it could not be read, which counts as
// changed) and the bytes the run installed. It also records the anchors a
// BUNDLE= TRUSTANCHORS= run committed once its bundle was confirmed or found
// already applied (windowsBundleRun.anchorCommit).
type anchorOnlyChange struct {
	path      string
	existed   bool
	previous  []byte
	installed []byte
}

// settleAnchorOnlyEnsure keeps the result of such a run truthful. The
// lifecycle then finds the deployment compliant and reported noop:true with
// noop_reason "compliant" although the run had replaced the anchor file, so
// Intune showed a successful install while the new anchors revoked the
// confirmed bundle signer. A run that changed the file is not a no-op: it
// says what it installed in changes, and that the confirmed bundle keeps
// enforcing only when one is current (confirmedBundle). The warning that
// names a confirmed signer the new anchors revoke or drop comes from the
// bundle summary (bundleCurrentSignerWarning). Byte-identical anchors stay
// a no-op. The same holds for a repeat of the confirmed bundle that commits
// other anchors: it is not an already_applied no-op (GAP-0034).
func settleAnchorOnlyEnsure(result *enterprisestatus.Result, change *anchorOnlyChange, confirmedBundle bool) {
	if result == nil || change == nil || len(result.Errors) != 0 || bytes.Equal(change.previous, change.installed) {
		return
	}
	result.Noop, result.NoopReason = false, ""
	text := "replaced the trust anchors in " + change.path
	if !change.existed {
		text = "installed trust anchors in " + change.path
	}
	if confirmedBundle {
		text += anchorOnlyConfirmedClause
	}
	result.Changes = append(result.Changes, text)
}
