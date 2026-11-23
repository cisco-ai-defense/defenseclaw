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

package gateway

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
)

// substrateSkillWriteTools are the file tools whose calls write the content
// they carry; attest.HookAssets turns such a call into a skill root into a
// skill asset. A Read, the Skill tool and a shell command that names a skill
// path are not writes (a shell command is matched by text, so cat or ls of
// a skill would look like one): the folder pass covers them.
var substrateSkillWriteTools = map[string]bool{"Write": true, "Edit": true, "MultiEdit": true, "NotebookEdit": true, "apply_patch": true}

// substrateSkillWriteRefusal is the hook pass for a skill the agent is about
// to write with a file tool (substrate-1 GAP-0519): a Write, Edit or patch
// into a skill root. The folder watch only sees the skill once it exists,
// so before this pass the write itself was allowed with no record. The
// content is scanned as a skill; with no skill scanner in the gateway (the
// GAP-0164 known limit) the unscanned-skill fail mode decides as for a
// skill copied in: managed installs and the strict tier refuse the write
// with a HIGH alert, the OSS default tiers allow it with a MEDIUM alert. A
// scan that blocks refuses in every tier. It returns the refusal message,
// or "" to let the call go on.
func (st *substrateState) substrateSkillWriteRefusal(ctx context.Context, env substrateEnvelope) string {
	if pre, _ := substrateMCPEvent(env.Event); !pre || st.cfg.Skills == nil {
		return ""
	}
	var view struct {
		Tool string `json:"tool_name"`
	}
	_ = json.Unmarshal(env.Payload, &view)
	if !substrateSkillWriteTools[view.Tool] {
		return ""
	}
	var attached []attest.AttachedFile
	if env.Facts != nil {
		for _, f := range env.Facts.Files {
			attached = append(attached, attest.AttachedFile{Role: f.Role, Path: f.Path, Content: f.Content, Truncated: f.Truncated})
		}
	}
	var until <-chan struct{}
	for _, a := range attest.HookAssets(env.Payload, attached) {
		if a.Kind != config.AdmissionTypeSkill {
			continue
		}
		if until == nil {
			var cancel context.CancelFunc
			until, cancel = st.skillPostUntil(ctx, true)
			defer cancel()
		}
		files := make([]SubstrateAttachedFile, 0, len(a.Files))
		for _, f := range a.Files {
			files = append(files, SubstrateAttachedFile{Role: f.Role, Path: f.Path, Content: f.Content, Truncated: f.Truncated})
		}
		res := st.scanSkillFolder(ctx, until, st.blocksUnscanned(env.Connector), a.Name, a.Path, files)
		blocked, reason, err := res.blocked, res.reason, res.err
		switch {
		case errors.Is(err, errSkillPending), errors.Is(err, errSkillScannerBusy):
			// B5.4 skill_pending: still scanning at the post's deadline
			// (GAP-0980), or no scan slot. Managed installs and the strict tier
			// refuse the write (the agent writes again and gets the verdict);
			// the OSS tiers allow it with an alert, as before.
			block := st.blocksUnscanned(env.Connector)
			outcome, sev := "allowed", "MEDIUM"
			if block {
				outcome, sev = "refused", "HIGH"
			}
			code, why := skillScanErrCode(err)
			st.auditSkill(ctx, AuditSkillPending, sev, env.Connector, a.Path, env.Facts, map[string]any{"reason": code, "waited_ms": res.waited.Milliseconds(), "outcome": outcome})
			if block {
				if code == SkillReasonScannerBusy {
					return "DefenseClaw refused writing the skill " + a.Name + ": " + why + "; try again in a few seconds"
				}
				return skillPendingMessage(a.Name)
			}
			st.alertOnce(ctx, "MEDIUM", "Substrate skill write allowed while its scan runs: "+a.Name, a.Path, env.Facts, nil)
		case err != nil:
			code, why0 := skillScanErrCode(err)
			why := "a skill the agent is writing (" + a.Name + ") could not be scanned: " + why0
			if q := st.substrateRefuseOrAlert(ctx, env.Connector, a.Path, why, code, env.Facts); q != nil {
				return "DefenseClaw refused writing the skill " + a.Name + ": " + q.Reason
			}
		case blocked:
			st.alertOnce(ctx, "HIGH", "Substrate skill write refused by the runtime skill scan: "+a.Name, a.Path, env.Facts, mcpReason(reason))
			return "DefenseClaw refused writing the skill " + a.Name + ": " + reason
		}
	}
	return ""
}
