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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strconv"
	"time"
)

// Reason codes of the skill pass (B5.4, GAP-0477). They go in the code field
// of a substrate_quarantine entry and in the reason of the audit rows below.
const (
	SkillReasonFinding     = "skill_finding"
	SkillReasonPending     = "skill_pending"
	SkillReasonScannerDown = "skill_scanner_down"
	SkillReasonScanTimeout = "skill_scan_timeout"
	SkillReasonScanFailed  = "skill_scan_failed"
	SkillReasonTooBig      = "skill_too_big"
	SkillReasonNotSent     = "skill_not_sent"
)

// Audit actions of the skill pass (B5.4): the passed side as well as the
// refused one, so an admin sees every folder that was checked.
const (
	AuditSkillScanned   = "substrate.skill.scanned"
	AuditSkillBlocked   = "substrate.skill.blocked"
	AuditSkillUnscanned = "substrate.skill.unscanned"
	AuditSkillPending   = "substrate.skill.pending"
)

var (
	// errSkillPending: the scan is still running after skills.pending_wait.
	// It goes on in the background; the kit sends the folder again with its
	// next hook and gets the verdict then.
	errSkillPending = errors.New("substrate: the skill is still being checked")
	// errSkillScanTimeout: the scan did not finish inside skills.scan.timeout.
	errSkillScanTimeout = errors.New("substrate: the skill scan did not finish in time")
)

// substrateSkillScansInFlight bounds the scans running on one replica (the
// sidecar queues 32); past it a new folder is pending, never allowed as scanned.
const substrateSkillScansInFlight = 32

// skillScanCall is one scan of one folder content; hooks of any actor that
// bring the same content while it runs wait for the same call.
type skillScanCall struct {
	done    chan struct{}
	blocked bool
	reason  string
	err     error
	took    time.Duration
}

// skillScanResult is what one hook learns from a scan.
type skillScanResult struct {
	blocked bool
	reason  string
	err     error
	took    time.Duration
	waited  time.Duration
}

// skillScanKey names a folder content: the folder path and every file.
func skillScanKey(name, dir string, files []SubstrateAttachedFile) string {
	h := sha256.New()
	h.Write([]byte(name + "\x00" + dir + "\x00"))
	for _, f := range files {
		h.Write([]byte(f.Path + "\x00" + strconv.Itoa(len(f.Content)) + "\x00" + strconv.FormatBool(f.Truncated) + "\x00"))
		h.Write(f.Content)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// scanSkillFolder scans one folder inside skills.scan.timeout and waits for
// it at most skills.pending_wait (B5.4). The scan runs detached from the
// hook, so a hook that stops waiting leaves it running: its verdict is
// cached by the runtime scanner and the next hook gets it at once. Without
// limits (tests, or no config) it waits for the whole scan, as before.
func (st *substrateState) scanSkillFolder(ctx context.Context, name, dir string, files []SubstrateAttachedFile) skillScanResult {
	var timeout, wait time.Duration
	if st.cfg.SkillScanLimits != nil {
		timeout, wait = st.cfg.SkillScanLimits()
	}
	key := skillScanKey(name, dir, files)
	st.scanMu.Lock()
	c, ok := st.scans[key]
	if !ok {
		if len(st.scans) >= substrateSkillScansInFlight {
			st.scanMu.Unlock()
			return skillScanResult{err: errSkillPending}
		}
		if st.scans == nil {
			st.scans = map[string]*skillScanCall{}
		}
		c = &skillScanCall{done: make(chan struct{})}
		st.scans[key] = c
		sctx := context.WithoutCancel(ctx)
		cancel := context.CancelFunc(func() {})
		if timeout > 0 {
			sctx, cancel = context.WithTimeout(sctx, timeout)
		}
		go func() {
			defer cancel()
			start := time.Now()
			c.blocked, c.reason, c.err = st.cfg.Skills.ScanSkillFolder(sctx, name, dir, files)
			c.took = time.Since(start)
			if sctx.Err() != nil {
				// Past the timeout nothing the scan said is a verdict.
				c.blocked, c.reason, c.err = false, "", errSkillScanTimeout
			}
			st.scanMu.Lock()
			delete(st.scans, key)
			st.scanMu.Unlock()
			close(c.done)
		}()
	}
	st.scanMu.Unlock()
	start := time.Now()
	var timer <-chan time.Time
	if wait > 0 {
		t := time.NewTimer(wait)
		defer t.Stop()
		timer = t.C
	}
	select {
	case <-c.done:
		return skillScanResult{blocked: c.blocked, reason: c.reason, err: c.err, took: c.took, waited: time.Since(start)}
	case <-timer:
	case <-ctx.Done():
	}
	return skillScanResult{err: errSkillPending, waited: time.Since(start)}
}

// skillScanErrCode is the reason code and the plain reason of a scan that
// gave no verdict.
func skillScanErrCode(err error) (code, why string) {
	switch {
	case errors.Is(err, errSkillPending):
		return SkillReasonPending, "DefenseClaw is still checking the skill"
	case errors.Is(err, errSkillScanTimeout):
		return SkillReasonScanTimeout, "the skill scan did not finish in time"
	case errors.Is(err, ErrSubstrateSkillScannerUnavailable):
		return SkillReasonScannerDown, "the skill scanner is not running"
	}
	return SkillReasonScanFailed, "the skill scan could not complete"
}

// skillPendingMessage is the hook reply for a use refused while the scan runs.
func skillPendingMessage(name string) string {
	return fmt.Sprintf("DefenseClaw is still checking the skill %q. Try again in a few seconds.", name)
}

// skillBlockedMessage is the reason of a folder the scan refused: the kit
// moves it to <root>/../.defenseclaw-quarantine/.
func skillBlockedMessage(dir, reason string) string {
	q := path.Join(path.Dir(path.Dir(dir)), ".defenseclaw-quarantine")
	return fmt.Sprintf("DefenseClaw blocked the skill %q: %s. It was moved to %s.", path.Base(dir), reason, q)
}

// auditSkill writes one skill audit row per actor, folder, fingerprint and
// action (bounded memory, as alertOnce), so a folder named in every hook
// post is recorded once per outcome.
func (st *substrateState) auditSkill(ctx context.Context, action, severity, connector, dir string, f *SubstrateFacts, extra map[string]any) {
	if st.action == nil {
		return
	}
	actor, _ := substrateActorFrom(ctx)
	fp := ""
	if f != nil {
		for _, s := range f.Skills {
			if path.Clean("/"+s.Path) == dir {
				fp = s.FP
			}
		}
	}
	key := "audit\x00" + action + "\x00" + actor.UID + "\x00" + dir + "\x00" + fp
	st.alertMu.Lock()
	if st.alerted == nil || len(st.alerted) >= substrateAlertMemory {
		st.alerted = map[string]bool{}
	}
	seen := st.alerted[key]
	st.alerted[key] = true
	st.alertMu.Unlock()
	if seen {
		return
	}
	details := map[string]any{"actor_uid": actor.UID, "atespace": actor.Atespace, "actor": actor.Name,
		"connector": connector, "folder": dir, "skill": path.Base(dir), "fingerprint": fp}
	for k, v := range extra {
		details[k] = v
	}
	st.action(ctx, action, severity, details)
}
