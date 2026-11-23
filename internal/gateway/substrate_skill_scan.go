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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"
)

// Reason codes of the skill pass (B5.4, GAP-0477). They go in the code field
// of a substrate_quarantine entry and in the reason of the audit rows below.
const (
	SkillReasonFinding     = "skill_finding"
	SkillReasonPending     = "skill_pending"
	SkillReasonScannerDown = "skill_scanner_down"
	SkillReasonScanTimeout = "skill_scan_timeout"
	SkillReasonScannerBusy = "skill_scanner_busy"
	SkillReasonScanFailed  = "skill_scan_failed"
	SkillReasonTooBig      = "skill_too_big"
	SkillReasonNotSent     = "skill_not_sent"
	SkillReasonArchive     = "skill_archive"
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
	// errSkillScannerBusy: no scan slot came free inside skills.pending_wait
	// (GAP-0932); never an allow as scanned.
	errSkillScannerBusy = errors.New("substrate: the skill scanner is busy")
)

// substrateSkillScansInFlight bounds the scans running on one replica (the
// sidecar queues 32), and substrateSkillScansPerActor one actor's share of
// them (GAP-0932: one post carries at most 8 folders), so one actor cannot
// keep every other actor's folders from being scanned. Past either a new
// folder waits for a slot inside pending_wait, then is skill_scanner_busy.
const (
	substrateSkillScansInFlight = 32
	substrateSkillScansPerActor = substrateSkillFoldersMax
)

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

// blocksUnscanned: managed installs and the strict tier refuse a skill
// folder DefenseClaw could not scan (the hook fail mode, GAP-0039).
func (st *substrateState) blocksUnscanned(connector string) bool {
	return st.cfg.BlockUnscannedSkills != nil && st.cfg.BlockUnscannedSkills(connector)
}

// scanSkillFolder scans one folder inside skills.scan.timeout. Managed
// installs and the strict tier wait for the whole scan, as the parent did
// (GAP-0931): a folder is never left pending there, it gets a verdict or the
// fail mode at the timeout, whatever the connector and however the agent
// later uses it. The OSS tiers wait at most skills.pending_wait (B5.4): the
// scan runs detached from the hook, so a hook that stops waiting leaves it
// running; its verdict is cached by the runtime scanner and the next hook
// gets it at once. Without limits (tests, or no config) it waits for the
// whole scan.
func (st *substrateState) scanSkillFolder(ctx context.Context, connector, name, dir string, files []SubstrateAttachedFile) skillScanResult {
	var timeout, wait time.Duration
	if st.cfg.SkillScanLimits != nil {
		timeout, wait = st.cfg.SkillScanLimits()
	}
	start := time.Now()
	// The wait for a scan slot is pending_wait in every tier.
	var slot <-chan time.Time
	if wait > 0 {
		t := time.NewTimer(wait)
		defer t.Stop()
		slot = t.C
	}
	if st.blocksUnscanned(connector) {
		wait = 0
	}
	actor, _ := substrateActorFrom(ctx)
	key := skillScanKey(name, dir, files)
	st.scanMu.Lock()
	c, ok := st.scans[key]
	for !ok && (len(st.scans) >= substrateSkillScansInFlight || st.scanActors[actor.UID] >= substrateSkillScansPerActor) {
		if st.scanFree == nil {
			st.scanFree = make(chan struct{})
		}
		free := st.scanFree
		st.scanMu.Unlock()
		select {
		case <-free:
		case <-slot:
			return skillScanResult{err: errSkillScannerBusy, waited: time.Since(start)}
		case <-ctx.Done():
			return skillScanResult{err: errSkillPending, waited: time.Since(start)}
		}
		st.scanMu.Lock()
		c, ok = st.scans[key]
	}
	if !ok {
		if st.scans == nil {
			st.scans = map[string]*skillScanCall{}
			st.scanActors = map[string]int{}
		}
		c = &skillScanCall{done: make(chan struct{})}
		st.scans[key] = c
		st.scanActors[actor.UID]++
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
			if st.scanActors[actor.UID]--; st.scanActors[actor.UID] <= 0 {
				delete(st.scanActors, actor.UID)
			}
			if st.scanFree != nil {
				close(st.scanFree)
				st.scanFree = nil
			}
			st.scanMu.Unlock()
			close(c.done)
		}()
	}
	st.scanMu.Unlock()
	var timer <-chan time.Time
	if wait > 0 {
		// What is left of pending_wait after the wait for a slot.
		t := time.NewTimer(max(wait-time.Since(start), time.Nanosecond))
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
	case errors.Is(err, errSkillScannerBusy):
		return SkillReasonScannerBusy, "the skill scanner is busy with other skills"
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
	key := "audit\x00" + action + "\x00" + actor.UID + "\x00" + dir + "\x00" + fp + "\x00" + fmt.Sprint(extra["outcome"])
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

// skillArchiveMagic are the leading bytes of archive formats; at offset 257
// a tar header says "ustar".
var skillArchiveMagic = [][]byte{
	[]byte("PK\x03\x04"), {0x1f, 0x8b}, []byte("BZh"), {0xfd, '7', 'z', 'X', 'Z', 0x00},
	{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}, {0x28, 0xb5, 0x2f, 0xfd},
}

// skillArchiveFile is the first file of a folder whose content is an
// archive (zip, gzip, bzip2, xz, 7z, zstd, tar), by its leading bytes, as a
// path inside the folder; "" when there is none. The static analyzers read
// files as they are, so a clean verdict says nothing of what an archive
// holds (B5.4 skill_archive): the fail mode decides.
func skillArchiveFile(dir string, files []SubstrateAttachedFile) string {
	for _, f := range files {
		c := f.Content
		hit := len(c) >= 262 && bytes.Equal(c[257:262], []byte("ustar"))
		for _, m := range skillArchiveMagic {
			hit = hit || bytes.HasPrefix(c, m)
		}
		if hit {
			return strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(f.Path, "/")), dir+"/")
		}
	}
	return ""
}

// skillArchiveMessage is the reason of a folder with an archive in it.
func skillArchiveMessage(file, name string) string {
	return fmt.Sprintf("DefenseClaw could not look inside %q in the skill %q", file, name)
}

// skillPendingAskMessage is the OSS ask for a use while the scan runs.
func skillPendingAskMessage(name string) string {
	return fmt.Sprintf("DefenseClaw is still checking the skill %q. Use it anyway?", name)
}

// skillAskConnectors are the connectors whose PreToolUse answer can ask the
// person (Claude Code: permissionDecision ask) and that reach the use gate
// (their Skill tool and skill reads run the folder pass).
var skillAskConnectors = map[string]bool{"claudecode": true}

// substrateSkillUseGate is the use gate of a PreToolUse call that uses a
// folder this call's own pass decided (the kit runs the pass for the Claude
// Code Skill tool and for reads of skill files). Managed installs and the
// strict tier refuse a use of a folder the pass refused (GAP-0931: the kit
// moves it, and the call that brought it does not run either); they never
// have a pending folder (scanSkillFolder waits for the whole scan there).
// The OSS tiers add no block: a use of a folder still being scanned asks
// where the agent can ask (sk.ask) and else is allowed with a MEDIUM alert,
// as rel (B5.4 skill_pending). It returns the refusal message, or "".
func (st *substrateState) substrateSkillUseGate(ctx context.Context, env substrateEnvelope, sk *substrateSkillAnswer) string {
	if len(sk.pending) == 0 && len(sk.Quarantine) == 0 {
		return ""
	}
	if pre, _ := substrateMCPEvent(env.Event); !pre {
		return ""
	}
	if st.blocksUnscanned(env.Connector) {
		dirs := make([]string, 0, len(sk.Quarantine))
		for _, q := range sk.Quarantine {
			dirs = append(dirs, q.Path)
		}
		dir := skillUsedFolder(env, dirs)
		if dir == "" {
			return ""
		}
		for _, q := range sk.Quarantine {
			if path.Clean("/"+strings.TrimPrefix(q.Path, "/")) == dir {
				return skillUseRefusedMessage(path.Base(dir), q)
			}
		}
		return ""
	}
	if len(sk.pending) == 0 {
		return ""
	}
	dirs := make([]string, 0, len(sk.pending))
	for _, p := range sk.pending {
		dirs = append(dirs, p.Path)
	}
	dir := skillUsedFolder(env, dirs)
	if dir == "" {
		return ""
	}
	name := path.Base(dir)
	outcome := "allowed"
	if skillAskConnectors[env.Connector] {
		outcome, sk.ask = "asked", skillPendingAskMessage(name)
	}
	st.auditSkill(ctx, AuditSkillPending, "MEDIUM", env.Connector, dir, env.Facts, map[string]any{"reason": SkillReasonPending, "outcome": outcome})
	if outcome == "allowed" {
		st.alertOnce(ctx, "MEDIUM", "Substrate skill used while its scan runs: "+name, dir, env.Facts, nil)
	}
	return ""
}

// skillUseRefusedMessage is the hook reply for a use of a refused folder.
func skillUseRefusedMessage(name string, q SubstrateQuarantine) string {
	switch {
	case q.Code == SkillReasonPending:
		return skillPendingMessage(name)
	case strings.HasPrefix(q.Reason, "DefenseClaw "):
		return q.Reason
	}
	return fmt.Sprintf("DefenseClaw refused the skill %q: %s.", name, q.Reason)
}

// skillUsedFolder is the folder of dirs a PreToolUse call uses: the one the
// Skill tool names by its folder name or its SKILL.md frontmatter name (a
// plugin skill is "plugin:name"; case-insensitive), the one holding a path
// the call names (as given, or as the kit resolved it: relative paths and
// links), or one a command names; "" when the call uses none of them.
func skillUsedFolder(env substrateEnvelope, dirs []string) string {
	var ev struct {
		Tool  string         `json:"tool_name"`
		Input map[string]any `json:"tool_input"`
	}
	if json.Unmarshal(env.Payload, &ev) != nil {
		return ""
	}
	str := func(k string) string { s, _ := ev.Input[k].(string); return s }
	skill := ""
	if ev.Tool == "Skill" {
		if skill = str("skill"); skill == "" {
			skill = str("name")
		}
		if i := strings.LastIndex(skill, ":"); i >= 0 {
			skill = skill[i+1:]
		}
	}
	var named []string
	for _, k := range []string{"file_path", "notebook_path", "path"} {
		if f := str(k); strings.HasPrefix(f, "/") {
			named = append(named, path.Clean(f))
		}
	}
	var folders map[string][]SubstrateAttachedFile
	if env.Facts != nil {
		for _, p := range env.Facts.Paths {
			for _, x := range []string{p.Abs, p.Resolved} {
				if strings.HasPrefix(x, "/") {
					named = append(named, path.Clean(x))
				}
			}
		}
		if skill != "" {
			folders = substrateSkillFolders(env.Facts)
		}
	}
	cmd := str("command")
	for _, d := range dirs {
		dir := path.Clean("/" + strings.TrimPrefix(d, "/"))
		if skill != "" && (strings.EqualFold(skill, path.Base(dir)) || strings.EqualFold(skill, skillFrontmatterName(dir, folders[dir]))) {
			return dir
		}
		for _, n := range named {
			if n == dir || strings.HasPrefix(n, dir+"/") {
				return dir
			}
		}
		if cmd != "" && strings.Contains(cmd, path.Base(path.Dir(dir))+"/"+path.Base(dir)) {
			return dir
		}
	}
	return ""
}

// skillFrontmatterName is the name: of the folder's SKILL.md frontmatter
// (the name the agent loads the skill by), read from its first 64 lines;
// "" when there is none.
func skillFrontmatterName(dir string, files []SubstrateAttachedFile) string {
	for _, f := range files {
		if path.Clean("/"+strings.TrimPrefix(f.Path, "/")) != dir+"/SKILL.md" {
			continue
		}
		lines := strings.SplitN(strings.TrimPrefix(string(f.Content), "\ufeff"), "\n", 65)
		if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
			return ""
		}
		for _, l := range lines[1:] {
			if strings.TrimSpace(l) == "---" {
				return ""
			}
			if k, v, ok := strings.Cut(l, ":"); ok && strings.TrimSpace(k) == "name" {
				return strings.Trim(strings.TrimSpace(v), `"'`)
			}
		}
	}
	return ""
}
