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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/substrate/skilldigest"
)

// Skill folders that arrive without a tool call (GAP-0039, A9's design):
// after UserPromptSubmit, PostToolUse, SessionStart and Stop the kit
// fingerprints every folder under a skill root and attaches the files of
// each new or changed one with role skill_file. The gateway scans each
// attached folder (the runtime skill scan, attest.RuntimeScanner) and adds
// to the connector's own answer:
//
//	"substrate_quarantine": [{"path": "<folder>", "reason": "..."}]
//	"substrate_scanned":    [{"path": "<folder>", "fp": "...", "receipt": "..."}]
//	"substrate_unscanned":  [{"path": "<folder>", "fp": "..."}]
//
// The kit moves a quarantined folder out of its skill root (only a folder
// it listed in that call), keeps a receipt with the fingerprint and sends it
// back instead of the files while the folder is unchanged, and attaches an
// unscanned folder in its next post. A receipt is an HMAC under a key every
// gateway replica shares, so the kit's cache, which the agent can edit,
// proves nothing by itself.

const (
	substrateSkillRoleFile   = "skill_file"
	substrateQuarantineField = "substrate_quarantine"
	substrateScannedField    = "substrate_scanned"
	// substrateUnscannedField names fingerprinted skill folders that were
	// not attached and have no valid receipt (A5's contract: the kit
	// attaches them again in its next post).
	substrateUnscannedField = "substrate_unscanned"
	// substrateSkillFoldersMax bounds the folders scanned per call (the
	// kit sends at most 4).
	substrateSkillFoldersMax = 8
)

// SubstrateSkillScanner scans one attached skill folder: name is the
// folder name, dir its path in the actor, files its attached files.
// Blocked means the folder must not reach the model.
type SubstrateSkillScanner interface {
	ScanSkillFolder(ctx context.Context, name, dir string, files []SubstrateAttachedFile) (blocked bool, reason string, err error)
}

// SubstrateQuarantine is one entry of the substrate_quarantine field.
type SubstrateQuarantine struct {
	Path   string `json:"path"`
	Reason string `json:"reason,omitempty"`
}

// substrateSkillFolders groups the attached skill files by the folders the
// kit listed as attached (facts.skills), so a skill folder's own subfolder
// named "skills" or a plugin's skills root groups the same way.
func substrateSkillFolders(f *SubstrateFacts) map[string][]SubstrateAttachedFile {
	if f == nil {
		return nil
	}
	out := map[string][]SubstrateAttachedFile{}
	for _, fp := range f.Skills {
		if fp.Attached && !fp.Over {
			out[path.Clean("/"+strings.TrimPrefix(fp.Path, "/"))] = nil
		}
	}
	for _, file := range f.Files {
		if file.Role != substrateSkillRoleFile {
			continue
		}
		p := path.Clean("/" + strings.TrimPrefix(file.Path, "/"))
		best := ""
		for dir := range out {
			if strings.HasPrefix(p, dir+"/") && len(dir) > len(best) {
				best = dir
			}
		}
		if best != "" {
			out[best] = append(out[best], file)
		}
	}
	return out
}

// substrateRefuseOrAlert applies the fail mode to a folder DefenseClaw could
// not scan (GAP-0039, GAP-0164): managed installs and the strict tier refuse
// it with a HIGH alert, the OSS default tiers alert (MEDIUM). It returns the
// quarantine entry, or nil when the folder is allowed.
func (st *substrateState) substrateRefuseOrAlert(ctx context.Context, connector, dir, why string, f *SubstrateFacts) *SubstrateQuarantine {
	if st.cfg.BlockUnscannedSkills != nil && st.cfg.BlockUnscannedSkills(connector) {
		st.alertOnce(ctx, "HIGH", "Substrate skill folder refused: "+why, dir, f, nil)
		return &SubstrateQuarantine{Path: dir, Reason: why + "; this install refuses skills it could not scan"}
	}
	st.alertOnce(ctx, "MEDIUM", "Substrate skill folder allowed unscanned: "+why, dir, f, nil)
	return nil
}

// substrateScanSkills scans the attached folders and returns the ones to
// quarantine and, for each folder that passed, a scan receipt. A scan error
// blocks the folder: the kit attached it because the model would see it
// next (fail closed, as the runtime scan does for an incomplete folder).
func (st *substrateState) substrateScanSkills(ctx context.Context, connector string, f *SubstrateFacts) ([]SubstrateQuarantine, []SubstrateScanned) {
	if f == nil || st.cfg.Skills == nil {
		return nil, nil
	}
	var out []SubstrateQuarantine
	// A folder past a kit cap (too many, too deep or too big files, or the
	// root's folders past the listing cap) has no digest and cannot be
	// scanned whole: the fail mode decides (GAP-0039).
	for _, fp := range f.Skills {
		if fp.Over {
			dir := path.Clean("/" + strings.TrimPrefix(fp.Path, "/"))
			if q := st.substrateRefuseOrAlert(ctx, connector, dir, "the skill folder is larger than DefenseClaw scans (more files, deeper or bigger files than the kit attaches)", f); q != nil {
				out = append(out, *q)
			}
		}
	}
	folders := substrateSkillFolders(f)
	listedFP := map[string]string{}
	for _, fp := range f.Skills {
		listedFP[path.Clean("/"+strings.TrimPrefix(fp.Path, "/"))] = fp.FP
	}
	dirs := make([]string, 0, len(folders))
	for d := range folders {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	trusted := st.templateSkillDigests(ctx)
	passed := map[string]string{} // folder -> the digest it passed with
	for i, dir := range dirs {
		if i >= substrateSkillFoldersMax {
			break
		}
		// The receipt binds the content the gateway saw: its own digest of
		// the attached files must be the fingerprint the kit listed, so a
		// folder whose files did not all come (or came cut) gets none.
		d := substrateSkillFolderDigest(dir, folders[dir])
		if d == "" || d != listedFP[dir] {
			if q := st.substrateRefuseOrAlert(ctx, connector, dir, "the attached files are not the whole skill folder", f); q != nil {
				out = append(out, *q)
			}
			continue
		}
		// GAP-0164: a folder that is exactly what the attested template build
		// scanned and admitted is trusted from the attestation.
		if trusted[d] {
			passed[dir] = d
			continue
		}
		blocked, reason, err := st.cfg.Skills.ScanSkillFolder(ctx, path.Base(dir), dir, folders[dir])
		switch {
		case errors.Is(err, ErrSubstrateSkillScannerUnavailable):
			// No scanner can run here: the fail mode decides, never silently.
			if q := st.substrateRefuseOrAlert(ctx, connector, dir, "no skill scanner can run in the gateway", f); q != nil {
				out = append(out, *q)
			}
			continue
		case err != nil:
			blocked, reason = true, "the skill scan could not complete"
			st.alertOnce(ctx, "HIGH", "Substrate skill folder refused: the skill scan could not complete", dir, f, err)
		case blocked:
			st.alertOnce(ctx, "HIGH", "Substrate skill folder refused by the runtime skill scan", dir, f, errors.New(reason))
		}
		if blocked {
			out = append(out, SubstrateQuarantine{Path: dir, Reason: reason})
		} else {
			passed[dir] = d
		}
	}
	if len(out) > 0 {
		st.logRefusal("%d skill folder(s) refused", len(out))
	}
	// A receipt for each folder that passed, bound to the actor, the folder
	// and the content digest the gateway computed: any replica that shares
	// the receipt key accepts it in a later post (GAP-0039).
	var scanned []SubstrateScanned
	if actor, ok := substrateActorFrom(ctx); ok {
		for _, dir := range dirs {
			if d, ok := passed[dir]; ok {
				scanned = append(scanned, SubstrateScanned{Path: dir, FP: d, Receipt: st.skillReceipt(actor.UID, dir, d)})
			}
		}
	}
	return out, scanned
}

// ErrSubstrateSkillScannerUnavailable is what a SubstrateSkillScanner returns
// when no scanner can run here (not installed in the gateway image, or the
// pod refuses scanner containment): the fail mode decides (GAP-0164).
var ErrSubstrateSkillScannerUnavailable = errors.New("substrate: no skill scanner can run in the gateway")

// templateSkillDigests are the admitted skill folder digests of the calling
// actor's attested template; empty when there is none or it cannot be read.
func (st *substrateState) templateSkillDigests(ctx context.Context) map[string]bool {
	if st.cfg.TemplateSkills == nil {
		return nil
	}
	reg, ok := substrateRegistrationFrom(ctx)
	if !ok || reg.Template == "" {
		return nil
	}
	digests, err := st.cfg.TemplateSkills(ctx, reg.Template)
	if err != nil {
		st.logRefusal("template skill digests of %s: %v (folders are scanned)", reg.Template, err)
		return nil
	}
	out := make(map[string]bool, len(digests))
	for _, d := range digests {
		out[d] = true
	}
	return out
}

// substrateSkillFolderDigest is skilldigest.Digest over the folder's
// attached files, computed from their content (the kit's sha256 is a claim).
// A folder with a cut file is never matched.
func substrateSkillFolderDigest(dir string, files []SubstrateAttachedFile) string {
	m := make(map[string][]byte, len(files))
	for _, f := range files {
		if f.Truncated {
			return ""
		}
		p := path.Clean("/" + strings.TrimPrefix(f.Path, "/"))
		rel := strings.TrimPrefix(p, dir+"/")
		if rel == p {
			return ""
		}
		m[rel] = f.Content
	}
	return skilldigest.Digest(m)
}

// alertOnce raises one audit alert per actor, folder, fingerprint and
// summary (bounded memory), so a folder named on every hook post alerts once.
func (st *substrateState) alertOnce(ctx context.Context, severity, summary, dir string, f *SubstrateFacts, cause error) {
	actor, _ := substrateActorFrom(ctx)
	fp := ""
	if f != nil {
		for _, s := range f.Skills {
			if path.Clean("/"+strings.TrimPrefix(s.Path, "/")) == dir {
				fp = s.FP
			}
		}
	}
	key := actor.UID + "\x00" + dir + "\x00" + fp + "\x00" + summary
	st.alertMu.Lock()
	if st.alerted == nil || len(st.alerted) >= substrateAlertMemory {
		st.alerted = map[string]bool{}
	}
	seen := st.alerted[key]
	st.alerted[key] = true
	st.alertMu.Unlock()
	if seen || st.alert == nil {
		return
	}
	details := map[string]any{"actor_uid": actor.UID, "atespace": actor.Atespace, "actor": actor.Name, "folder": dir, "fingerprint": fp}
	if cause != nil {
		details["reason"] = cause.Error()
	}
	st.alert(ctx, severity, summary, details)
}

// substrateAlertMemory bounds alertOnce's and pendingPosts' memory.
const substrateAlertMemory = 10000

// substrateSkillMaxPending is how many posts a folder may stay pending.
const substrateSkillMaxPending = 8

// pendingPosts counts the posts in which a folder fingerprint stayed pending
// on this replica (bounded memory).
func (st *substrateState) pendingPosts(uid, dir, fp string) int {
	key := uid + "\x00" + dir + "\x00" + fp
	st.alertMu.Lock()
	defer st.alertMu.Unlock()
	if st.pending == nil || len(st.pending) >= substrateAlertMemory {
		st.pending = map[string]int{}
	}
	st.pending[key]++
	return st.pending[key]
}

// SubstrateUnscanned is one entry of the substrate_unscanned field.
type SubstrateUnscanned struct {
	Path string `json:"path"`
	FP   string `json:"fp,omitempty"`
}

// SubstrateScanned is one entry of the substrate_scanned field: the kit
// keeps the receipt with the fingerprint and sends it back instead of the
// folder's files while the folder does not change.
type SubstrateScanned struct {
	Path    string `json:"path"`
	FP      string `json:"fp"`
	Receipt string `json:"receipt"`
}

// skillReceipt is the scan receipt of one folder fingerprint for one actor
// incarnation: an HMAC under the receipt key, so code in the actor cannot
// mint one for a folder no gateway scanned.
func (st *substrateState) skillReceipt(uid, dir, fp string) string {
	m := hmac.New(sha256.New, st.receiptKey)
	m.Write([]byte("defenseclaw substrate skill receipt v1\x00" + uid + "\x00" + dir + "\x00" + fp))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:18])
}

func (st *substrateState) skillReceiptOK(uid, dir, fp, receipt string) bool {
	return receipt != "" && hmac.Equal([]byte(receipt), []byte(st.skillReceipt(uid, dir, fp)))
}

// substrateUnscannedSkills sorts the fingerprinted folders the kit did not
// attach and has no valid receipt for:
//
//   - every one is named in substrate_unscanned, and the kit attaches it
//     in its next post;
//   - when the kit had room to attach it in this post (the facts are not
//     truncated) and still did not, the folder is not scanned on purpose (an
//     edited cache, a forged receipt): in managed installs and the strict
//     tier the folder is refused (quarantined, so the agent cannot load or
//     use it), and in the OSS default tiers it raises an alert.
//
// A folder whose files did not fit (truncated) is pending, not refused, for
// at most substrateSkillMaxPending posts (per replica); then it counts as
// one the kit had room for. Without a receipt key every replica shares,
// a receipt from another replica cannot be checked, so a folder that has one
// is only named, never refused.
func (st *substrateState) substrateUnscannedSkills(ctx context.Context, connector string, f *SubstrateFacts) ([]SubstrateUnscanned, []SubstrateQuarantine) {
	actor, ok := substrateActorFrom(ctx)
	if !ok || f == nil || st.cfg.Skills == nil {
		return nil, nil
	}
	var out []SubstrateUnscanned
	var refused []SubstrateQuarantine
	for _, fp := range f.Skills {
		if fp.Attached || fp.FP == "" {
			continue
		}
		dir := path.Clean("/" + strings.TrimPrefix(fp.Path, "/"))
		if st.skillReceiptOK(actor.UID, dir, fp.FP, fp.Receipt) {
			continue
		}
		out = append(out, SubstrateUnscanned{Path: dir, FP: fp.FP})
		if fp.Receipt != "" && !st.receiptShared {
			continue
		}
		// A folder that did not fit is pending, for a bounded number of
		// posts: the kit rotates pending folders least recently attached
		// first, so one still pending after substrateSkillMaxPending posts
		// is being kept out (folders that change on every call, an edited
		// rotation): it counts as one the kit had room for.
		if f.Truncated && st.pendingPosts(actor.UID, dir, fp.FP) <= substrateSkillMaxPending {
			continue
		}
		block := st.cfg.BlockUnscannedSkills != nil && st.cfg.BlockUnscannedSkills(connector)
		details := map[string]any{"actor_uid": actor.UID, "atespace": actor.Atespace, "actor": actor.Name,
			"folder": dir, "fingerprint": fp.FP, "connector": connector, "refused": block}
		if block {
			refused = append(refused, SubstrateQuarantine{Path: dir,
				Reason: "the skill folder was not scanned: the DefenseClaw kit did not send it although it had room"})
			st.alert(ctx, "HIGH", "Substrate skill folder refused: it reached the actor without a scan", details)
		} else {
			st.alert(ctx, "MEDIUM", "Substrate skill folder reached the actor without a scan", details)
		}
	}
	return out, refused
}

// substrateSkillAnswer are the skill fields added to a hook answer.
type substrateSkillAnswer struct {
	Quarantine []SubstrateQuarantine
	Scanned    []SubstrateScanned
	Unscanned  []SubstrateUnscanned
}

func (s substrateSkillAnswer) empty() bool {
	return len(s.Quarantine) == 0 && len(s.Scanned) == 0 && len(s.Unscanned) == 0
}

// substrateSkills runs the skill pass of one hook post.
func (st *substrateState) substrateSkills(ctx context.Context, connector string, f *SubstrateFacts) substrateSkillAnswer {
	q, scanned := st.substrateScanSkills(ctx, connector, f)
	unscanned, refused := st.substrateUnscannedSkills(ctx, connector, f)
	return substrateSkillAnswer{Quarantine: append(q, refused...), Scanned: scanned, Unscanned: unscanned}
}

// substrateAnswerRecorder holds a hook answer so the quarantine field can
// be added to it.
type substrateAnswerRecorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *substrateAnswerRecorder) Header() http.Header { return r.header }
func (r *substrateAnswerRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
}
func (r *substrateAnswerRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(b)
}

// withSubstrateAnswer serves next, adds the quarantine field (when q has
// entries) to a 200 JSON object answer, and returns the answer body for
// the decision log. Any other answer passes unchanged.
func withSubstrateAnswer(w http.ResponseWriter, r *http.Request, next http.Handler, sk substrateSkillAnswer) []byte {
	rec := &substrateAnswerRecorder{header: http.Header{}}
	next.ServeHTTP(rec, r)
	body := rec.body.Bytes()
	original := body
	if rec.status == http.StatusOK && !sk.empty() {
		var obj map[string]json.RawMessage
		if json.Unmarshal(body, &obj) == nil && obj != nil {
			if len(sk.Quarantine) > 0 {
				obj[substrateQuarantineField], _ = json.Marshal(sk.Quarantine)
			}
			if len(sk.Scanned) > 0 {
				obj[substrateScannedField], _ = json.Marshal(sk.Scanned)
			}
			if len(sk.Unscanned) > 0 {
				obj[substrateUnscannedField], _ = json.Marshal(sk.Unscanned)
			}
			if merged, err := json.Marshal(obj); err == nil {
				body = append(merged, '\n')
				rec.header.Set("Content-Type", "application/json")
			}
		}
	}
	for k, v := range rec.header {
		w.Header()[k] = v
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	status := rec.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
	return original
}
