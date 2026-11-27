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
	"sync"

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
//	"substrate_pending":    [{"path": "<folder>", "fp": "..."}] (managed, strict)
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
	// SubstratePendingField names the folders a managed or strict call is
	// refused for while they are being checked (GAP-0980), in the answer and
	// in the refusal: the kit records them and refuses every tool call while
	// one is in reach and the gateway does not answer.
	SubstratePendingField = "substrate_pending"
	// substrateSkillFoldersMax bounds the folders scanned per call (the
	// kit attaches at most 8, maxSkillFoldersPerCall); past it the fail
	// mode decides.
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
	// Code is the reason code (SkillReason*, B5.4); the kit ignores it.
	Code string `json:"code,omitempty"`
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
func (st *substrateState) substrateRefuseOrAlert(ctx context.Context, connector, dir, why, code string, f *SubstrateFacts) *SubstrateQuarantine {
	if st.blocksUnscanned(connector) {
		st.alertOnce(ctx, "HIGH", "Substrate skill folder refused: "+why, dir, f, nil)
		st.auditSkill(ctx, AuditSkillUnscanned, "HIGH", connector, dir, f, map[string]any{"reason": code, "detail": why, "outcome": "refused"})
		return &SubstrateQuarantine{Path: dir, Reason: why + "; this install refuses skills it could not scan", Code: code}
	}
	st.alertOnce(ctx, "MEDIUM", "Substrate skill folder allowed unscanned: "+why, dir, f, nil)
	st.auditSkill(ctx, AuditSkillUnscanned, "MEDIUM", connector, dir, f, map[string]any{"reason": code, "detail": why, "outcome": "allowed"})
	return nil
}

// substrateScanSkills scans the attached folders and returns the ones to
// quarantine and, for each folder that passed, a scan receipt, plus the
// folders it decided (so the unscanned pass leaves them alone). A scan error
// blocks the folder: the kit attached it because the model would see it
// next (fail closed, as the runtime scan does for an incomplete folder).
func (st *substrateState) substrateScanSkills(ctx context.Context, connector string, f *SubstrateFacts) ([]SubstrateQuarantine, []SubstrateScanned, map[string]bool, []SubstrateUnscanned) {
	if f == nil || st.cfg.Skills == nil {
		return nil, nil, nil, nil
	}
	var pending []SubstrateUnscanned
	decided := map[string]bool{}
	var out []SubstrateQuarantine
	// A folder past a kit cap (too many, too deep or too big files, or the
	// root's folders past the listing cap) has no digest and cannot be
	// scanned whole: the fail mode decides (GAP-0039).
	for _, fp := range f.Skills {
		if fp.Over {
			dir := path.Clean("/" + strings.TrimPrefix(fp.Path, "/"))
			if q := st.substrateRefuseOrAlert(ctx, connector, dir, "the skill folder is larger than DefenseClaw scans (more files, deeper or bigger files than the kit attaches)", SkillReasonTooBig, f); q != nil {
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
	// GAP-0164: a folder that did not fit the post comes with its file
	// digests. One whose rebuilt digest is the listed fingerprint and is in
	// the attested template build is trusted without its files, whatever its
	// size. One bigger than a post that is not attested can never be scanned
	// here: the fail mode decides now, with that reason (never "had room").
	if actor, ok := substrateActorFrom(ctx); ok {
		for _, fp := range f.Skills {
			if fp.Attached || fp.Over || fp.FP == "" || len(fp.Sums) == 0 {
				continue
			}
			dir := path.Clean("/" + strings.TrimPrefix(fp.Path, "/"))
			if st.skillReceiptOK(actor.UID, dir, fp.FP, fp.Receipt) || skilldigest.DigestSums(fp.Sums) != fp.FP {
				continue
			}
			switch {
			case trusted[fp.FP]:
				passed[dir], decided[dir] = fp.FP, true
			case fp.Big:
				decided[dir] = true
				if q := st.substrateRefuseOrAlert(ctx, connector, dir, "the skill folder is bigger than one DefenseClaw hook post carries and is not one the attested template build scanned", SkillReasonTooBig, f); q != nil {
					out = append(out, *q)
				}
			}
		}
	}
	// The folders left are scanned in parallel inside one deadline for the
	// whole post (skillPostWait; GAP-0980, GAP-0982), so the post is
	// answered before the kit gives up on it, however many folders it has.
	var jobs []*skillScanJob
	for i, dir := range dirs {
		if i >= substrateSkillFoldersMax {
			// More attached folders than one post scans: none of them is left
			// silently unscanned (fail closed past the cap).
			if q := st.substrateRefuseOrAlert(ctx, connector, dir, "more skill folders came in one post than DefenseClaw scans", SkillReasonTooBig, f); q != nil {
				out = append(out, *q)
			}
			continue
		}
		// The receipt binds the content the gateway saw: its own digest of
		// the attached files must be the fingerprint the kit listed, so a
		// folder whose files did not all come (or came cut) gets none.
		d := substrateSkillFolderDigest(dir, folders[dir])
		if d == "" || d != listedFP[dir] {
			if q := st.substrateRefuseOrAlert(ctx, connector, dir, "the attached files are not the whole skill folder", SkillReasonNotSent, f); q != nil {
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
		// GAP-0981: the payload of a plain .gz is scanned in its place (the
		// parent and rel let it through unscanned), not refused as an
		// archive the scan could not look inside.
		files, from := skillExpandGzip(dir, folders[dir])
		jobs = append(jobs, &skillScanJob{dir: dir, digest: d, files: files, from: from})
	}
	until, cancel := st.skillPostUntil(ctx, len(jobs) > 0)
	defer cancel()
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			j.res = st.scanSkillFolder(ctx, until, st.blocksUnscanned(connector), path.Base(j.dir), j.dir, j.files)
		}()
	}
	wg.Wait()
	for _, j := range jobs {
		dir, d, res := j.dir, j.digest, j.res
		blocked, reason, err := res.blocked, res.reason, res.err
		code := SkillReasonFinding
		switch {
		case errors.Is(err, errSkillPending), errors.Is(err, errSkillScannerBusy):
			// B5.4: still scanning at the post's deadline, or no scan slot
			// came free (GAP-0932). A slow scan is no verdict: the folder is
			// neither hidden nor moved (that would break a write in progress).
			// The kit sends it again with its next hook, which gets the
			// verdict. Until then managed installs and the strict tier refuse
			// every PreToolUse call (GAP-0980: the use gate, and the kit's
			// record when a post goes unanswered); the OSS tiers follow
			// skill_pending at the use gate.
			c, _ := skillScanErrCode(err)
			decided[dir] = true
			pending = append(pending, SubstrateUnscanned{Path: dir, FP: listedFP[dir]})
			outcome := "sent again"
			if st.blocksUnscanned(connector) {
				outcome = "refused until scanned"
			}
			st.auditSkill(ctx, AuditSkillPending, "MEDIUM", connector, dir, f, map[string]any{"reason": c, "waited_ms": res.waited.Milliseconds(), "outcome": outcome})
			continue
		case errors.Is(err, ErrSubstrateSkillScannerUnavailable), errors.Is(err, ErrSubstrateSkillScanTimeout):
			// No verdict (scanner down or off, or too slow): the fail mode
			// decides, never silently.
			c, why := skillScanErrCode(err)
			if q := st.substrateRefuseOrAlert(ctx, connector, dir, why, c, f); q != nil {
				out = append(out, *q)
			}
			continue
		case err != nil:
			blocked, reason, code = true, "the skill scan could not complete", SkillReasonScanFailed
			st.alertOnce(ctx, "HIGH", "Substrate skill folder refused: the skill scan could not complete", dir, f, err)
		case blocked:
			st.alertOnce(ctx, "HIGH", "Substrate skill folder refused by the runtime skill scan", dir, f, errors.New(reason))
		}
		if blocked {
			msg := skillBlockedMessage(dir, reason)
			out = append(out, SubstrateQuarantine{Path: dir, Reason: msg, Code: code})
			st.auditSkill(ctx, AuditSkillBlocked, "HIGH", connector, dir, f, map[string]any{"reason": code, "detail": reason, "duration_ms": res.took.Milliseconds(),
				"quarantine": path.Join(path.Dir(path.Dir(dir)), ".defenseclaw-quarantine")})
		} else if a := skillArchiveFileFrom(dir, j.files, j.from); a != "" {
			// B5.4 skill_archive: the scan could not look inside it.
			if q := st.substrateRefuseOrAlert(ctx, connector, dir, skillArchiveMessage(a, path.Base(dir)), SkillReasonArchive, f); q != nil {
				out = append(out, *q)
			}
		} else {
			passed[dir] = d
			st.auditSkill(ctx, AuditSkillScanned, "INFO", connector, dir, f, map[string]any{"duration_ms": res.took.Milliseconds()})
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
		names := make([]string, 0, len(passed))
		for dir := range passed {
			names = append(names, dir)
		}
		sort.Strings(names)
		for _, dir := range names {
			d := passed[dir]
			scanned = append(scanned, SubstrateScanned{Path: dir, FP: d, Receipt: st.skillReceipt(actor.UID, dir, d)})
		}
	}
	return out, scanned, decided, pending
}

// skillScanJob is one folder of a post the runtime scan decides.
type skillScanJob struct {
	dir, digest string
	files       []SubstrateAttachedFile // what is scanned (skillExpandGzip)
	from        map[string]string
	res         skillScanResult
}

// ErrSubstrateSkillScannerUnavailable is what a SubstrateSkillScanner returns
// when the skill scanner is not running (no scanner sidecar, the sidecar
// down, scanning turned off, or the pod refuses scanner containment): the
// fail mode decides (GAP-0164, B5.4 skill_scanner_down).
var ErrSubstrateSkillScannerUnavailable = errors.New("substrate: the skill scanner is not running")

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
// on this replica. The memory is bounded in two generations: when the
// current one is full it becomes the previous one, and a key found there is
// carried over with its count, so a folder that stays pending (seen in every
// post) never has its count reset by other folders filling the memory.
func (st *substrateState) pendingPosts(uid, dir, fp string) int {
	key := uid + "\x00" + dir + "\x00" + fp
	st.alertMu.Lock()
	defer st.alertMu.Unlock()
	if st.pending == nil {
		st.pending = map[string]int{}
	}
	if _, ok := st.pending[key]; !ok && len(st.pending) >= substrateAlertMemory/2 {
		st.pendingOld, st.pending = st.pending, map[string]int{}
	}
	if _, ok := st.pending[key]; !ok {
		st.pending[key] = st.pendingOld[key]
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
func (st *substrateState) substrateUnscannedSkills(ctx context.Context, connector string, f *SubstrateFacts, decided map[string]bool) ([]SubstrateUnscanned, []SubstrateQuarantine) {
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
		if decided[dir] || st.skillReceiptOK(actor.UID, dir, fp.FP, fp.Receipt) {
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
		why := "the DefenseClaw kit did not send it although it had room"
		if f.Truncated {
			if st.pendingPosts(actor.UID, dir, fp.FP) <= substrateSkillMaxPending {
				continue
			}
			why = "the DefenseClaw kit did not send it in " + strconv.Itoa(substrateSkillMaxPending) + " posts"
		}
		// One alert per actor, folder and fingerprint, not one per post.
		if st.blocksUnscanned(connector) {
			refused = append(refused, SubstrateQuarantine{Path: dir, Reason: "the skill folder was not scanned: " + why, Code: SkillReasonNotSent})
			st.alertOnce(ctx, "HIGH", "Substrate skill folder refused: it reached the actor without a scan", dir, f, errors.New(why))
		} else {
			st.alertOnce(ctx, "MEDIUM", "Substrate skill folder reached the actor without a scan", dir, f, errors.New(why))
		}
	}
	return out, refused
}

// substrateSkillAnswer are the skill fields added to a hook answer.
type substrateSkillAnswer struct {
	Quarantine []SubstrateQuarantine
	Scanned    []SubstrateScanned
	Unscanned  []SubstrateUnscanned
	// pending are the folders still being scanned (also in Unscanned), for
	// the use gate (substrateSkillUseGate); only the OSS tiers have any.
	pending []SubstrateUnscanned
	// held are the pending folders of a managed or strict call (GAP-0980):
	// every PreToolUse is refused while one is, and the kit records them
	// (substrate_pending) and sends them again with every call.
	held []SubstrateUnscanned
	// ask, when set, turns an allow of this PreToolUse call into the
	// connector's ask with this text (B5.4 skill_pending, OSS).
	ask string
	// calloutNote, when set, is added to the connector's native answer: the
	// actor reaches only DefenseClaw because another callout holds
	// Substrate's egress slot (GAP-0505, substrateAddCalloutNote).
	calloutNote string
}

func (s substrateSkillAnswer) empty() bool {
	return len(s.Quarantine) == 0 && len(s.Scanned) == 0 && len(s.Unscanned) == 0 && s.ask == "" && s.calloutNote == ""
}

// substrateSkills runs the skill pass of one hook post.
func (st *substrateState) substrateSkills(ctx context.Context, connector string, f *SubstrateFacts) substrateSkillAnswer {
	q, scanned, decided, pending := st.substrateScanSkills(ctx, connector, f)
	unscanned, refused := st.substrateUnscannedSkills(ctx, connector, f, decided)
	sk := substrateSkillAnswer{Quarantine: append(q, refused...), Scanned: scanned, Unscanned: append(unscanned, pending...), pending: pending}
	if len(pending) > 0 && st.blocksUnscanned(connector) {
		sk.held = pending
	}
	return sk
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
			if len(sk.held) > 0 {
				obj[SubstratePendingField], _ = json.Marshal(sk.held)
			}
			var action string
			if sk.ask != "" && json.Unmarshal(obj["action"], &action) == nil && (action == "allow" || action == "alert") {
				// The connector's own ask (Claude Code PreToolUse), the shape
				// its hook handler renders for a confirm verdict.
				obj["action"], _ = json.Marshal("confirm")
				obj["reason"], _ = json.Marshal(sk.ask)
				obj["claude_code_output"], _ = json.Marshal(map[string]any{"hookSpecificOutput": map[string]any{
					"hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": sk.ask}})
			}
			noted := false
			if env, ok := substrateEnvelopeFrom(r.Context()); ok && sk.calloutNote != "" {
				noted = substrateNoteAnswer(obj, env, sk.calloutNote)
			}
			// A note this answer cannot carry leaves it byte for byte.
			sk.calloutNote = ""
			if !noted && sk.empty() {
				obj = nil
			}
			if merged, err := json.Marshal(obj); obj != nil && err == nil {
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
