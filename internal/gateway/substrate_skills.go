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
	"encoding/json"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Skill folders that arrive without a tool call (GAP-0039, A9's design):
// after PostToolUse, SessionStart and Stop the kit attaches every new or
// changed folder under a skill root with role skill_file. The gateway
// scans each folder (the runtime skill scan, attest.RuntimeScanner) and
// names the folders it blocks in the hook answer:
//
//	"substrate_quarantine": [{"path": "<folder>", "reason": "..."}]
//
// The kit moves a named folder out of its skill root, and only a folder it
// attached in that call. The answer is otherwise the connector's own.

const (
	substrateSkillRoleFile   = "skill_file"
	substrateQuarantineField = "substrate_quarantine"
	// substrateUnscannedField names fingerprinted skill folders that were
	// not attached and that the gateway has no scan of (A5's contract: the
	// kit attaches them again in its next post).
	substrateUnscannedField = "substrate_unscanned"
	// substrateSkillsSeenMax bounds the scanned-fingerprint memory.
	substrateSkillsSeenMax = 100000
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

// substrateSkillFolders groups the attached skill files by folder:
// <root>/skills/<name>, the folder the kit attached.
func substrateSkillFolders(f *SubstrateFacts) map[string][]SubstrateAttachedFile {
	if f == nil {
		return nil
	}
	out := map[string][]SubstrateAttachedFile{}
	for _, file := range f.Files {
		if file.Role != substrateSkillRoleFile {
			continue
		}
		p := path.Clean("/" + strings.TrimPrefix(file.Path, "/"))
		i := strings.LastIndex(p, "/skills/")
		if i < 0 {
			continue
		}
		rest := p[i+len("/skills/"):]
		name, _, _ := strings.Cut(rest, "/")
		if name == "" || name == "." || name == ".." {
			continue
		}
		dir := p[:i] + "/skills/" + name
		out[dir] = append(out[dir], file)
	}
	return out
}

// substrateScanSkills scans the attached folders and returns the ones to
// quarantine. A scan error blocks the folder: the kit attached it because
// the model would see it next (fail closed, as the runtime scan does for an
// incomplete folder).
func (st *substrateState) substrateScanSkills(ctx context.Context, f *SubstrateFacts) []SubstrateQuarantine {
	folders := substrateSkillFolders(f)
	if len(folders) == 0 || st.cfg.Skills == nil {
		return nil
	}
	dirs := make([]string, 0, len(folders))
	for d := range folders {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	var out []SubstrateQuarantine
	for i, dir := range dirs {
		if i >= substrateSkillFoldersMax {
			break
		}
		blocked, reason, err := st.cfg.Skills.ScanSkillFolder(ctx, path.Base(dir), dir, folders[dir])
		if err != nil {
			st.logRefusal("skill folder scan failed, folder blocked: %v", err)
			blocked, reason = true, "the skill scan could not complete"
		}
		if blocked {
			out = append(out, SubstrateQuarantine{Path: dir, Reason: reason})
		}
	}
	if len(out) > 0 {
		st.logRefusal("%d attached skill folder(s) blocked by the runtime skill scan", len(out))
	}
	// Remember what was scanned, by actor, folder and fingerprint, so a
	// later post that only fingerprints the folder counts it as scanned.
	if actor, ok := substrateActorFrom(ctx); ok && f != nil {
		for _, fp := range f.Skills {
			dir := path.Clean("/" + strings.TrimPrefix(fp.Path, "/"))
			if _, scanned := folders[dir]; scanned && fp.FP != "" {
				st.rememberSkill(actor.UID, dir, fp.FP)
			}
		}
	}
	return out
}

// SubstrateUnscanned is one entry of the substrate_unscanned field.
type SubstrateUnscanned struct {
	Path string `json:"path"`
	FP   string `json:"fp,omitempty"`
}

func (st *substrateState) rememberSkill(uid, dir, fp string) {
	st.skillsMu.Lock()
	defer st.skillsMu.Unlock()
	if st.skillsSeen == nil || len(st.skillsSeen) >= substrateSkillsSeenMax {
		st.skillsSeen = map[string]string{}
	}
	st.skillsSeen[uid+"\x00"+dir] = fp
}

// substrateUnscannedSkills lists the fingerprinted folders the kit did not
// attach whose current fingerprint has not been scanned here: they count
// as not scanned (A5's handoff). A replica that did not see the scan names
// the folder too; the kit then attaches it once more, which costs bytes
// only.
func (st *substrateState) substrateUnscannedSkills(ctx context.Context, f *SubstrateFacts) []SubstrateUnscanned {
	actor, ok := substrateActorFrom(ctx)
	if !ok || f == nil || st.cfg.Skills == nil {
		return nil
	}
	var out []SubstrateUnscanned
	st.skillsMu.Lock()
	defer st.skillsMu.Unlock()
	for _, fp := range f.Skills {
		if fp.Attached || fp.FP == "" {
			continue
		}
		dir := path.Clean("/" + strings.TrimPrefix(fp.Path, "/"))
		if st.skillsSeen[actor.UID+"\x00"+dir] != fp.FP {
			out = append(out, SubstrateUnscanned{Path: dir, FP: fp.FP})
		}
	}
	return out
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
func withSubstrateAnswer(w http.ResponseWriter, r *http.Request, next http.Handler, q []SubstrateQuarantine, unscanned []SubstrateUnscanned) []byte {
	rec := &substrateAnswerRecorder{header: http.Header{}}
	next.ServeHTTP(rec, r)
	body := rec.body.Bytes()
	original := body
	if rec.status == http.StatusOK && (len(q) > 0 || len(unscanned) > 0) {
		var obj map[string]json.RawMessage
		if json.Unmarshal(body, &obj) == nil && obj != nil {
			if len(q) > 0 {
				obj[substrateQuarantineField], _ = json.Marshal(q)
			}
			if len(unscanned) > 0 {
				obj[substrateUnscannedField], _ = json.Marshal(unscanned)
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
