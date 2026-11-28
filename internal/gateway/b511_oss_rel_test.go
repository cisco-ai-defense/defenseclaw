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
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
)

// b511OSSScanner answers each folder after a delay, clean, blocked or down.
type b511OSSScanner struct {
	delay   time.Duration
	blocked bool
	down    bool
}

func (s b511OSSScanner) ScanSkillFolder(ctx context.Context, name, dir string, files []SubstrateAttachedFile) (bool, string, error) {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return false, "", ctx.Err()
	}
	if s.down {
		return false, "", ErrSubstrateSkillScannerUnavailable
	}
	if s.blocked {
		return true, "the skill reads credentials and sends them out", nil
	}
	return false, "", nil
}

type b511OSSCase struct {
	name      string
	connector string
	event     string
	scanner   b511OSSScanner
	folders   map[string]map[string]string // folder -> files; nil files = listed with a receipt, not attached
	unlisted  bool                         // the receipted folders come with no receipt (substrate_unscanned)
}

func b511OSSCases() []b511OSSCase {
	skill := map[string]string{"SKILL.md": "---\nname: pdf-helper\ndescription: Fill PDF forms\n---\n# PDF helper\n", "scripts/run.py": "print('hi')\n"}
	corpus := map[string]map[string]string{}
	for i, c := range []map[string]string{
		{"SKILL.md": "---\nname: a\n---\n", "data/dates.csv": "070701,first release\n"},
		{"SKILL.md": "---\nname: b\n---\n", "locales/messages.ar": "greeting = marhaba\n"},
		{"SKILL.md": "---\nname: c\n---\n", "README.pt.br": "Leia-me\n"},
		{"SKILL.md": "---\nname: d\n---\n", "tests/fixtures/sample.zip": b511ZipOne("a.txt", "hello")},
		{"SKILL.md": "---\nname: e\n---\n", "templates/report.docx": b511ZipOne("word/document.xml", "<w/>")},
		{"SKILL.md": "---\nname: f\n---\n", "tests/data.json.gz": b511OGz(`{"a":1}`)},
	} {
		corpus[fmt.Sprintf("/home/agent/.claude/skills/corpus%02d", i)] = c
	}
	dir := "/home/agent/.claude/skills/pdf-helper"
	return []b511OSSCase{
		{name: "no-folder", connector: "claudecode", event: "PreToolUse"},
		{name: "fresh-clean", connector: "claudecode", event: "PreToolUse", folders: map[string]map[string]string{dir: skill}},
		{name: "fresh-clean-session", connector: "claudecode", event: "SessionStart", folders: map[string]map[string]string{dir: skill}},
		{name: "fresh-clean-codex", connector: "codex", event: "PreToolUse", folders: map[string]map[string]string{"/home/agent/.codex/skills/pdf-helper": skill}},
		{name: "receipted", connector: "claudecode", event: "PreToolUse", folders: map[string]map[string]string{dir: nil}},
		{name: "unscanned-listed", connector: "claudecode", event: "PreToolUse", folders: map[string]map[string]string{dir: nil}, unlisted: true},
		{name: "slow-clean", connector: "claudecode", event: "PreToolUse", scanner: b511OSSScanner{delay: 400 * time.Millisecond}, folders: map[string]map[string]string{dir: skill}},
		{name: "blocked", connector: "claudecode", event: "PreToolUse", scanner: b511OSSScanner{blocked: true}, folders: map[string]map[string]string{dir: skill}},
		{name: "scanner-down", connector: "claudecode", event: "PreToolUse", scanner: b511OSSScanner{down: true}, folders: map[string]map[string]string{dir: skill}},
		{name: "benign-corpus", connector: "claudecode", event: "PreToolUse", folders: corpus},
	}
}

func b511ZipOne(name, body string) string {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, _ := w.Create(name)
	f.Write([]byte(body))
	w.Close()
	return b.String()
}

func b511OGz(body string) string {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(body))
	w.Close()
	return b.String()
}

// b511OSSAnswer is the status, content headers and body of one OSS hook
// post through the envelope middleware.
func b511OSSAnswer(t *testing.T, c b511OSSCase) string {
	t.Helper()
	uid := "7f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e77"
	st := &substrateState{receiptKey: bytes.Repeat([]byte{7}, 32)}
	st.cfg.Skills = c.scanner
	st.cfg.BlockUnscannedSkills = func(string) bool { return false }
	st.cfg.SkillScanLimits = func() (time.Duration, time.Duration) { return 20 * time.Second, 8 * time.Second } // b511:head-only
	key, _ := sandboxreg.SubstrateKey("eng-web", uid)
	ctx := withSubstrateActor(context.Background(), substrateActor{Atespace: "eng-web", Name: "b511", UID: uid,
		Subject: "actor/eng-web/b511", RegistrationKey: key, verified: substrateVerified})
	ctx = withSubstrateRoute(ctx, substrateActorRoute{class: sandboxauth.RouteHook, connector: c.connector})

	var facts *SubstrateFacts
	if len(c.folders) > 0 {
		facts = &SubstrateFacts{}
		dirs := make([]string, 0, len(c.folders))
		for d := range c.folders {
			dirs = append(dirs, d)
		}
		sort.Strings(dirs)
		for _, d := range dirs {
			files := c.folders[d]
			if files == nil {
				files = map[string]string{"SKILL.md": "---\nname: kept\n---\n"}
				var fs []SubstrateAttachedFile
				for rel, body := range files {
					fs = append(fs, SubstrateAttachedFile{Role: substrateSkillRoleFile, Path: d + "/" + rel, Content: []byte(body), Size: int64(len(body))})
				}
				fp := substrateSkillFolderDigest(d, fs)
				r := st.skillReceipt(uid, d, fp)
				if c.unlisted {
					r = ""
				}
				facts.Skills = append(facts.Skills, SubstrateSkillFingerprint{Path: d, FP: fp, Receipt: r})
				continue
			}
			rels := make([]string, 0, len(files))
			for rel := range files {
				rels = append(rels, rel)
			}
			sort.Strings(rels)
			var fs []SubstrateAttachedFile
			for _, rel := range rels {
				body := files[rel]
				fs = append(fs, SubstrateAttachedFile{Role: substrateSkillRoleFile, Path: d + "/" + rel, Content: []byte(body), Size: int64(len(body))})
			}
			facts.Files = append(facts.Files, fs...)
			facts.Skills = append(facts.Skills, SubstrateSkillFingerprint{Path: d, FP: substrateSkillFolderDigest(d, fs), Attached: true})
		}
	}
	payload, _ := json.Marshal(map[string]any{"session_id": "b511", "hook_event_name": c.event, "tool_name": "Read",
		"tool_input": map[string]any{"file_path": "/home/agent/notes.md"}, "cwd": "/home/agent"})
	env, _ := json.Marshal(substrateEnvelope{V: substrateEnvelopeVersion, Connector: c.connector, Event: c.event, Mode: "action", KitVersion: "1.0.11", Payload: payload, Facts: facts})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}` + "\n"))
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+c.connector+"/hook", bytes.NewReader(env)).WithContext(ctx)
	w := httptest.NewRecorder()
	substrateEnvelopeMiddleware(st, next).ServeHTTP(w, req)
	return fmt.Sprintf("%d\nContent-Type: %s\nContent-Length: %s\n%s", w.Code, w.Header().Get("Content-Type"), w.Header().Get("Content-Length"), w.Body.String())
}

// Condition (a) of the managed hold (GAP-0980/0981): an OSS hook post's
// answer is byte for byte the answer rel/1.0.11 e37e499e97 gives (captured
// there with this file; B511_CAPTURE=1 prints them again).
func TestB511OSSAnswersAreRel(t *testing.T) {
	capture := os.Getenv("B511_CAPTURE") != ""
	for _, c := range b511OSSCases() {
		got := b511OSSAnswer(t, c)
		if capture {
			t.Logf("B511GOLD %q: %s,", c.name, strconv.Quote(got))
			continue
		}
		want, ok := b511OSSRel[c.name]
		if !ok {
			t.Errorf("%s: no rel answer pinned", c.name)
			continue
		}
		if design, ok := b511OSSDesign[c.name]; ok {
			// Same decision as rel (same status, fields and folders), with
			// the B5.4 reason text and code; those bytes are pinned too.
			if got != design || b511OSSShape(t, got) != b511OSSShape(t, want) {
				t.Errorf("%s: OSS answer is not rel's decision with the B5.4 text\n got: %s\nwant: %s", c.name, strings.ReplaceAll(got, "\n", `\n`), strings.ReplaceAll(design, "\n", `\n`))
			}
			continue
		}
		if got != want {
			t.Errorf("%s: OSS answer differs from rel/1.0.11\n got: %s\nwant: %s", c.name, strings.ReplaceAll(got, "\n", `\n`), strings.ReplaceAll(want, "\n", `\n`))
		}
	}
}

// b511OSSRel are the rel/1.0.11 e37e499e97 answers (B511_CAPTURE=1 there).
var b511OSSRel = map[string]string{
	"no-folder":           "200\nContent-Type: application/json\nContent-Length: 83\n{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"}}\n",
	"fresh-clean":         "200\nContent-Type: application/json\nContent-Length: 270\n{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"},\"substrate_scanned\":[{\"path\":\"/home/agent/.claude/skills/pdf-helper\",\"fp\":\"sha256:f7be8b0309d825abc49b6a8eeff78348445101c2e67f798bef19bbc17ad03922\",\"receipt\":\"B3P3Zfc3g6ClDotNn_RgOjAk\"}]}\n",
	"fresh-clean-session": "200\nContent-Type: application/json\nContent-Length: 270\n{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"},\"substrate_scanned\":[{\"path\":\"/home/agent/.claude/skills/pdf-helper\",\"fp\":\"sha256:f7be8b0309d825abc49b6a8eeff78348445101c2e67f798bef19bbc17ad03922\",\"receipt\":\"B3P3Zfc3g6ClDotNn_RgOjAk\"}]}\n",
	"fresh-clean-codex":   "200\nContent-Type: application/json\nContent-Length: 269\n{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"},\"substrate_scanned\":[{\"path\":\"/home/agent/.codex/skills/pdf-helper\",\"fp\":\"sha256:f7be8b0309d825abc49b6a8eeff78348445101c2e67f798bef19bbc17ad03922\",\"receipt\":\"PG-dppUl8SwjjbAYy0zeiWtd\"}]}\n",
	"receipted":           "200\nContent-Type: application/json\nContent-Length: 83\n{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"}}\n",
	"unscanned-listed":    "200\nContent-Type: application/json\nContent-Length: 235\n{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"},\"substrate_unscanned\":[{\"path\":\"/home/agent/.claude/skills/pdf-helper\",\"fp\":\"sha256:c9d34c65b08bb3699f8d140eebce1c9de942f19a070b1974fafba7bd8292028e\"}]}\n",
	"slow-clean":          "200\nContent-Type: application/json\nContent-Length: 270\n{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"},\"substrate_scanned\":[{\"path\":\"/home/agent/.claude/skills/pdf-helper\",\"fp\":\"sha256:f7be8b0309d825abc49b6a8eeff78348445101c2e67f798bef19bbc17ad03922\",\"receipt\":\"B3P3Zfc3g6ClDotNn_RgOjAk\"}]}\n",
	"blocked":             "200\nContent-Type: application/json\nContent-Length: 215\n{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"},\"substrate_quarantine\":[{\"path\":\"/home/agent/.claude/skills/pdf-helper\",\"reason\":\"the skill reads credentials and sends them out\"}]}\n",
	"scanner-down":        "200\nContent-Type: application/json\nContent-Length: 83\n{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"}}\n",
	"benign-corpus":       "200\nContent-Type: application/json\nContent-Length: 1083\n{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"},\"substrate_scanned\":[{\"path\":\"/home/agent/.claude/skills/corpus00\",\"fp\":\"sha256:b07edf8a096decc8d263ecf157a19bc940e4587096a8a515e735586d0422bbe4\",\"receipt\":\"T1amZGB_6gkI8Hp4eTVr7ePD\"},{\"path\":\"/home/agent/.claude/skills/corpus01\",\"fp\":\"sha256:0b1c9e7ce2be179ccf074325380e0e468115ed8c7ca48c29f1b9633ab9a53a9e\",\"receipt\":\"Pj5gLdBjvAjQUBQ7AjE2Zt03\"},{\"path\":\"/home/agent/.claude/skills/corpus02\",\"fp\":\"sha256:8380eb10a4aa5fe2c98705a761cfbb805c67bf73c55b3eb58ea88ae034b092f5\",\"receipt\":\"sB9SGdw_DNQ0nIYUtS3RGNM-\"},{\"path\":\"/home/agent/.claude/skills/corpus03\",\"fp\":\"sha256:1b2b64203c43c9ec3cdf16a43fb6faad3a6ecfc3ba328624daa5e644f2367906\",\"receipt\":\"eQQR9NwxpASpm9CvwjNaHZaU\"},{\"path\":\"/home/agent/.claude/skills/corpus04\",\"fp\":\"sha256:7e0a5e614e1280e5f781d983a38ce4a6763242c6c59a8ee434e79314de974d6f\",\"receipt\":\"b2esc9GGwQI9lFAhbeEaI3f_\"},{\"path\":\"/home/agent/.claude/skills/corpus05\",\"fp\":\"sha256:bbff0048f8dce230e2d8ccd3a523745643671490c15b05392d0de5986f236db6\",\"receipt\":\"XSactmJkz-6rCWYJOaN1v8Ab\"}]}\n",
}

// b511OSSDesign are the OSS answers that differ from rel by design: a folder
// the scan blocked is refused in both, and since B5.4 S2 (7a80e7b374) its
// reason is the plain message naming the skill and where it was moved, with
// a reason code the kit reads. Nothing of the managed hold (GAP-0980) shows
// in an OSS answer.
var b511OSSDesign = map[string]string{
	"blocked": "200\nContent-Type: application/json\nContent-Length: 346\n{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"},\"substrate_quarantine\":[{\"path\":\"/home/agent/.claude/skills/pdf-helper\",\"reason\":\"DefenseClaw blocked the skill \\\"pdf-helper\\\": the skill reads credentials and sends them out. It was moved to /home/agent/.claude/.defenseclaw-quarantine.\",\"code\":\"skill_finding\"}]}\n",
}

// b511OSSShape is an answer's status, top-level fields and quarantined
// folders (the decision, without the reason text).
func b511OSSShape(t *testing.T, a string) string {
	t.Helper()
	parts := strings.SplitN(a, "\n", 4)
	var obj map[string]json.RawMessage
	if len(parts) != 4 || json.Unmarshal([]byte(parts[3]), &obj) != nil {
		t.Fatalf("not an answer: %q", a)
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var q []struct {
		Path string `json:"path"`
	}
	_ = json.Unmarshal(obj[substrateQuarantineField], &q)
	return fmt.Sprint(parts[0], keys, string(obj["hookSpecificOutput"]), q)
}
