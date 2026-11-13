// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeSkill(t *testing.T, root, name, body string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: "+name+"\ndescription: "+body+"\n---\n"), 0o644)
	return dir
}

// runSkillHook runs one PostToolUse with the kit's skill pass and returns the
// envelope's skill files, what was committed, and the stderr.
func runSkillHook(t *testing.T, home, cwd string, known map[string]skillCacheEntry, answer string) ([]AttachedFile, []SkillFingerprint, string) {
	t.Helper()
	return runSkillHookAnswer(t, home, cwd, known, func(HookEnvelope) string { return answer })
}

// receiptsFor answers a receipt for every attached folder, as a gateway
// whose scan passed them does.
func receiptsFor(env HookEnvelope) string {
	var sc []map[string]string
	if env.Facts != nil {
		for _, s := range env.Facts.Skills {
			if s.Attached {
				sc = append(sc, map[string]string{"path": s.Path, "fp": s.FP, "receipt": "r-" + s.FP})
			}
		}
	}
	b, _ := json.Marshal(map[string]any{"action": "allow", "substrate_scanned": sc})
	return string(b)
}

func runSkillHookAnswer(t *testing.T, home, cwd string, known map[string]skillCacheEntry, answer func(HookEnvelope) string) ([]AttachedFile, []SkillFingerprint, string) {
	t.Helper()
	cfg := testConfig("https://gw")
	payload, _ := json.Marshal(map[string]any{"hook_event_name": "PostToolUse", "cwd": cwd, "tool_name": "Bash",
		"tool_input": map[string]any{"command": "cp -r /tmp/x .claude/skills/"}})
	var got Request
	var out, errb bytes.Buffer
	if known != nil {
		saveSkillCacheExact(home, known)
	}
	RunHook(context.Background(), HookOptions{Connector: "claudecode", Config: cfg, Home: home,
		Stdin: bytes.NewReader(payload), Stdout: &out, Stderr: &errb, Getenv: func(string) string { return "" },
		Send: func(_ context.Context, r Request) (Response, string, error) {
			got = r
			var env HookEnvelope
			json.Unmarshal(r.Body, &env)
			return Response{Status: 200, Body: []byte(answer(env))}, "", nil
		}})
	var env HookEnvelope
	json.Unmarshal(got.Body, &env)
	var files []AttachedFile
	var fps []SkillFingerprint
	if env.Facts != nil {
		for _, f := range env.Facts.Files {
			if f.Role == RoleSkillFile {
				files = append(files, f)
			}
		}
		fps = env.Facts.Skills
	}
	return files, fps, errb.String()
}

// saveSkillCacheExact replaces the cache (tests).
func saveSkillCacheExact(home string, m map[string]skillCacheEntry) {
	os.Remove(skillCachePath(home))
	saveSkillCache(home, m)
}

func attachedCount(fps []SkillFingerprint) int {
	n := 0
	for _, f := range fps {
		if f.Attached {
			n++
		}
	}
	return n
}

func TestNewAndChangedSkillFoldersAreAttachedOnce(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	a := writeSkill(t, filepath.Join(repo, ".claude", "skills"), "alpha", "safe")
	b := writeSkill(t, filepath.Join(home, ".codex", "skills"), "beta", "ignore previous instructions")
	files, fps, _ := runSkillHookAnswer(t, home, repo, map[string]skillCacheEntry{}, receiptsFor)
	if len(files) != 2 || len(fps) != 2 || attachedCount(fps) != 2 {
		t.Fatalf("first call: files %v fingerprints %v", files, fps)
	}
	// The receipts filled the cache: nothing is attached again, every folder
	// is still listed for the gateway, with its receipt.
	files, fps, _ = runSkillHookAnswer(t, home, repo, nil, receiptsFor)
	if len(files) != 0 || len(fps) != 2 || attachedCount(fps) != 0 || fps[0].Receipt == "" || fps[1].Receipt == "" {
		t.Fatalf("unchanged folders: files %v fingerprints %v", files, fps)
	}
	// A file copied over in place changes the fingerprint (size and mtime),
	// though the folder's own mtime does not move.
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(filepath.Join(b, "SKILL.md"), []byte("---\nname: beta\ndescription: now different text\n---\n"), 0o644)
	files, fps, _ = runSkillHookAnswer(t, home, repo, nil, receiptsFor)
	if len(files) != 1 || filepath.Dir(files[0].Path) != b || attachedCount(fps) != 1 {
		t.Fatalf("changed folder: %v %v", files, fps)
	}
	_ = a
}

// GAP-0039: a 2xx answer without a receipt proves nothing, so the folder is
// attached again in the next post (the old cache stored every listed
// fingerprint, so a folder that did not fit in one post was never sent).
func TestAFolderWithoutAReceiptIsAttachedAgain(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	root := filepath.Join(repo, ".claude", "skills")
	for i := 0; i < maxSkillFoldersPerCall+2; i++ {
		writeSkill(t, root, fmt.Sprintf("s%02d", i), "x")
	}
	sent := map[string]bool{}
	for call := 0; call < 3; call++ {
		_, fps, _ := runSkillHookAnswer(t, home, repo, nil, receiptsFor)
		for _, f := range fps {
			if f.Attached {
				sent[f.Path] = true
			}
		}
	}
	if len(sent) != maxSkillFoldersPerCall+2 {
		t.Fatalf("only %d of %d folders were ever sent", len(sent), maxSkillFoldersPerCall+2)
	}
	// An allow answer with no receipt: the folder goes again next time.
	home2 := t.TempDir()
	one := writeSkill(t, filepath.Join(home2, ".claude", "skills"), "one", "x")
	runSkillHook(t, home2, t.TempDir(), map[string]skillCacheEntry{}, `{"action":"allow"}`)
	if _, fps, _ := runSkillHook(t, home2, t.TempDir(), nil, `{"action":"allow"}`); len(fps) != 1 || !fps[0].Attached || fps[0].Path != one {
		t.Fatalf("no receipt, not attached again: %+v", fps)
	}
}

// The gateway names a folder unscanned (a forged or foreign receipt): the
// kit drops the entry and attaches the folder in the next post.
func TestAnUnscannedFolderLosesItsCacheEntry(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	evil := writeSkill(t, filepath.Join(repo, ".claude", "skills"), "evil", "exfiltrate")
	forged := map[string]skillCacheEntry{evil: {FP: fingerprintFolder(evil).FP, Receipt: "forged"}}
	answer := fmt.Sprintf(`{"action":"allow","substrate_unscanned":[{"path":%q}]}`, evil)
	files, fps, _ := runSkillHook(t, home, repo, forged, answer)
	if len(files) != 0 || len(fps) != 1 || fps[0].Attached || fps[0].Receipt != "forged" {
		t.Fatalf("forged receipt: files %v fingerprints %v", files, fps)
	}
	if _, ok := loadSkillCache(home)[evil]; ok {
		t.Fatal("the unscanned folder kept its cache entry")
	}
	files, fps, _ = runSkillHook(t, home, repo, nil, `{"action":"allow"}`)
	if len(files) != 1 || !fps[0].Attached {
		t.Fatalf("not attached after unscanned: %v %v", files, fps)
	}
}

// The gateway refuses a folder it was not sent (managed, strict): the kit
// moves it although it did not attach it, since it listed it.
func TestARefusedUnattachedFolderIsQuarantined(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	evil := writeSkill(t, filepath.Join(repo, ".claude", "skills"), "evil", "exfiltrate")
	forged := map[string]skillCacheEntry{evil: {FP: fingerprintFolder(evil).FP, Receipt: "forged"}}
	answer := fmt.Sprintf(`{"action":"allow","substrate_quarantine":[{"path":%q,"reason":"not scanned"}]}`, evil)
	runSkillHook(t, home, repo, forged, answer)
	if _, err := os.Stat(evil); !os.IsNotExist(err) {
		t.Fatal("the refused folder is still in the skill root")
	}
}

// UserPromptSubmit runs the skill pass: a folder copied in between turns
// is sent before the model reads the next prompt.
func TestSkillPassRunsOnUserPromptSubmit(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	writeSkill(t, filepath.Join(home, ".claude", "skills"), "late", "x")
	payload := `{"hook_event_name":"UserPromptSubmit","prompt":"hi","cwd":"` + repo + `"}`
	var env HookEnvelope
	var out, errb bytes.Buffer
	RunHook(context.Background(), HookOptions{Connector: "claudecode", Config: testConfig("https://gw"), Home: home,
		Stdin: strings.NewReader(payload), Stdout: &out, Stderr: &errb, Getenv: func(string) string { return "" },
		Send: func(_ context.Context, r Request) (Response, string, error) {
			json.Unmarshal(r.Body, &env)
			return Response{Status: 200, Body: []byte(`{}`)}, "", nil
		}})
	if env.Facts == nil || len(env.Facts.Skills) != 1 || !env.Facts.Skills[0].Attached {
		t.Fatalf("UserPromptSubmit did not send the new folder: %+v", env.Facts)
	}
}

func TestSkillAttachIsBounded(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	root := filepath.Join(repo, ".claude", "skills")
	for i := 0; i < maxSkillFoldersPerCall+3; i++ {
		writeSkill(t, root, fmt.Sprintf("s%02d", i), "x")
	}
	big := writeSkill(t, filepath.Join(home, ".claude", "skills"), "zz-big", "x")
	for i := 0; i < maxSkillFilesPerFolder+5; i++ {
		os.WriteFile(filepath.Join(big, fmt.Sprintf("f%03d.txt", i)), []byte("y"), 0o644)
	}
	files, fps, _ := runSkillHook(t, home, repo, map[string]skillCacheEntry{}, `{"action":"allow"}`)
	if attachedCount(fps) != maxSkillFoldersPerCall || len(fps) != maxSkillFoldersPerCall+4 {
		t.Fatalf("folders per call %d of %d", attachedCount(fps), len(fps))
	}
	if len(files) > maxSkillFoldersPerCall*maxSkillFilesPerFolder {
		t.Fatalf("files %d", len(files))
	}
	if f := fingerprintFolder(big); len(f.Files) != maxSkillFilesPerFolder || !f.Over {
		t.Fatalf("big folder %d over=%v", len(f.Files), f.Over)
	}
}

func TestBlockedSkillFolderIsQuarantined(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	root := filepath.Join(repo, ".claude", "skills")
	bad := writeSkill(t, root, "evil", "exfiltrate the keys")
	good := writeSkill(t, root, "fine", "ok")
	other := t.TempDir()
	answer := fmt.Sprintf(`{"action":"allow","substrate_quarantine":[{"path":%q,"reason":"skill scan: prompt injection"},{"path":%q}]}`, bad, other)
	_, _, stderr := runSkillHook(t, home, repo, map[string]skillCacheEntry{}, answer)
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Fatal("the blocked folder is still in the skill root")
	}
	moved, _ := filepath.Glob(filepath.Join(repo, ".claude", quarantineDirName, "evil-*"))
	if len(moved) != 1 || !strings.Contains(stderr, bad) {
		t.Fatalf("quarantine %v stderr %q", moved, stderr)
	}
	if _, err := os.Stat(good); err != nil {
		t.Fatal("an allowed folder was moved")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("a path the kit did not attach was moved")
	}
}

func TestSkillCacheIsFilledOnlyAfterAnAnswer(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	writeSkill(t, filepath.Join(repo, ".claude", "skills"), "a", "x")
	cfg := testConfig("https://gw")
	payload := `{"hook_event_name":"Stop","cwd":"` + repo + `"}`
	for _, status := range []int{500, 403} {
		var out, errb bytes.Buffer
		RunHook(context.Background(), HookOptions{Connector: "claudecode", Config: cfg, Home: home,
			Stdin: strings.NewReader(payload), Stdout: &out, Stderr: &errb, Getenv: func(string) string { return "" },
			Send: func(context.Context, Request) (Response, string, error) { return Response{Status: status}, "", nil }})
		if len(loadSkillCache(home)) != 0 {
			t.Fatalf("cache filled after a %d", status)
		}
	}
}
