// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// brokeredTestHome is a session home the test account owns, with the
// account lookup and the uid floor pointed at it and the gateway's own read
// of it closed, as defenseclaw-cowork's is in the VM.
func brokeredTestHome(t *testing.T) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "cwk-v1")
	if err := os.Mkdir(home, 0o750); err != nil {
		t.Fatal(err)
	}
	prevMin, prevAccount, prevReadable := brokeredHomeMinUID, brokeredHomeAccount, brokeredHomeReadable
	brokeredHomeMinUID = 0
	brokeredHomeAccount = func(uid int) (string, string, error) {
		if uid != os.Getuid() {
			return "", "", errors.New("unknown uid")
		}
		return "cwk-v1", home, nil
	}
	brokeredHomeReadable = func(string) bool { return false }
	t.Cleanup(func() {
		brokeredHomeMinUID, brokeredHomeAccount, brokeredHomeReadable = prevMin, prevAccount, prevReadable
	})
	return home
}

func writeBrokeredFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func brokeredEntry(report BrokeredHomeReport, rel string) (BrokeredHomeEntry, bool) {
	for _, home := range report.Homes {
		for _, entry := range home.Entries {
			if entry.Path == rel {
				return entry, true
			}
		}
	}
	return BrokeredHomeEntry{}, false
}

// The helper's read of a session home gives the gateway the signals, and the
// fingerprints, its own detectors give the same home read directly, and none
// of the files' secrets (cowork-1-0-8 GAP-0008).
func TestBrokeredHomeReadMatchesADirectRead(t *testing.T) {
	home := brokeredTestHome(t)
	const secret = "tok-s2-secret-value"
	writeBrokeredFile(t, filepath.Join(home, ".claude.json"),
		`{"mcpServers":{"alpha":{"command":"npx","env":{"API_TOKEN":"`+secret+`"}}},"projects":{"/w":{"mcpServers":{"beta":{"url":"https://`+secret+`"}}}}}`)
	writeBrokeredFile(t, filepath.Join(home, ".claude", "settings.json"), `{"env":{"KEY":"`+secret+`"}}`)
	writeBrokeredFile(t, filepath.Join(home, "CLAUDE.md"), "# notes "+secret)
	writeBrokeredFile(t, filepath.Join(home, ".mcp.json"), `{"mcpServers":{"gamma":{"headers":{"Authorization":"`+secret+`"}}}}`)
	writeBrokeredFile(t, filepath.Join(home, ".claude", "skills", "review", "SKILL.md"), "---\nname: review\n---\n")

	catalog, err := LoadAISignatures()
	if err != nil {
		t.Fatal(err)
	}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "passive", DataDir: filepath.Join(t.TempDir(), "data"),
		HomeDir: home, HomeDirs: []string{home}, ScanRoots: []string{"~"},
	}, catalog)
	cleanupPreparedDiscoveryService(t, svc)

	fingerprints := func(signals []AISignal) []string {
		var out []string
		for _, sig := range signals {
			out = append(out, sig.Detector+" "+sig.SignatureID+" "+sig.Fingerprint)
		}
		sort.Strings(out)
		return out
	}
	var direct []AISignal
	for _, detect := range []func() []AISignal{svc.detectConfigPaths, svc.detectMCPPaths, svc.detectSkills, svc.detectRules, svc.detectPlugins} {
		direct = append(direct, detect()...)
	}

	// Claude Code's config folder, settings, CLAUDE.md and skills folder as
	// config, its two MCP configs, and the review skill, at least.
	if len(direct) < 7 {
		t.Fatalf("the fixture gave only %d direct signals: %v", len(direct), fingerprints(direct))
	}
	report := ReadBrokeredHomes(context.Background(), []string{home}, NewBrokeredHomeAllowlist(catalog))
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatalf("the helper's answer carries file contents: %s", raw)
	}
	for _, name := range []string{`"alpha"`, `"beta"`, `"gamma"`, `"review"`} {
		if !bytes.Contains(raw, []byte(name)) {
			t.Fatalf("the helper's answer lacks %s: %s", name, raw)
		}
	}

	brokered, files, note, err := svc.detectBrokeredHomes(context.Background(),
		func(context.Context) (BrokeredHomeReport, error) { return report, nil })
	if err != nil || files != 2 || !strings.Contains(note, "1 homes read") {
		t.Fatalf("detectBrokeredHomes: files %d note %q err %v", files, note, err)
	}
	if got, want := fingerprints(brokered), fingerprints(direct); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("brokered signals differ from a direct read:\n got %v\nwant %v", got, want)
	}
	uid := strconv.Itoa(os.Getuid())
	for _, sig := range brokered {
		if sig.UserID != uid || sig.UserName != "cwk-v1" || sig.Source != AISourceSensorHelper || sig.LastActiveAt == nil {
			t.Fatalf("brokered signal %s %s: user %q/%q source %q", sig.Detector, sig.SignatureID, sig.UserID, sig.UserName, sig.Source)
		}
		for _, ev := range sig.Evidence {
			if ev.RawPath != "" || strings.Contains(ev.Basename, secret) {
				t.Fatalf("brokered evidence leaks: %+v", ev)
			}
		}
	}
}

// A session user cannot point the root helper anywhere else: links, hard
// links, special files, foreign owners and oversized configs are refused or
// capped, and a home is read only when it is its account's own folder.
func TestBrokeredHomeReadRefusesLinksAndCapsSizes(t *testing.T) {
	home := brokeredTestHome(t)
	writeBrokeredFile(t, filepath.Join(home, "CLAUDE.md"), "ok")
	for link, target := range map[string]string{
		"AGENTS.md": "/etc/shadow", // a file link
		".codex":    "/etc",        // a folder link on the way
	} {
		if err := os.Symlink(target, filepath.Join(home, link)); err != nil {
			t.Fatal(err)
		}
	}
	writeBrokeredFile(t, filepath.Join(home, "outside.json"), `{"mcpServers":{"linked":{}}}`)
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(home, "outside.json"), filepath.Join(home, ".cursor", "mcp.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".copilot"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(home, ".copilot", "mcp-config.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeBrokeredFile(t, filepath.Join(home, ".kiro", "settings", "mcp.json"),
		`{"mcpServers":{"big":{}}, "pad":"`+strings.Repeat("x", maxBrokeredFileBytes)+`"}`)

	catalog, err := LoadAISignatures()
	if err != nil {
		t.Fatal(err)
	}
	allow := NewBrokeredHomeAllowlist(catalog)
	done := make(chan BrokeredHomeReport, 1)
	go func() { done <- ReadBrokeredHomes(context.Background(), []string{home}, allow) }()
	var report BrokeredHomeReport
	select {
	case report = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the read hung on a FIFO")
	}
	if len(report.Homes) != 1 {
		t.Fatalf("homes = %+v", report.Homes)
	}
	if _, ok := brokeredEntry(report, "CLAUDE.md"); !ok {
		t.Fatalf("CLAUDE.md missing: %+v", report.Homes[0].Entries)
	}
	for _, rel := range []string{"AGENTS.md", ".codex", ".codex/config.toml", ".cursor/mcp.json", ".copilot/mcp-config.json", "outside.json"} {
		if entry, ok := brokeredEntry(report, rel); ok {
			t.Fatalf("%s was read: %+v", rel, entry)
		}
	}
	// AGENTS.md, .codex/* (every allowlisted path below the link), the hard
	// link and the FIFO.
	if refused := report.Homes[0].Refused; refused < 4 {
		t.Fatalf("refused = %d, want at least 4", refused)
	}
	kiro, ok := brokeredEntry(report, ".kiro/settings/mcp.json")
	if !ok || len(kiro.MCP) != 1 || kiro.MCP[0].Partial != CoverageReasonCapExceeded || len(kiro.MCP[0].Servers) != 0 {
		t.Fatalf("oversized config: %+v", kiro)
	}

	// An element another account owns is refused.
	fd, err := unix.Open(home, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	budget := brokeredReadBudget{remaining: maxBrokeredReadBytes}
	if _, outcome := readBrokeredEntry(fd, os.Getuid()+1, "CLAUDE.md", allow["CLAUDE.md"], filepath.Join(home, "CLAUDE.md"), &budget); outcome != brokeredRefused {
		t.Fatalf("a file another account owns: outcome %d", outcome)
	}

	// A home that is a link, or that is not its account's passwd home, is
	// not read at all.
	link := filepath.Join(filepath.Dir(home), "cwk-link")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}
	if got := ReadBrokeredHomes(context.Background(), []string{link}, allow); len(got.Homes) != 0 {
		t.Fatalf("a linked home was read: %+v", got.Homes)
	}
	brokeredHomeAccount = func(int) (string, string, error) { return "cwk-v1", "/sessions/cwk-v1", nil }
	if got := ReadBrokeredHomes(context.Background(), []string{home}, allow); len(got.Homes) != 0 {
		t.Fatalf("a home its account does not own was read: %+v", got.Homes)
	}
}
