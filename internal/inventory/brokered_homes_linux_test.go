// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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

// brokeredPeakHeapGrowth runs read and returns how far the heap in use rose
// above where it started, sampled every millisecond.
func brokeredPeakHeapGrowth(read func()) uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base := ms.HeapInuse
	stop, peak := make(chan struct{}), make(chan uint64, 1)
	go func() {
		var ms runtime.MemStats
		var high uint64
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			runtime.ReadMemStats(&ms)
			high = max(high, ms.HeapInuse)
			select {
			case <-stop:
				peak <- high
				return
			case <-tick.C:
			}
		}
	}()
	read()
	close(stop)
	if high := <-peak; high > base {
		return high - base
	}
	return 0
}

// writeBrokeredMembers writes head, count members made by member, and tail,
// within size bytes.
func writeBrokeredMembers(t *testing.T, path string, size int, head, tail string, member func(int) string) {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString(head)
	for i := 0; ; i++ {
		next := member(i)
		if buf.Len()+len(next)+len(tail) > size {
			break
		}
		buf.WriteString(next)
	}
	buf.WriteString(tail)
	writeBrokeredFile(t, path, buf.String())
}

// A session user's MCP configs cannot exhaust the root helper's memory
// (MemoryMax=300M): a 32 MiB ~/.claude.json of millions of tiny servers, or
// of one huge value, is walked for its names, not decoded, and every other
// shape is capped (1 MiB, 128 KiB for YAML and TOML) at a size its parser
// builds within bounds. A config with more servers than the evidence cap
// answers cap_exceeded with at most maxEvidencePerSignal names, and one
// nested past json.Unmarshal's depth is a parse error (cowork-1-0-8 GAP-0008
// F1, F2). Run it with the release toolchain too: before jsonv2,
// json.Decoder.Token has no depth limit.
func TestBrokeredHomeReadBoundsParseMemory(t *testing.T) {
	catalog, err := LoadAISignatures()
	if err != nil {
		t.Fatal(err)
	}
	allow := NewBrokeredHomeAllowlist(catalog)
	const limit = 150 << 20
	jsonMembers := func(i int) string { return fmt.Sprintf(`"%06x":{},`, i) }
	for _, tc := range []struct {
		rel, head, tail string
		size            int
		member          func(int) string
		// partial is the expected coverage reason: cap_exceeded comes with
		// names, parse_error with none, and "" with exactly one.
		partial string
	}{
		{".claude.json", `{"mcpServers":{`, `"z":0}}`, maxBrokeredClaudeStateBytes,
			func(i int) string { return fmt.Sprintf(`"%06x":0,`, i) }, CoverageReasonCapExceeded},
		{".claude.json", `{"projects":{`, `"/z":{}}}`, maxBrokeredClaudeStateBytes,
			func(i int) string { return fmt.Sprintf(`"/%06x":{"mcpServers":{"s%06x":0}},`, i, i) }, CoverageReasonCapExceeded},
		{".claude.json", `{"mcpServers":{"alpha":{}},"pad":"`, `"}`, maxBrokeredClaudeStateBytes,
			func(int) string { return strings.Repeat("x", 4096) }, ""},
		{".qwen/settings.json", `{"mcpServers":{`, `"z":{}}}`, maxBrokeredFileBytes, jsonMembers, CoverageReasonCapExceeded},
		{".mcp.json", `{"mcpServers":{`, `"z":{}}}`, maxBrokeredFileBytes, jsonMembers, CoverageReasonCapExceeded},
		{".hermes/config.yaml", "mcp_servers:\n", "", maxBrokeredYAMLTOMLBytes,
			func(i int) string { return fmt.Sprintf("  s%06x: {}\n", i) }, CoverageReasonCapExceeded},
		{".codex/config.toml", "", "", maxBrokeredYAMLTOMLBytes,
			func(i int) string { return fmt.Sprintf("[mcp_servers.s%06x]\n", i) }, CoverageReasonCapExceeded},
		{".claude.json", `{"x":`, "", maxBrokeredClaudeStateBytes,
			func(int) string { return strings.Repeat("[", 4096) }, CoverageReasonParseError},
	} {
		t.Run(tc.rel, func(t *testing.T) {
			home := brokeredTestHome(t)
			writeBrokeredMembers(t, filepath.Join(home, tc.rel), tc.size, tc.head, tc.tail, tc.member)
			var report BrokeredHomeReport
			growth := brokeredPeakHeapGrowth(func() {
				report = ReadBrokeredHomes(context.Background(), []string{home}, allow)
			})
			t.Logf("%s: peak heap growth %d MB", tc.rel, growth>>20)
			if growth > limit {
				t.Fatalf("%s: the read grew the heap by %d MB, over %d MB", tc.rel, growth>>20, limit>>20)
			}
			entry, ok := brokeredEntry(report, tc.rel)
			if !ok || len(entry.MCP) == 0 {
				t.Fatalf("%s: no MCP read: %+v", tc.rel, report)
			}
			for _, cfg := range entry.MCP {
				switch {
				case len(cfg.Servers) > maxEvidencePerSignal:
					t.Fatalf("%s %s: %d names", tc.rel, cfg.Shape, len(cfg.Servers))
				case cfg.Partial != tc.partial,
					tc.partial == CoverageReasonCapExceeded && len(cfg.Servers) == 0,
					tc.partial == CoverageReasonParseError && len(cfg.Servers) != 0,
					tc.partial == "" && len(cfg.Servers) != 1:
					t.Fatalf("%s %s: partial %q with %d names, want %q", tc.rel, cfg.Shape, cfg.Partial, len(cfg.Servers), tc.partial)
				}
			}
		})
	}
}

// Each home reads within its own share of the request's byte budget: one
// account's large configs leave it cap_exceeded, not the homes after it
// (cowork-1-0-8 GAP-0008 N1).
func TestBrokeredHomeReadBudgetIsPerHome(t *testing.T) {
	catalog, err := LoadAISignatures()
	if err != nil {
		t.Fatal(err)
	}
	allow := NewBrokeredHomeAllowlist(catalog)
	paths := allow.Paths()
	heavy := brokeredTestHome(t)
	writeBrokeredFile(t, filepath.Join(heavy, ".claude.json"), strings.Repeat(" ", maxBrokeredClaudeStateBytes-2)+"{}")
	filled := 0
	for _, rel := range paths {
		if len(allow[rel].MCPShapes) > 0 && rel != ".claude.json" {
			writeBrokeredFile(t, filepath.Join(heavy, rel), strings.Repeat(" ", maxBrokeredFileBytes))
			filled++
		}
	}
	if maxBrokeredClaudeStateBytes+filled*maxBrokeredFileBytes <= maxBrokeredHomeReadBytes {
		t.Fatalf("the fixture (%d configs) does not pass the per-home budget", filled)
	}
	light := filepath.Join(t.TempDir(), "cwk-v2")
	writeBrokeredFile(t, filepath.Join(light, ".mcp.json"), `{"mcpServers":{"bee":{}}}`)

	read := func(home string, budget *brokeredReadBudget) BrokeredHome {
		t.Helper()
		brokeredHomeAccount = func(int) (string, string, error) { return filepath.Base(home), home, nil }
		got, ok := readBrokeredHome(context.Background(), home, paths, allow, budget)
		if !ok {
			t.Fatalf("%s was not read", home)
		}
		return got
	}
	budget := brokeredReadBudget{remaining: maxBrokeredReadBytes, reply: maxBrokeredReplyBytes}
	got := read(heavy, &budget)
	if used := maxBrokeredReadBytes - budget.remaining; used > maxBrokeredHomeReadBytes || !budget.truncated {
		t.Fatalf("the heavy home read %d bytes (truncated %v), its share is %d", used, budget.truncated, maxBrokeredHomeReadBytes)
	}
	capped := 0
	for _, entry := range got.Entries {
		for _, cfg := range entry.MCP {
			if cfg.Partial == CoverageReasonCapExceeded {
				capped++
			}
		}
	}
	if capped == 0 {
		t.Fatalf("no config of the heavy home was cut by its share: %+v", got.Entries)
	}
	other := read(light, &budget)
	for _, entry := range other.Entries {
		if entry.Path == ".mcp.json" && len(entry.MCP) == 1 && slices.Equal(entry.MCP[0].Servers, []string{"bee"}) && entry.MCP[0].Partial == "" {
			return
		}
	}
	t.Fatalf("the home after the heavy one lost its config: %+v", other.Entries)
}

// One home's answer is bounded: past its share of the reply an entry keeps
// its presence and drops its names (cap_exceeded), so the answer is partial,
// never a frame over the helper's 64 MiB limit, whatever the homes hold
// (cowork-1-0-8 GAP-0008 N2).
func TestBrokeredHomeReplyStaysInsideTheFrame(t *testing.T) {
	catalog, err := LoadAISignatures()
	if err != nil {
		t.Fatal(err)
	}
	allow := NewBrokeredHomeAllowlist(catalog)
	home := brokeredTestHome(t)
	var folders []string
	for _, rel := range allow.Paths() {
		if allow[rel].Children && len(folders) < 12 {
			folders = append(folders, rel)
		}
	}
	for f, rel := range folders {
		dir := filepath.Join(home, rel)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		for i := range maxBrokeredChildren {
			name := fmt.Sprintf("%02d-%04d-%s", f, i, strings.Repeat("n", 200))
			if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	report := ReadBrokeredHomes(context.Background(), []string{home}, allow)
	if len(report.Homes) != 1 || !report.Truncated {
		t.Fatalf("homes %d truncated %v", len(report.Homes), report.Truncated)
	}
	full, bare := 0, 0
	var fullBytes int
	for _, entry := range report.Homes[0].Entries {
		if !slices.Contains(folders, entry.Path) {
			continue
		}
		switch {
		case len(entry.Children) > 0:
			full++
			raw, _ := json.Marshal(entry)
			fullBytes += len(raw)
		case entry.ChildrenTruncated:
			bare++
		}
	}
	if full == 0 || bare == 0 || full+bare != len(folders) || fullBytes > maxBrokeredHomeReplyBytes {
		t.Fatalf("folders: %d full (%d bytes), %d bare, of %d", full, fullBytes, bare, len(folders))
	}
	// The gateway takes the partial answer: a bare folder is a partial signal.
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "passive", DataDir: filepath.Join(t.TempDir(), "data"),
		HomeDir: home, HomeDirs: []string{home}, ScanRoots: []string{"~"},
	}, catalog)
	cleanupPreparedDiscoveryService(t, svc)
	signals, _, _, err := svc.detectBrokeredHomes(context.Background(),
		func(context.Context) (BrokeredHomeReport, error) { return report, nil })
	if err != nil {
		t.Fatal(err)
	}
	partial := 0
	for _, sig := range signals {
		if sig.Partial && sig.CoverageReason == CoverageReasonCapExceeded {
			partial++
		}
	}
	if partial < bare {
		t.Fatalf("%d partial signals for %d bare folders", partial, bare)
	}

	// The worst answer: every home at the limit, every allowlisted entry
	// bare with the longest fields, beside the request's full-entry share.
	worst := BrokeredHome{Home: "/" + strings.Repeat("h", 4094), UID: math.MaxInt32, User: strings.Repeat("u", maxUserScanField), Refused: math.MaxInt32}
	for _, rel := range allow.Paths() {
		entry := BrokeredHomeEntry{Path: rel, Dir: true, ModTimeUnixNano: math.MaxInt64, ChildrenTruncated: true}
		for _, shape := range allow[rel].MCPShapes {
			entry.MCP = append(entry.MCP, BrokeredMCPConfig{Shape: shape, Partial: CoverageReasonCapExceeded})
		}
		worst.Entries = append(worst.Entries, entry)
	}
	raw, err := json.Marshal(worst)
	if err != nil {
		t.Fatal(err)
	}
	const frame = 64 << 20 // acquire.maxFrameBytes
	if bound := (len(raw)+1)*maxBrokeredHomes + maxBrokeredReplyBytes + 4096; bound >= frame {
		t.Fatalf("the worst answer is %d bytes, the frame %d", bound, frame)
	}
}
