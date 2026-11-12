// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// rel-1-0-6 R108-COWORK-3 / cowork-edr-spike GAP-0003 (port check for 1.0.10):
// the Claude Code client doing ordinary work is not local_inference on any
// OS. Each source hands the host plane a different exec shape: Linux cn_proc
// and Tetragon give a uid, a joined argv and a native versions/<v> image;
// macOS Endpoint Security gives a uid, a joined argv and a native or Homebrew
// cask image; the Windows 4688 record gives no uid, the account SID and the
// raw CommandLine with a quoted image path that may contain spaces. The
// decision must come from the exec-time image digest alone, so every shape
// classifies the same way. Not build-tagged: it runs in every OS's Go suite.
func TestClaudeClientClassificationIsTheSameOnEveryOS(t *testing.T) {
	release := sha256.Sum256([]byte("claude release image"))
	other := sha256.Sum256([]byte("another program"))
	signed, unsigned := hex.EncodeToString(release[:]), hex.EncodeToString(other[:])
	uid := os.Getuid() + 1000
	type shape struct {
		os, name, exe, image string // image is how the OS's argv names the client
		uid                      *int
		sid                      string
		source                   plane.EventSource
	}
	shapes := []shape{
		{"linux", "2.1.317", "/home/cwk-v1/.local/share/claude/versions/2.1.317", "claude", &uid, "", plane.SourceCNProc},
		{"linux-tetragon", "2.1.317", "/home/cwk-v1/.local/share/claude/versions/2.1.317", "/home/cwk-v1/.local/bin/claude", &uid, "", plane.SourceTetragon},
		{"darwin-native", "2.1.317", "/Users/cwk-v1/.local/share/claude/versions/2.1.317", "/Users/cwk-v1/.local/bin/claude", &uid, "", ""},
		{"darwin-cask", "claude", "/opt/homebrew/Caskroom/claude-code/2.1.317/claude", "claude", &uid, "", ""},
		{"windows", "claude.exe", `C:\Users\cwk v1\.local\bin\claude.exe`, `"C:\Users\cwk v1\.local\bin\claude.exe"`, nil, "S-1-5-21-1-2-3-1001", ""},
	}
	cases := []struct {
		name, args, digest string
		keepClientMCP      bool
		classified         int64
	}{
		{"print prompt", ` -p "use npx -y @modelcontextprotocol/server-filesystem to list /workspace"`, signed, false, 0},
		{"configuration values", ` --mcp-config first.json mcp_server.json`, signed, false, 0},
		{"configuration then print prompt", ` --mcp-config first.json -p "@modelcontextprotocol/server-filesystem"`, signed, false, 0},
		{"positional server twin", ` @modelcontextprotocol/server-filesystem /workspace`, signed, false, 1},
		{"unsigned image twin", ` -p "use @modelcontextprotocol/server-filesystem"`, unsigned, false, 1},
		{"image not read twin", ` -p "use @modelcontextprotocol/server-filesystem"`, "", false, 1},
		{"Secure Client twin", ` -p "use @modelcontextprotocol/server-filesystem"`, signed, true, 1},
	}
	for _, s := range shapes {
		for _, tc := range cases {
			t.Run(s.os+"/"+tc.name, bubbled(func(t *testing.T) {
				host := newHost(newFake(fullCoverage()))
				host.indicators.KeepClientMCP = tc.keepClientMCP
				host.coldHold, host.coldPoll = 20*time.Millisecond, 5*time.Millisecond
				host.clientChecksums = func(version string) ([][32]byte, bool) {
					if version != "2.1.317" {
						return nil, false
					}
					return [][32]byte{release}, true
				}
				version := "2.1.317"
				if tc.digest == "" {
					version = ""
				}
				host.handle(plane.Event{
					Kind: plane.KindExec, PID: 1 << 30, PPID: 1,
					Name: s.name, Exe: s.exe, Cmdline: s.image + tc.args,
					UID: s.uid, UserSID: s.sid, Source: s.source,
					At:          time.Unix(1_760_000_000, 0),
					ImageSHA256: tc.digest, ImageVersion: version,
				})
				time.Sleep(5 * host.coldHold)
				if classified, _, _, _ := host.stats(); classified != tc.classified {
					t.Fatalf("classified=%d, want %d", classified, tc.classified)
				}
			}))
		}
	}
}
