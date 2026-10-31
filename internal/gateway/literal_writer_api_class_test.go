// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// Every interpreter API that copies, moves or writes a literal file is one
// class in the protected-file proof (rel-1-0-2:GAP-0429, GAP-0366): Perl
// File::Copy copy, cp, move and mv (also after -MFile::Copy or a -we
// cluster), Node's callback and fs.promises writeFile, appendFile, cp and
// cpSync, Python shutil.move and Ruby FileUtils. A managed gateway runs
// with ProtectHome, so it cannot see the user's link and decides from the
// hook client's target map alone: the client must list the destination.
// The per-user gateway sees the link. Both block in action mode and warn in
// observe mode; an ordinary destination and code that only prints stay
// allowed. Every write goes to a decoy authorized_keys in the test home.
func TestLiteralWriterAPIClassBlocksProtectedLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX link forms; a Windows hook client sends no write evidence")
	}
	home, cwd := r104ReviewHome(t)
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "disklink")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "payload"), []byte("payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		command string
		block   bool
	}{
		// Writers the class already had: they must keep blocking.
		{`perl -e 'use File::Copy; copy("payload","disklink")'`, true},
		{`python3 -c 'import shutil; shutil.copy2("payload","disklink")'`, true},
		{`python3 -c 'import io; io.FileIO("disklink","a").write(b"x")'`, true},
		{`node -e 'require("fs").copyFileSync("payload","disklink")'`, true},
		{`node -e 'require("fs").writeFileSync("disklink","x")'`, true},
		// Perl File::Copy, every exported name and import spelling.
		{`perl -MFile::Copy -e 'copy("payload","disklink")'`, true},
		{`perl -MFile::Copy=cp -e 'cp("payload","disklink")'`, true},
		{`perl -M File::Copy -e 'move("payload","disklink")'`, true},
		{`perl -e 'use File::Copy; cp("payload","disklink")'`, true},
		{`perl -e 'use File::Copy; move("payload","disklink")'`, true},
		{`perl -e 'use File::Copy qw(cp mv); mv("payload","disklink")'`, true},
		{`perl -e 'File::Copy::cp("payload","disklink")'`, true},
		{`perl -e 'File::Copy::move("payload","disklink")'`, true},
		{`perl -e 'use File::Copy; move "payload", "disklink"'`, true},
		{`perl -we 'use File::Copy; copy("payload","disklink")'`, true},
		{`perl -E 'use File::Copy; copy("payload","disklink")'`, true},
		{`/usr/bin/perl -w -MFile::Copy -e 'copy("payload","disklink")'`, true},
		// Node asynchronous writers and copies.
		{`node -e 'require("fs").writeFile("disklink","x",()=>{})'`, true},
		{`node -e "require('fs').writeFile('disklink','x',()=>{})"`, true},
		{`node -e 'require("fs").promises.writeFile("disklink","x")'`, true},
		{`node -e 'require("fs").appendFile("disklink","x",()=>{})'`, true},
		{`node -e 'require("fs").promises.appendFile("disklink","x")'`, true},
		{`node -e 'require("fs").cpSync("payload","disklink")'`, true},
		{`node -e 'require("fs").cp("payload","disklink",()=>{})'`, true},
		// Python and Ruby copies and moves.
		{`python3 -c 'import shutil; shutil.move("payload","disklink")'`, true},
		{`ruby -e 'require "fileutils"; FileUtils.cp("payload","disklink")'`, true},
		{`ruby -e 'require "fileutils"; FileUtils.mv("payload","disklink")'`, true},
		{`ruby -e 'IO.copy_stream("payload","disklink")'`, true},
		// Hard negatives: an ordinary destination, the keys file name only
		// in a string, code that only prints.
		{`perl -e 'print "hello\n"'`, false},
		{`perl -e 'print "authorized_keys\n"'`, false},
		{`perl -MFile::Copy -e 'copy("payload","out.txt")'`, false},
		{`perl -e 'use File::Copy; move("payload","moved.txt")'`, false},
		{`perl -e 'sub cp { print @_ } cp("payload","out.txt")'`, false},
		{`node -e 'require("fs").writeFile("out.txt","x",()=>{})'`, false},
		{`node -e 'require("fs").cpSync("payload","copy.txt")'`, false},
		{`node -e 'const cp = require("child_process"); cp.execSync("ls")'`, false},
		{`python3 -c 'import shutil; shutil.move("payload","moved.txt")'`, false},
		{`ruby -e 'require "fileutils"; FileUtils.cp("payload","copy.txt")'`, false},
	}
	for _, name := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, name)
		profile := connector.NewClaudeCodeConnector().HookProfile(connector.SetupOpts{})
		if name == "codex" {
			profile = connector.NewCodexConnector().HookProfile(connector.SetupOpts{})
		}
		for _, managed := range []bool{false, true} {
			for _, row := range rows {
				input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home}
				request := trustedActionRequest{Input: input, Connector: name, EnforcementCapable: true,
					ProtectedHomeHook: managed}
				if managed {
					payload, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd,
						"tool_name": "Bash", "tool_input": map[string]string{"command": row.command}})
					if err != nil {
						t.Fatal(err)
					}
					targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
					if !ok {
						t.Fatalf("%q: no client target map", row.command)
					}
					request.ResolvedWriteTargets = targets
					// ProtectHome: the managed gateway does not see the home.
					if err := os.Rename(home, home+".protected"); err != nil {
						t.Fatal(err)
					}
				}
				verdict := buildVerdict(dispatchTrustedAction(t.Context(), request), "tool_call")
				if managed {
					if err := os.Rename(home+".protected", home); err != nil {
						t.Fatal(err)
					}
				}
				if blocked := verdict.Action == "block"; blocked != row.block {
					t.Errorf("%s managed=%v %q: block=%v, want %v (%v)", name, managed, row.command, blocked, row.block, verdict.Findings)
					continue
				}
				if !row.block {
					continue
				}
				req := agentHookRequest{ConnectorName: name, HookEventName: "PreToolUse", ToolName: "Bash"}
				if got := agentHookResponseForProfile(profile, req, "block", verdict.Action, verdict.Severity,
					verdict.Reason, verdict.Findings, "action", true, connector.HookCapability{}); got.Action != "block" {
					t.Errorf("%s managed=%v %q: action mode answered %q", name, managed, row.command, got.Action)
				}
				if got := agentHookResponseForProfile(profile, req, "allow", verdict.Action, verdict.Severity,
					verdict.Reason, verdict.Findings, "observe", true, connector.HookCapability{}); got.Action != "allow" || !got.WouldBlock {
					t.Errorf("%s managed=%v %q: observe mode answered %q would_block=%v", name, managed, row.command, got.Action, got.WouldBlock)
				}
			}
		}
	}
	if data, err := os.ReadFile(filepath.Join(home, ".ssh", "authorized_keys")); err != nil || string(data) != "marker\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}
