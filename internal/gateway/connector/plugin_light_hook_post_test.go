// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// The OpenCode and Amp per-user plugins post every hook event through a
// native helper that proves the connected peer. Starting the full gateway CLI
// for each event saturated a host under load, so the plugins use the small
// defenseclaw-hook-post helper when the installer put it beside the gateway,
// keep the gateway CLI when it is absent (Windows, an older installer's
// roll-forward), and refuse a helper that another account could replace.
func TestPerUserPluginsPostThroughTheLightHelper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Node harness uses POSIX stub binaries; Windows keeps the gateway CLI")
	}
	node := nodeForTest(t)
	const record = "#!/bin/sh\nprintf '%s %s\\n' \"$DC_STUB_NAME\" \"$*\" >> \"$DC_PEER_MARKER\"\nexit 1\n"
	for _, plugin := range []struct{ asset, connector string }{
		{"opencode-plugin.js", "opencode"},
		{"amp-plugin.ts", "amp"},
	} {
		for _, tc := range []struct {
			name   string
			helper string // "", "file", "symlink", "writable", "dir"
			want   string // the stub that receives hook-post, or "" for none
		}{
			{name: "installed helper", helper: "file", want: "helper"},
			{name: "no helper keeps the gateway CLI", want: "gateway"},
			{name: "symlinked helper is refused", helper: "symlink"},
			{name: "writable helper is refused", helper: "writable"},
			{name: "directory helper is refused", helper: "dir"},
		} {
			t.Run(plugin.connector+"/"+tc.name, func(t *testing.T) {
				root := testenv.PrivateTempDir(t)
				bin := filepath.Join(root, ".local", "bin")
				if err := os.MkdirAll(bin, 0o700); err != nil {
					t.Fatal(err)
				}
				write := func(path, name string, mode os.FileMode) {
					t.Helper()
					body := strings.Replace(record, "$DC_STUB_NAME", name, 1)
					if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(path, mode); err != nil {
						t.Fatal(err)
					}
				}
				write(filepath.Join(bin, "defenseclaw-gateway"), "gateway", 0o700)
				helper := filepath.Join(bin, "defenseclaw-hook-post")
				switch tc.helper {
				case "file":
					write(helper, "helper", 0o700)
				case "writable":
					write(helper, "helper", 0o722)
				case "symlink":
					other := filepath.Join(root, "elsewhere")
					write(other, "symlink", 0o700)
					if err := os.Symlink(other, helper); err != nil {
						t.Fatal(err)
					}
				case "dir":
					if err := os.Mkdir(helper, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				// The plugins take the gateway from the .gateway-helper record
				// setup writes beside the hook (fix/r104-oss-outage-open), and
				// the light helper from beside that gateway.
				hookDir := filepath.Join(root, ".defenseclaw", "hooks")
				recordGatewayHelperForTest(t, hookDir, filepath.Join(bin, "defenseclaw-gateway"))
				tokenPath := filepath.Join(hookDir, ".hook-"+plugin.connector+".token")
				if err := os.WriteFile(tokenPath, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				recorder := &listenerProofRecorder{}
				impostor := newImpostorListener(t, recorder)
				addr := strings.TrimPrefix(impostor.URL, "http://")
				harness, name := openCodeListenerProofHarness, "opencode-plugin.mjs"
				if plugin.connector == "amp" {
					harness, name = ampListenerProofHarness, "amp-plugin.mts"
				}
				rendered := filepath.Join(testenv.PrivateTempDir(t), name)
				body := renderPluginAssetForTest(t, plugin.asset, templateData{
					APIAddr: addr, TokenFileJS: javaScriptStringContent(tokenPath), FailMode: "closed",
				})
				if err := os.WriteFile(rendered, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				marker := filepath.Join(root, "calls")
				ctx, cancel := context.WithTimeout(context.Background(), nodeHarnessTimeout)
				defer cancel()
				cmd := exec.CommandContext(ctx, node, "--input-type=module", "-e", harness, rendered)
				cmd.Env = append(os.Environ(), "HOME="+root, "DC_PEER_MARKER="+marker)
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("node: %v: %s", err, output)
				}
				if !strings.Contains(string(output), "block:") {
					t.Fatalf("a failed native post did not fail closed: %s", output)
				}
				if got := recorder.snapshot(); len(got) != 0 {
					t.Fatalf("the plugin sent to the listener itself: %+v", got)
				}
				calls, _ := os.ReadFile(marker)
				var posts []string
				for _, line := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
					if strings.Contains(line, " hook-post ") {
						posts = append(posts, line)
					}
				}
				if tc.want == "" {
					if len(posts) != 0 {
						t.Fatalf("an untrusted helper path still posted: %q", posts)
					}
					return
				}
				if len(posts) == 0 {
					t.Fatalf("no native post ran; calls: %q, output: %s", calls, output)
				}
				for _, line := range posts {
					if line != tc.want+" hook-post --api-addr "+addr {
						t.Fatalf("post ran as %q, want %s hook-post --api-addr %s", line, tc.want, addr)
					}
				}
			})
		}
	}
}
