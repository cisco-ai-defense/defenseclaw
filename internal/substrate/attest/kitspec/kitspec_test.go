// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// These tests render the sandbox artifacts of an image, which OpenShell does not do on Windows hosts.
//go:build !windows

package kitspec

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// fakeAgentPin swaps the Claude Code pin for a small fake build.
func fakeAgentPin(t *testing.T) []byte {
	t.Helper()
	saved := kit.AgentReleases["claudecode"]
	t.Cleanup(func() { kit.AgentReleases["claudecode"] = saved })
	body := []byte("fake claude build")
	sum := sha256.Sum256(body)
	r := saved
	r.SHA256 = map[string]string{"amd64": hex.EncodeToString(sum[:])}
	kit.AgentReleases["claudecode"] = r
	return body
}

func TestSpecRefusesAnAgentThatIsNotThePin(t *testing.T) {
	if _, _, err := Spec(Options{Connector: "claudecode", KitVersion: "1", HookBinary: []byte("h"), RelayBinary: []byte("r"),
		AgentBinary: []byte("something else")}); err == nil {
		t.Fatal("an agent binary that is not the pinned build was accepted")
	}
	if _, _, err := Spec(Options{Connector: "claudecode", KitVersion: "1", HookBinary: []byte("h"), RelayBinary: []byte("r"),
		MetadataOnly: true}); err != nil {
		t.Fatalf("metadata only: %v", err)
	}
}

func TestSpecLayerOwnershipAndSwitches(t *testing.T) {
	agent := fakeAgentPin(t)
	for _, name := range []string{"claudecode", "codex"} {
		t.Run(name, func(t *testing.T) {
			o := Options{Connector: name, KitVersion: "1.2.3", Provider: map[string]string{"claudecode": "bedrock", "codex": "openai"}[name],
				HookBinary: []byte("hook"), RelayBinary: []byte("relay")}
			if name == "claudecode" {
				o.AgentBinary = agent
			}
			spec, tpl, err := Spec(o)
			if err != nil {
				t.Fatal(err)
			}
			if tpl.Connector != name || tpl.AgentVersion == "" || spec.HookContract == "" || spec.User != "1000:1000" {
				t.Fatalf("spec: %+v", tpl)
			}
			layer, err := attest.BuildLayer(spec.Files, nil, spec.HomeOwners, nil)
			if err != nil {
				t.Fatal(err)
			}
			zr, err := gzip.NewReader(bytes.NewReader(layer.Gzip))
			if err != nil {
				t.Fatal(err)
			}
			tr := tar.NewReader(zr)
			contents := map[string]string{}
			for {
				h, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				p := "/" + strings.TrimSuffix(h.Name, "/")
				body, _ := io.ReadAll(tr)
				contents[p] = string(body)
				user := spec.UserFiles[p] || strings.HasPrefix(p, Home) || p == Workdir
				if user && h.Uid != 1000 {
					t.Errorf("%s should belong to the image user, uid %d", p, h.Uid)
				}
				if !user && (h.Uid != 0 || h.Gid != 0 || h.Mode&0o022 != 0) {
					t.Errorf("%s must be root-owned and not group or world writable: uid %d gid %d mode %o", p, h.Uid, h.Gid, h.Mode)
				}
			}
			if contents[kit.HookBinary] != "hook" || contents[kit.RelayBinary] != "relay" || contents[kit.ConfigPath] == "" {
				t.Fatal("the hook, relay or kit config is missing from the layer")
			}
			if r, ok := kit.AgentReleases[name]; ok {
				if contents[r.Path] != string(agent) || tpl.AgentVersion != r.Version {
					t.Fatalf("pinned agent: %d bytes at %s, version %q", len(contents[r.Path]), r.Path, tpl.AgentVersion)
				}
			}
			for k, v := range kit.PhoneHomeOff[name] {
				if spec.PhoneHome[k] != v || spec.Env[k] != v {
					t.Errorf("switch %s not set", k)
				}
			}
			for file, wants := range spec.ConfigSwitches {
				for _, w := range wants {
					if !strings.Contains(contents[file], w) {
						t.Errorf("%s lacks %q", file, w)
					}
				}
			}
			if len(spec.Remove) == 0 || spec.Entrypoint[0] != kit.RelayBinary {
				t.Errorf("remove %v entrypoint %v", spec.Remove, spec.Entrypoint)
			}
		})
	}
	if _, _, err := Spec(Options{Connector: "nope", HookBinary: []byte("h"), RelayBinary: []byte("r")}); err == nil {
		t.Fatal("unknown connector accepted")
	}
	if _, _, err := Spec(Options{Connector: "codex"}); err == nil {
		t.Fatal("missing binaries accepted")
	}
}

// GAP-0117 on the template path: Antigravity's hooks.json registration lives in
// ~/.gemini/config, which must be root-owned, and Devin's tool folders under
// its root-owned XDG config home belong to the image user.
func TestSpecOverlayFolders(t *testing.T) {
	owner := func(files []attest.LayerFile, dir string) (uid int, found bool) {
		for i := len(files) - 1; i >= 0; i-- {
			if files[i].Dir && files[i].Path == dir {
				return files[i].UID, true
			}
		}
		return 0, false
	}
	spec, _, _, err := Spec(Options{Connector: "antigravity", KitVersion: "1", HookBinary: []byte("h"), RelayBinary: []byte("r")})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{Home + "/.gemini", Home + "/.gemini/config"} {
		if uid, ok := owner(spec.Files, d); !ok || uid != 0 {
			t.Errorf("antigravity %s: root-owned folder entry = %v, %v", d, uid, ok)
		}
	}
	spec, _, _, err = Spec(Options{Connector: "devin", KitVersion: "1", HookBinary: []byte("h"), RelayBinary: []byte("r")})
	if err != nil {
		t.Fatal(err)
	}
	if uid, ok := owner(spec.Files, kit.XDGConfigHome); !ok || uid != 0 {
		t.Errorf("devin XDG config home: root-owned entry = %v, %v", uid, ok)
	}
	if uid, ok := owner(spec.Files, kit.XDGConfigHome+"/git"); !ok || uid != 1000 {
		t.Errorf("devin %s/git: user-owned entry = %v, %v", kit.XDGConfigHome, uid, ok)

	}
}

// The --connector help lists kit.Connectors: each one has a kit spec, and
// the list is exactly what the relay can start.
func TestEveryListedConnectorHasAKitSpec(t *testing.T) {
	names := kit.Connectors()
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			t.Errorf("%s listed twice", name)
		}
		seen[name] = true
		if _, _, err := Spec(Options{Connector: name, KitVersion: "test", HookBinary: []byte("x"), RelayBinary: []byte("x"), MetadataOnly: true}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(names) != 10 {
		t.Errorf("%d connectors, want 10: %v", len(names), names)
	}
	// The argv tables (wave 1 here, waves 2 and 3 added by their init) are
	// what the relay can start: exactly the listed connectors.
	for table, argv := range map[string]map[string][]string{"InteractiveArgv": kit.InteractiveArgv, "HeadlessArgv": kit.HeadlessArgv} {
		for name := range argv {
			if !seen[name] {
				t.Errorf("%s has %s, which kit.Connectors does not list", table, name)
			}
		}
		for _, name := range names {
			if argv[name] == nil {
				t.Errorf("%s has no entry for listed %s", table, name)
			}
		}
	}
	if got := kit.ConnectorList(); !strings.HasPrefix(got, "claudecode, codex, ") || !strings.HasSuffix(got, " or devin") {
		t.Errorf("ConnectorList = %q", got)
	}
}

// Lane K1: Antigravity's root-owned hooks.json registration in the user's home
// stays root-owned in the layer but is not one of the paths the build expects
// to be root-owned all the way up (the home is the user's); the canonical
// copy outside the home is.
func TestSpecRootOwnedFilesInTheHomeAreNotExpectedChains(t *testing.T) {
	spec, _, _, err := Spec(Options{Connector: "antigravity", KitVersion: "1", HookBinary: []byte("h"), RelayBinary: []byte("r")})
	if err != nil {
		t.Fatal(err)
	}
	hooks := Home + "/.gemini/config/hooks.json"
	var found bool
	for _, f := range spec.Files {
		if f.Path == hooks {
			found = true
			if f.UID != 0 || f.Mode != 0o644 {
				t.Errorf("%s must stay root 0644 in the layer, got uid %d mode %o", hooks, f.UID, f.Mode)
			}
		}
	}
	if !found {
		t.Fatalf("%s is not in the layer", hooks)
	}
	if !spec.UserFiles[hooks] || !spec.UserFiles[Home+"/.gemini"] || !spec.UserFiles[Home+"/.gemini/config"] {
		t.Error("root-owned paths below the home must not be expected as root-owned chains")
	}
	if spec.UserFiles["/usr/local/lib/defenseclaw/antigravity/hooks.json"] {
		t.Error("the canonical hooks copy outside the home is the checked file")
	}
}
