// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kitspec

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

func TestSpecLayerOwnershipAndSwitches(t *testing.T) {
	for _, name := range []string{"claudecode", "codex"} {
		t.Run(name, func(t *testing.T) {
			spec, tpl, version, err := Spec(Options{Connector: name, KitVersion: "1.2.3", Provider: map[string]string{"claudecode": "bedrock", "codex": "openai"}[name],
				HookBinary: []byte("hook"), RelayBinary: []byte("relay")})
			if err != nil {
				t.Fatal(err)
			}
			if tpl.Connector != name || version == "" || spec.HookContract == "" || spec.User != "1000:1000" {
				t.Fatalf("spec: %+v %q", tpl, version)
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
	if _, _, _, err := Spec(Options{Connector: "nope", HookBinary: []byte("h"), RelayBinary: []byte("r")}); err == nil {
		t.Fatal("unknown connector accepted")
	}
	if _, _, _, err := Spec(Options{Connector: "codex"}); err == nil {
		t.Fatal("missing binaries accepted")
	}
}
