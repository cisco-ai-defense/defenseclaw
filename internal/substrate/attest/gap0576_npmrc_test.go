// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// GAP-0576 item 1: npm_config_globalconfig makes npm read the kit's npmrc
// instead of the base image's global one (<prefix>/etc/npmrc), so a base
// image's registry, scope registry, strict-ssl and cafile were dropped and
// installs went to registry.npmjs.org. The template build carries them into
// the kit's file, before the kit's own lines; a base global npmrc that holds
// a credential is refused, one that names an environment variable is not.
func TestGAP0576BaseGlobalNpmrcIsCarriedIntoTheKits(t *testing.T) {
	const kitRC = "# kit\nupdate-notifier=false\nfund=false\naudit=false\n"
	base := "registry=https://npm.corp.example/\n@corp:registry=https://npm.corp.example/corp/\nstrict-ssl=false\n; comment\ncafile=/etc/ssl/corp.pem\n"
	f := newFixture(t, tarFile{path: "/usr/bin/npm", mode: 0o755, data: "#!npm"}, tarFile{path: "/usr/etc/npmrc", mode: 0o644, data: base})
	res, err := f.build(t, func(o *BuildOptions) {
		o.Kit.Files = append(o.Kit.Files, LayerFile{Path: kit.NPMGlobalConfig, Mode: 0o644, Data: []byte(kitRC)})
	})
	if err != nil || !res.Pushed {
		t.Fatalf("build: %v", err)
	}
	ctx := context.Background()
	ref, err := ParseRef(f.m.host() + "/tmpl/claude@" + res.Digest)
	if err != nil {
		t.Fatal(err)
	}
	img, err := f.reg.Image(ctx, ref, DefaultPlatform)
	if err != nil {
		t.Fatal(err)
	}
	fsys, err := f.reg.OpenFS(ctx, img, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	b, err := fsys.Read(kit.NPMGlobalConfig)
	if err != nil {
		t.Fatal(err)
	}
	rc := string(b)
	for _, line := range []string{"registry=https://npm.corp.example/", "@corp:registry=https://npm.corp.example/corp/", "strict-ssl=false", "cafile=/etc/ssl/corp.pem", "fund=false"} {
		if !strings.Contains(rc, line+"\n") {
			t.Errorf("the built image's %s lost %q:\n%s", kit.NPMGlobalConfig, line, rc)
		}
	}
	if strings.Index(rc, "registry=https://npm.corp.example/") > strings.Index(rc, "fund=false") {
		t.Errorf("the kit's settings must come after the base's:\n%s", rc)
	}

	// A credential in the base global npmrc: the build refuses, naming it.
	bad := newFixture(t, tarFile{path: "/usr/bin/npm", mode: 0o755, data: "#!npm"},
		tarFile{path: "/usr/etc/npmrc", mode: 0o644, data: "//npm.corp.example/:_authToken=npm_0123456789abcdef\n"})
	_, err = bad.build(t, func(o *BuildOptions) {
		o.Kit.Files = append(o.Kit.Files, LayerFile{Path: kit.NPMGlobalConfig, Mode: 0o644, Data: []byte(kitRC)})
	})
	if err == nil || !strings.Contains(err.Error(), "_authToken") || strings.Contains(err.Error(), "npm_0123456789abcdef") {
		t.Fatalf("a base npmrc with a token: %v, want a refusal naming the key and not the value", err)
	}
	var blocked *BuildBlocked
	if errors.As(err, &blocked) {
		t.Fatalf("refusal is not a scan block: %v", err)
	}
	// An environment reference is not a credential.
	ref2 := newFixture(t, tarFile{path: "/usr/bin/npm", mode: 0o755, data: "#!npm"},
		tarFile{path: "/usr/etc/npmrc", mode: 0o644, data: "//npm.corp.example/:_authToken=${NPM_TOKEN}\n"})
	if _, err := ref2.build(t, func(o *BuildOptions) {
		o.Kit.Files = append(o.Kit.Files, LayerFile{Path: kit.NPMGlobalConfig, Mode: 0o644, Data: []byte(kitRC)})
	}); err != nil {
		t.Fatalf("a base npmrc naming an environment variable: %v", err)
	}
}
