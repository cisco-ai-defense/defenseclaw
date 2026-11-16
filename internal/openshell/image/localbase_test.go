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

//go:build !windows

package image

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

// localBaseDocker is a daemon that holds the administrator's base image
// (built on this computer, so known by its ID only unless repoDigest is
// set) and builds the overlay on it; onBase says whether the built image's
// layers start with the base's.
func localBaseDocker(t *testing.T, c *Context, baseID, repoDigest string, onBase bool) *fakeDocker {
	t.Helper()
	alias := BaseAliasRepository + ":" + strings.TrimPrefix(baseID, "sha256:")
	baseJSON := `{"Id":"` + baseID + `","RepoDigests":[` + repoDigest + `],"RootFS":{"Layers":["sha256:` + strings.Repeat("a", 64) + `"]}}`
	builtLayers := `"sha256:` + strings.Repeat("a", 64) + `","sha256:` + strings.Repeat("b", 64) + `"`
	if !onBase {
		builtLayers = `"sha256:` + strings.Repeat("c", 64) + `","sha256:` + strings.Repeat("b", 64) + `"`
	}
	builtID := "sha256:" + strings.Repeat("1", 64)
	tagged, built := false, false
	return &fakeDocker{handler: func(args []string, stdin []byte) (string, int) {
		switch {
		case args[0] == "image" && args[1] == "inspect" && args[len(args)-1] == c.Spec.BaseImage:
			if repoDigest == "" {
				return "", 1 // the classic store: no repo digest for a local build
			}
			return baseJSON, 0
		case args[0] == "image" && args[1] == "inspect" && args[len(args)-1] == baseID:
			return baseJSON, 0
		case args[0] == "tag":
			if len(args) != 3 || args[1] != baseID || args[2] != alias {
				t.Errorf("docker tag argv = %v", args)
			}
			tagged = true
			return "", 0
		case args[0] == "build":
			if !tagged {
				t.Error("built before the base image had its local name")
			}
			if !bytes.Contains(stdin, []byte("\nFROM "+alias+"\n")) || bytes.Contains(stdin, []byte("FROM "+c.Spec.BaseImage)) {
				t.Errorf("the build context does not start FROM the local name %s", alias)
			}
			built = true
			return "", 0
		case args[0] == "image" && args[1] == "inspect" && args[len(args)-1] == c.Tag:
			if !built {
				return "", 1
			}
			if containsSeq(args, "--format", "{{.Id}}") {
				return builtID + "\n", 0
			}
			return `{"Id":"` + builtID + `","RootFS":{"Layers":[` + builtLayers + `]}}`, 0
		case args[0] == "run" && containsSeq(args, "--network", "none"):
			return goodProbeOutput(c), 0
		case args[0] == "image" && args[1] == "rm":
			built = false
			return "", 0
		}
		t.Errorf("unexpected docker call %v", args)
		return "", 1
	}}
}

// GAP-0230: openshell.image.base names an image the administrator built in
// the person's Docker engine by its image ID. The overlay builds FROM a
// local name of exactly that image, never from the registry, with the
// classic store (found by ID) and the containerd store (a repo digest);
// the record keeps the configured base. An image that is not built on that
// base is removed and refused.
func TestBuildRunsOnALocalBaseImage(t *testing.T) {
	baseID := "sha256:" + strings.Repeat("f6", 32)
	for _, tc := range []struct {
		name       string
		repoDigest string
		microVM    bool
	}{
		{"classic store", "", false},
		{"containerd store", `"corp-base@` + baseID + `"`, false},
		{"MicroVM classic store", "", true},
		{"MicroVM containerd store", `"corp-base@` + baseID + `"`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := testSpec(harness.Codex)
			spec.BaseImage = "corp-base@" + baseID
			spec.MicroVM = tc.microVM
			c := mustContext(t, spec)
			docker := localBaseDocker(t, c, baseID, tc.repoDigest, true)
			b := &Builder{Docker: docker, Store: testStore(t)}
			rec, err := b.Build(context.Background(), spec, BuildOptions{SkipHookFire: true})
			if err != nil {
				t.Fatalf("Build on the local base: %v", err)
			}
			if rec.BaseImage != spec.BaseImage || rec.Tag != c.Tag || docker.count("build") != 1 || docker.count("tag") != 1 {
				t.Fatalf("record %+v, builds %d, tags %d", rec, docker.count("build"), docker.count("tag"))
			}
		})
	}

	spec := testSpec(harness.Codex)
	spec.BaseImage = "corp-base@" + baseID
	c := mustContext(t, spec)
	docker := localBaseDocker(t, c, baseID, "", false)
	b := &Builder{Docker: docker, Store: testStore(t)}
	if _, err := b.Build(context.Background(), spec, BuildOptions{SkipHookFire: true}); err == nil ||
		!strings.Contains(err.Error(), "was not built on the base image") {
		t.Fatalf("an image not built on the base: %v", err)
	}
	if docker.count("image", "rm") != 1 {
		t.Fatal("the image not built on the base was kept")
	}
}

func TestMicroVMLocalBaseUsesFinalStage(t *testing.T) {
	spec := testSpec(harness.Codex)
	spec.MicroVM = true
	c := mustContext(t, spec)
	_, baseID, ok := strings.Cut(c.Spec.BaseImage, "@")
	if !ok {
		t.Fatal("the pinned base has no digest")
	}
	b := &Builder{Docker: localBaseDocker(t, c, baseID, "", true)}
	files, _, local, err := b.localBase(context.Background(), c)
	if err != nil || !local {
		t.Fatalf("local base: %v, local %t", err, local)
	}
	file := string(files[0].Data)
	alias := BaseAliasRepository + ":" + strings.TrimPrefix(baseID, "sha256:")
	if !strings.Contains(file, "FROM "+c.Spec.BaseImage+" AS dc-localhost-tool\n") ||
		!strings.Contains(file, "FROM "+alias+"\n") ||
		strings.Contains(file, "FROM "+c.Spec.BaseImage+"\n") {
		t.Fatalf("MicroVM base stages do not use the selected local base: %s", file[:300])
	}
}

// A base named by tag is refused before docker runs, with the digest form
// to use for an image built on this computer.
func TestATaggedBaseImageSaysHowToPinIt(t *testing.T) {
	spec := testSpec(harness.Codex)
	spec.BaseImage = "corp-base:1"
	_, err := NewContext(spec)
	if err == nil || !strings.Contains(err.Error(), "not digest-pinned") || !strings.Contains(err.Error(), "image ID") {
		t.Fatalf("tagged base: %v", err)
	}
}
