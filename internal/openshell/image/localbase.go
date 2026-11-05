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

package image

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// BaseAliasRepository is the repository of the local name an overlay build
// gives a base image that Docker already holds (localBase). The tag is the
// image ID's hex digits, so one name always means one image.
const BaseAliasRepository = "defenseclaw/sandbox-base"

// localBase returns the build context files for c and, when Docker already
// holds c's base image, that image's facts. The base must be named by
// digest, and the digest must be the image's ID or one of its repo digests.
// The Dockerfile's FROM then names a local alias tagged from the image ID,
// so the build runs on exactly that image without a registry. BuildKit
// resolves FROM name@sha256:... in the registry even with --pull=false, so
// a base an administrator built in the person's Docker engine
// (openshell.image.base set to name@sha256:<image ID>) failed with "pull
// access denied" and no sandbox started (GAP-0230). A base Docker does not
// hold is built as before and pulled by its digest. The content hash, and
// so the tag and the record, stay those of the base reference: only the
// name the build reads the same image under changes.
func (b *Builder) localBase(ctx context.Context, c *Context) ([]ContextFile, imageFacts, bool, error) {
	ref := c.Spec.BaseImage
	_, digest, ok := strings.Cut(ref, "@")
	if !ok || !imageIDRE.MatchString(digest) {
		return c.Files, imageFacts{}, false, nil
	}
	facts, err := inspectImage(ctx, b.Docker, ref)
	if err != nil || !facts.named(digest) {
		// The classic image store finds a locally built image by its ID only.
		facts, err = inspectImage(ctx, b.Docker, digest)
	}
	if err != nil || !facts.named(digest) || len(facts.Layers) == 0 {
		return c.Files, imageFacts{}, false, nil
	}
	from := []byte("FROM " + ref + "\n")
	if len(c.Files) == 0 || c.Files[0].Name != "Dockerfile" || !bytes.Contains(c.Files[0].Data, from) {
		return nil, imageFacts{}, false, errors.New("openshell image: the build context has no FROM line for its base image")
	}
	alias := BaseAliasRepository + ":" + strings.TrimPrefix(facts.ID, "sha256:")
	if err := tagImage(ctx, b.Docker, facts.ID, alias); err != nil {
		return nil, imageFacts{}, false, fmt.Errorf("openshell image: name the local base image %s: %w", ref, err)
	}
	files := slices.Clone(c.Files)
	// A MicroVM image can also start with a pinned resolver-tool stage.
	// The final base stage is the last matching FROM line.
	index := bytes.LastIndex(files[0].Data, from)
	files[0].Data = slices.Concat(files[0].Data[:index], []byte("FROM "+alias+"\n"), files[0].Data[index+len(from):])
	return files, facts, true, nil
}

// named reports whether digest is f's image ID or one of its repo digests.
func (f imageFacts) named(digest string) bool {
	if f.ID == digest {
		return true
	}
	for _, repoDigest := range f.RepoDigests {
		if _, d, ok := strings.Cut(repoDigest, "@"); ok && d == digest {
			return true
		}
	}
	return false
}

// checkBuiltOn confirms that the image tag names was built on base: its
// layers start with all of base's. Another image tagged with the alias
// between the tag and the build would fail here.
func (b *Builder) checkBuiltOn(ctx context.Context, tag string, base imageFacts) error {
	built, err := inspectImage(ctx, b.Docker, tag)
	if err != nil {
		return err
	}
	if len(built.Layers) <= len(base.Layers) || !slices.Equal(built.Layers[:len(base.Layers)], base.Layers) {
		return fmt.Errorf("openshell image: %s was not built on the base image %s", tag, base.ID)
	}
	return nil
}
