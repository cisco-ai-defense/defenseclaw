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
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Builder builds, verifies, records and prunes overlay images.
type Builder struct {
	Docker Docker
	Store  *Store
	// Log receives docker build output; nil discards it.
	Log io.Writer
	// Now defaults to time.Now.
	Now func() time.Time
}

// BuildOptions tune one build.
type BuildOptions struct {
	// Force rebuilds even when a verified image with the same content hash
	// is already recorded and present.
	Force bool
}

// Build renders the context, streams it to `docker build -t <tag> -`,
// probes the result with --network none, verifies it and records it. An
// image that fails verification is removed.
func (b *Builder) Build(ctx context.Context, spec BuildSpec, opts BuildOptions) (Record, error) {
	c, err := NewContext(spec)
	if err != nil {
		return Record{}, err
	}
	if !opts.Force {
		if rec, ok, err := b.Store.Get(c.Tag); err != nil {
			return Record{}, err
		} else if ok && rec.ContentHash == c.ContentHash {
			if id, err := b.imageID(ctx, c.Tag); err == nil && id == rec.ImageID {
				return rec, nil
			}
		}
	}

	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(c.WriteTar(pw))
	}()
	args := []string{"build", "--pull=false"}
	labelKeys := make([]string, 0, len(c.Labels))
	for key := range c.Labels {
		labelKeys = append(labelKeys, key)
	}
	sort.Strings(labelKeys)
	for _, key := range labelKeys {
		args = append(args, "--label", key+"="+c.Labels[key])
	}
	args = append(args, "-t", c.Tag, "-")
	logw := b.Log
	if logw == nil {
		logw = io.Discard
	}
	err = b.Docker.Run(ctx, pr, logw, logw, args...)
	_ = pr.CloseWithError(io.ErrClosedPipe)
	if err != nil {
		return Record{}, fmt.Errorf("openshell image: docker build %s: %w", c.Tag, err)
	}

	id, err := b.imageID(ctx, c.Tag)
	if err != nil {
		return Record{}, err
	}
	res, err := b.Probe(ctx, c)
	if err == nil {
		err = c.Verify(res)
	}
	if err != nil {
		_, _ = output(ctx, b.Docker, nil, "image", "rm", "-f", c.Tag)
		return Record{}, err
	}
	now := time.Now
	if b.Now != nil {
		now = b.Now
	}
	rec := Record{
		Tag:                c.Tag,
		ImageID:            id,
		ContentHash:        c.ContentHash,
		Connector:          c.Spec.Harness.Name,
		HarnessVersion:     c.HarnessVersion,
		HookContract:       c.Contract,
		BaseImage:          c.Spec.BaseImage,
		UID:                c.Spec.UID,
		GID:                c.Spec.GID,
		IngressPort:        c.Spec.IngressPort,
		DefenseClawVersion: c.Spec.DefenseClawVersion,
		BuiltAt:            now().UTC(),
		NetworkBinaries:    res.NetworkBinary,
	}
	names := make([]string, 0, len(res.Binaries))
	for name := range res.Binaries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		rec.Binaries = append(rec.Binaries, res.Binaries[name])
	}
	if err := b.Store.Put(rec); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// Probe runs the post-build probe for c and parses its output.
func (b *Builder) Probe(ctx context.Context, c *Context) (ProbeResult, error) {
	out, err := output(ctx, b.Docker, nil, probeRunArgs(c)...)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("openshell image: probe %s: %w", c.Tag, err)
	}
	return ParseProbe([]byte(out), c.Spec.Harness.Probe().VersionRE)
}

func (b *Builder) imageID(ctx context.Context, tag string) (string, error) {
	id, err := output(ctx, b.Docker, nil, "image", "inspect", "--format", "{{.Id}}", tag)
	if err != nil {
		return "", fmt.Errorf("openshell image: inspect %s: %w", tag, err)
	}
	if !strings.HasPrefix(id, "sha256:") {
		return "", fmt.Errorf("openshell image: inspect %s returned %q", tag, id)
	}
	return id, nil
}

// PruneOptions select what Prune removes.
type PruneOptions struct {
	// Repository limits pruning to one image repository (default
	// DefaultRepository).
	Repository string
	// Keep lists tags that must survive in addition to the current image of
	// every identity.
	Keep []string
	// DryRun reports without removing.
	DryRun bool
}

// PruneReport lists what Prune did.
type PruneReport struct {
	Removed        []string
	Kept           []string
	ForgottenStale []string
}

// Prune removes DefenseClaw overlay images of one repository except the
// most recent image per (connector, uid, gid, ingress port) and opts.Keep,
// and forgets store records whose image no longer exists.
func (b *Builder) Prune(ctx context.Context, opts PruneOptions) (PruneReport, error) {
	repo := opts.Repository
	if repo == "" {
		repo = DefaultRepository
	}
	if !repositoryRE.MatchString(repo) {
		return PruneReport{}, fmt.Errorf("openshell image: invalid repository %q", repo)
	}
	listed, err := output(ctx, b.Docker, nil, "image", "ls", "--filter", "label="+LabelSandboxImage+"=1",
		"--format", "{{.Repository}}:{{.Tag}}")
	if err != nil {
		return PruneReport{}, fmt.Errorf("openshell image: list images: %w", err)
	}
	present := map[string]bool{}
	for _, line := range strings.Split(listed, "\n") {
		tag := strings.TrimSpace(line)
		if strings.HasPrefix(tag, repo+":") && !strings.HasSuffix(tag, ":<none>") {
			present[tag] = true
		}
	}
	records, err := b.Store.List()
	if err != nil {
		return PruneReport{}, err
	}
	keep := map[string]bool{}
	for _, tag := range opts.Keep {
		keep[tag] = true
	}
	type identity struct {
		connector         string
		uid, gid, ingress int
	}
	latest := map[identity]Record{}
	var stale []string
	for _, r := range records {
		if !strings.HasPrefix(r.Tag, repo+":") {
			continue
		}
		if !present[r.Tag] {
			stale = append(stale, r.Tag)
			continue
		}
		id := identity{r.Connector, r.UID, r.GID, r.IngressPort}
		if cur, ok := latest[id]; !ok || r.BuiltAt.After(cur.BuiltAt) {
			latest[id] = r
		}
	}
	for _, r := range latest {
		keep[r.Tag] = true
	}
	var report PruneReport
	tags := make([]string, 0, len(present))
	for tag := range present {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	var removeErrs []error
	for _, tag := range tags {
		if keep[tag] {
			report.Kept = append(report.Kept, tag)
			continue
		}
		if !opts.DryRun {
			if _, err := output(ctx, b.Docker, nil, "image", "rm", tag); err != nil {
				removeErrs = append(removeErrs, fmt.Errorf("remove %s: %w", tag, err))
				continue
			}
		}
		report.Removed = append(report.Removed, tag)
	}
	sort.Strings(stale)
	report.ForgottenStale = stale
	if !opts.DryRun {
		if err := b.Store.Remove(append(append([]string(nil), report.Removed...), stale...)...); err != nil {
			return report, err
		}
	}
	return report, errors.Join(removeErrs...)
}
