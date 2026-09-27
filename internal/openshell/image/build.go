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
	// HookFire configures the hook-fire probe Build runs before it returns
	// an image; the zero value uses the built-in mock LLM and scenarios.
	HookFire HookFireOptions
	// SkipHookFire records the image without the hook-fire probe. The
	// record stays unverified, so Store.Current does not select it until
	// VerifyHooks passes.
	SkipHookFire bool
}

// Build renders the context, streams it to `docker build -t <tag> -`,
// probes the result with --network none, verifies it and records it, then
// runs VerifyHooks, so a fresh image is proven to enforce before anything
// selects it. An image that fails the static verification is removed; one
// whose hooks are proven not to fire stays recorded as unverified (for
// diagnosis) and Build returns the ErrHooksNotFired error. A new build is
// recorded with HookFireVerified unset (a rebuild clears an earlier
// verdict); a cached image keeps its verdict and is probed again only when
// it is not verified yet.
func (b *Builder) Build(ctx context.Context, spec BuildSpec, opts BuildOptions) (Record, error) {
	c, err := b.Context(spec)
	if err != nil {
		return Record{}, err
	}
	if !opts.Force {
		if rec, ok, err := b.Store.Get(c.Tag); err != nil {
			return Record{}, err
		} else if ok && recordMatches(rec, c) {
			if id, err := b.imageID(ctx, c.Tag); err == nil && id == rec.ImageID {
				if rec.HookFireVerified || opts.SkipHookFire {
					return rec, nil
				}
				return b.verifyBuilt(ctx, c, rec, opts)
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
		FailMode:           c.Spec.FailMode,
		Owner:              c.Spec.Owner,
		BuiltAt:            b.now().UTC(),
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
	if opts.SkipHookFire {
		return rec, nil
	}
	return b.verifyBuilt(ctx, c, rec, opts)
}

// verifyBuilt runs VerifyHooks for a just-built or cached image and returns
// the verified record, or the unverified one and the probe error.
func (b *Builder) verifyBuilt(ctx context.Context, c *Context, rec Record, opts BuildOptions) (Record, error) {
	verified, _, err := b.VerifyHooks(ctx, c, opts.HookFire)
	if err != nil {
		if verified.Tag == "" {
			verified = rec
		}
		return verified, fmt.Errorf("openshell image: %s built but not verified: %w", c.Tag, err)
	}
	return verified, nil
}

// Context renders spec's build context for this builder's store: an empty
// spec.Owner becomes the store's owner, and a spec owned by another data dir
// is refused.
func (b *Builder) Context(spec BuildSpec) (*Context, error) {
	owner, err := b.Store.Owner()
	if err != nil {
		return nil, err
	}
	switch spec.Owner {
	case "":
		spec.Owner = owner
	case owner:
	default:
		return nil, fmt.Errorf("openshell image: spec belongs to image store owner %q, not this store's %q", spec.Owner, owner)
	}
	return NewContext(spec)
}

// Current returns the verified image a sandbox built from spec must run
// (see Store.Current).
func (b *Builder) Current(spec BuildSpec) (Record, bool, error) {
	c, err := b.Context(spec)
	if err != nil {
		return Record{}, false, err
	}
	return b.Store.Current(c)
}

func (b *Builder) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
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
	// Unrecorded are images labelled with this store's owner that it holds
	// no record for (for example after images.json was restored from an
	// older copy). They are reported, never removed.
	Unrecorded []string
	// Foreign are the repository's other DefenseClaw images: built by
	// another data dir sharing the daemon, or recorded here without this
	// store's owner label. They are reported, never removed.
	Foreign []string
}

// Prune removes overlay images this store built, in one repository, except,
// per (connector, uid, gid, ingress port), the most recent image and the
// most recent hook-verified one (what Store.Current selects for an unchanged
// spec), plus opts.Keep, and forgets store records whose image no longer
// exists. An image is removed only when this store recorded it under its own
// owner and the image carries that owner label; every other DefenseClaw
// image is reported, never removed, so data dirs sharing a Docker daemon (or
// a data dir that lost images.json) never delete images another one runs.
// Images in use by a container are refused by docker itself (no --force).
func (b *Builder) Prune(ctx context.Context, opts PruneOptions) (PruneReport, error) {
	repo := opts.Repository
	if repo == "" {
		repo = DefaultRepository
	}
	if !repositoryRE.MatchString(repo) {
		return PruneReport{}, fmt.Errorf("openshell image: invalid repository %q", repo)
	}
	owner, err := b.Store.Owner()
	if err != nil {
		return PruneReport{}, err
	}
	present, err := b.listTags(ctx, repo, "label="+LabelSandboxImage+"=1")
	if err != nil {
		return PruneReport{}, err
	}
	owned, err := b.listTags(ctx, repo, "label="+LabelSandboxImage+"=1", "label="+LabelOwner+"="+owner)
	if err != nil {
		return PruneReport{}, err
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
	verified := map[identity]Record{}
	recorded := map[string]bool{}
	var report PruneReport
	var candidates []Record
	for _, r := range records {
		if !strings.HasPrefix(r.Tag, repo+":") {
			continue
		}
		recorded[r.Tag] = true
		switch {
		case !present[r.Tag]:
			report.ForgottenStale = append(report.ForgottenStale, r.Tag)
			continue
		case r.Owner != owner || !owned[r.Tag]:
			report.Foreign = append(report.Foreign, r.Tag)
			continue
		}
		candidates = append(candidates, r)
		id := identity{r.Connector, r.UID, r.GID, r.IngressPort}
		if cur, ok := latest[id]; !ok || r.BuiltAt.After(cur.BuiltAt) {
			latest[id] = r
		}
		if cur, ok := verified[id]; r.HookFireVerified && (!ok || r.BuiltAt.After(cur.BuiltAt)) {
			verified[id] = r
		}
	}
	for _, r := range latest {
		keep[r.Tag] = true
	}
	for _, r := range verified {
		keep[r.Tag] = true
	}
	for tag := range present {
		switch {
		case recorded[tag]:
		case owned[tag]:
			report.Unrecorded = append(report.Unrecorded, tag)
		default:
			report.Foreign = append(report.Foreign, tag)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Tag < candidates[j].Tag })
	var removeErrs []error
	for _, r := range candidates {
		if keep[r.Tag] {
			report.Kept = append(report.Kept, r.Tag)
			continue
		}
		if !opts.DryRun {
			if _, err := output(ctx, b.Docker, nil, "image", "rm", r.Tag); err != nil {
				removeErrs = append(removeErrs, fmt.Errorf("remove %s: %w", r.Tag, err))
				continue
			}
		}
		report.Removed = append(report.Removed, r.Tag)
	}
	sort.Strings(report.ForgottenStale)
	sort.Strings(report.Unrecorded)
	sort.Strings(report.Foreign)
	if !opts.DryRun {
		if err := b.Store.Remove(append(append([]string(nil), report.Removed...), report.ForgottenStale...)...); err != nil {
			return report, err
		}
	}
	return report, errors.Join(removeErrs...)
}

// listTags lists the tags of repo whose images match every docker filter.
func (b *Builder) listTags(ctx context.Context, repo string, filters ...string) (map[string]bool, error) {
	args := []string{"image", "ls"}
	for _, f := range filters {
		args = append(args, "--filter", f)
	}
	listed, err := output(ctx, b.Docker, nil, append(args, "--format", "{{.Repository}}:{{.Tag}}")...)
	if err != nil {
		return nil, fmt.Errorf("openshell image: list images: %w", err)
	}
	tags := map[string]bool{}
	for _, line := range strings.Split(listed, "\n") {
		tag := strings.TrimSpace(line)
		if strings.HasPrefix(tag, repo+":") && !strings.HasSuffix(tag, ":<none>") {
			tags[tag] = true
		}
	}
	return tags, nil
}
