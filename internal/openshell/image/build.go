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
	"maps"
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

	if err := buildImage(ctx, b.Docker, c.Files, c.Labels, c.Tag, b.Log); err != nil {
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
		MicroVM:            c.Spec.MicroVM,
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
// (see Store.Current). It also confirms with Docker that the tag still
// resolves to the verified ImageID (p2-render-3).
func (b *Builder) Current(spec BuildSpec) (Record, bool, error) {
	c, err := b.Context(spec)
	if err != nil {
		return Record{}, false, err
	}
	rec, ok, err := b.Store.Current(c)
	if err != nil || !ok {
		return Record{}, false, err
	}
	// Verify the tag still points to the verified ImageID. During a Force
	// rebuild, the tag moves before verification completes, and a failed
	// rebuild may have deleted the tag but left the old verified record.
	id, err := b.imageID(context.Background(), c.Tag)
	if err != nil || id != rec.ImageID {
		// Tag moved or is gone; the record is stale.
		return Record{}, false, nil
	}
	return rec, true, nil
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
	// AliasRepository, when set, also prunes the run images and aliases
	// made for a driver whose image references use it
	// (openshell.Driver.ImageRepository): the aliases in it and the run
	// images in RunRepository(AliasRepository). Unset, they are left alone
	// and reported in RunImagesLeft.
	AliasRepository string
	// Keep lists tags, or image IDs, that must survive in addition to the
	// current image of every identity: the images sandboxes run.
	Keep []string
	// DryRun reports without removing.
	DryRun bool
}

// PruneReport lists what Prune did.
type PruneReport struct {
	Removed []string
	Kept    []string
	// InUse are the kept images Keep names.
	InUse          []string
	ForgottenStale []string
	// RemovedRunImageIDs are the image IDs of the run images removed: the
	// vm driver keeps the disk it prepared from each (VMDisks), which
	// DefenseClaw does not remove.
	RemovedRunImageIDs []string
	// RunImagesLeft are the recorded run images and aliases a prune
	// without AliasRepository left alone.
	RunImagesLeft []string
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
// per (connector, uid, gid, ingress port, docker or MicroVM image), the most
// recent image and the most recent hook-verified one (what Store.Current
// selects for an unchanged spec), plus opts.Keep, and forgets store records whose image no longer
// exists. An image is removed only when this store recorded it under its own
// owner and the image carries that owner label; every other DefenseClaw
// image is reported, never removed, so data dirs sharing a Docker daemon (or
// a data dir that lost images.json) never delete images another one runs.
// Images in use by a container are refused by docker itself (no --force).
// With opts.AliasRepository it prunes that driver's run images and aliases
// by the same rules (pruneRunImages).
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
	keep, inUse := map[string]bool{}, map[string]bool{}
	for _, ref := range opts.Keep {
		keep[ref], inUse[ref] = true, true
	}
	type identity struct {
		connector         string
		uid, gid, ingress int
		microVM           bool
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
		id := identity{r.Connector, r.UID, r.GID, r.IngressPort, r.MicroVM}
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
		if keep[r.Tag] || keep[r.ImageID] {
			report.Kept = append(report.Kept, r.Tag)
			if inUse[r.Tag] || inUse[r.ImageID] {
				report.InUse = append(report.InUse, r.Tag)
			}
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
	// A store that never made a run image (a docker gateway's) has none to
	// prune, and docker is not asked about their repositories.
	runs, runErr := b.Store.RunImages()
	switch {
	case runErr != nil || len(runs) == 0:
	case opts.AliasRepository != "":
		gone := map[string]bool{}
		for _, tag := range append(append([]string(nil), report.Removed...), report.ForgottenStale...) {
			gone[tag] = true
		}
		kept := map[string]bool{}
		for _, r := range records {
			if !gone[r.Tag] {
				kept[r.ImageID] = true
			}
		}
		runErr = b.pruneRunImages(ctx, opts, owner, runs, kept, inUse, &report, &removeErrs)
	default:
		for _, r := range runs {
			report.RunImagesLeft = append(report.RunImagesLeft, r.Tag)
		}
	}
	sort.Strings(report.ForgottenStale)
	sort.Strings(report.Unrecorded)
	sort.Strings(report.Foreign)
	if !opts.DryRun {
		if err := b.Store.Remove(append(append([]string(nil), report.Removed...), report.ForgottenStale...)...); err != nil {
			return report, err
		}
	}
	return report, errors.Join(append(removeErrs, runErr)...)
}

// pruneRunImages is Prune for the run images and aliases (runs, as the
// store records them) of the driver whose image references use
// opts.AliasRepository. Only recorded, owned ones are removed, run images
// before aliases, and only when Keep names
// neither their tag nor their ID and their overlay image is not kept
// either (baseKept holds the IDs of the overlay images that stay
// recorded). A run image of a kept overlay image is what the next sandbox
// of its posture boots: a rebuilt one would get a new image ID, which the
// vm driver prepares a new disk for (about a minute and about 5 GB it never
// removes), while the run image itself only adds its files' few layers.
// An alias shares its overlay image's ID, so untagging it frees nothing
// while that image stays.
func (b *Builder) pruneRunImages(ctx context.Context, opts PruneOptions, owner string, runs []RunImage, baseKept, inUse map[string]bool,
	report *PruneReport, removeErrs *[]error) error {
	aliasRepo, runRepo := opts.AliasRepository, RunRepository(opts.AliasRepository)
	for _, repo := range []string{aliasRepo, runRepo} {
		if !repositoryRE.MatchString(repo) {
			return fmt.Errorf("openshell image: invalid repository %q", repo)
		}
	}
	unlock, err := b.Store.runImageLock()
	if err != nil {
		return err
	}
	defer unlock()
	present, owned := map[string]bool{}, map[string]bool{}
	for _, repo := range []string{aliasRepo, runRepo} {
		p, err := b.listTags(ctx, repo, "label="+LabelSandboxImage+"=1")
		if err != nil {
			return err
		}
		o, err := b.listTags(ctx, repo, "label="+LabelSandboxImage+"=1", "label="+LabelOwner+"="+owner)
		if err != nil {
			return err
		}
		maps.Copy(present, p)
		maps.Copy(owned, o)
	}
	recorded := map[string]bool{}
	var candidates []RunImage
	for _, r := range runs {
		repo := runRepo
		if r.Alias {
			repo = aliasRepo
		}
		if !strings.HasPrefix(r.Tag, repo+":") {
			continue
		}
		recorded[r.Tag] = true
		switch {
		case !present[r.Tag]:
			report.ForgottenStale = append(report.ForgottenStale, r.Tag)
		case r.Owner != owner || !owned[r.Tag]:
			report.Foreign = append(report.Foreign, r.Tag)
		default:
			candidates = append(candidates, r)
		}
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
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Alias != candidates[j].Alias {
			return !candidates[i].Alias
		}
		return candidates[i].Tag < candidates[j].Tag
	})
	for _, r := range candidates {
		switch {
		case inUse[r.Tag] || inUse[r.ImageID]:
			report.Kept = append(report.Kept, r.Tag)
			report.InUse = append(report.InUse, r.Tag)
			continue
		case baseKept[r.BaseImageID]:
			report.Kept = append(report.Kept, r.Tag)
			continue
		}
		if !opts.DryRun {
			if _, err := output(ctx, b.Docker, nil, "image", "rm", r.Tag); err != nil {
				*removeErrs = append(*removeErrs, fmt.Errorf("remove %s: %w", r.Tag, err))
				continue
			}
		}
		report.Removed = append(report.Removed, r.Tag)
		if !r.Alias {
			report.RemovedRunImageIDs = append(report.RemovedRunImageIDs, r.ImageID)
		}
	}
	return nil
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
