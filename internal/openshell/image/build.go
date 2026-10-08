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
	"strconv"
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
	// TempDir is where the hook-fire probe writes the files it mounts into
	// a probe container (default os.TempDir()). On a Mac, Docker Desktop
	// shares /private, /tmp and /var/folders (the user's $TMPDIR) by
	// default, where a data dir such as /opt/cisco/defenseclaw/runtime is
	// not shared.
	TempDir string
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
// it is not verified yet, or, built for the MicroVM driver, not checked for
// it yet (Record.MicroVMUnchecked).
func (b *Builder) Build(ctx context.Context, spec BuildSpec, opts BuildOptions) (Record, error) {
	c, err := b.Context(spec)
	if err != nil {
		return Record{}, err
	}
	if rec, ok, err := b.cached(ctx, c, opts); err != nil {
		return Record{}, err
	} else if ok {
		if (rec.HookFireVerified && !rec.MicroVMUnchecked()) || opts.SkipHookFire {
			return rec, nil
		}
		return b.verifyBuilt(ctx, c, rec, opts)
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

// cached returns the record of c's image when Build(opts) builds nothing:
// not forced, recorded from exactly c's inputs, and Docker's tag still
// names the recorded image.
func (b *Builder) cached(ctx context.Context, c *Context, opts BuildOptions) (Record, bool, error) {
	if opts.Force {
		return Record{}, false, nil
	}
	rec, ok, err := b.Store.Get(c.Tag)
	if err != nil || !ok || !recordMatches(rec, c) {
		return Record{}, false, err
	}
	if id, err := b.imageID(ctx, c.Tag); err != nil || id != rec.ImageID {
		return Record{}, false, nil
	}
	return rec, true, nil
}

// Preflight returns the refusal Build(spec, opts) would return before
// docker build runs, without building: a build context that cannot be
// rendered (a harness version that is not an exact release, or has no
// reviewed hook contract for sandboxes) and, when Build would build, a
// docker without BuildKit. A caller that says a build starts, or opens a
// build log, does so past it.
func (b *Builder) Preflight(ctx context.Context, spec BuildSpec, opts BuildOptions) error {
	c, err := b.Context(spec)
	if err != nil {
		return err
	}
	if _, ok, err := b.cached(ctx, c, opts); err != nil || ok {
		return err
	}
	if err := checkBuildKit(ctx, b.Docker); err != nil {
		return fmt.Errorf("openshell image: docker build %s: %w", c.Tag, err)
	}
	return nil
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

// Gone returns the tags of recs that Docker no longer has as DefenseClaw
// sandbox images (removed with `docker rmi`, say), whose records still say
// built and hook-verified. Current does not select them, and Prune forgets
// them (PruneReport.ForgottenStale).
func (b *Builder) Gone(ctx context.Context, recs []Record) (map[string]bool, error) {
	byRepo := map[string][]string{}
	for _, r := range recs {
		if repo, _, ok := strings.Cut(r.Tag, ":"); ok && repositoryRE.MatchString(repo) {
			byRepo[repo] = append(byRepo[repo], r.Tag)
		}
	}
	gone := map[string]bool{}
	for repo, tags := range byRepo {
		present, err := b.listTags(ctx, repo, "label="+LabelSandboxImage+"=1")
		if err != nil {
			return nil, err
		}
		for _, tag := range tags {
			if !present[tag] {
				gone[tag] = true
			}
		}
	}
	return gone, nil
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
	// MicroVMGateway says the gateway sandboxes start on boots only the
	// images built for the MicroVM driver (MicroVMTarget of its compute
	// driver, known). Every overlay image built for the docker driver,
	// those recorded before MicroVM images existed included, is then
	// superseded, however new: it is removed unless Keep names it, and so
	// are the run images and aliases the vm driver made from it, whose
	// image IDs (and so the disks it prepared from them) RemovedImageIDs
	// names. Unset (a docker gateway, or one whose driver is not known),
	// the newest images of both kinds are kept.
	MicroVMGateway bool
	// DefenseClawVersion is the DefenseClaw build new sandboxes start with
	// (manager.ImageVersion). An image another build made is never current
	// again (Store.Current matches the build), so it is superseded unless
	// Keep names it: after an upgrade, prune called the earlier build's
	// images current and kept them, with their MicroVM disks (GAP-0320).
	// Empty, every build's newest image is kept.
	DefenseClawVersion string
}

// PruneReport lists what Prune did.
type PruneReport struct {
	Removed []string
	Kept    []string
	// InUse are the kept images Keep names.
	InUse          []string
	ForgottenStale []string
	// RemovedImageIDs are the image IDs of the images removed (on a dry
	// run, that would be), overlay images, run images and aliases alike,
	// that no image the prune keeps or leaves in place has and Keep does not
	// name: the vm driver keeps the disk it prepared from each (VMDisks). A
	// caller removes such a disk only once Docker no longer has its image
	// (GoneIDs).
	RemovedImageIDs []string
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
// selects for an unchanged spec; on a MicroVM gateway, opts.MicroVMGateway,
// only of the MicroVM images), plus opts.Keep, and forgets store records
// whose image no longer exists. An image is removed only when this store recorded it under its own
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
		if opts.MicroVMGateway && !r.MicroVM {
			// The gateway never boots it again: Store.Current selects
			// only a MicroVM image for its sandboxes.
			continue
		}
		if opts.DefenseClawVersion != "" && r.DefenseClawVersion != opts.DefenseClawVersion {
			continue
		}
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
	report.RemovedImageIDs = removedImageIDs(records, runs, opts.Keep, &report)
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
	}
	return nil
}

// removedImageIDs are PruneReport.RemovedImageIDs: the IDs of the removed
// tags, less those of every recorded image that stays (kept, another data
// dir's, or not pruned in this repository) and those Keep names.
func removedImageIDs(records []Record, runs []RunImage, keep []string, report *PruneReport) []string {
	removed := map[string]bool{}
	for _, t := range report.Removed {
		removed[t] = true
	}
	stale := map[string]bool{}
	for _, t := range report.ForgottenStale {
		stale[t] = true
	}
	held := map[string]bool{}
	for _, ref := range keep {
		held[ref] = true
	}
	ids := map[string]bool{}
	note := func(tag, id string) {
		switch {
		case removed[tag]:
			ids[id] = true
		case !stale[tag]:
			held[id] = true
		}
	}
	for _, r := range records {
		note(r.Tag, r.ImageID)
	}
	for _, r := range runs {
		note(r.Tag, r.ImageID)
	}
	var out []string
	for id := range ids {
		if imageIDRE.MatchString(id) && !held[id] {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// ImageSize is the size of the image ref (a tag or an image ID) in Docker,
// its layers uncompressed: about what the MicroVM driver's root disk
// prepared from it takes.
func (b *Builder) ImageSize(ctx context.Context, ref string) (uint64, error) {
	out, err := output(ctx, b.Docker, nil, "image", "inspect", "--format", "{{.Size}}", ref)
	if err != nil {
		return 0, fmt.Errorf("openshell image: inspect %s: %w", ref, err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(out), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("openshell image: inspect %s returned the size %q", ref, out)
	}
	return n, nil
}

// GoneIDs returns those of the image IDs ids that Docker holds no image of
// (`docker image ls --all`), untagged ones included.
func (b *Builder) GoneIDs(ctx context.Context, ids []string) (map[string]bool, error) {
	listed, err := output(ctx, b.Docker, nil, "image", "ls", "--all", "--no-trunc", "--quiet")
	if err != nil {
		return nil, fmt.Errorf("openshell image: list images: %w", err)
	}
	present := map[string]bool{}
	for _, line := range strings.Split(listed, "\n") {
		present[strings.TrimSpace(line)] = true
	}
	gone := map[string]bool{}
	for _, id := range ids {
		if imageIDRE.MatchString(id) && !present[id] {
			gone[id] = true
		}
	}
	return gone, nil
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
