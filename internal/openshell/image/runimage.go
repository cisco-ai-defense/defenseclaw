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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

// Run images.
//
// A compute driver that mounts no host folders (OpenShell's MicroVM driver)
// cannot take a sandbox's per-run managed harness files
// (connector.SandboxRunConfig) as the read-only bind mounts a docker
// sandbox gets, so they are baked into a run image instead: the verified
// overlay image plus one layer per file, each file root-owned 0644 under
// /etc or /usr, which the workload's policy keeps read-only. The tag is a
// content hash of the files, so every sandbox of one posture boots the same
// run image: the MicroVM driver prepares a root disk from each image ID the
// first time it boots it (about a minute and about 5 GB, which it never
// removes), and a shared image pays that once. A harness without run files
// is sent an alias instead, the overlay image itself under the driver's
// repository, which shares its image ID and so its prepared disk. Run
// images and aliases are recorded in the Store with the overlay image they
// come from, and only recorded ones are ever pruned or removed.

// Labels of a run image, next to the ones it inherits from its overlay
// image (its content hash, connector and owner among them): a consumer
// that selects images by label rather than by repository must leave out
// LabelRunImage.
const (
	// LabelRunImage marks a run image with the schema of its layout.
	LabelRunImage = "io.defenseclaw.run-image"
	// LabelBaseImageID is the ID of the overlay image a run image adds its
	// files to.
	LabelBaseImageID = "io.defenseclaw.base-image-id"
	// LabelRunConfigDigest is the RunConfigDigest of the files baked in.
	LabelRunConfigDigest = "io.defenseclaw.run-config-digest"
)

// runImageSchema versions the run image's Dockerfile layout; bump it
// whenever the layout changes shape so older run images stop matching.
const runImageSchema = 1

// runRepositorySuffix names a driver's run image repository after its
// image repository.
const runRepositorySuffix = "-run"

var (
	imageIDRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hashRE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	tagNameRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
)

// RunImage is a run image, or an alias, as the Store records it.
type RunImage struct {
	// Tag is the name a sandbox template is sent.
	Tag     string `json:"tag"`
	ImageID string `json:"image_id"`
	// Digest is the RunConfigDigest of the files baked in; empty for an
	// alias.
	Digest string `json:"run_config_digest,omitempty"`
	// Alias marks the overlay image itself under the driver's repository,
	// for a harness without run files.
	Alias bool `json:"alias,omitempty"`
	// BaseTag and BaseImageID are the overlay image it comes from.
	BaseTag     string `json:"base_tag"`
	BaseImageID string `json:"base_image_id"`
	Connector   string `json:"connector"`
	UID         int    `json:"uid"`
	GID         int    `json:"gid"`
	// Owner is the Store.Owner of the data dir that made it.
	Owner   string    `json:"owner"`
	BuiltAt time.Time `json:"built_at"`
	// Files are the in-image paths of the files baked in.
	Files []string `json:"files,omitempty"`
}

// RunRepository is the repository of the run images of a driver whose image
// references use repo (openshell.Driver.ImageRepository; empty is
// DefaultRepository).
func RunRepository(repo string) string {
	if repo == "" {
		repo = DefaultRepository
	}
	return repo + runRepositorySuffix
}

// RunConfigDigest is the hex sha256 of a run's files: their paths, modes,
// owners and the sha256 of their contents, in path order. Equal digests
// mean equal files, so a run image is reused exactly when a sandbox would
// get the same files.
func RunConfigDigest(files []connector.SandboxFile) string {
	type entry struct {
		Path   string `json:"path"`
		Mode   string `json:"mode"`
		Owner  string `json:"owner"`
		SHA256 string `json:"sha256"`
	}
	entries := make([]entry, 0, len(files))
	for _, f := range files {
		sum := sha256.Sum256(f.Data)
		entries = append(entries, entry{Path: f.Path, Mode: fmt.Sprintf("%04o", uint32(f.Mode)), Owner: string(f.Owner), SHA256: hex.EncodeToString(sum[:])})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	raw, _ := json.Marshal(entries) // strings only: it cannot fail
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// runImagePlan is one run image to build: its name, its build context and
// what the result must look like.
type runImagePlan struct {
	base   Record
	owner  string
	digest string
	tag    string
	alias  string
	// dirs are the parent directories of the files that the overlay image
	// lacks.
	dirs   []string
	paths  []string
	files  []ContextFile
	labels map[string]string
	// layers is how many layers the build adds to the overlay image's: one
	// per file, and one for dirs when there are any.
	layers int
}

// RunImage returns the run image that bakes files into the verified
// overlay image base, in the run repository of repo
// (openshell.Driver.ImageRepository): the recorded one when docker still
// has it as recorded, else a new build, which is checked to add exactly
// its planned layers to base's before it is recorded. The build starts
// FROM the alias of base (AliasImage), tagged from base's image ID, so it
// runs on exactly the image that was verified. Every file must be
// root-owned, mode 0644 and under /etc or /usr.
func (b *Builder) RunImage(ctx context.Context, base Record, files []connector.SandboxFile, repo string) (RunImage, error) {
	plan, err := b.planRunImage(base, files, repo)
	if err != nil {
		return RunImage{}, err
	}
	unlock, err := b.Store.runImageLock()
	if err != nil {
		return RunImage{}, err
	}
	defer unlock()
	if ri, ok, err := b.recordedRunImage(ctx, plan); err != nil || ok {
		return ri, err
	}
	if _, err := b.alias(ctx, base, plan.alias, plan.owner); err != nil {
		return RunImage{}, err
	}
	baseFacts, err := inspectImage(ctx, b.Docker, base.ImageID)
	if err != nil {
		return RunImage{}, err
	}
	if baseFacts.ID != base.ImageID || len(baseFacts.Layers) == 0 {
		return RunImage{}, fmt.Errorf("openshell image: %s is not the image %s records", base.ImageID, base.Tag)
	}
	if err := buildImage(ctx, b.Docker, plan.files, plan.labels, plan.tag, b.Log); err != nil {
		return RunImage{}, fmt.Errorf("openshell image: docker build %s: %w", plan.tag, err)
	}
	facts, err := inspectImage(ctx, b.Docker, plan.tag)
	if err == nil {
		err = plan.check(facts, baseFacts)
	}
	if err != nil {
		_, _ = output(ctx, b.Docker, nil, "image", "rm", "-f", plan.tag)
		return RunImage{}, err
	}
	ri := RunImage{
		Tag: plan.tag, ImageID: facts.ID, Digest: plan.digest, BaseTag: base.Tag, BaseImageID: base.ImageID,
		Connector: base.Connector, UID: base.UID, GID: base.GID, Owner: plan.owner, BuiltAt: b.now().UTC(), Files: plan.paths,
	}
	if err := b.Store.putRunImage(ri); err != nil {
		return RunImage{}, err
	}
	return ri, nil
}

// RecordedRunImage returns, without building or tagging anything, the run
// image RunImage would return for files (or, for no files, the alias
// AliasImage would), when it is recorded and docker still has it; false
// otherwise.
func (b *Builder) RecordedRunImage(ctx context.Context, base Record, files []connector.SandboxFile, repo string) (RunImage, bool, error) {
	if len(files) == 0 {
		owner, err := b.checkRunBase(base, repo)
		if err != nil {
			return RunImage{}, false, err
		}
		tag, err := aliasTag(base, repo)
		if err != nil {
			return RunImage{}, false, err
		}
		return b.recordedAlias(ctx, base, tag, owner)
	}
	plan, err := b.planRunImage(base, files, repo)
	if err != nil {
		return RunImage{}, false, err
	}
	return b.recordedRunImage(ctx, plan)
}

// recordedRunImage returns plan's run image when the store recorded it
// from the same overlay image and files and docker holds it with the
// recorded ID and the labels a build gave it.
func (b *Builder) recordedRunImage(ctx context.Context, plan *runImagePlan) (RunImage, bool, error) {
	rec, ok, err := b.Store.runImage(plan.tag)
	if err != nil || !ok {
		return RunImage{}, false, err
	}
	if rec.Alias || rec.Owner != plan.owner || rec.BaseImageID != plan.base.ImageID || rec.Digest != plan.digest {
		return RunImage{}, false, nil
	}
	facts, err := inspectImage(ctx, b.Docker, plan.tag)
	if err != nil || facts.ID != rec.ImageID || !plan.labelled(facts) {
		return RunImage{}, false, nil
	}
	return rec, true, nil
}

// AliasImage returns the verified overlay image base under repo
// (openshell.Driver.ImageRepository): the name a sandbox without run files
// is sent on a driver with its own image repository. It tags base's image
// ID, so it is exactly the verified image, and records the alias.
func (b *Builder) AliasImage(ctx context.Context, base Record, repo string) (RunImage, error) {
	owner, err := b.checkRunBase(base, repo)
	if err != nil {
		return RunImage{}, err
	}
	tag, err := aliasTag(base, repo)
	if err != nil {
		return RunImage{}, err
	}
	unlock, err := b.Store.runImageLock()
	if err != nil {
		return RunImage{}, err
	}
	defer unlock()
	return b.alias(ctx, base, tag, owner)
}

// alias tags base's image ID as tag and records it, unless it is recorded
// and docker resolves it to that ID already. Callers hold the run image
// lock.
func (b *Builder) alias(ctx context.Context, base Record, tag, owner string) (RunImage, error) {
	if ri, ok, err := b.recordedAlias(ctx, base, tag, owner); err != nil || ok {
		return ri, err
	}
	if err := tagImage(ctx, b.Docker, base.ImageID, tag); err != nil {
		return RunImage{}, fmt.Errorf("openshell image: docker tag %s: %w", tag, err)
	}
	facts, err := inspectImage(ctx, b.Docker, tag)
	if err != nil {
		return RunImage{}, err
	}
	if facts.ID != base.ImageID {
		return RunImage{}, fmt.Errorf("openshell image: %s resolves to %s, not the verified %s", tag, facts.ID, base.ImageID)
	}
	ri := RunImage{
		Tag: tag, ImageID: base.ImageID, Alias: true, BaseTag: base.Tag, BaseImageID: base.ImageID,
		Connector: base.Connector, UID: base.UID, GID: base.GID, Owner: owner, BuiltAt: b.now().UTC(),
	}
	if err := b.Store.putRunImage(ri); err != nil {
		return RunImage{}, err
	}
	return ri, nil
}

// recordedAlias returns the alias tag of base when the store recorded it
// and docker resolves it to base's image ID.
func (b *Builder) recordedAlias(ctx context.Context, base Record, tag, owner string) (RunImage, bool, error) {
	rec, ok, err := b.Store.runImage(tag)
	if err != nil || !ok {
		return RunImage{}, false, err
	}
	if !rec.Alias || rec.Owner != owner || rec.BaseImageID != base.ImageID {
		return RunImage{}, false, nil
	}
	if facts, err := inspectImage(ctx, b.Docker, tag); err != nil || facts.ID != base.ImageID {
		return RunImage{}, false, nil
	}
	return rec, true, nil
}

// checkRunBase refuses to make a run image or alias of anything but a
// hook-verified overlay image this store recorded, and returns the store's
// owner. repo must be another repository than base's.
func (b *Builder) checkRunBase(base Record, repo string) (string, error) {
	owner, err := b.Store.Owner()
	if err != nil {
		return "", err
	}
	baseRepo, _, _ := strings.Cut(base.Tag, ":")
	switch {
	case !imageIDRE.MatchString(base.ImageID) || !hashRE.MatchString(base.ContentHash) || baseRepo == "" || base.UID <= 0 || base.GID <= 0:
		return "", fmt.Errorf("openshell image: %q is not a recorded overlay image", base.Tag)
	case base.Owner != owner:
		return "", fmt.Errorf("openshell image: %s belongs to image store owner %q, not this store's %q", base.Tag, base.Owner, owner)
	case !base.HookFireVerified:
		return "", fmt.Errorf("openshell image: the hooks of %s are not verified", base.Tag)
	case repo == "" || !repositoryRE.MatchString(repo) || len(repo) > 200 || repo == baseRepo || RunRepository(repo) == baseRepo:
		return "", fmt.Errorf("openshell image: invalid run image repository %q", repo)
	}
	return owner, nil
}

// aliasTag names base in repo, with base's own tag.
func aliasTag(base Record, repo string) (string, error) {
	_, name, _ := strings.Cut(base.Tag, ":")
	if !tagNameRE.MatchString(name) {
		return "", fmt.Errorf("openshell image: %q is not a recorded overlay image", base.Tag)
	}
	return repo + ":" + name, nil
}

// planRunImage checks files and renders the run image of base with them.
func (b *Builder) planRunImage(base Record, files []connector.SandboxFile, repo string) (*runImagePlan, error) {
	owner, err := b.checkRunBase(base, repo)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("openshell image: a run image needs run files; a harness without them is sent the alias")
	}
	has, err := baseDirs(base)
	if err != nil {
		return nil, err
	}
	sorted := append([]connector.SandboxFile(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	missing := map[string]bool{}
	plan := &runImagePlan{base: base, owner: owner, digest: RunConfigDigest(files)}
	for i, f := range sorted {
		if err := checkRunFile(f); err != nil {
			return nil, err
		}
		if i > 0 && f.Path == sorted[i-1].Path {
			return nil, fmt.Errorf("openshell image: duplicate run file %s", f.Path)
		}
		for dir := path.Dir(f.Path); !has[dir]; dir = path.Dir(dir) {
			missing[dir] = true
		}
		plan.paths = append(plan.paths, f.Path)
	}
	for dir := range missing {
		plan.dirs = append(plan.dirs, dir)
	}
	sort.Strings(plan.dirs)
	plan.alias, err = aliasTag(base, repo)
	if err != nil {
		return nil, err
	}
	plan.tag = fmt.Sprintf("%s:%s-%s-%s-u%d", RunRepository(repo), base.Connector, base.ContentHash[:12], plan.digest[:12], base.UID)
	plan.layers = len(sorted)
	if len(plan.dirs) > 0 {
		plan.layers++
	}
	dockerfile := renderRunDockerfile(base, plan.alias, plan.dirs, sorted)
	plan.files = append(plan.files, ContextFile{Name: "Dockerfile", Mode: 0o644, Data: dockerfile})
	for _, f := range sorted {
		plan.files = append(plan.files, ContextFile{Name: contextName(f.Path), Mode: 0o644, Data: f.Data})
	}
	plan.labels = map[string]string{
		LabelSandboxImage:    "1",
		LabelRunImage:        strconv.Itoa(runImageSchema),
		LabelBaseImageID:     base.ImageID,
		LabelRunConfigDigest: plan.digest,
		LabelOwner:           owner,
	}
	return plan, nil
}

// checkRunFile refuses a run file an image cannot keep from the workload:
// one not root-owned and read-only, or outside /etc and /usr, the trees
// the workload's policy keeps read-only (HOME and the work root are the
// workload's own).
func checkRunFile(f connector.SandboxFile) error {
	switch {
	case !safePathRE.MatchString(f.Path) || path.Clean(f.Path) != f.Path:
		return fmt.Errorf("openshell image: run file path %q is not a safe absolute path", f.Path)
	case !strings.HasPrefix(f.Path, "/etc/") && !strings.HasPrefix(f.Path, "/usr/"):
		return fmt.Errorf("openshell image: run file %s is outside /etc and /usr, where the workload could change it", f.Path)
	case f.Owner != connector.SandboxOwnerRoot || f.Mode != 0o644:
		return fmt.Errorf("openshell image: run file %s must be root-owned with mode 0644, not %s %04o", f.Path, f.Owner, uint32(f.Mode))
	}
	return nil
}

// baseDirs are the directories the overlay image base certainly holds, as
// root-owned 0755 or system directories: the ones every image has
// (systemDirs) and the ones its own root-owned files are in. They come from
// rendering base's build context again from its record, which must give
// base's content hash and tag, so they are the directories of exactly that
// image.
func baseDirs(base Record) (map[string]bool, error) {
	h, ok := harness.Get(base.Connector)
	if !ok {
		return nil, fmt.Errorf("openshell image: %s is for an unknown harness %q", base.Tag, base.Connector)
	}
	repo, _, _ := strings.Cut(base.Tag, ":")
	c, err := NewContext(BuildSpec{
		Harness: h, HarnessVersion: base.HarnessVersion, BaseImage: base.BaseImage, UID: base.UID, GID: base.GID,
		IngressPort: base.IngressPort, FailMode: base.FailMode, DefenseClawVersion: base.DefenseClawVersion,
		Repository: repo, Owner: base.Owner,
	})
	if err != nil || c.ContentHash != base.ContentHash || c.Tag != base.Tag {
		return nil, fmt.Errorf("openshell image: %s is not the image this DefenseClaw builds from its record; rebuild it (`defenseclaw sandbox image build %s --force`)",
			base.Tag, base.Connector)
	}
	dirs := map[string]bool{}
	for dir := range systemDirs {
		dirs[dir] = true
	}
	for _, dir := range c.Dirs {
		dirs[dir] = true
	}
	return dirs, nil
}

// renderRunDockerfile renders the run image's Dockerfile: FROM the alias
// of the overlay image, the parent directories it lacks made root 0755
// first (COPY --chmod would give the directories it creates the file's
// mode, which cannot be traversed), then one COPY per file.
func renderRunDockerfile(base Record, alias string, dirs []string, files []connector.SandboxFile) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# DefenseClaw OpenShell run image: %s with one sandbox posture's managed harness files.\n", base.Tag)
	b.WriteString("# Generated by DefenseClaw; the image tag is a content hash of the files. Do not edit.\n")
	fmt.Fprintf(&b, "FROM %s\n", alias)
	b.WriteString("USER root\n")
	if len(dirs) > 0 {
		fmt.Fprintf(&b, "RUN install -d -o root -g root -m 0755 %s\n", strings.Join(dirs, " "))
	}
	for _, f := range files {
		fmt.Fprintf(&b, "COPY --chown=0:0 --chmod=0644 %s %s\n", contextName(f.Path), f.Path)
	}
	b.WriteString("USER sandbox\n")
	return b.Bytes()
}

// labelled reports whether facts carry the labels plan's build gives, and
// the overlay image's own, which the run image inherits.
func (plan *runImagePlan) labelled(facts imageFacts) bool {
	for k, v := range plan.labels {
		if facts.Labels[k] != v {
			return false
		}
	}
	return facts.Labels[LabelContentHash] == plan.base.ContentHash
}

// check refuses a built image that is not plan's run image: other labels,
// or layers that are not the overlay image's plus exactly the planned
// ones.
func (plan *runImagePlan) check(facts, base imageFacts) error {
	switch {
	case !plan.labelled(facts):
		return fmt.Errorf("openshell image: %s does not carry the labels of its build", plan.tag)
	case len(facts.Layers) != len(base.Layers)+plan.layers || !slices.Equal(facts.Layers[:len(base.Layers)], base.Layers):
		return fmt.Errorf("openshell image: %s is not %s plus %d layers of run files (it has %d layers, the base %d)",
			plan.tag, plan.base.Tag, plan.layers, len(facts.Layers), len(base.Layers))
	}
	return nil
}

// VMDisk is a MicroVM root disk OpenShell's vm driver prepared from an
// image, in its image cache (openshell.Driver.ImageCache).
type VMDisk struct {
	Path string
	// UID and GID are the workload identity it was prepared for (the
	// gateway's sandbox_uid and sandbox_gid), -1 for the image's own
	// account.
	UID, GID int
	// Bytes is the space it takes on disk.
	Bytes int64
}

// VMDisks lists the root disks under cacheDir the vm driver prepared from
// imageID: the directories, not links, named
// openshell.PreparedDiskPrefix...-sha256-<the ID>. An unreadable cache
// holds none.
func VMDisks(cacheDir, imageID string) []VMDisk {
	id, ok := strings.CutPrefix(imageID, "sha256:")
	if !ok || !hashRE.MatchString(id) || cacheDir == "" {
		return nil
	}
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return nil
	}
	suffix := "-sha256-" + id
	var out []VMDisk
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || !strings.HasPrefix(name, openshell.PreparedDiskPrefix) || !strings.HasSuffix(name, suffix) {
			continue
		}
		d := VMDisk{Path: filepath.Join(cacheDir, name), UID: -1, GID: -1}
		rest := strings.TrimSuffix(name, suffix)
		if i := strings.LastIndex(rest, "-configured-"); i >= 0 {
			uid, gid, _ := strings.Cut(rest[i+len("-configured-"):], "-")
			u, uerr := strconv.Atoi(uid)
			g, gerr := strconv.Atoi(gid)
			if uerr == nil && gerr == nil {
				d.UID, d.GID = u, g
			}
		}
		d.Bytes = treeBytes(d.Path)
		out = append(out, d)
	}
	return out
}

// RemoveVMDisk removes a root disk VMDisks listed, which must still be a
// directory (not a link) named as the vm driver names its prepared disks.
// The driver prepares it again from its image when a sandbox boots one
// that has none. Nothing else of the driver's state is touched.
func RemoveVMDisk(d VMDisk) error {
	name := filepath.Base(d.Path)
	i := strings.LastIndex(name, "-sha256-")
	if i < 0 || !strings.HasPrefix(name, openshell.PreparedDiskPrefix) || !hashRE.MatchString(name[i+len("-sha256-"):]) {
		return fmt.Errorf("openshell image: %s is not a MicroVM disk the vm driver prepared", d.Path)
	}
	info, err := os.Lstat(d.Path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("openshell image: %s is not a directory", d.Path)
	}
	return os.RemoveAll(d.Path)
}

// treeBytes is the space the files under root take on disk (sparse root
// disks take far less than their size).
func treeBytes(root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += allocatedBytes(info)
		}
		return nil
	})
	return total
}
