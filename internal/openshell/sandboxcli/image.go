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

package sandboxcli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
)

// ImageService builds, lists and removes the overlay images.
type ImageService interface {
	// Build builds (and hook-verifies) spec's image unless a verified one
	// is current; log receives the docker build output.
	Build(ctx context.Context, spec *harness.Spec, force bool, log io.Writer) (image.Record, bool, error)
	// Current reports whether spec's image is built and hook-verified (the
	// daemon uses it without building).
	Current(spec *harness.Spec) (bool, error)
	List() ([]image.Record, error)
	// Prune removes superseded images (image.Builder.Prune).
	Prune(ctx context.Context, opts image.PruneOptions) (image.PruneReport, error)
	// Remove deletes every image this data dir built or named: its overlay
	// images and the run images and aliases made from them.
	Remove(ctx context.Context, dryRun bool) ([]string, error)
}

// builderImages is the real ImageService: it builds exactly the image the
// daemon would select (the same BuildSpec as the manager).
type builderImages struct {
	app *App
}

func (b *builderImages) store() *image.Store { return image.NewStore(b.app.dataDir()) }

func (b *builderImages) spec(h *harness.Spec) image.BuildSpec {
	a := b.app
	bs := image.BuildSpec{
		Harness: h, UID: os.Getuid(), GID: os.Getgid(), FailMode: connector.SandboxFailMode,
		DefenseClawVersion: manager.ImageVersion(),
	}
	if a.Cfg != nil {
		bs.HarnessVersion = a.Cfg.OpenShell.Image.HarnessVersions[h.Name]
		bs.BaseImage = a.Cfg.OpenShell.Image.Base
		bs.IngressPort = a.Cfg.OpenShellIngressPort()
	}
	return bs
}

func (b *builderImages) Build(ctx context.Context, h *harness.Spec, force bool, log io.Writer) (image.Record, bool, error) {
	builder := &image.Builder{Docker: image.CLI{}, Store: b.store(), Log: log}
	spec := b.spec(h)
	if !force {
		if rec, ok, err := builder.Current(spec); err != nil {
			return image.Record{}, false, err
		} else if ok && rec.HookFireVerified {
			return rec, false, nil
		}
	}
	rec, err := builder.Build(ctx, spec, image.BuildOptions{Force: force})
	if err != nil {
		return image.Record{}, true, err
	}
	if !rec.HookFireVerified {
		return rec, true, fmt.Errorf("the %s image %s was built but its hooks did not verify", h.DisplayName, rec.Tag)
	}
	return rec, true, nil
}

func (b *builderImages) Current(h *harness.Spec) (bool, error) {
	builder := &image.Builder{Docker: image.CLI{}, Store: b.store(), Log: io.Discard}
	rec, ok, err := builder.Current(b.spec(h))
	return ok && rec.HookFireVerified, err
}

func (b *builderImages) List() ([]image.Record, error) { return b.store().List() }

func (b *builderImages) Prune(ctx context.Context, opts image.PruneOptions) (image.PruneReport, error) {
	builder := &image.Builder{Docker: image.CLI{}, Store: b.store(), Log: io.Discard}
	return builder.Prune(ctx, opts)
}

func (b *builderImages) Remove(ctx context.Context, dryRun bool) ([]string, error) {
	store := b.store()
	if _, err := os.Stat(store.Path()); err != nil {
		// No image was ever recorded here; do not create the store.
		return nil, nil
	}
	recs, err := store.List()
	if err != nil {
		return nil, err
	}
	owner, err := store.Owner()
	if err != nil {
		return nil, err
	}
	runs, err := store.RunImages()
	if err != nil {
		return nil, err
	}
	var tags []string
	for _, r := range recs {
		if r.Owner == "" || r.Owner == owner {
			tags = append(tags, r.Tag)
		}
	}
	for _, r := range runs {
		if r.Owner == owner {
			tags = append(tags, r.Tag)
		}
	}
	// Sorted, the run images (defenseclaw.invalid/sandbox-run:) come before
	// the aliases, and both before the overlay images they come from.
	sort.Strings(tags)
	if dryRun || len(tags) == 0 {
		return tags, nil
	}
	var removed []string
	var firstErr error
	for _, tag := range tags {
		var stderr bytes.Buffer
		err := image.CLI{}.Run(ctx, nil, io.Discard, &stderr, "image", "rm", "--", tag)
		if err != nil && !strings.Contains(stderr.String()+err.Error(), "No such image") {
			if firstErr == nil {
				firstErr = fmt.Errorf("docker image rm %s: %w", tag, err)
			}
			continue
		}
		removed = append(removed, tag)
	}
	if len(removed) > 0 {
		if err := store.Remove(removed...); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return removed, firstErr
}

// storeImageIDs are the image IDs of the images Remove removes: this data
// dir's overlay images and the run images made from them (an alias has its
// overlay image's ID). A data dir without a store has none, and gets none
// created.
func (a *App) storeImageIDs() []string {
	store := image.NewStore(a.dataDir())
	if _, err := os.Stat(store.Path()); err != nil {
		return nil
	}
	owner, err := store.Owner()
	if err != nil {
		return nil
	}
	recs, _ := store.List()
	runs, _ := store.RunImages()
	var ids []string
	for _, r := range recs {
		if r.Owner == "" || r.Owner == owner {
			ids = append(ids, r.ImageID)
		}
	}
	for _, r := range runs {
		if r.Owner == owner && !r.Alias {
			ids = append(ids, r.ImageID)
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

// ImageBuildOptions are the `image build` flags.
type ImageBuildOptions struct {
	Harnesses []string
	Force     bool
	// Verbose streams docker's build output instead of logging it.
	Verbose bool
}

// ImageBuild builds the harnesses' overlay images (default: the
// configured openshell.harnesses, else every supported harness).
func (a *App) ImageBuild(ctx context.Context, o ImageBuildOptions) error {
	if err := a.CheckSupported(); err != nil {
		return err
	}
	specs, err := a.harnesses(o.Harnesses)
	if err != nil {
		return err
	}
	for _, spec := range specs {
		if err := a.buildImage(ctx, spec, o.Force, o.Verbose); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) buildImage(ctx context.Context, spec *harness.Spec, force, verbose bool) error {
	var log io.Writer = io.Discard
	logPath := ""
	if verbose {
		log = a.IO.Out
	} else {
		dir := filepath.Join(a.dataDir(), "logs")
		if err := os.MkdirAll(dir, 0o700); err == nil {
			logPath = filepath.Join(dir, "sandbox-image-"+spec.Name+".log")
			if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err == nil {
				defer f.Close()
				log = f
			}
		}
	}
	a.note("Building the " + spec.DisplayName + " image (the first build downloads about 3 GB)…")
	started := a.Now()
	rec, built, err := a.Images.Build(ctx, spec, force, log)
	if err != nil {
		// A build refused before docker build ran has nothing in its log.
		if logPath != "" && !errors.Is(err, image.ErrNoBuildKit) {
			// A failed docker build ends with the last lines docker
			// printed, one per line: the log path goes after them.
			sep := " "
			if strings.Contains(err.Error(), "\n") {
				sep = "\n"
			}
			return fmt.Errorf("%s image: %w%s(build log: %s)", spec.DisplayName, err, sep, logPath)
		}
		return fmt.Errorf("%s image: %w", spec.DisplayName, err)
	}
	how := "up to date"
	if built {
		how = "built in " + a.Now().Sub(started).Round(time.Second).String()
	}
	a.ok(fmt.Sprintf("%s %s: %s, hooks verified (%s)", spec.DisplayName, rec.HarnessVersion, rec.Tag, how))
	return nil
}

// defaultHarnesses are the harnesses setup selects, and image commands and
// doctor cover, when neither the command nor openshell.harnesses names any:
// Claude Code and Codex. Every other sandbox harness is opt-in by name
// (setup --harness, openshell.harnesses), and one whose verification is
// unverified builds an image that never passes the hook-fire probe.
var defaultHarnesses = []string{"claudecode", "codex"}

// harnesses resolves names, defaulting to openshell.harnesses and then to
// defaultHarnesses.
func (a *App) harnesses(names []string) ([]*harness.Spec, error) {
	if len(names) == 0 && a.Cfg != nil {
		names = a.Cfg.OpenShell.Harnesses
	}
	if len(names) == 0 {
		names = defaultHarnesses
	}
	var out []*harness.Spec
	seen := map[string]bool{}
	for _, n := range names {
		spec, err := ResolveHarness(n)
		if err != nil {
			return nil, err
		}
		if !seen[spec.Name] {
			seen[spec.Name] = true
			out = append(out, spec)
		}
	}
	return out, nil
}

// ImageList prints the recorded overlay images.
func (a *App) ImageList(format OutputFormat) error {
	a.defaults()
	recs, err := a.Images.List()
	if err != nil {
		return err
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].BuiltAt.After(recs[j].BuiltAt) })
	if format == OutputJSON {
		if recs == nil {
			recs = []image.Record{}
		}
		return writeJSON(a.IO.Out, map[string]any{"images": recs})
	}
	if len(recs) == 0 {
		a.note("no images yet; `" + CommandName + " image build` builds them")
		return nil
	}
	rows := make([][]string, 0, len(recs))
	for _, r := range recs {
		verified := "no"
		if r.HookFireVerified {
			verified = "yes"
		}
		rows = append(rows, []string{r.Tag, r.Connector, r.HarnessVersion, verified, fmt.Sprint(r.UID), r.BuiltAt.Local().Format("2006-01-02 15:04")})
	}
	a.table([]string{"TAG", "HARNESS", "VERSION", "HOOKS VERIFIED", "UID", "BUILT"}, rows)
	return nil
}

// ImagePrune removes superseded overlay images. The images the daemon's
// sandboxes run are kept. The MicroVM driver's run images and aliases,
// which no container holds, are pruned only with that list: without the
// daemon they are left alone.
func (a *App) ImagePrune(ctx context.Context, dryRun bool) error {
	a.defaults()
	opts := image.PruneOptions{DryRun: dryRun}
	vm, _ := openshell.LookupDriver(string(openshell.DriverVM))
	if api, err := a.api(); err == nil {
		if list, err := api.List(ctx); err == nil {
			for _, sb := range list {
				for _, ref := range []string{sb.Image, sb.ImageID, sb.RunImage, sb.RunImageID} {
					if ref != "" {
						opts.Keep = append(opts.Keep, ref)
					}
				}
			}
			opts.AliasRepository = vm.ImageRepository
		}
	}
	rep, err := a.Images.Prune(ctx, opts)
	if err != nil {
		return err
	}
	verb := "removed"
	if dryRun {
		verb = "would remove"
	}
	if len(rep.Removed) == 0 {
		a.ok("nothing to prune")
	}
	for _, t := range rep.Removed {
		a.ok(verb + " " + t)
	}
	for _, t := range rep.Kept {
		if slices.Contains(rep.InUse, t) {
			a.note("kept " + t + " (a sandbox runs it)")
		} else {
			a.note("kept " + t + " (current)")
		}
	}
	for _, t := range rep.Foreign {
		a.note("left " + t + " (another DefenseClaw data directory's)")
	}
	for _, t := range rep.Unrecorded {
		a.note("left " + t + " (not recorded here)")
	}
	if n := len(rep.RunImagesLeft); n > 0 {
		a.note(fmt.Sprintf("left %d MicroVM run image(s) and alias(es) (%s...) alone: the DefenseClaw daemon did not answer, so which sandboxes run them is not known",
			n, vm.ImageRepository))
	}
	if note := a.vmDiskNote(vm, rep.RemovedRunImageIDs); note != "" {
		a.note(note)
	}
	return nil
}

// vmDiskNote says how much of the MicroVM driver's image cache the disks it
// prepared from the images ids take, which OpenShell keeps after the images
// are gone and DefenseClaw never removes; "" when there are none. The cache
// is under the user's home, where the gateway runs as the user.
func (a *App) vmDiskNote(vm openshell.Driver, ids []string) string {
	home, err := a.Home()
	if err != nil || vm.ImageCache == "" {
		return ""
	}
	dir := filepath.Join(home, vm.ImageCache)
	var count int
	var size int64
	for _, id := range ids {
		for _, d := range image.VMDisks(dir, id) {
			count++
			size += d.Bytes
		}
	}
	if count == 0 {
		return ""
	}
	return fmt.Sprintf("OpenShell keeps the %d MicroVM disk(s) it prepared from these images (%s in %s); DefenseClaw does not remove them",
		count, humanBytes(size), a.tildePath(dir))
}
