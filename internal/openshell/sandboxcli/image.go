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
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// ImageService builds, lists and removes the overlay images.
type ImageService interface {
	// Build builds (and hook-verifies) spec's image unless a verified one
	// is current; log receives the docker build output. microVM builds the
	// image for the MicroVM driver (image.BuildSpec.MicroVM), the one a
	// gateway on that driver boots.
	Build(ctx context.Context, spec *harness.Spec, microVM, force bool, log io.Writer) (image.Record, bool, error)
	// Preflight returns the refusal Build would return before docker
	// build runs (image.Builder.Preflight): a pinned harness version that
	// is not an exact release or has no reviewed hook contract for
	// sandboxes, or, when it would build, a docker without BuildKit.
	Preflight(ctx context.Context, spec *harness.Spec, microVM, force bool) error
	// Current reports whether spec's image for the MicroVM driver
	// (microVM) or the docker driver is built and hook-verified (the daemon
	// uses it without building).
	Current(spec *harness.Spec, microVM bool) (bool, error)
	List() ([]image.Record, error)
	// Gone returns the tags of recs Docker no longer has (image.Builder.Gone).
	Gone(ctx context.Context, recs []image.Record) (map[string]bool, error)
	// GoneIDs returns the image IDs among ids Docker holds no image of
	// (image.Builder.GoneIDs).
	GoneIDs(ctx context.Context, ids []string) (map[string]bool, error)
	// Size is the size in Docker of spec's current image for the MicroVM
	// driver (microVM) or the docker driver, or of the image ref when spec
	// is nil; 0 when there is none.
	Size(ctx context.Context, spec *harness.Spec, microVM bool, ref string) (uint64, error)
	// Prune removes superseded images (image.Builder.Prune).
	Prune(ctx context.Context, opts image.PruneOptions) (image.PruneReport, error)
	// Remove deletes the images this data dir built or named: its overlay
	// images and the run images and aliases made from them, of the
	// harnesses named (by connector name), or of every harness when none
	// is. It forgets their records, also of those Docker no longer has.
	Remove(ctx context.Context, harnesses []string, dryRun bool) ([]string, error)
}

// builderImages is the real ImageService: it builds exactly the image the
// daemon would select (the same BuildSpec as the manager).
type builderImages struct {
	app *App
}

func (b *builderImages) store() *image.Store { return image.NewStore(b.app.dataDir()) }

func (b *builderImages) spec(h *harness.Spec, microVM bool) image.BuildSpec {
	a := b.app
	bs := image.BuildSpec{
		Harness: h, UID: os.Getuid(), GID: os.Getgid(), FailMode: connector.SandboxFailMode,
		DefenseClawVersion: manager.ImageVersion(), MicroVM: microVM,
	}
	if a.Cfg != nil {
		bs.HarnessVersion = a.Cfg.OpenShell.Image.HarnessVersions[h.Name]
		bs.BaseImage = a.Cfg.OpenShell.Image.Base
		bs.IngressPort = a.Cfg.OpenShellIngressPort()
	}
	return bs
}

func (b *builderImages) Build(ctx context.Context, h *harness.Spec, microVM, force bool, log io.Writer) (image.Record, bool, error) {
	builder := &image.Builder{Docker: image.CLI{}, Store: b.store(), Log: log}
	spec := b.spec(h, microVM)
	if !force {
		// An image for the MicroVM driver not checked for it yet is
		// probed again by the build (image.Record.MicroVMUnchecked).
		if rec, ok, err := builder.Current(spec); err != nil {
			return image.Record{}, false, err
		} else if ok && rec.HookFireVerified && !rec.MicroVMUnchecked() {
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

func (b *builderImages) Preflight(ctx context.Context, h *harness.Spec, microVM, force bool) error {
	builder := &image.Builder{Docker: image.CLI{}, Store: b.store(), Log: io.Discard}
	return builder.Preflight(ctx, b.spec(h, microVM), image.BuildOptions{Force: force})
}

func (b *builderImages) Current(h *harness.Spec, microVM bool) (bool, error) {
	builder := &image.Builder{Docker: image.CLI{}, Store: b.store(), Log: io.Discard}
	rec, ok, err := builder.Current(b.spec(h, microVM))
	// A MicroVM image whose MicroVM check settled nothing is checked
	// again before its next sandbox, so it is not current yet.
	return ok && rec.HookFireVerified && !rec.MicroVMUnchecked(), err
}

func (b *builderImages) List() ([]image.Record, error) { return b.store().List() }

func (b *builderImages) Gone(ctx context.Context, recs []image.Record) (map[string]bool, error) {
	builder := &image.Builder{Docker: image.CLI{}, Store: b.store(), Log: io.Discard}
	return builder.Gone(ctx, recs)
}

func (b *builderImages) Size(ctx context.Context, h *harness.Spec, microVM bool, ref string) (uint64, error) {
	builder := &image.Builder{Docker: image.CLI{}, Store: b.store(), Log: io.Discard}
	if h != nil {
		rec, ok, err := builder.Current(b.spec(h, microVM))
		if err != nil || !ok {
			return 0, err
		}
		ref = rec.ImageID
	}
	if ref == "" {
		return 0, nil
	}
	return builder.ImageSize(ctx, ref)
}

func (b *builderImages) GoneIDs(ctx context.Context, ids []string) (map[string]bool, error) {
	builder := &image.Builder{Docker: image.CLI{}, Store: b.store(), Log: io.Discard}
	return builder.GoneIDs(ctx, ids)
}

func (b *builderImages) Prune(ctx context.Context, opts image.PruneOptions) (image.PruneReport, error) {
	builder := &image.Builder{Docker: image.CLI{}, Store: b.store(), Log: io.Discard}
	return builder.Prune(ctx, opts)
}

func (b *builderImages) Remove(ctx context.Context, harnesses []string, dryRun bool) ([]string, error) {
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
		if (r.Owner == "" || r.Owner == owner) && harnessOf(harnesses, r.Connector) {
			tags = append(tags, r.Tag)
		}
	}
	for _, r := range runs {
		if r.Owner == owner && harnessOf(harnesses, r.Connector) {
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

// harnessOf reports whether an image of the harness connector is among
// the images of harnesses (every harness when none is named).
func harnessOf(harnesses []string, connector string) bool {
	return len(harnesses) == 0 || slices.Contains(harnesses, connector)
}

// storeImageIDs are the image IDs of the images Remove removes for
// harnesses (every harness when none is named): this data dir's overlay
// images and the run images and aliases made from them (an alias has its
// overlay image's ID, which Docker keeps while the alias is there, also
// once the overlay image's record is gone). A data dir without a store has
// none, and gets none created.
func (a *App) storeImageIDs(harnesses ...string) []string {
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
		if (r.Owner == "" || r.Owner == owner) && harnessOf(harnesses, r.Connector) {
			ids = append(ids, r.ImageID)
		}
	}
	for _, r := range runs {
		if r.Owner == owner && harnessOf(harnesses, r.Connector) {
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
// configured openshell.harnesses, else every supported harness), for the
// compute driver the gateway runs (gatewayDriverNow).
func (a *App) ImageBuild(ctx context.Context, o ImageBuildOptions) error {
	if err := a.CheckSupported(); err != nil {
		return err
	}
	specs, err := a.harnesses(o.Harnesses)
	if err != nil {
		return err
	}
	microVM := image.MicroVMTarget(a.gatewayDriverNow(ctx))
	for _, spec := range specs {
		if err := a.buildImage(ctx, spec, microVM, o.Force, o.Verbose); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) buildImage(ctx context.Context, spec *harness.Spec, microVM, force, verbose bool) error {
	// A build refused before docker build runs (a harness_versions pin
	// that is not an exact release or has no reviewed contract, a docker
	// without BuildKit) says only why: no build starts, and the last
	// build's log stays.
	if err := a.Images.Preflight(ctx, spec, microVM, force); err != nil {
		return fmt.Errorf("%s image: %w", spec.DisplayName, err)
	}
	var log io.Writer = io.Discard
	var file *lazyLog
	if verbose {
		log = a.IO.Out
	} else {
		file = &lazyLog{path: filepath.Join(a.dataDir(), "logs", "sandbox-image-"+spec.Name+".log")}
		defer file.Close()
		log = file
	}
	// A current image is only checked: its one line is the verdict below.
	if current, err := a.Images.Current(spec, microVM); force || err != nil || !current {
		a.note("Building the " + spec.DisplayName + " image (the first build downloads about 3 GB)…")
	}
	started := a.Now()
	rec, built, err := a.Images.Build(ctx, spec, microVM, force, log)
	if err != nil {
		// A build that failed before docker wrote anything has no log.
		if logPath := file.opened(); logPath != "" {
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
	if built {
		// A new image is a new image ID: on MicroVMs its first sandbox
		// prepares a disk from it.
		if warning, err := a.vmDiskShortage(ctx, a.gatewayDriverNow(ctx), nil, rec.ImageID, "the first start of a sandbox from it"); err != nil {
			a.warn(err.Error())
		} else if warning != "" {
			a.warn(warning)
		}
	}
	if !rec.MicroVM || rec.MicroVMVerified {
		return nil
	}
	recheck := "`" + CommandName + " image build " + spec.Name + " --force`"
	switch {
	case rec.MicroVMProblem != "":
		a.warn(spec.DisplayName + " cannot start in an OpenShell MicroVM, so a gateway on the vm driver (a Mac's) refuses to run it: " + rec.MicroVMProblem +
			"; " + recheck + " checks it again")
	case rec.MicroVMInconclusive != "":
		a.warn(spec.DisplayName + "'s image is not checked for an OpenShell MicroVM yet: " + rec.MicroVMInconclusive +
			"; the next `" + CommandName + " run " + spec.Name + "` on the vm driver checks it again, as does " + recheck)
	}
	return nil
}

// lazyLog is a build log that is created (or emptied) by its first write,
// so a build that writes nothing keeps the previous build's log. One that
// cannot be opened discards what it gets.
type lazyLog struct {
	path string
	mu   sync.Mutex
	f    *os.File
	err  error
}

func (l *lazyLog) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil && l.err == nil {
		if l.err = os.MkdirAll(filepath.Dir(l.path), 0o700); l.err == nil {
			l.f, l.err = os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		}
	}
	if l.err != nil {
		return len(p), nil
	}
	return l.f.Write(p)
}

// opened is the log's path once a write created it, else "".
func (l *lazyLog) opened() string {
	if l == nil {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return ""
	}
	return l.path
}

// Close closes the log if a write opened it.
func (l *lazyLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	return l.f.Close()
}

// vmDiskShortage judges the free space where the gateway's compute driver d
// would prepare a disk from spec's current image for d (or, with spec nil,
// the image ref) for what, when d prepares one (the MicroVM driver): an error
// below the floor, a warning below the recommended space
// (openshell.VMDiskShortage). Nothing on another driver, or when the space
// cannot be measured.
func (a *App) vmDiskShortage(ctx context.Context, d openshell.Driver, spec *harness.Spec, ref, what string) (string, error) {
	if d.ImageCache == "" {
		return "", nil
	}
	dir := a.vmImageCache()
	if dir == "" {
		return "", nil
	}
	free, err := openshell.FreeUnder(a.DiskFree, dir)
	if err != nil {
		return "", nil
	}
	// An image to build first: its size is not known yet.
	size, _ := a.Images.Size(ctx, spec, image.MicroVMTarget(d), ref)
	// The first starts under way take their room first (GAP-0219).
	free, inFlight := image.FreeAfterStaging(dir, free, size, a.Now())
	return openshell.VMDiskShortage(a.tildePath(dir), free, size, what+image.UnderWay(inFlight))
}

// gatewayDriverNow is the compute driver of the gateway sandboxes start
// on: the one the daemon reports, else the one the gateway's configuration
// selects (OPENSHELL_COMPUTE_DRIVER or compute_driver; docker when it
// names none, or cannot be read). The harness images are built for it: a
// MicroVM gateway boots only an image built for it, which answers
// localhost itself; a docker gateway's images stay as they were.
func (a *App) gatewayDriverNow(ctx context.Context) openshell.Driver {
	if d, ok := a.gatewayDriverKnown(ctx); ok {
		return d
	}
	d, _ := openshell.LookupDriver(string(openshell.DriverDocker))
	return d
}

// gatewayDriverKnown is the compute driver gatewayDriverNow finds when the
// daemon or the gateway's configuration says which (a configuration that
// names none selects docker), and false when neither does.
func (a *App) gatewayDriverKnown(ctx context.Context) (openshell.Driver, bool) {
	if api, err := a.api(); err == nil {
		if st, err := api.Status(ctx); err == nil && st.Gateway != nil && st.Gateway.Driver != "" {
			// A driver DefenseClaw does not drive (podman, say) is not
			// known: nothing says which images it boots.
			d, ok := openshell.LookupDriver(st.Gateway.Driver)
			return d, ok
		}
	}
	if st, err := a.Gateway.State(); err == nil && st != nil {
		if d, ok := st.Driver(); ok {
			return d, true
		}
	}
	return openshell.Driver{}, false
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

// listedImage is a recorded overlay image as `image list --json` shows it:
// Missing marks one Docker no longer has (removed with `docker rmi`), whose
// record still says built and verified.
type listedImage struct {
	image.Record
	Missing bool `json:"missing,omitempty"`
}

// ImageList prints the recorded overlay images Docker still has, and names
// the recorded ones it no longer has: the next run of their harness builds
// them again, and `image prune` forgets their records. Each row says which
// compute driver the image is for, and a note names those the gateway, when
// its driver is known, does not boot.
func (a *App) ImageList(ctx context.Context, format OutputFormat) error {
	a.defaults()
	recs, err := a.Images.List()
	if err != nil {
		return err
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].BuiltAt.After(recs[j].BuiltAt) })
	var gone map[string]bool
	var goneErr error
	if len(recs) > 0 {
		gone, goneErr = a.Images.Gone(ctx, recs)
	}
	if format == OutputJSON {
		listed := make([]listedImage, 0, len(recs))
		for _, r := range recs {
			listed = append(listed, listedImage{Record: r, Missing: gone[r.Tag]})
		}
		return writeJSON(a.IO.Out, map[string]any{"images": listed})
	}
	if len(recs) == 0 {
		a.note("no images yet; `" + CommandName + " image build` builds them")
		return nil
	}
	// The gateway boots only the images built for its compute driver: a
	// MicroVM one only the MicroVM images, a docker one only the others.
	driver, driverKnown := a.gatewayDriverKnown(ctx)
	microVMGateway := image.MicroVMTarget(driver)
	rows := make([][]string, 0, len(recs))
	var missing, superseded, builds []string
	unused := 0
	for _, r := range recs {
		if gone[r.Tag] {
			missing = append(missing, fmt.Sprintf("%s (%s %s)", r.Tag, r.Connector, r.HarnessVersion))
			continue
		}
		if r.DefenseClawVersion != manager.ImageVersion() {
			superseded = append(superseded, r.Tag)
			if b := firstNonEmpty(r.DefenseClawVersion, "an earlier build"); !slices.Contains(builds, b) {
				builds = append(builds, b)
			}
		}
		verified := "no"
		if r.HookFireVerified {
			verified = "yes"
		}
		target := "docker"
		if r.MicroVM {
			target = "MicroVM"
		}
		if driverKnown && r.MicroVM != microVMGateway {
			unused++
		}
		rows = append(rows, []string{r.Tag, r.Connector, r.HarnessVersion, target, verified, fmt.Sprint(r.UID), r.BuiltAt.Local().Format("2006-01-02 15:04")})
	}
	if len(rows) > 0 {
		a.table([]string{"TAG", "HARNESS", "VERSION", "FOR", "HOOKS VERIFIED", "UID", "BUILT"}, rows)
	}
	switch {
	case unused == 0:
	case microVMGateway:
		a.note(fmt.Sprintf("this gateway runs sandboxes in MicroVMs (the vm driver) and boots only the MicroVM images: it does not use the %s for the docker driver, "+
			"which `%s image prune` removes unless a sandbox runs one", plural(int64(unused), "image", "images"), CommandName))
	default:
		a.note(fmt.Sprintf("this gateway runs sandboxes on the docker driver and boots only the docker images: it does not use the %s for MicroVMs",
			plural(int64(unused), "image", "images")))
	}
	if len(superseded) > 0 {
		// An upgrade's images are built on the next run (GAP-0320). The
		// note names the build that made them: "another build than this one
		// (1.0.31)" read as if 1.0.31 had (GAP-0358).
		sort.Strings(builds)
		a.note(fmt.Sprintf("not used by this DefenseClaw build (%s): %s, built by DefenseClaw %s, so no new sandbox uses %s; the next run of each harness builds "+
			"its image for this build, and `%s image prune` removes them unless a sandbox runs one",
			manager.ImageVersion(), strings.Join(superseded, ", "), strings.Join(builds, ", "), itThem(superseded), CommandName))
	}
	if len(missing) > 0 {
		a.note(fmt.Sprintf("recorded but no longer in Docker: %s; the next run of the harness builds its image again, and `%s image prune` forgets the record",
			strings.Join(missing, ", "), CommandName))
	}
	if goneErr != nil {
		a.note("could not ask Docker which of these images it still has: " + goneErr.Error())
	}
	return nil
}

// ImagePrune removes superseded overlay images. The images the daemon's
// sandboxes run are kept. The MicroVM driver's run images and aliases,
// which no container holds, are pruned only with that list: without the
// daemon they are left alone. So are the disks the MicroVM driver prepared
// from the images it removed: with the list, the disk of each image ID it
// removed, that no sandbox is recorded with and that Docker no longer
// has, is removed too, and nothing else of OpenShell's image cache. With
// the list, on a gateway known to boot only MicroVM images, the images
// built for the docker driver (those recorded before MicroVM images
// existed included) are superseded too (image.PruneOptions.MicroVMGateway).
// The disks another OpenShell release than the gateway's prepared, which it
// never boots (those of the release before an in-place upgrade), are
// removed whatever the list says (staleVMDisks).
func (a *App) ImagePrune(ctx context.Context, dryRun bool) error {
	a.defaults()
	// Another DefenseClaw build's images are not current (GAP-0320).
	opts := image.PruneOptions{DryRun: dryRun, DefenseClawVersion: manager.ImageVersion()}
	vm, _ := openshell.LookupDriver(string(openshell.DriverVM))
	listed := false
	if api, err := a.api(); err == nil {
		if list, err := api.List(ctx); err == nil {
			listed = true
			for _, sb := range list {
				for _, ref := range []string{sb.Image, sb.ImageID, sb.RunImage, sb.RunImageID} {
					if ref != "" {
						opts.Keep = append(opts.Keep, ref)
					}
				}
			}
			opts.AliasRepository = vm.ImageRepository
			if d, ok := a.gatewayDriverKnown(ctx); ok {
				opts.MicroVMGateway = image.MicroVMTarget(d)
			}
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
	stale, release := a.staleVMDisks(ctx)
	staging := a.abandonedVMStaging()
	if len(rep.Removed) == 0 && len(rep.ForgottenStale) == 0 && len(stale.disks) == 0 && len(staging.disks) == 0 {
		a.ok("nothing to prune")
	}
	for _, t := range rep.Removed {
		a.ok(verb + " " + t)
	}
	forget := "forgot"
	if dryRun {
		forget = "would forget"
	}
	for _, t := range rep.ForgottenStale {
		a.ok(forget + " the record of " + t + " (no longer in Docker)")
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
	// The disks the MicroVM driver prepared from the images removed, which
	// no sandbox the daemon listed boots.
	if set := a.vmDisksOf(rep.RemovedImageIDs, refSet(opts.Keep)); len(set.disks) > 0 {
		if listed {
			a.removeVMDisks(ctx, set, dryRun, "these images")
		} else {
			a.note(fmt.Sprintf("left the %s OpenShell prepared from these images (%s in %s): the DefenseClaw daemon did not answer, so which sandboxes boot them is not known",
				plural(int64(len(set.disks)), "MicroVM disk", "MicroVM disks"), humanBytes(set.size), a.tildePath(set.dir)))
		}
	}
	if len(stale.disks) > 0 {
		a.removeStaleVMDisks(stale, release, dryRun)
	}
	if len(staging.disks) > 0 {
		a.removeVMStaging(staging, dryRun)
	}
	return nil
}

// abandonedVMStaging lists the half-prepared MicroVM disks in the driver's
// image cache that nothing has written to for image.VMStagingIdle: what a
// first start that failed or was cancelled left (GAP-0218).
func (a *App) abandonedVMStaging() vmDiskSet {
	set := vmDiskSet{dir: a.vmImageCache()}
	for _, d := range image.VMStaging(set.dir) {
		if a.Now().Sub(d.Changed) >= image.VMStagingIdle {
			set.disks = append(set.disks, d)
			set.size += d.Bytes
		}
	}
	return set
}

// removeVMStaging removes the half-prepared disks abandonedVMStaging
// listed and says what it freed; with dryRun, what it would remove.
func (a *App) removeVMStaging(set vmDiskSet, dryRun bool) {
	what := func(n int, size int64) string {
		return fmt.Sprintf("%s that failed or cancelled first starts left in %s (%s)", plural(int64(n), "half-prepared MicroVM disk", "half-prepared MicroVM disks"),
			a.tildePath(set.dir), humanBytes(size))
	}
	if dryRun {
		a.ok("would remove the " + what(len(set.disks), set.size))
		return
	}
	var removed int
	var freed int64
	for _, d := range set.disks {
		if err := image.RemoveVMStaging(d); err != nil {
			a.warn("could not remove " + a.tildePath(d.Path) + ": " + err.Error())
			continue
		}
		removed++
		freed += d.Bytes
	}
	if removed > 0 {
		a.ok("removed the " + what(removed, freed))
	}
}

// staleVMDisks lists the disks in the MicroVM driver's image cache that
// another OpenShell release than the gateway's prepared (image.StaleVMDisks),
// with the gateway's release: the driver prepares its own disk from each
// image and never boots them, so after an in-place upgrade those of the
// release before stay behind. None when the gateway does not answer with a
// release.
func (a *App) staleVMDisks(ctx context.Context) (vmDiskSet, string) {
	set := vmDiskSet{dir: a.vmImageCache()}
	if info, err := os.Stat(set.dir); err != nil || !info.IsDir() {
		// No MicroVM ever ran here: nothing to ask the gateway about.
		return set, ""
	}
	c, _, err := a.OpenShell(ctx)
	if err != nil {
		return set, ""
	}
	defer c.Close()
	h, err := c.Health(ctx)
	if err != nil || !h.Healthy || h.Version == (openshell.Version{}) {
		return set, ""
	}
	release := h.Version.String()
	set.disks = image.StaleVMDisks(set.dir, release)
	for _, d := range set.disks {
		set.size += d.Bytes
	}
	return set, release
}

// removeStaleVMDisks removes the disks staleVMDisks listed, which no
// sandbox on the gateway of release boots; with dryRun it says what it
// would remove.
func (a *App) removeStaleVMDisks(set vmDiskSet, release string, dryRun bool) {
	var releases []string
	for _, d := range set.disks {
		releases = append(releases, d.OpenShell)
	}
	slices.Sort(releases)
	what := fmt.Sprintf("OpenShell %s prepared in %s, which the OpenShell %s gateway does not boot", strings.Join(slices.Compact(releases), ", "),
		a.tildePath(set.dir), release)
	if dryRun {
		a.ok(fmt.Sprintf("would remove the %s %s (%s)", plural(int64(len(set.disks)), "MicroVM disk", "MicroVM disks"), what, humanBytes(set.size)))
		return
	}
	var removed int
	var freed int64
	for _, d := range set.disks {
		if err := image.RemoveVMDisk(d); err != nil {
			a.warn("could not remove the MicroVM disk " + a.tildePath(d.Path) + ": " + err.Error())
			continue
		}
		removed++
		freed += d.Bytes
	}
	if removed > 0 {
		a.ok(fmt.Sprintf("removed the %s %s, freeing %s", plural(int64(removed), "MicroVM disk", "MicroVM disks"), what, humanBytes(freed)))
	}
}

// ImageRemoveOptions are the `image rm` flags.
type ImageRemoveOptions struct {
	Harnesses []string
	// DryRun says what would be removed, and removes nothing.
	DryRun bool
	// Yes removes without asking.
	Yes bool
}

// harnessImages are the images of one harness that `image rm` removes.
type harnessImages struct {
	spec *harness.Spec
	// tags are the recorded images (Remove), gone those of them Docker no
	// longer has, and ids their image IDs (storeImageIDs).
	tags []string
	gone map[string]bool
	ids  []string
	// disks are the MicroVM disks OpenShell prepared from them.
	disks vmDiskSet
}

// imageRemovePlan is what `image rm` removes.
type imageRemovePlan struct {
	harnesses []harnessImages
}

// bootingSandbox is a sandbox of this data dir with the images it boots,
// by tag and ID: its overlay image and, on the MicroVM driver, its run
// image or alias.
type bootingSandbox struct {
	name string
	refs []string
}

// bootingSandboxes are the sandboxes of this data dir that can boot an
// image: the ones the daemon lists and the ones it recorded (it need not
// be running), less the deleted ones whose record keeps only their
// snapshot. The error says why the daemon did not list its sandboxes.
func (a *App) bootingSandboxes(ctx context.Context) ([]bootingSandbox, error) {
	var out []bootingSandbox
	at := map[string]int{}
	add := func(name string, refs ...string) {
		i, ok := at[name]
		if !ok {
			i = len(out)
			at[name] = i
			out = append(out, bootingSandbox{name: name})
		}
		for _, ref := range refs {
			if ref != "" && !slices.Contains(out[i].refs, ref) {
				out[i].refs = append(out[i].refs, ref)
			}
		}
	}
	api, listErr := a.api()
	if listErr == nil {
		var list []sandboxapi.Sandbox
		if list, listErr = api.List(ctx); listErr == nil {
			for _, sb := range list {
				if sb.Phase != "deleted" {
					add(sb.Name, sb.Image, sb.RunImage, sb.ImageID, sb.RunImageID)
				}
			}
		}
	}
	for _, r := range manager.RecordedSandboxes(a.dataDir()) {
		if !r.Retained {
			add(r.Name, r.Images...)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, apiError(listErr)
}

// planImageRemove finds the images of specs that `image rm` removes, and
// refuses while sandboxes use one of them (naming them), and while the
// daemon does not list its sandboxes and MicroVM disks were prepared from
// them.
func (a *App) planImageRemove(ctx context.Context, specs []*harness.Spec) (imageRemovePlan, error) {
	sandboxes, listErr := a.bootingSandboxes(ctx)
	booted := map[string]bool{}
	for _, sb := range sandboxes {
		for _, ref := range sb.refs {
			booted[ref] = true
		}
	}
	var plan imageRemovePlan
	ours := map[string]bool{}
	for _, spec := range specs {
		tags, err := a.Images.Remove(ctx, []string{spec.Name}, true)
		if err != nil {
			return plan, err
		}
		if len(tags) == 0 {
			continue
		}
		h := harnessImages{spec: spec, tags: tags, ids: a.storeImageIDs(spec.Name)}
		recs := make([]image.Record, 0, len(tags))
		for _, t := range tags {
			ours[t] = true
			recs = append(recs, image.Record{Tag: t})
		}
		for _, id := range h.ids {
			ours[id] = true
		}
		// Which are gone only words the plan: Remove forgets their records
		// either way.
		h.gone, _ = a.Images.Gone(ctx, recs)
		h.disks = a.vmDisksOf(h.ids, booted)
		plan.harnesses = append(plan.harnesses, h)
	}
	var busy, names []string
	for _, sb := range sandboxes {
		used := ""
		for _, ref := range sb.refs {
			// A tag says more than an image ID.
			if ours[ref] && (used == "" || strings.HasPrefix(used, "sha256:") && !strings.HasPrefix(ref, "sha256:")) {
				used = ref
			}
		}
		if used != "" {
			busy = append(busy, "sandbox "+sb.name+" uses "+used)
			names = append(names, sb.name)
		}
	}
	if len(names) > 0 {
		them, list := "it", strings.Join(names, " ")
		if len(names) > 1 {
			them = "them"
		}
		return plan, fmt.Errorf("%s: delete %s first (`%s delete %s`); nothing was removed", strings.Join(busy, "; "), them, CommandName, list)
	}
	if listErr != nil {
		// Once the records are forgotten, no prune or teardown finds the
		// IDs of these disks again.
		var n int
		var size int64
		dir := ""
		for _, h := range plan.harnesses {
			n, size, dir = n+len(h.disks.disks), size+h.disks.size, h.disks.dir
		}
		if n > 0 {
			return plan, fmt.Errorf("the DefenseClaw daemon did not list its sandboxes, so which of them boot the %s OpenShell prepared from these images (%s in %s) is not known, "+
				"and nothing was removed: %w", plural(int64(n), "MicroVM disk", "MicroVM disks"), humanBytes(size), a.tildePath(dir), listErr)
		}
	}
	return plan, nil
}

// ImageRemove removes the images this data dir recorded for the named
// harnesses, from Docker and from the records: their overlay images, and
// the MicroVM run images and aliases made from them. On the MicroVM driver
// it also removes the disks OpenShell prepared from them (about 5 GB each),
// by removeVMDisks's rules: only while the daemon lists its sandboxes, and
// only the disks of image IDs Docker no longer has. It refuses, removing
// nothing, while a sandbox is recorded with one of the images: that
// sandbox is deleted first. The next run of such a harness builds its image
// again.
func (a *App) ImageRemove(ctx context.Context, o ImageRemoveOptions) error {
	a.defaults()
	if len(o.Harnesses) == 0 {
		return fmt.Errorf("name the harnesses whose images to remove, for example `%s image rm claudecode`", CommandName)
	}
	specs, err := a.harnesses(o.Harnesses)
	if err != nil {
		return err
	}
	plan, err := a.planImageRemove(ctx, specs)
	if err != nil {
		return err
	}
	for _, spec := range specs {
		if !slices.ContainsFunc(plan.harnesses, func(h harnessImages) bool { return h.spec == spec }) {
			a.note("no " + spec.DisplayName + " image is recorded here")
		}
	}
	if len(plan.harnesses) == 0 {
		a.ok("nothing to remove")
		return nil
	}
	for _, h := range plan.harnesses {
		a.println(a.bold(h.spec.DisplayName + " images"))
		for _, t := range h.tags {
			if h.gone[t] {
				t += " (no longer in Docker: its record is forgotten)"
			}
			a.line(t)
		}
		if n := len(h.disks.disks); n > 0 {
			a.line(fmt.Sprintf("and the %s OpenShell prepared from them (%s in %s)",
				plural(int64(n), "MicroVM disk", "MicroVM disks"), humanBytes(h.disks.size), a.tildePath(h.disks.dir)))
		}
	}
	if o.DryRun {
		a.println()
		a.note("dry run: nothing was changed")
		return nil
	}
	yes, err := a.confirm("Remove them? The next run of the harness builds its image again.", o.Yes)
	if err != nil {
		return err
	}
	if !yes {
		a.note("nothing changed")
		return nil
	}
	// A sandbox started while the question waited boots them too.
	if plan, err = a.planImageRemove(ctx, specs); err != nil {
		return err
	}
	var errs []error
	for _, h := range plan.harnesses {
		removed, err := a.Images.Remove(ctx, []string{h.spec.Name}, false)
		for _, t := range removed {
			if h.gone[t] {
				a.ok("forgot the record of " + t + " (no longer in Docker)")
			} else {
				a.ok("removed image " + t)
			}
		}
		if err != nil {
			a.bad("remove the " + h.spec.DisplayName + " images: " + err.Error())
			errs = append(errs, fmt.Errorf("remove the %s images: %w", h.spec.DisplayName, err))
		}
		if len(h.disks.disks) > 0 {
			a.removeVMDisks(ctx, h.disks, false, "the "+h.spec.DisplayName+" images")
		}
	}
	if len(errs) > 0 {
		return &Silent{Err: errors.Join(errs...)}
	}
	return nil
}

func refSet(refs []string) map[string]bool {
	out := map[string]bool{}
	for _, r := range refs {
		out[r] = true
	}
	return out
}

// vmDiskSet is what the MicroVM driver keeps of some images: the root
// disks it prepared from them in its image cache, which OpenShell keeps
// after the images and sandboxes are gone.
type vmDiskSet struct {
	dir   string
	disks []image.VMDisk
	// ids are the image IDs each disk was prepared from, in disks' order.
	ids  []string
	size int64
}

// vmImageCache is the MicroVM driver's image cache: images under the
// state_dir the gateway's configuration sets, else under
// ~/.local/state/openshell/vm-driver of this user, whom the gateway runs
// as. "" when neither is known.
func (a *App) vmImageCache() string {
	stateDir := ""
	if st, err := a.Gateway.State(); err == nil && st != nil {
		stateDir = st.VM.StateDir
	}
	home, err := a.Home()
	if err != nil {
		home = ""
	}
	return openshell.VMImageCache(stateDir, home)
}

// vmDisksOf lists the disks the MicroVM driver prepared from the images
// ids, leaving out those of an image refs names (the images sandboxes are
// recorded with, by tag and ID).
func (a *App) vmDisksOf(ids []string, refs map[string]bool) vmDiskSet {
	set := vmDiskSet{dir: a.vmImageCache()}
	if set.dir == "" {
		return set
	}
	for _, id := range ids {
		if refs[id] {
			continue
		}
		for _, d := range image.VMDisks(set.dir, id) {
			set.disks, set.ids = append(set.disks, d), append(set.ids, id)
			set.size += d.Bytes
		}
	}
	return set
}

// removeVMDisks removes the disks of set whose image Docker no longer has
// (a disk of an image that is still there stays: a sandbox could boot it
// again), and says what it freed; with dryRun it says what it would
// remove. what names the images the disks come from. The driver prepares a
// disk again from an image it boots without one. Nothing else of
// OpenShell's state is removed.
func (a *App) removeVMDisks(ctx context.Context, set vmDiskSet, dryRun bool, what string) {
	count := func(n int, size int64) string {
		return fmt.Sprintf("%s OpenShell prepared from %s in %s (%s)", plural(int64(n), "MicroVM disk", "MicroVM disks"), what, a.tildePath(set.dir), humanBytes(size))
	}
	if dryRun {
		a.ok("would remove the " + count(len(set.disks), set.size))
		return
	}
	gone, err := a.Images.GoneIDs(ctx, slices.Compact(slices.Sorted(slices.Values(set.ids))))
	if err != nil {
		a.warn("kept the " + count(len(set.disks), set.size) + ": could not ask Docker whether their images are gone: " + err.Error())
		return
	}
	var removed, kept int
	var freed, keptSize int64
	for i, d := range set.disks {
		if !gone[set.ids[i]] {
			kept++
			keptSize += d.Bytes
			continue
		}
		if err := image.RemoveVMDisk(d); err != nil {
			a.warn("could not remove the MicroVM disk " + a.tildePath(d.Path) + ": " + err.Error())
			continue
		}
		removed++
		freed += d.Bytes
	}
	if removed > 0 {
		a.ok(fmt.Sprintf("removed the %s OpenShell prepared from %s in %s, freeing %s",
			plural(int64(removed), "MicroVM disk", "MicroVM disks"), what, a.tildePath(set.dir), humanBytes(freed)))
	}
	if kept > 0 {
		a.note("kept the " + count(kept, keptSize) + ": Docker still has the images they were prepared from")
	}
}
