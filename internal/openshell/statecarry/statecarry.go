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

// Package statecarry keeps the sandbox setup of a per-user install when the
// installer swaps installs while sandboxes run (rel-1-0-2:GAP-0483).
//
// OpenShell sandboxes outlive a DefenseClaw install: their containers keep
// running while `defenseclaw rollback` puts back the data directory of the
// install the last upgrade replaced. That data directory is from before the
// upgrade, so it has none of what DefenseClaw set up for the sandboxes
// since: openshell.enabled was off, the gateway opened no sandbox ingress
// and the hook bindings were gone, so every hook of a running sandbox failed
// closed ("gateway unreachable") and `sandbox list` refused, under the
// restored install and under the next upgrade, which starts from the data
// the rollback restored.
//
// Carry copies that setup from the install the installer leaves into the
// one it makes live: the openshell: section of config.yaml and the sandbox
// state directories (StateDirs). The install left keeps its own copy, so a
// second rollback (a roll forward, which the restored install's installer
// runs without this package) finds it as it was.
package statecarry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// StateDirs are the data-directory entries that hold the sandboxes' state:
// sandboxes/ (the daemon's records, the hook bindings, the image records
// and each sandbox's run files and workspace state), snapshots/ (the undo
// points) and shadows/ (the git shadows of the projects the undo points
// use). Every path the sandbox manager, the binding store, the image store
// and the workspace use is under one of them.
var StateDirs = []string{"sandboxes", "snapshots", "shadows"}

// configKey is the config.yaml section the sandbox setup lives in.
const configKey = "openshell"

// recordDir is where the daemon keeps one record per sandbox
// (<data_dir>/sandboxes/manager/<name>.json, manager.recordDirName).
var recordDir = filepath.Join("sandboxes", "manager")

// Options names the two installs.
type Options struct {
	// FromDataDir and FromConfig are the install the installer leaves.
	FromDataDir, FromConfig string
	// DataDir and Config are the install it makes live.
	DataDir, Config string
	// OnlyIfUnset carries nothing when the live install has a sandbox setup
	// of its own (openshell.enabled on, or a sandbox record). An upgrade
	// after a rollback by an earlier release uses it: the older install may
	// have set up sandboxes since, and then its setup is the one in use.
	OnlyIfUnset bool
}

// Result says what Carry did.
type Result struct {
	// Carried is true when the setup was copied into the live install.
	Carried bool
	// Skipped says why nothing was copied.
	Skipped string
	// Sandboxes are the sandboxes whose records were copied.
	Sandboxes []string
}

// legacyGuestStep is what Summary adds for a kept sandbox: after a roll
// forward a retained guest can still run the older release's supervisor, and
// a healthy gateway alone does not let it connect (GAP-1161).
const legacyGuestStep = "; if `defenseclaw sandbox connect NAME` then says legacy sandbox running, save or pull its work, then run `defenseclaw sandbox stop NAME` and `defenseclaw sandbox start NAME`"

// Summary is the installer's line for a carried setup.
func (r Result) Summary() string {
	if !r.Carried {
		return ""
	}
	switch len(r.Sandboxes) {
	case 0:
		return "Kept the sandbox setup (the openshell settings and the sandbox state)"
	case 1:
		return "Kept the sandbox setup (the openshell settings and the state of sandbox " + r.Sandboxes[0] +
			"): it stays managed, and its hooks work again once the gateway is up" + legacyGuestStep
	default:
		return fmt.Sprintf("Kept the sandbox setup (the openshell settings and the state of %d sandboxes: %s): "+
			"they stay managed, and their hooks work again once the gateway is up"+legacyGuestStep,
			len(r.Sandboxes), strings.Join(r.Sandboxes, ", "))
	}
}

// Carry copies the sandbox setup of the install in o.FromDataDir into the
// live one. Nothing is copied when the install left has sandboxes off (its
// setup is not the one the running sandboxes need), when the live install
// has no config.yaml, or, with o.OnlyIfUnset, when the live install has a
// sandbox setup of its own. The state directories are copied next to the
// live ones first, then swapped in, then config.yaml is written; a failure
// at any step puts the live install back as it was.
func Carry(ctx context.Context, o Options) (Result, error) {
	if o.FromDataDir == "" || o.FromConfig == "" || o.DataDir == "" || o.Config == "" {
		return Result{}, errors.New("statecarry: the data directory and config.yaml of both installs are required")
	}
	if same, err := sameFile(o.FromDataDir, o.DataDir); err != nil {
		return Result{}, err
	} else if same {
		return Result{}, errors.New("statecarry: the two data directories are the same")
	}
	// A carry stopped between its renames left the live install's own
	// state beside its place; put it back before anything else.
	for _, name := range StateDirs {
		if err := recoverInterrupted(o.DataDir, name); err != nil {
			return Result{}, err
		}
	}
	section, on, err := openShellSection(o.FromConfig)
	if err != nil {
		return Result{}, err
	}
	if !on {
		return Result{Skipped: "the install left has sandboxes off"}, nil
	}
	if _, err := os.Stat(o.Config); errors.Is(err, fs.ErrNotExist) {
		return Result{Skipped: o.Config + " does not exist"}, nil
	} else if err != nil {
		return Result{}, err
	}
	if o.OnlyIfUnset {
		_, liveOn, err := openShellSection(o.Config)
		if err != nil {
			return Result{}, err
		}
		if liveOn || len(sandboxRecords(o.DataDir)) > 0 {
			return Result{Skipped: "the live install has a sandbox setup of its own"}, nil
		}
	}
	// An alias would point into the other document: write its value.
	var value any = section
	if hasAlias(section) {
		var plain any
		if err := section.Decode(&plain); err != nil {
			return Result{}, fmt.Errorf("statecarry: %s: openshell: %w", o.FromConfig, err)
		}
		value = plain
	}
	names := sandboxRecords(o.FromDataDir)
	moves, err := stage(o.FromDataDir, o.DataDir)
	if err != nil {
		return Result{}, err
	}
	if err := install(moves); err != nil {
		return Result{}, errors.Join(err, undo(moves))
	}
	if _, err := configwrite.Apply(ctx, o.Config, []configwrite.Change{{Path: configKey, Value: value}}, configwrite.Options{
		Actor:  configwrite.ActorMigration,
		Reason: "installer: keep the sandbox setup of the install it replaced",
	}); err != nil {
		err = fmt.Errorf("write the openshell settings into %s: %w", o.Config, err)
		return Result{}, errors.Join(err, undo(moves))
	}
	done(moves)
	return Result{Carried: true, Sandboxes: names}, nil
}

// openShellSection returns the openshell: mapping of the config.yaml at
// path and whether it turns sandboxes on.
func openShellSection(path string) (*yaml.Node, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, false, fmt.Errorf("statecarry: %s: %w", path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, false, nil
	}
	section := mapValue(doc.Content[0], configKey)
	if section == nil || section.Kind != yaml.MappingNode {
		return nil, false, nil
	}
	var enabled bool
	if node := mapValue(section, "enabled"); node == nil || node.Decode(&enabled) != nil {
		enabled = false
	}
	return section, enabled, nil
}

func hasAlias(n *yaml.Node) bool {
	if n.Kind == yaml.AliasNode {
		return true
	}
	for _, c := range n.Content {
		if hasAlias(c) {
			return true
		}
	}
	return false
}

func mapValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// displayName is a sandbox name the installer may print as it is.
var displayName = lazyregexp.New(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// sandboxRecords names the sandboxes the daemon of dataDir has records of.
func sandboxRecords(dataDir string) []string {
	entries, err := os.ReadDir(filepath.Join(dataDir, recordDir))
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if ok && e.Type().IsRegular() && displayName.MatchString(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func sameFile(a, b string) (bool, error) {
	ai, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	return os.SameFile(ai, bi), nil
}

// move is one state directory on its way into the live install.
type move struct {
	live, staged, old string
	hadLive, placed   bool
}

// stage copies each state directory of from next to its place in to.
func stage(from, to string) ([]*move, error) {
	var moves []*move
	for _, name := range StateDirs {
		m := &move{live: filepath.Join(to, name), staged: stagedPath(to, name), old: oldPath(to, name)}
		src := filepath.Join(from, name)
		info, err := os.Lstat(src)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, errors.Join(err, discard(moves))
		}
		if !info.IsDir() {
			// A link or a file is not state this release wrote: leave both.
			continue
		}
		if err := copyTree(src, m.staged); err != nil {
			err = fmt.Errorf("statecarry: copy %s: %w", src, err)
			return nil, errors.Join(err, os.RemoveAll(m.staged), discard(moves))
		}
		moves = append(moves, m)
	}
	return moves, nil
}

func stagedPath(dataDir, name string) string { return filepath.Join(dataDir, "."+name+".carry") }
func oldPath(dataDir, name string) string    { return filepath.Join(dataDir, "."+name+".carry-old") }

// recoverInterrupted finishes a carry that stopped between its renames: an
// old copy without a live one is the live install's own state, and an old
// copy beside a live one was replaced by it. A staged copy never went live.
func recoverInterrupted(dataDir, name string) error {
	live, old := filepath.Join(dataDir, name), oldPath(dataDir, name)
	if err := os.RemoveAll(stagedPath(dataDir, name)); err != nil {
		return err
	}
	if _, err := os.Lstat(old); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if _, err := os.Lstat(live); errors.Is(err, fs.ErrNotExist) {
		return os.Rename(old, live)
	} else if err != nil {
		return err
	}
	return os.RemoveAll(old)
}

func discard(moves []*move) error {
	var errs []error
	for _, m := range moves {
		errs = append(errs, os.RemoveAll(m.staged))
	}
	return errors.Join(errs...)
}

// install puts each staged copy in place, keeping the live one beside it.
func install(moves []*move) error {
	for _, m := range moves {
		if _, err := os.Lstat(m.live); err == nil {
			if err := os.Rename(m.live, m.old); err != nil {
				return err
			}
			m.hadLive = true
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := os.Rename(m.staged, m.live); err != nil {
			return err
		}
		m.placed = true
	}
	return nil
}

// undo puts the live install's own state back.
func undo(moves []*move) error {
	var errs []error
	for i := len(moves) - 1; i >= 0; i-- {
		m := moves[i]
		if m.placed {
			errs = append(errs, os.RemoveAll(m.live))
		}
		if m.hadLive {
			errs = append(errs, os.Rename(m.old, m.live))
		}
		errs = append(errs, os.RemoveAll(m.staged))
	}
	return errors.Join(errs...)
}

// done drops the live install's own state, which the copy replaced.
func done(moves []*move) {
	for _, m := range moves {
		if m.hadLive {
			_ = os.RemoveAll(m.old)
		}
	}
}

// copyTree copies src to dst (which must not exist) with each entry's
// permission bits and modification time. Links are copied as links and
// never followed; sockets and pipes are runtime state and are left out.
func copyTree(src, dst string) error {
	type dirMeta struct {
		path  string
		perm  fs.FileMode
		mtime time.Time
	}
	var dirs []dirMeta
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		mode := info.Mode()
		switch {
		case mode.IsDir():
			// Writable until its entries are in; its own bits come last.
			if err := os.Mkdir(target, 0o700); err != nil {
				return err
			}
			dirs = append(dirs, dirMeta{target, mode.Perm(), info.ModTime()})
		case mode&fs.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		case mode.IsRegular():
			return copyFile(path, target, mode.Perm(), info.ModTime())
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := os.Chmod(dirs[i].path, dirs[i].perm); err != nil {
			return err
		}
		_ = os.Chtimes(dirs[i].path, dirs[i].mtime, dirs[i].mtime)
	}
	return nil
}

func copyFile(src, dst string, perm fs.FileMode, mtime time.Time) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		return errors.Join(err, out.Close())
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Chmod(dst, perm); err != nil {
		return err
	}
	_ = os.Chtimes(dst, mtime, mtime)
	return nil
}
