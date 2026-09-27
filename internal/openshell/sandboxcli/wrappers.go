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
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sort"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/wrapper"
)

// WrapperOptions are the `enable|disable` flags.
type WrapperOptions struct {
	Harness string
	// Shell is bash, zsh or fish (default: $SHELL).
	Shell string
	// RC overrides the rc file.
	RC string
}

func (a *App) wrapperTarget(o WrapperOptions) (wrapper.Shell, string, error) {
	a.defaults()
	name := o.Shell
	if name == "" {
		name = a.Getenv("SHELL")
	}
	sh, err := wrapper.ParseShell(name)
	if err != nil {
		return "", "", fmt.Errorf("%w; pass --shell bash|zsh|fish", err)
	}
	if o.RC != "" {
		p, err := filepath.Abs(o.RC)
		return sh, p, err
	}
	home, err := a.Home()
	if err != nil {
		return "", "", err
	}
	p, err := wrapper.RCPath(sh, home, a.Getenv)
	return sh, p, err
}

func wrapFor(spec *harness.Spec) wrapper.Wrap {
	return wrapper.Wrap{Command: spec.Command, Harness: spec.Command}
}

// Enable makes typing the harness command run it in a sandbox.
func (a *App) Enable(o WrapperOptions) error {
	if err := a.CheckSupported(); err != nil {
		return err
	}
	spec, err := ResolveHarness(o.Harness)
	if err != nil {
		return err
	}
	sh, rc, err := a.wrapperTarget(o)
	if err != nil {
		return err
	}
	bin, err := a.Executable()
	if err != nil {
		return fmt.Errorf("locate the DefenseClaw binary: %w", err)
	}
	ch, err := wrapper.Enable(sh, rc, bin, wrapFor(spec))
	if err != nil {
		return err
	}
	a.recordWrappers()
	if ch.Changed {
		a.ok(fmt.Sprintf("`%s` now runs in a DefenseClaw sandbox in new %s sessions (%s)", spec.Command, sh, a.tildePath(ch.Path)))
	} else {
		a.ok(fmt.Sprintf("`%s` already runs in a DefenseClaw sandbox (%s)", spec.Command, a.tildePath(ch.Path)))
	}
	a.note(fmt.Sprintf("apply it now: source %s · bypass once: %s=1 %s · undo: %s disable %s",
		a.tildePath(ch.Path), wrapper.EnvBypass, spec.Command, CommandName, spec.Command))
	return nil
}

// Disable removes the harness's wrapper from every supported shell's rc
// file (or only --rc).
func (a *App) Disable(o WrapperOptions) error {
	a.defaults()
	spec, err := ResolveHarness(o.Harness)
	if err != nil {
		return err
	}
	type target struct {
		shell wrapper.Shell
		path  string
	}
	var targets []target
	if o.RC != "" || o.Shell != "" {
		sh, rc, err := a.wrapperTarget(o)
		if err != nil {
			return err
		}
		targets = append(targets, target{sh, rc})
	} else {
		home, err := a.Home()
		if err != nil {
			return err
		}
		for _, in := range wrapper.Scan(home, a.Getenv) {
			targets = append(targets, target{in.Shell, in.Path})
		}
	}
	removed := 0
	var errs []error
	for _, t := range targets {
		ch, err := wrapper.Disable(t.shell, t.path, spec.Command)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if ch.Changed {
			removed++
			a.ok(fmt.Sprintf("removed the `%s` wrapper from %s", spec.Command, a.tildePath(ch.Path)))
		}
	}
	a.recordWrappers()
	if removed == 0 && len(errs) == 0 {
		a.ok(fmt.Sprintf("`%s` has no sandbox wrapper", spec.Command))
	}
	if removed > 0 {
		a.note("open a new shell (or `unset -f " + spec.Command + "`) for it to take effect")
	}
	return errors.Join(errs...)
}

// wrappedHarnesses lists the harnesses wrapped in any rc file.
func (a *App) wrappedHarnesses() []string {
	home, err := a.Home()
	if err != nil {
		return nil
	}
	var names []string
	for _, in := range wrapper.Scan(home, a.Getenv) {
		for _, w := range in.Block.Wraps {
			if spec, err := ResolveHarness(w.Harness); err == nil && !slices.Contains(names, spec.Name) {
				names = append(names, spec.Name)
			}
		}
	}
	sort.Strings(names)
	return names
}

// recordWrappers mirrors the wrapped harnesses into openshell.wrappers
// (best effort: the rc files are the truth).
func (a *App) recordWrappers() {
	if a.Cfg == nil {
		return
	}
	names := a.wrappedHarnesses()
	if slices.Equal(names, a.Cfg.OpenShell.Wrappers) {
		return
	}
	if names == nil {
		names = []string{}
	}
	if err := a.patchConfig(map[string]any{"openshell.wrappers": names}); err != nil {
		a.warn("could not record openshell.wrappers: " + err.Error())
		return
	}
	a.Cfg.OpenShell.Wrappers = names
}
