// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// WindowsLaunchSelection is a runtime selector entry that named a launch
// image of an install (bin\hooks\<16 hex>\defenseclaw-hook.exe).
type WindowsLaunchSelection struct {
	Connector string
	SID       string
	// Selector is the selector file the entry was in.
	Selector string
}

// DeselectWindowsStandaloneSignedOutLaunchSelections is the runtime selector
// step of `enterprise windows hook-image retire` (rel-1-0-10 GAP-0856). A
// connector's selector is a machine file, but each of its entries is
// published only by that account's own install, which the guardian runs only
// in the account's Windows session (the runtime bundle the entry names is
// written as the account, in its profile). So the entry of a signed-out
// account kept naming the launch folder, the selector kept naming it, and
// retire stayed pending on machine files no step could rewrite until that
// account signed in. This drops, under each selector's lock, the entries
// that name a launch image of bin for the accounts signedOut reports (the
// guardian cannot repair them now). Such an account is then an account
// enrolled while signed out: its machine policy still registers it, it has
// no runtime selected (the pending proof of this release and of 1.0.9,
// GAP-0909), and the guardian installs the transition hook in its session at
// its next sign-in. Entries naming the transition image, another install's
// image, or an account with a session are kept: the guardian rewrites those.
// The bundle a dropped entry named is left for generation GC. It returns the
// entries dropped and, by selector file, why one could not be dropped or an
// account's session could not be told.
func DeselectWindowsStandaloneSignedOutLaunchSelections(
	bin string,
	signedOut func(sid string) (bool, error),
) ([]WindowsLaunchSelection, map[string]error) {
	if !windowsEnterpriseStandaloneProcess() || signedOut == nil {
		return nil, nil
	}
	bin = strings.TrimRight(strings.TrimSpace(bin), `\`)
	failures := map[string]error{}
	if bin == "" {
		failures[""] = errors.New("enterprise hooks: deselect launch selections: no install bin")
		return nil, failures
	}
	known := map[string]bool{}
	sessionErrs := map[string]error{}
	isSignedOut := func(sid string) (bool, error) {
		key := strings.ToUpper(strings.TrimSpace(sid))
		if err, failed := sessionErrs[key]; failed {
			return false, err
		}
		if out, seen := known[key]; seen {
			return out, nil
		}
		out, err := signedOut(sid)
		if err != nil {
			sessionErrs[key] = err
			return false, err
		}
		known[key] = out
		return out, nil
	}
	connectors := append(
		append([]string(nil), windowsMachinePolicySelectorConnectors...),
		WindowsStandalonePerUserConnectorNames()...,
	)
	var dropped []WindowsLaunchSelection
	for _, name := range connectors {
		path, err := windowsManagedRuntimeSelectorPath(name)
		if err != nil {
			failures[name] = err
			continue
		}
		if kept, err := windowsManagedPolicyLinkKept(filepath.Dir(path)); err != nil {
			failures[path] = fmt.Errorf("enterprise hooks: inspect %s: %w", filepath.Dir(path), err)
			continue
		} else if kept {
			continue
		}
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			failures[path] = fmt.Errorf("enterprise hooks: inspect %s: %w", path, err)
			continue
		}
		if err := windowsManagedRuntimeSelectorMutationAuthorize(); err != nil {
			failures[path] = err
			continue
		}
		var removed []WindowsLaunchSelection
		err = withWindowsManagedRuntimeSelectorTeardownTransaction(name, func() error {
			selector, _, exists, err := readWindowsManagedRuntimeSelector(name, true)
			if err != nil || !exists {
				return err
			}
			kept := make([]windowsManagedRuntimeSelectorTarget, 0, len(selector.Targets))
			var errs []error
			for _, entry := range selector.Targets {
				if !windowsSelectionNamesLaunchImageOf(entry.HookExecutable, bin) {
					kept = append(kept, entry)
					continue
				}
				out, err := isSignedOut(entry.SID)
				if err != nil {
					errs = append(errs, fmt.Errorf("the session of %s could not be told: %w", entry.SID, err))
				}
				if err != nil || !out {
					kept = append(kept, entry)
					continue
				}
				removed = append(removed, WindowsLaunchSelection{Connector: name, SID: entry.SID, Selector: path})
			}
			if len(removed) == 0 {
				return errors.Join(errs...)
			}
			selector.Targets = kept
			if err := publishOrRemoveWindowsManagedRuntimeSelector(selector); err != nil {
				removed = nil
				return errors.Join(append(errs, err)...)
			}
			return errors.Join(errs...)
		})
		dropped = append(dropped, removed...)
		if err != nil {
			failures[path] = err
		}
	}
	return dropped, failures
}

// windowsSelectionNamesLaunchImageOf reports a selector entry's hook
// executable that is a launch image (not the transition image) of bin.
func windowsSelectionNamesLaunchImageOf(hookExecutable, bin string) bool {
	location, ok := winpath.ParseEnterpriseHookImagePath(hookExecutable)
	return ok && location.Digest != "" && strings.EqualFold(strings.TrimRight(location.Bin, `\`), bin)
}
