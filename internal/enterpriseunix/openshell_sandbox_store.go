// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// The gateway's sandbox registration store and the key behind it, below
// Layout.DataDir. A sandbox an account keeps after a non-purge uninstall
// is started, reviewed and pulled through its daemon, and the daemon names
// it to the gateway by the registration id the gateway gave it. The
// registrations (sandboxreg.RegistrationsDir, DecisionsDir) and the
// correlation key their subject keys are HMACs of
// (redaction.LoadOrCreateCorrelationKey) are what lets the gateway of the
// next activation know those ids again. Without them it answered
// sandbox_registration_unknown, the daemon marked every kept sandbox
// revoked, and a stopped copy-mode MicroVM, whose review and pull have to
// start it, could not be reached any more (GAP-0598).
const (
	sandboxStoreDirName    = "sandbox"
	correlationKeyFileName = "redaction-correlation.key"
)

// removeDataDirKeepingSandboxStore removes the gateway data folder dir but
// for the sandbox registration store and the correlation key: the folder
// sandbox/ when a file is below it (never through a symlink to one), and
// the key when it is a regular file. With neither there, the whole folder
// goes, as it did before. It reports whether anything was kept.
func removeDataDirKeepingSandboxStore(dir string) (bool, error) {
	info, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.IsDir() {
		return false, os.RemoveAll(dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	var keep []string
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		switch {
		case entry.Name() == sandboxStoreDirName && info.IsDir() && pruneEmptyDirs(path),
			entry.Name() == correlationKeyFileName && info.Mode().IsRegular():
			keep = append(keep, path)
		}
	}
	if len(keep) == 0 {
		return false, os.RemoveAll(dir)
	}
	var errs []error
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		kept := false
		for _, k := range keep {
			kept = kept || k == path
		}
		if !kept {
			errs = append(errs, os.RemoveAll(path))
		}
	}
	return true, errors.Join(errs...)
}

// handSandboxStoreToRoot gives the kept sandbox store, and the data folder
// that holds it, to root once the service account that owned them is gone:
// an account created later with its uid would otherwise read the key and
// the registrations. The modes stay (0700 folders, 0600 files), and the
// next ensure hands every entry to the service account it creates
// (settleStateModes). Symlinks are changed, never followed.
func (e *Env) handSandboxStoreToRoot() error {
	data := e.P(e.Layout.DataDir)
	errs := []error{e.Lchown(data, 0, 0)}
	for _, name := range []string{sandboxStoreDirName, correlationKeyFileName} {
		root := filepath.Join(data, name)
		if _, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		errs = append(errs, filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			return e.Lchown(path, 0, 0)
		}))
	}
	return errors.Join(errs...)
}

// keepSandboxStore reports whether a non-purge uninstall keeps the sandbox
// registration store: an account keeps its sandboxes.
func (l *lifecycle) keepSandboxStore() bool {
	return !l.opts.Purge && !l.opts.KeepState && len(l.sandboxesKept) > 0
}

// keptSandboxStoreLine is the uninstall summary line for the kept sandbox
// registration store, or "".
func (l *lifecycle) keptSandboxStoreLine() string {
	if !l.sandboxStoreKept {
		return ""
	}
	env := l.env
	data := env.Layout.DataDir
	return "kept the gateway's sandbox registrations (" + filepath.Join(data, sandboxStoreDirName) + ") and their key (" +
		filepath.Join(data, correlationKeyFileName) + ") for the sandboxes the accounts keep: once the deployment is activated again, those sandboxes " +
		"start, review and pull as before. `" + env.lifecycleCommand(ActionUninstall) + " --purge` removes them (install the package again first if it is gone), or delete " +
		data + " by hand"
}
