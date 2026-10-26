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
	"os"
	"path/filepath"
	"strings"
)

// kitStateDir is the root-only state folder of the MDM wrapper
// (packaging/mdm/<os>/defenseclaw-enterprise.sh DC_KIT_STATE).
func (e *Env) kitStateDir() string {
	if e.GOOS == "darwin" {
		return "/var/db/defenseclaw-mdm"
	}
	return "/var/lib/defenseclaw-mdm"
}

// removeKitRotationJournal removes the MDM wrapper's credential rotation
// journal once an uninstall has removed the credentials, as the wrapper's
// uninstall.sh does: each <name>.value (a plaintext copy of an earlier
// credential) is overwritten with zeros first. A purge run directly with
// this command left the journal and that copy after the deployment was gone
// (GAP-1615). A journal that is a link or not an administrator's folder is
// left as it is. A purge also removes the wrapper's state folder once it is
// empty.
func (l *lifecycle) removeKitRotationJournal() {
	env := l.env
	state := env.P(env.kitStateDir())
	journal := filepath.Join(state, "rotation")
	if info, err := os.Lstat(journal); err == nil {
		if !info.IsDir() || env.Trust(journal, TrustAdminDir) != nil {
			l.result.AddWarning(codeLeftovers, "left the MDM wrapper's credential rotation journal "+l.canonicalPath(journal)+" as it is: it is not an administrator's folder")
			return
		}
		entries, _ := os.ReadDir(journal)
		for _, entry := range entries {
			name := entry.Name()
			path := filepath.Join(journal, name)
			switch {
			case strings.HasSuffix(name, ".value") && entry.Type().IsRegular():
				if info, err := entry.Info(); err == nil {
					if file, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
						_, _ = file.Write(make([]byte, info.Size()))
						_ = file.Sync()
						_ = file.Close()
					}
				}
				_ = removeFile(path)
			case strings.HasSuffix(name, ".entry"), strings.HasSuffix(name, ".entry.partial"), name == ".lock":
				_ = removeFile(path)
			}
		}
		if err := os.Remove(journal); err != nil {
			l.result.AddWarning(codeLeftovers, "could not remove the MDM wrapper's credential rotation journal "+l.canonicalPath(journal)+": it holds files the wrapper does not write")
			return
		}
		l.result.Changes = append(l.result.Changes, "removed the MDM wrapper's credential rotation journal "+l.canonicalPath(journal))
	}
	if l.opts.Purge {
		_ = removeDirIfEmpty(state)
	}
}
