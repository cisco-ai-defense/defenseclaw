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

package packs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Subject is the account a resolution is for: whose home "~/" names and
// whose pack files count as their own (checkPackOwnership). The managed
// gateway resolves for the peer of a hook-socket call, so it passes the
// peer's uid and the home the account database gives it; nothing in this
// package may read the identity of the process instead
// (ambient_identity_test.go).
type Subject struct {
	// UID is the account's uid (the peer uid in managed mode).
	UID int
	// Home is the account's home directory from the account database;
	// "" means it has none, and a "~/" reference then refuses.
	Home string
}

// The two OSS defaults: the identity of the process itself, for callers
// that resolve for their own account (Flags.Subject nil, Load, List). They
// are the only ambient identity reads in this package and are swapped in
// tests.
var (
	ownUID  = os.Getuid
	ownHome = os.UserHomeDir
)

// callerSubject is the Subject of the account this process runs as.
func callerSubject() Subject {
	home, err := ownHome()
	if err != nil {
		home = ""
	}
	return Subject{UID: ownUID(), Home: home}
}

// InputError is a resolve failure the subject's own input caused: the pack
// they named with --pack, a pack file of theirs, or their repository policy.
// Its text is safe to show them and they can act on it, unlike every other
// resolve failure, which is a problem of the organization's own files and
// configuration (GAP-0559, GAP-0563).
type InputError struct{ Err error }

func (e *InputError) Error() string { return e.Err.Error() }
func (e *InputError) Unwrap() error { return e.Err }

// checkSubjectPack keeps a resolution for an explicit subject from reading
// what the subject named with this process's file access, which can be
// wider than the subject's (a pack folder only the service can read): a
// confused deputy that would show another profile's pack in the
// subject's Effective. A custom --pack is either one of the
// administrator's own references (openshell.pack, the floor's required
// pack) or the bytes the daemon read as the subject (UserPack), and those
// bytes must come from a path outside the administrator's pack folders,
// so they cannot wear the name or the source of an administrator's pack.
// Every refusal is the same sentence: it says nothing about whether a file
// exists or whose it is.
func (r *resolver) checkSubjectPack(cfg *config.Config, flags Flags) error {
	ref := strings.TrimSpace(flags.Pack)
	if !r.explicit || ref == "" || IsBuiltin(ref) {
		return nil
	}
	refuse := &InputError{Err: fmt.Errorf("sandbox policy: --pack %q is not a pack this computer can load for you; "+
		"use a built-in pack (%s) or a pack file of your own", truncateText(ref, 120), strings.Join(BuiltinNames(), ", "))}
	if flags.UserPack == nil {
		if ref == strings.TrimSpace(cfg.OpenShell.Pack) || ref == strings.TrimSpace(r.admin.RequiredPack) {
			return nil
		}
		return refuse
	}
	if packNamePattern.MatchString(ref) {
		// A name is a pack in openshell.pack_dir, the administrator's.
		return refuse
	}
	file, err := expandHome(ref, r.subject.Home)
	if err != nil || !filepath.IsAbs(file) {
		// loadSelected names the problem; it reveals nothing.
		return nil
	}
	file = filepath.Clean(file)
	var folders []string
	if dir, err := expandHome(strings.TrimSpace(cfg.OpenShell.PackDir), r.subject.Home); err == nil && filepath.IsAbs(dir) {
		folders = append(folders, filepath.Clean(dir))
	}
	if policyDir := strings.TrimSpace(cfg.PolicyDir); filepath.IsAbs(policyDir) {
		folders = append(folders, filepath.Join(policyDir, "sandbox"))
	}
	for _, folder := range folders {
		if rel, err := filepath.Rel(folder, file); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return refuse
		}
	}
	return nil
}

// subjectOf returns the explicit subject, or the caller's own account.
func subjectOf(s *Subject) (Subject, error) {
	if s == nil {
		return callerSubject(), nil
	}
	if s.UID < 0 {
		return Subject{}, fmt.Errorf("sandbox policy: subject uid %d is not an account", s.UID)
	}
	if s.Home != "" && !filepath.IsAbs(s.Home) {
		return Subject{}, fmt.Errorf("sandbox policy: subject home %q must be absolute", s.Home)
	}
	out := Subject{UID: s.UID}
	if s.Home != "" {
		out.Home = filepath.Clean(s.Home)
	}
	return out, nil
}
