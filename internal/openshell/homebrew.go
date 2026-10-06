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

package openshell

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
)

// findHomebrewPrefix finds the Homebrew prefix like `brew --prefix`
// without running brew: HOMEBREW_PREFIX (which `brew shellenv` sets),
// else the prefix of the brew on PATH (the one holding a Cellar, through
// its link when it has none), else /opt/homebrew, Apple silicon's.
func findHomebrewPrefix(getenv func(string) string, lookPath func(string) (string, error)) string {
	if p := getenv("HOMEBREW_PREFIX"); filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	if brew, err := lookPath("brew"); err == nil && filepath.IsAbs(brew) {
		candidates := []string{brew}
		if real, err := filepath.EvalSymlinks(brew); err == nil {
			candidates = append(candidates, real)
		}
		for _, c := range candidates {
			prefix := filepath.Dir(filepath.Dir(c))
			if info, err := os.Stat(filepath.Join(prefix, "Cellar")); err == nil && info.IsDir() {
				return prefix
			}
		}
	}
	return "/opt/homebrew"
}

// ErrHomebrewNotWritable means the Homebrew prefix belongs to another
// account, so NVIDIA's installer, which runs Homebrew as you without
// sudo, could not add its tap or install the formula. Nothing was
// downloaded or run.
var ErrHomebrewNotWritable = errors.New("openshell: Homebrew's directories are not writable by this account")

// HomebrewNotWritableError names the Homebrew directory this account
// cannot write and who owns it.
type HomebrewNotWritableError struct {
	Prefix string
	// Dir is the directory under Prefix that cannot be written.
	Dir string
	// Owner is the account that owns Dir ("" when unknown); User is this
	// account ("" when unknown).
	Owner, User string
}

// Problem says what is wrong.
func (e *HomebrewNotWritableError) Problem() string {
	owner := "another account"
	if e.Owner != "" {
		owner = e.Owner
	}
	who := "you"
	if e.User != "" {
		who = "you (" + e.User + ")"
	}
	return fmt.Sprintf("Homebrew at %s belongs to %s, and %s cannot write to %s, where Homebrew adds NVIDIA's tap and installs the formula",
		e.Prefix, owner, who, e.Dir)
}

// Fix says what to do about it.
func (e *HomebrewNotWritableError) Fix() string {
	owner := "the account that owns it"
	if e.Owner != "" {
		owner = e.Owner
	}
	return "ask " + owner + " (or an administrator) to make " + e.Prefix + " writable for you, or use a Homebrew of your own " +
		"(install one in your home directory, see https://docs.brew.sh/Installation; then `eval \"$(~/homebrew/bin/brew shellenv)\"`), " +
		"and run `defenseclaw sandbox setup` again"
}

func (e *HomebrewNotWritableError) Error() string {
	return ErrHomebrewNotWritable.Error() + ": " + e.Problem()
}

// Unwrap lets errors.Is match ErrHomebrewNotWritable.
func (e *HomebrewNotWritableError) Unwrap() error { return ErrHomebrewNotWritable }

// homebrewWritableDirs are the directories under the prefix that the
// formula install writes: the tap NVIDIA's script creates, and the keg.
var homebrewWritableDirs = []string{filepath.Join("Library", "Taps"), "Cellar"}

// checkHomebrewWritable refuses a Homebrew prefix whose directories this
// account cannot write, before NVIDIA's installer runs Homebrew in them.
// A directory that does not exist is Homebrew's to report.
func checkHomebrewWritable(prefix string, writable func(dir string) bool) error {
	for _, rel := range homebrewWritableDirs {
		dir := filepath.Join(prefix, rel)
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() || writable(dir) {
			continue
		}
		e := &HomebrewNotWritableError{Prefix: prefix, Dir: dir, Owner: ownerName(info)}
		if u, err := user.Current(); err == nil {
			e.User = u.Username
		}
		return e
	}
	return nil
}
