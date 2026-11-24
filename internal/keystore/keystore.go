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

// Package keystore reaches the operating-system secret stores DefenseClaw
// keeps small keys in: the macOS default keychain through the Security
// framework (no cgo), and the Linux Secret Service through secret-tool.
// It holds no policy: callers decide what to keep and what an error means
// for the person. A secret never goes into a process argument.
package keystore

import (
	"bytes"
	"context"
	"fmt"
	"strings"
)

// Runner runs a helper program (secret-tool). exit is the exit code; err is
// set only when the helper could not run.
type Runner func(ctx context.Context, stdin []byte, name string, args ...string) (stdout []byte, stderr string, exit int, err error)

// OSStatus values of the macOS Security framework.
const (
	StatusItemNotFound           = -25300
	StatusDuplicateItem          = -25299
	StatusAuthFailed             = -25293
	StatusInteractionNotAllowed  = -25308
	StatusUserCanceled           = -128
	StatusNoSuchKeychain         = -25294
	StatusDefaultKeychainMissing = -25307
)

// Keychain is the two Security framework calls DefenseClaw needs: find and
// add one generic password of the default keychain. An item added this
// way trusts the calling program, which then reads it without a prompt.
type Keychain interface {
	Find(service, account string) ([]byte, int32)
	Add(service, account string, secret []byte) int32
}

// MacStatusReason says in plain words why a keychain call failed.
func MacStatusReason(st int32) string {
	switch st {
	case StatusInteractionNotAllowed, StatusAuthFailed:
		return "the macOS keychain is locked, or its DefenseClaw item does not trust this DefenseClaw build yet " +
			"(as after an upgrade), and this session cannot ask you (for example over SSH); run the command once " +
			"in a Terminal on the Mac's desktop to unlock the keychain or allow this build"
	case StatusUserCanceled:
		return "you declined the macOS keychain request"
	case StatusNoSuchKeychain, StatusDefaultKeychainMissing:
		return "this account has no default macOS keychain"
	}
	return fmt.Sprintf("the macOS keychain answered status %d", st)
}

// SecretTool keeps secrets in the Secret Service through secret-tool. The
// secret goes on stdin, never in arguments; attrs are attribute/value pairs.
type SecretTool struct {
	Run Runner
	Bin string
}

// Lookup returns the secret stored under attrs; found is false when
// secret-tool gives none. secret-tool answers the same way (exit 1, nothing
// on stderr) when the item is missing and when the keyring is locked and its
// unlock was dismissed or could not be asked for: found false does not prove
// the item is gone (Listed tells the two apart where it can).
func (s SecretTool) Lookup(ctx context.Context, attrs ...string) (secret []byte, found bool, err error) {
	out, stderr, exit, err := s.Run(ctx, nil, s.Bin, append([]string{"lookup"}, attrs...)...)
	if err != nil {
		return nil, false, err
	}
	if exit != 0 {
		if exit == 1 && strings.TrimSpace(stderr) == "" {
			return nil, false, nil // no such item
		}
		return nil, false, toolError("read", exit, stderr)
	}
	out = bytes.TrimSpace(out)
	if len(out) == 0 {
		return nil, false, nil
	}
	return out, true, nil
}

// Listed says whether the Secret Service lists an item under attrs, locked
// or not, without unlocking anything (secret-tool search, no --unlock). The
// listing of an unlocked item carries its secret: only the item lines are
// looked at, and the output is cleared.
func (s SecretTool) Listed(ctx context.Context, attrs ...string) (bool, error) {
	out, stderr, exit, err := s.Run(ctx, nil, s.Bin, append([]string{"search"}, attrs...)...)
	defer clear(out)
	if err != nil {
		return false, err
	}
	if exit != 0 {
		if exit == 1 && strings.TrimSpace(stderr) == "" {
			return false, nil // nothing listed
		}
		return false, toolError("search for", exit, stderr)
	}
	for _, l := range bytes.Split(out, []byte("\n")) {
		if bytes.HasPrefix(bytes.TrimSpace(l), []byte("[/")) {
			return true, nil
		}
	}
	return false, nil
}

// Store keeps secret under attrs with label.
func (s SecretTool) Store(ctx context.Context, label string, secret []byte, attrs ...string) error {
	_, stderr, exit, err := s.Run(ctx, secret, s.Bin, append([]string{"store", "--label=" + label}, attrs...)...)
	if err != nil {
		return err
	}
	if exit != 0 {
		return toolError("save", exit, stderr)
	}
	return nil
}

// Clear deletes the secret under attrs; a missing one is not an error.
func (s SecretTool) Clear(ctx context.Context, attrs ...string) error {
	_, stderr, exit, err := s.Run(ctx, nil, s.Bin, append([]string{"clear"}, attrs...)...)
	if err != nil {
		return err
	}
	if exit != 0 && strings.TrimSpace(stderr) != "" {
		return toolError("delete", exit, stderr)
	}
	return nil
}

func toolError(what string, exit int, stderr string) error {
	msg := fmt.Sprintf("the Secret Service could not %s the item (secret-tool exit %d", what, exit)
	if l := FirstLine(stderr, 160); l != "" {
		msg += ": " + l
	}
	return fmt.Errorf("%s); it needs a running Secret Service such as GNOME Keyring in this session", msg)
}

// FirstLine is the first line of a helper's output, printable and at most
// max bytes.
func FirstLine(s string, max int) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
	}
	return strings.TrimSpace(s)
}
