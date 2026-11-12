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

package workspace

import (
	"context"
	"errors"
	"fmt"
	"strings"

	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// DefaultMaxBytes caps the project copy, git history included.
const DefaultMaxBytes int64 = osw.DefaultCopyMaxBytes

// StartOptions configures Start.
type StartOptions struct {
	// Transport reaches the actor: a *Client, or a fake in tests.
	Transport osw.Transport
	// Project is the local folder to copy; Name names the copy (the
	// actor's name works).
	Project string
	Name    string
	// DataDir is the DefenseClaw state directory (the CLI passes it); Home
	// is the person's home, which the project must be below.
	DataDir   string
	Home      string
	Protected []string
	// RemoteRoot is the actor directory the project is copied into; when
	// empty, the Client's (detected from the relay) or DefaultRemoteRoot.
	RemoteRoot string
	// GitDepth is the history depth of the copy (200 by default).
	GitDepth int
	// MaxBytes caps the copy (DefaultMaxBytes, 500 MiB).
	MaxBytes int64
	// Masks add secret-file globs to the built-in rules; Unmask shares a
	// held-back file after all, UnmaskAsked being the person's own
	// --unmask values (a warning for each that matches nothing).
	Masks, Unmask, UnmaskAsked []string
	Detector                   osw.SecretDetector
	DisableContentScan         bool
	// Replace discards an earlier copy of the same name once the new one is
	// staged.
	Replace bool
}

// StartResult is the copy that is now in the actor.
type StartResult struct {
	*osw.CopyRecord
	// KeptBack are the files held back because they look like secrets; the
	// actor never sees them. Unmasked are those shared by --unmask.
	KeptBack []string
	Unmasked []string
	// Warnings are what the staging noted (a folder inside a larger
	// repository, an --unmask pattern that matched nothing).
	Warnings []string
}

// KeptBackLine is "kept back: .env, id_rsa (2 files)", or "" when nothing
// was held back.
func (r *StartResult) KeptBackLine() string {
	n := len(r.KeptBack)
	if n == 0 {
		return ""
	}
	shown := r.KeptBack
	more := ""
	if n > 6 {
		shown, more = shown[:6], fmt.Sprintf(" and %d more", n-6)
	}
	noun := "files"
	if n == 1 {
		noun = "file"
	}
	return fmt.Sprintf("kept back: %s%s (%d %s)", strings.Join(shown, ", "), more, n, noun)
}

// TooLargeError is a project that is over the size limit.
type TooLargeError struct {
	Size, Limit int64 // bytes, or entries when Entries is set
	Entries     bool
	Err         error
}

func (e *TooLargeError) Error() string {
	const clone = "Use --clone REPO_URL to start from a repository instead, or keep the large folders out of the copy by adding them to .gitignore."
	if e.Entries {
		return fmt.Sprintf("This folder has more than %d files and folders, over the limit. %s", e.Limit, clone)
	}
	return fmt.Sprintf("This folder is %d MB, over the %d MB limit. %s", mb(e.Size), mb(e.Limit), clone)
}

func (e *TooLargeError) Unwrap() error { return e.Err }

func mb(n int64) int64 { return (n + (1 << 20) - 1) >> 20 }

// Start copies the project into the actor: it stages the folder with the
// secrets held back, uploads it over the Transport, confirms it arrived and
// records the baseline Pull measures against. The copy is a normal git
// repository in the actor when the project is one.
func Start(ctx context.Context, opts StartOptions) (*StartResult, error) {
	t := opts.Transport
	if t == nil {
		return nil, errors.New("workspace: start needs a transport to the actor")
	}
	root := opts.RemoteRoot
	if root == "" {
		root = DefaultRemoteRoot
		if r, ok := t.(interface {
			Root(context.Context) (string, error)
		}); ok {
			var err error
			if root, err = r.Root(ctx); err != nil {
				return nil, fmt.Errorf("workspace: ask the actor for its working directory: %w", err)
			}
		}
	}
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	rec, err := osw.Stage(ctx, osw.StageOptions{
		Project: opts.Project, Name: opts.Name, DataDir: opts.DataDir, Home: opts.Home, Protected: opts.Protected,
		RemoteRoot: root, GitDepth: opts.GitDepth, MaxBytes: maxBytes,
		Masks: opts.Masks, Unmask: opts.Unmask, UnmaskAsked: opts.UnmaskAsked,
		Detector: opts.Detector, DisableContentScan: opts.DisableContentScan, Replace: opts.Replace,
	})
	if err != nil {
		var large *osw.TooLargeError
		if errors.As(err, &large) {
			return nil, &TooLargeError{Size: large.Size, Limit: large.Limit, Entries: large.Entries, Err: err}
		}
		return nil, cleanErr("copy the project", err)
	}
	if rec, err = osw.Upload(ctx, opts.DataDir, opts.Name, t, t); err != nil {
		return nil, cleanErr("upload the project to the actor", err)
	}
	if rec, err = osw.EstablishBaseline(ctx, opts.DataDir, opts.Name, t); err != nil {
		return nil, cleanErr("record the copy's baseline in the actor", err)
	}
	return &StartResult{CopyRecord: rec, KeptBack: rec.HeldBack, Unmasked: rec.Unmasked, Warnings: rec.Warnings}, nil
}

// Error is a failure of a workspace step, in plain words; Unwrap gives the
// pipeline's own error for errors.Is and errors.As.
type Error struct {
	Msg string
	Err error
}

func (e *Error) Error() string { return e.Msg }
func (e *Error) Unwrap() error { return e.Err }

func cleanErr(what string, err error) error {
	return &Error{Msg: what + ": " + strings.ReplaceAll(err.Error(), "workspace: ", ""), Err: err}
}
