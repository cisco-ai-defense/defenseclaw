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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

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
	// StateDir is the directory in the actor that holds this copy's pull
	// bundle, upload receipts and checkpoints. When empty Start picks a new
	// private one beside the project (see NewStateDir), so every session of
	// an actor has its own and the agent's project folder never holds it.
	// It is created with mode 0700 and recorded in the copy.
	StateDir string
	// GitDepth is the history depth of the copy (200 by default).
	GitDepth int
	// Upstream makes a "this checkout" copy (run --clone .): only the
	// unpushed commits and the working tree go up, and Send has the actor
	// fetch the rest of the branch's history from its remote. Windows (the
	// host copy) does not take it; the CLI clones there instead.
	Upstream bool
	// UpstreamHTTPS turns an ssh or scp-form remote into the https address
	// the actor clones (osw.StageOptions.UpstreamHTTPS).
	UpstreamHTTPS func(string) (string, bool)
	// MaxBytes caps the copy at the limit reported by the cluster.
	MaxBytes int64
	// Masks add secret-file globs to the built-in rules; Unmask shares a
	// held-back file after all, UnmaskAsked being the person's own
	// --unmask values (a warning for each that matches nothing).
	Masks, Unmask, UnmaskAsked []string
	// UnmaskExact shares files by exact path (push: the run's shared files).
	UnmaskExact        []string
	Detector           osw.SecretDetector
	DisableContentScan bool
	// RewriteSecrets, ScanMaxFileBytes and ScanTimeBudget are the upload
	// scan (substrate.launcher.upload_scan, osw.StageOptions). The Windows
	// host copy does not rewrite: it keeps holding such files back.
	RewriteSecrets   string
	ScanMaxFileBytes int64
	ScanTimeBudget   time.Duration
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

// ReplacedLines say which files went up with their credentials replaced by
// placeholders ("2 secrets replaced in config.py") and which of those are
// signing keys a header swap cannot stand in for; nil when none were.
func (r *StartResult) ReplacedLines() []string {
	if r.CopyRecord == nil || len(r.SecretLines) == 0 {
		return nil
	}
	var order []string
	count := map[string]int{}
	signing := map[string]bool{}
	for _, l := range r.SecretLines {
		if count[l.Rel] == 0 {
			order = append(order, l.Rel)
		}
		count[l.Rel]++
		signing[l.Rel] = signing[l.Rel] || l.Signing
	}
	var out, keys []string
	for _, rel := range order {
		noun := "secrets"
		if count[rel] == 1 {
			noun = "secret"
		}
		out = append(out, fmt.Sprintf("%d %s replaced in %s", count[rel], noun, safetext.Path(rel)))
		if signing[rel] {
			keys = append(keys, safetext.Path(rel))
		}
	}
	lines := []string{"Replaced with placeholders in the copy (your files are unchanged; the agent sees only DC_SECRET_<n>): " + strings.Join(out, ", ") + "."}
	if len(keys) > 0 {
		lines = append(lines, "Note: "+strings.Join(keys, ", ")+" held a signing key (an AWS secret key or a private key); the cluster cannot add it for the agent. Use workload identity or actor_secrets.")
	}
	return lines
}

// TooLargeError is a project that is over the size limit.
type TooLargeError struct {
	Size, Limit int64 // bytes, or entries when Entries is set
	Entries     bool
	Biggest     string
	Err         error
}

func (e *TooLargeError) Error() string {
	const clone = "Leave large folders out with --exclude 'data/**', or start from a repository with --clone REPO_URL."
	if e.Entries {
		return fmt.Sprintf("This folder has more than %d files and folders, over the limit. %s", e.Limit, clone)
	}
	return fmt.Sprintf("This folder is %s, over the %s upload limit.%s %s", uploadSize(e.Size), uploadSize(e.Limit), e.Biggest, clone)
}

func (e *TooLargeError) Unwrap() error { return e.Err }

func uploadSize(n int64) string {
	if n < 1<<20 {
		return fmt.Sprintf("%d bytes", n)
	}
	return fmt.Sprintf("%.4g MiB", float64(n)/(1<<20))
}

// PreparedUpload holds the local copy until an actor is ready for it.
type PreparedUpload struct {
	opts    StartOptions
	copy    *osw.PreparedCopy
	host    *hostUpload
	summary osw.CopySummary
	bytes   int64
}

func (p *PreparedUpload) biggest() string {
	var sizes []string
	for _, d := range p.summary.BiggestDirs(3) {
		sizes = append(sizes, safetext.Line(d.Path)+"/ "+uploadSize(d.Bytes))
	}
	if len(sizes) == 0 {
		return ""
	}
	return " Biggest: " + strings.Join(sizes, ", ") + "."
}

// UsesHigherUploadLimit reports when an old relay may apply a lower cap.
func (p *PreparedUpload) UsesHigherUploadLimit() bool {
	return p.opts.MaxBytes > relay.DefaultFilesMaxBytes
}

// Preview describes the staged upload, including the effective size limit.
func (p *PreparedUpload) Preview(w io.Writer) {
	fmt.Fprintf(w, "Upload: %s in %d files (upload limit %s).%s\n",
		uploadSize(p.bytes), p.summary.Files, uploadSize(p.opts.MaxBytes), p.biggest())
}

// Preflight stages the exact copy locally, with the normal masking rules.
func Preflight(ctx context.Context, opts StartOptions) (*PreparedUpload, error) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = osw.DefaultCopyMaxBytes
	}
	p := &PreparedUpload{opts: opts}
	var err error
	if hostCopy && opts.Upstream {
		return nil, errors.New("workspace: a this-checkout copy needs the git copy pipeline, which this system does not run")
	}
	if hostCopy && (opts.Transport == nil || isRelayClient(opts.Transport)) {
		p.host, err = prepareHostUpload(ctx, opts, &p.summary)
		p.bytes = p.summary.Bytes
	} else {
		p.copy, err = osw.PrepareCopy(ctx, osw.StageOptions{
			Project: opts.Project, DataDir: opts.DataDir, Home: opts.Home, Protected: opts.Protected,
			RemoteRoot: opts.RemoteRoot, GitDepth: opts.GitDepth, MaxBytes: opts.MaxBytes, Upstream: opts.Upstream, UpstreamHTTPS: opts.UpstreamHTTPS,
			FolderName: hostFolderName(opts.Project), Summary: &p.summary,
			Masks: opts.Masks, Unmask: opts.Unmask, UnmaskAsked: opts.UnmaskAsked, UnmaskExact: opts.UnmaskExact,
			Detector: opts.Detector, DisableContentScan: opts.DisableContentScan,
			RewriteSecrets: opts.RewriteSecrets, ScanMaxFileBytes: opts.ScanMaxFileBytes, ScanTimeBudget: opts.ScanTimeBudget,
		})
		if err == nil {
			p.bytes = p.copy.Record().Bytes
		}
	}
	if err != nil {
		var large *osw.TooLargeError
		if errors.As(err, &large) {
			return nil, &TooLargeError{Size: large.Size, Limit: large.Limit, Entries: large.Entries, Biggest: p.biggest(), Err: err}
		}
		return nil, cleanErr("copy the project", err)
	}
	return p, nil
}

func isRelayClient(t osw.Transport) bool {
	_, ok := t.(*Client)
	return ok
}

// Upstream is the remote side of a this-checkout copy, nil for any other.
func (p *PreparedUpload) Upstream() *osw.Upstream {
	if p.copy == nil {
		return nil
	}
	return p.copy.Record().Upstream
}

// UpstreamLine says what a this-checkout copy sends ("" for any other).
func (p *PreparedUpload) UpstreamLine() string {
	up := p.Upstream()
	if up == nil {
		return ""
	}
	return fmt.Sprintf("Sending %s and %s (%s).", upPlural(up.Commits, "unpushed commit", "unpushed commits"),
		upPlural(up.Changes, "uncommitted change", "uncommitted changes"), uploadSize(p.bytes))
}

func upPlural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// Close discards a local stage that has not been sent.
func (p *PreparedUpload) Close() {
	if p.copy != nil {
		p.copy.Close()
	}
	if p.host != nil {
		p.host.close()
	}
}

// Send uploads the stage and establishes the baseline Pull measures against.
func (p *PreparedUpload) Send(ctx context.Context, name string, t osw.Transport) (*StartResult, error) {
	opts := p.opts
	root := opts.RemoteRoot
	if root == "" {
		root = DefaultRemoteRoot
		if r, ok := t.(interface {
			Root(context.Context) (string, error)
		}); ok {
			detected, err := r.Root(ctx)
			if err != nil {
				return nil, err
			}
			root = detected
		}
	}
	stateDir := opts.StateDir
	if stateDir == "" {
		base := root
		if sr, ok := t.(interface {
			StateRoot(context.Context) (string, error)
		}); ok {
			if d, err := sr.StateRoot(ctx); err == nil && d != "" {
				base = d
			}
		}
		dir, err := NewStateDir(base, name)
		if err != nil {
			return nil, cleanErr("copy the project", err)
		}
		stateDir = dir
	}
	if p.host != nil {
		c, ok := t.(*Client)
		if !ok {
			return nil, errors.New("workspace: the host copy needs the relay client")
		}
		return p.host.send(ctx, c, opts.DataDir, name, root, stateDir)
	}
	prev, _ := osw.LoadCopy(opts.DataDir, name)
	if err := p.copy.Install(name, root, stateDir, opts.Replace); err != nil {
		return nil, cleanErr("copy the project", err)
	}
	if _, err := osw.Upload(ctx, opts.DataDir, name, t, t); err != nil {
		return nil, cleanErr("upload the project to the actor", err)
	}
	rec, err := osw.EstablishBaseline(ctx, opts.DataDir, name, t)
	if err != nil {
		return nil, cleanErr("record the copy's baseline in the actor", err)
	}
	removePrevState(ctx, t, prev, rec)
	if rec.Upstream != nil {
		if rec, err = osw.FetchUpstream(ctx, opts.DataDir, name, t); err != nil {
			return nil, cleanErr("fetch the branch history in the actor", err)
		}
	}
	return &StartResult{CopyRecord: rec, KeptBack: rec.HeldBack, Unmasked: rec.Unmasked, Warnings: rec.Warnings}, nil
}

// StateDirPrefix starts the name of every state directory Start picks.
const StateDirPrefix = ".dc-state-"

// NewStateDir returns a state directory for a copy called name whose
// project lands under root in the actor: a sibling of the project folder,
// never inside it, named for the copy and a random suffix, so each Start
// (each session) has its own. It does not create it; the copy pipeline does,
// with mode 0700, before anything is written there.
func NewStateDir(root, name string) (string, error) {
	if !path.IsAbs(root) || path.Clean(root) == "/" {
		return "", fmt.Errorf("workspace: remote root %q must be an absolute directory below /", root)
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("workspace: %w", err)
	}
	return path.Join(path.Clean(root), StateDirPrefix+name+"-"+hex.EncodeToString(b[:])), nil
}

// removePrevState removes the private state directory of the copy that
// cur replaced, once cur is in the actor. It is best effort: what stays is
// a few kilobytes of receipts and, at most, one result bundle. Only
// directories Start named (StateDirPrefix) and that are not cur's own are
// removed.
func removePrevState(ctx context.Context, ex osw.Execer, prev, cur *osw.CopyRecord) {
	if prev == nil || prev.UploadedAt == nil || prev.StateDir == "" || prev.StateDir == cur.StateDir {
		return
	}
	d := prev.StateDir
	if path.Clean(d) != d || !strings.HasPrefix(path.Base(d), StateDirPrefix) || path.Dir(d) == "/" {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	_, _ = ex.Exec(ctx, cur.Name, osw.ExecRequest{Argv: []string{"rm", "-rf", "--", d}, Timeout: time.Minute, Idempotent: true})
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
