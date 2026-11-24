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

// Pull on another computer (GAP-0489). Only the computer that ran run keeps
// the record of the folder it sent. A copy of that baseline inside the
// actor is the agent's to rewrite, so it is never used. On another computer
// the trusted baseline is the person's own checkout instead: the last commit
// of the folder pull runs in, read from this computer's git. Every byte of
// the agent's folder that differs from that commit is a change, reviewed with
// the same rules; secrets are held back on both sides with the same rules the
// upload uses, so a secret file is neither measured nor brought back. Changes
// not committed here are never part of the baseline, so --apply cannot undo
// them silently: a patch that does not fit the folder is kept as a file.
//
// The baseline is HEAD's exact bytes (git ls-tree and cat-file, no filters):
// git archive applies export-ignore, export-subst and eol conversion, so files
// it leaves out or rewrites showed as changed (RV-T6A). What run left out
// with --exclude is known only on the first computer, and the actor's copy of
// it is the agent's to rewrite, so here the person repeats it (pull
// --exclude, or --no-exclude when run had none) and it is held back on both
// sides; until then --apply and --branch refuse (ExcludesUnknownError), since
// any path the agent wrote or left out may be one run held back.

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// NoRecordError is pull's refusal on a computer that has no record of the
// copy and cannot take this folder's last commit as the baseline either.
// Reason says why, in plain words.
type NoRecordError struct{ Reason string }

func (e *NoRecordError) Error() string {
	return "this computer has no record of the folder you sent, and " + e.Reason
}

// elsewhereFolders are the names the first computer may have given the
// folder in the actor: the copy pipeline's (Linux, macOS) and the host
// copy's (Windows), the same for ordinary names.
func elsewhereFolders(project string) []string {
	a, b := osw.RepoName(project), hostFolderName(project)
	if a == b {
		return []string{a}
	}
	return []string{a, b}
}

// ExcludesUnknownError is Apply's refusal, on a computer that did not run
// run, to write or branch the agent's work before the person said what run
// left out with --exclude there (GAP-0489, RV-T6A).
type ExcludesUnknownError struct{ Name string }

func (e *ExcludesUnknownError) Error() string {
	return "nothing was written: this computer cannot know which paths run left out with --exclude on the computer you started the agent from, " +
		"and any file the agent wrote or left out may be one of them. Pull again with the same --exclude run had (repeat it for each), or --no-exclude if it had none; " +
		"or write a patch with --patch-out FILE and look at it first"
}

// adoptBaseline makes the host-copy record pull measures against on a
// computer that has none: the last commit of project, without what the
// upload holds back (the default rules and masks, the --exclude the person
// repeated here; stated says they did), and the agent's folder of the same
// name. A record adopted before for the same folder and the same masks is
// kept, so a later pull goes on from what an apply brought back.
func adoptBaseline(ctx context.Context, c *Client, dataDir, name, project string, masks []string, stated bool) error {
	if project == "" {
		return &NoRecordError{Reason: "pull was not given a folder to compare with"}
	}
	abs, err := filepath.Abs(project)
	if err != nil {
		return err
	}
	if rec, err := loadHostRecord(dataDir, name); err == nil && rec.LocalHead != "" && rec.Project == abs &&
		slices.Equal(rec.Masks, masks) && rec.ExcludesStated == stated {
		return nil
	}
	out, err := hostGit(ctx, abs, nil, nil, "rev-parse", "--verify", "--quiet", "HEAD^{commit}")
	if err != nil {
		return &NoRecordError{Reason: "this folder is not a git checkout with a commit to compare the agent's work with"}
	}
	head := strings.TrimSpace(string(out))
	root, err := c.Root(ctx)
	if err != nil {
		return cleanErr("find the agent's folder", err)
	}
	var folder, remote string
	for _, f := range elsewhereFolders(abs) {
		dir := path.Join(root, f)
		resp, err := c.request(ctx, "the agent's folder", http.MethodGet, relay.RouteFiles, url.Values{"path": {dir}}, nil, "", http.StatusOK)
		if err == nil {
			resp.Body.Close()
			folder, remote = f, dir
			break
		}
		var he *HTTPError
		if !errors.As(err, &he) || he.Status != http.StatusNotFound {
			return cleanErr("find the agent's folder", err)
		}
	}
	if remote == "" {
		return &NoRecordError{Reason: fmt.Sprintf("the agent has no folder named %s under %s: run pull in a checkout of the folder you sent", elsewhereFolders(abs)[0], root)}
	}
	if err := safefile.ProtectDirectory(hostDir(dataDir)); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(hostDir(dataDir), ".elsewhere-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	limit := c.MaxDownloadBytes
	if limit <= 0 {
		limit = DefaultMaxDownloadBytes
	}
	tarball, err := headTreeTar(ctx, abs, folder, limit)
	if err != nil {
		return cleanErr("read this folder's last commit", err)
	}
	files, _, held, err := stageHostTree(bytes.NewReader(tarball), folder, stage, limit, func(rel string) bool {
		_, h := osw.HeldBack(rel, masks, nil, nil, nil)
		return h
	})
	if err != nil {
		return cleanErr("read this folder's last commit", err)
	}
	det := osw.DefaultSecretDetector()
	kept := files[:0]
	var bytesTotal int64
	for _, f := range files {
		content := func() ([]byte, bool) {
			if f.size > 256<<10 {
				return nil, false
			}
			b, err := os.ReadFile(filepath.Join(stage, filepath.FromSlash(f.rel)))
			return b, err == nil
		}
		if _, h := osw.HeldBack(f.rel, masks, nil, content, det); h {
			held = append(held, f.rel)
			continue
		}
		bytesTotal += f.size
		kept = append(kept, f)
	}
	gitDir := hostGitDir(dataDir, name)
	if err := os.RemoveAll(gitDir); err != nil {
		return err
	}
	if _, err := hostGit(ctx, stage, nil, nil, "init", "-q", "--bare", gitDir); err != nil {
		return err
	}
	baseline, err := hostCommit(ctx, gitDir, stage, kept, "")
	if err != nil {
		return cleanErr("read this folder's last commit", err)
	}
	rec := &hostRecord{Version: hostRecordVersion, Name: name, Project: abs, Folder: folder, RemoteDir: remote,
		Baseline: baseline, HeldBack: held, Files: len(kept), Bytes: bytesTotal, UploadedAt: time.Now().UTC(), LocalHead: head,
		Masks: masks, ExcludesStated: stated}
	return rec.save(dataDir)
}

// headTreeTar is a tar of HEAD's tree of the folder dir (HEAD:./, also below
// the top of the repository) under folder/, with the bytes as committed: the
// blobs read with cat-file, which applies no attribute (git archive applies
// export-ignore, export-subst and eol and smudge conversion). Links and
// submodules are left out, as stageHostTree leaves them out of the agent's
// copy.
func headTreeTar(ctx context.Context, dir, folder string, limit int64) ([]byte, error) {
	out, err := hostGit(ctx, dir, nil, nil, "ls-tree", "-r", "-z", "-l", "HEAD:./")
	if err != nil {
		return nil, err
	}
	type entry struct {
		exec      bool
		oid, path string
		size      int64
	}
	var entries []entry
	var total int64
	var batch bytes.Buffer
	for _, line := range splitNUL(out) {
		meta, p, ok := strings.Cut(line, "\t")
		f := strings.Fields(meta)
		if !ok || len(f) != 4 || f[1] != "blob" || f[0] != "100644" && f[0] != "100755" {
			continue
		}
		size, err := strconv.ParseInt(f[3], 10, 64)
		if err != nil || size < 0 {
			return nil, fmt.Errorf("git ls-tree gave %q", line)
		}
		if total += size; total > limit {
			return nil, fmt.Errorf("this folder's last commit is larger than %d MB", limit>>20)
		}
		entries = append(entries, entry{exec: f[0] == "100755", oid: f[2], path: p, size: size})
		batch.WriteString(f[2] + "\n")
	}
	var blobs []byte
	if len(entries) > 0 {
		if blobs, err = hostGit(ctx, dir, nil, batch.Bytes(), "cat-file", "--batch"); err != nil {
			return nil, err
		}
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		nl := bytes.IndexByte(blobs, '\n')
		if nl < 0 {
			return nil, errors.New("git cat-file gave a short answer")
		}
		head := strings.Fields(string(blobs[:nl]))
		end := int64(nl) + 1 + e.size
		if len(head) != 3 || head[0] != e.oid || head[1] != "blob" || head[2] != strconv.FormatInt(e.size, 10) || int64(len(blobs)) < end+1 {
			return nil, fmt.Errorf("git cat-file gave %q for %s", blobs[:nl], e.path)
		}
		mode := int64(0o644)
		if e.exec {
			mode = 0o755
		}
		if err := tw.WriteHeader(&tar.Header{Name: folder + "/" + e.path, Mode: mode, Size: e.size, Typeflag: tar.TypeReg}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(blobs[nl+1 : end]); err != nil {
			return nil, err
		}
		blobs = blobs[end+1:]
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// elsewhereNote is the review line of a pull measured against this
// folder's last commit.
func elsewhereNote(head string) string {
	if len(head) > 12 {
		head = head[:12]
	}
	return fmt.Sprintf("this computer has no record of the folder you sent, so the changes are measured against this folder's last commit (%s): "+
		"files the other computer sent that are not in that commit show as added", head)
}

// elsewhereExcludesNote says how the --exclude of run is honoured here.
func elsewhereExcludesNote(rec *hostRecord) string {
	switch {
	case !rec.ExcludesStated:
		return "this computer does not know what run left out with --exclude, so files it left out show as deleted and the agent's files there as changes; " +
			"--apply and --branch refuse until you pull again with the same --exclude (or --no-exclude if run had none)"
	case len(rec.Masks) > 0:
		return "held back on both sides, as run's --exclude: " + strings.Join(rec.Masks, ", ")
	}
	return ""
}
