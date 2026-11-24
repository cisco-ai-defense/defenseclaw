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

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
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

// adoptBaseline makes the host-copy record pull measures against on a
// computer that has none: the last commit of project, without what the
// upload holds back, and the agent's folder of the same name. A record
// adopted before for the same folder is kept, so a later pull goes on from
// what an apply brought back.
func adoptBaseline(ctx context.Context, c *Client, dataDir, name, project string) error {
	if project == "" {
		return &NoRecordError{Reason: "pull was not given a folder to compare with"}
	}
	abs, err := filepath.Abs(project)
	if err != nil {
		return err
	}
	if rec, err := loadHostRecord(dataDir, name); err == nil && rec.LocalHead != "" && rec.Project == abs {
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
	// The committed bytes as git checks them out here (HEAD:./ is the tree
	// of this folder, also below the top of the repository).
	tarball, err := hostGit(ctx, abs, nil, nil, "archive", "--format=tar", "--prefix="+folder+"/", "HEAD:./")
	if err != nil {
		return cleanErr("read this folder's last commit", err)
	}
	limit := c.MaxDownloadBytes
	if limit <= 0 {
		limit = DefaultMaxDownloadBytes
	}
	files, _, held, err := stageHostTree(bytes.NewReader(tarball), folder, stage, limit, func(rel string) bool {
		_, h := osw.HeldBack(rel, nil, nil, nil, nil)
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
		if _, h := osw.HeldBack(f.rel, nil, nil, content, det); h {
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
		Baseline: baseline, HeldBack: held, Files: len(kept), Bytes: bytesTotal, UploadedAt: time.Now().UTC(), LocalHead: head}
	return rec.save(dataDir)
}

// elsewhereNote is the review line of a pull measured against this
// folder's last commit.
func elsewhereNote(head string) string {
	if len(head) > 12 {
		head = head[:12]
	}
	return fmt.Sprintf("this computer has no record of the folder you sent, so the changes are measured against this folder's last commit (%s): "+
		"files the other computer sent that are not in that commit show as added, and files run left out there with --exclude show as deleted", head)
}
