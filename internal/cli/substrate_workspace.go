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

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/attach"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
	"github.com/defenseclaw/defenseclaw/internal/config"
	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// substrateCopyName is the name of an agent's local copy record. The cluster
// names agents freely; the copy store wants short lowercase names, so the
// name is a fixed function of atespace and name.
func substrateCopyName(a api.Actor) string {
	sum := sha256.Sum256([]byte(a.Atespace + "/" + a.Name))
	return "sub-" + hex.EncodeToString(sum[:])[:12]
}

// substrateRelay is a tunnel to one agent with a workspace client on it.
type substrateRelay struct {
	Tunnel *attach.Tunnel
	Client *workspace.Client
}

func (r *substrateRelay) Close() { r.Tunnel.Close() }

// substrateOpenRelay opens the tunnel to an agent for file and command
// transfer (upload, pull, checkpoint).
func substrateOpenRelay(ctx context.Context, s *substrateSession, a api.Actor) (*substrateRelay, error) {
	target := attach.Target{Atespace: a.Atespace, Name: a.Name}
	tun, err := attach.NewTunnel(ctx, attach.Gateway{BaseURL: s.Ctx.AdminURL, CAFile: s.Ctx.AdminCAFile}, s.Bearer, target)
	if err != nil {
		return nil, substrateFail(err)
	}
	return &substrateRelay{Tunnel: tun, Client: workspace.NewClient(tun.HTTPClient(), tun.BaseURL(), tun.Bearer)}, nil
}

// substrateUploadLimit reads the cluster's upload limit and launcher
// settings; a gateway predating the route gets the launcher default.
func substrateUploadLimit(ctx context.Context, cmd *cobra.Command, s *substrateSession) (int64, api.LauncherSettings, error) {
	settings, err := s.Client.Launcher(ctx)
	if err != nil {
		apiErr, ok := api.AsError(err)
		if !ok || apiErr.Status != http.StatusNotFound {
			return 0, settings, substrateFail(err)
		}
		// Compatibility with clusters predating launcher settings.
		fmt.Fprintln(cmd.ErrOrStderr(), "Note: this cluster does not report its upload limit. Using the 500 MiB launcher default.")
		return osw.DefaultCopyMaxBytes, settings, nil
	}
	if settings.WorkspaceMaxBytes <= 0 || settings.WorkspaceMaxBytes > relay.MaxFilesBytes {
		return 0, settings, errors.New("the cluster reported an invalid workspace upload limit")
	}
	return settings.WorkspaceMaxBytes, settings, nil
}

// substratePreflight stages the source before Create can leave actor state.
func substratePreflight(ctx context.Context, cmd *cobra.Command, s *substrateSession, f *substrateRunFlags, project string) (*workspace.PreparedUpload, error) {
	w := cmd.ErrOrStderr()
	maxBytes, settings, err := substrateUploadLimit(ctx, cmd, s)
	if err != nil {
		return nil, err
	}
	if f.git == nil {
		g := substrateGitFrom(settings)
		f.git = &g
	}
	if n := int64(f.maxUploadMB); n > 0 && n <= maxBytes>>20 {
		maxBytes = n << 20
	}
	rewrite, scanMax, scanBudget := substrateUploadScan(settings.UploadScan)
	home, _ := os.UserHomeDir()
	prepared, err := workspace.Preflight(ctx, workspace.StartOptions{
		Project: project, DataDir: auth.StateDir(), Home: home, RemoteRoot: f.remoteDir, MaxBytes: maxBytes,
		Masks: f.exclude, Unmask: f.unmask, UnmaskAsked: f.unmask, Replace: true, Upstream: f.cloneHere,
		UpstreamHTTPS:  substrateGitHTTPS(f.git.HTTPSRewrite),
		RewriteSecrets: rewrite, ScanMaxFileBytes: scanMax, ScanTimeBudget: scanBudget,
	})
	if err != nil {
		var big *workspace.TooLargeError
		if errors.As(err, &big) {
			return nil, cliusage.WithExitCode(big, substrateExitRefused)
		}
		return nil, fmt.Errorf("could not stage the folder: %w", err)
	}
	prepared.Preview(w)
	if line := prepared.UpstreamLine(); line != "" {
		fmt.Fprintln(w, line)
	}
	return prepared, nil
}

// substrateUploadScan turns the cluster's upload_scan settings into the
// copy's: the placeholder form when the action is replace ("" holds files
// back, as does a gateway that predates the setting), the per-file limit
// and the time budget (0 = the pipeline defaults).
func substrateUploadScan(u *api.LauncherUploadScan) (string, int64, time.Duration) {
	if u == nil {
		return "", 0, 0
	}
	budget, _ := time.ParseDuration(u.TimeBudget)
	rewrite := ""
	if u.SecretAction == config.SubstrateUploadReplace {
		rewrite = osw.PlaceholderToken
		if u.PlaceholderForm == config.SubstratePlaceholderEnv {
			rewrite = osw.PlaceholderEnv
		}
	}
	return rewrite, u.MaxFileBytes, budget
}

// substrateCloneHere reports whether --clone names this checkout ("." or a
// folder) rather than a repository address.
func substrateCloneHere(v string) bool {
	if v == "." {
		return true
	}
	if strings.Contains(v, "://") {
		return false
	}
	st, err := os.Stat(v)
	return err == nil && st.IsDir()
}

// substratePrepareCloneHere turns run --clone . (B2 2.3, Preview) into a
// copy of the checkout that carries its upstream: only the unpushed commits
// and the working tree go up and the agent fetches the rest of the history
// from the remote. It returns the folder to copy. Windows copies have no git
// history (the host copy), so there the agent clones the remote at the
// branch instead, which needs the local work pushed: it returns "" and sets
// --clone to the remote's address.
func substratePrepareCloneHere(cmd *cobra.Command, s *substrateSession, f *substrateRunFlags) (string, error) {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	dir, err := filepath.Abs(f.clone)
	if err != nil {
		return "", err
	}
	if err := substrateCheckProject(dir); err != nil {
		return "", err
	}
	up, err := osw.ResolveUpstream(ctx, dir, substrateGitHTTPS(substrateGitSettings(ctx, s, f).HTTPSRewrite))
	if err != nil {
		var refused *osw.UpstreamError
		if errors.As(err, &refused) {
			return "", cliusage.WithExitCode(err, 2)
		}
		return "", fmt.Errorf("could not read the checkout: %w", err)
	}
	if err := workspace.CheckCloneURL(up.URL); err != nil {
		return "", cliusage.WithExitCode(err, 2)
	}
	if !workspace.UsesHostCopy() {
		f.cloneHere, f.clone = true, ""
		return dir, nil
	}
	if up.Commits > 0 || up.Dirty {
		return "", cliusage.WithExitCode(errors.New("on Windows, --clone . does not send unpushed commits or uncommitted changes yet; commit and push them first, or leave out --clone"), 2)
	}
	f.clone, f.ref = up.URL, up.Base
	if up.AtTip && up.Branch != "" && up.Branch != "HEAD" {
		f.ref = up.Branch
	}
	return "", nil
}

// substrateUploadFolder sends the prepared copy and reports what was kept back.
func substrateUploadFolder(ctx context.Context, cmd *cobra.Command, s *substrateSession, a api.Actor, prepared *workspace.PreparedUpload) error {
	w := cmd.ErrOrStderr()
	rel, err := substrateOpenRelay(ctx, s, a)
	if err != nil {
		return err
	}
	defer rel.Close()
	up := prepared.Upstream()
	if up != nil {
		fmt.Fprintf(w, "Cloning %s (branch %s) in the agent...\n", safetext.Line(up.URL), safetext.Line(up.Branch))
	} else {
		fmt.Fprintln(w, "Copying this folder into the agent...")
	}
	res, err := prepared.Send(ctx, substrateCopyName(a), rel.Client)
	if err != nil {
		var refused *workspace.HTTPError
		if prepared.UsesHigherUploadLimit() && errors.As(err, &refused) && refused.Status == http.StatusRequestEntityTooLarge && !rel.Client.ReportsUploadLimit() {
			return cliusage.WithExitCode(errors.New("this agent's image caps uploads at 1 GiB; rebuild the template to use your cluster's limit"), substrateExitRefused)
		}
		return fmt.Errorf("could not copy the folder into the agent: %w", err)
	}
	if prepared.UsesHigherUploadLimit() && !rel.Client.ReportsUploadLimit() {
		fmt.Fprintln(w, "Note: this agent's image caps uploads at 1 GiB; rebuild the template to use your cluster's limit.")
	}
	if up != nil {
		fmt.Fprintf(w, "The agent has the full history of %s.\n", safetext.Line(up.Branch))
	}
	if line := res.KeptBackLine(); line != "" {
		fmt.Fprintln(w, "Held back from the copy: "+line[len("kept back: "):]+". Share one anyway with --unmask.")
	}
	for _, line := range res.ReplacedLines() {
		fmt.Fprintln(w, line)
	}
	for _, warn := range res.Warnings {
		fmt.Fprintln(w, "Note: "+warn)
	}
	return nil
}
