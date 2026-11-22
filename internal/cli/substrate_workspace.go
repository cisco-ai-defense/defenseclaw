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

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/attach"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
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

// substratePreflight stages the source before Create can leave actor state.
func substratePreflight(ctx context.Context, cmd *cobra.Command, s *substrateSession, f *substrateRunFlags, project string) (*workspace.PreparedUpload, error) {
	w := cmd.ErrOrStderr()
	settings, err := s.Client.Launcher(ctx)
	maxBytes := settings.WorkspaceMaxBytes
	if err != nil {
		apiErr, ok := api.AsError(err)
		if !ok || apiErr.Status != http.StatusNotFound {
			return nil, substrateFail(err)
		}
		// Compatibility with clusters predating launcher settings.
		maxBytes = osw.DefaultCopyMaxBytes
		fmt.Fprintln(w, "Note: this cluster does not report its upload limit. Using the 500 MiB launcher default.")
	} else if maxBytes <= 0 || maxBytes > relay.MaxFilesBytes {
		return nil, errors.New("the cluster reported an invalid workspace upload limit")
	}
	if n := int64(f.maxUploadMB); n > 0 && n <= maxBytes>>20 {
		maxBytes = n << 20
	}
	home, _ := os.UserHomeDir()
	prepared, err := workspace.Preflight(ctx, workspace.StartOptions{
		Project: project, DataDir: auth.StateDir(), Home: home, RemoteRoot: f.remoteDir, MaxBytes: maxBytes,
		Masks: f.exclude, Unmask: f.unmask, UnmaskAsked: f.unmask, Replace: true,
	})
	if err != nil {
		var big *workspace.TooLargeError
		if errors.As(err, &big) {
			return nil, cliusage.WithExitCode(big, substrateExitRefused)
		}
		return nil, fmt.Errorf("could not stage the folder: %w", err)
	}
	prepared.Preview(w)
	return prepared, nil
}

// substrateUploadFolder sends the prepared copy and reports what was kept back.
func substrateUploadFolder(ctx context.Context, cmd *cobra.Command, s *substrateSession, a api.Actor, prepared *workspace.PreparedUpload) error {
	w := cmd.ErrOrStderr()
	rel, err := substrateOpenRelay(ctx, s, a)
	if err != nil {
		return err
	}
	defer rel.Close()
	fmt.Fprintln(w, "Copying this folder into the agent...")
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
	if line := res.KeptBackLine(); line != "" {
		fmt.Fprintln(w, "Held back from the copy: "+line[len("kept back: "):]+". Share one anyway with --unmask.")
	}
	for _, warn := range res.Warnings {
		fmt.Fprintln(w, "Note: "+warn)
	}
	return nil
}
