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
	"os"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/attach"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
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

// substrateUploadFolder copies the project into the agent (secret files held
// back) and says what was kept back.
func substrateUploadFolder(ctx context.Context, cmd *cobra.Command, s *substrateSession, a api.Actor, f *substrateRunFlags, project string) error {
	w := cmd.ErrOrStderr()
	rel, err := substrateOpenRelay(ctx, s, a)
	if err != nil {
		return err
	}
	defer rel.Close()
	home, _ := os.UserHomeDir()
	opts := workspace.StartOptions{
		Transport: rel.Client, Project: project, Name: substrateCopyName(a), DataDir: auth.StateDir(), Home: home,
		RemoteRoot: f.remoteDir, Masks: f.exclude, Unmask: f.unmask, UnmaskAsked: f.unmask, Replace: true,
	}
	if f.maxUploadMB > 0 {
		opts.MaxBytes = int64(f.maxUploadMB) << 20
	}
	fmt.Fprintln(w, "Copying this folder into the agent...")
	res, err := workspace.Start(ctx, opts)
	if err != nil {
		var big *workspace.TooLargeError
		if errors.As(err, &big) {
			return withExitCode(big, substrateExitRefused)
		}
		return fmt.Errorf("could not copy the folder into the agent: %w", err)
	}
	if line := res.KeptBackLine(); line != "" {
		fmt.Fprintln(w, "Held back from the copy: "+line[len("kept back: "):]+". Share one anyway with --unmask.")
	}
	for _, warn := range res.Warnings {
		fmt.Fprintln(w, "Note: "+warn)
	}
	return nil
}
