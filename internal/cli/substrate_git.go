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
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// substrateGitFrom is substrate.git as the launcher settings report it,
// the defaults (the built-in rewrites, submodules and LFS on) from a
// gateway that predates it.
func substrateGitFrom(settings api.LauncherSettings) api.LauncherGit {
	g := api.LauncherGit{Submodules: true, LFS: true}
	if settings.Git != nil {
		g = *settings.Git
	}
	if g.HTTPSRewrite == nil {
		g.HTTPSRewrite = config.DefaultSubstrateGitHTTPSRewrite()
	}
	return g
}

// substrateGitSettings reads substrate.git once per run; any error gives
// the defaults, which are what the images bake in.
func substrateGitSettings(ctx context.Context, s *substrateSession, f *substrateRunFlags) api.LauncherGit {
	if f.git == nil {
		settings, _ := s.Client.Launcher(ctx)
		g := substrateGitFrom(settings)
		f.git = &g
	}
	return *f.git
}

// substrateGitRules is the rewrite map read so far, nil (the default)
// before any.
func substrateGitRules(f *substrateRunFlags) []config.SubstrateGitRewrite {
	if f == nil || f.git == nil {
		return nil
	}
	return f.git.HTTPSRewrite
}

// substrateGitHTTPS turns an ssh or scp-form address into the https
// address git in the agent uses with rules and the image's ssh://git@
// rules; ok is false when none gives https.
func substrateGitHTTPS(rules []config.SubstrateGitRewrite) func(string) (string, bool) {
	return func(raw string) (string, bool) {
		v, ok := config.RewriteGitURL(raw, rules)
		return v, ok && strings.HasPrefix(v, "https://")
	}
}

// substrateGitRewriteAtStart writes a rewrite map other than the default
// into the new agent's git config, before any upload or clone (B2 2.5).
// Images bake the default, so it then does nothing. A failure is a
// warning: the map is a convenience, not a control.
func substrateGitRewriteAtStart(ctx context.Context, cmd *cobra.Command, s *substrateSession, a api.Actor, f *substrateRunFlags) {
	g := substrateGitSettings(ctx, s, f)
	if slices.Equal(g.HTTPSRewrite, config.DefaultSubstrateGitHTTPSRewrite()) {
		return
	}
	err := func() error {
		rel, err := substrateOpenRelay(ctx, s, a)
		if err != nil {
			return err
		}
		defer rel.Close()
		return workspace.WriteGitRewrite(ctx, rel.Client, g.HTTPSRewrite)
	}()
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: the cluster's git address rewrites are not in the agent (%s); ssh addresses of your git servers may not clone.\n", safetext.Line(err.Error()))
	}
}
