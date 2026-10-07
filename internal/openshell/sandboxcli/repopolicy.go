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

package sandboxcli

import (
	"context"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// parseRepoPolicy is the repository policy a daemon's explain carries, as
// the packs package reads it: exactly the copy the daemon resolved the run
// with, so what the CLI resolves itself (the masks of a copy it stages)
// matches.
func parseRepoPolicy(rp *sandboxapi.RepoPolicy) (*packs.RepoPolicy, error) {
	if rp == nil {
		return nil, nil
	}
	p, err := packs.ParseRepoPolicy(rp.Content, rp.Path)
	if err != nil {
		return nil, fmt.Errorf("the repository policy %s: %w", packs.RepoPolicyPath, err)
	}
	if p.Digest != rp.Digest {
		return nil, fmt.Errorf("the repository policy %s the daemon sent does not match its digest", packs.RepoPolicyPath)
	}
	return p, nil
}

// sandboxRepoPolicy is the repository policy sandbox name runs with: the
// one its run read.
func (a *App) sandboxRepoPolicy(ctx context.Context, api API, name string) (*packs.RepoPolicy, error) {
	ex, err := api.Explain(ctx, sandboxapi.ExplainRequest{Sandbox: name})
	if err != nil {
		return nil, apiError(err)
	}
	return parseRepoPolicy(ex.RepoPolicy)
}

// repoPolicyChanged reports whether the repository policy a new run of the
// project reads (fresh, the preflight explain) differs from the copy a
// sandbox runs with (kept, its own explain; nil: unknown), which a resume
// keeps.
func repoPolicyChanged(fresh, kept *sandboxapi.Explain) bool {
	return fresh != nil && kept != nil && repoPolicyDigest(fresh.RepoPolicy) != repoPolicyDigest(kept.RepoPolicy)
}

// repoPolicyDigest is CreateRequest.RepoPolicyDigest for the repository
// policy a preflight explain reported.
func repoPolicyDigest(rp *sandboxapi.RepoPolicy) string {
	if rp == nil {
		return sandboxapi.NoRepoPolicy
	}
	return rp.Digest
}

// repoPolicyText is the banner's Policy line: what the project's repository
// policy did to the run, "" without one.
func repoPolicyText(rp *sandboxapi.RepoPolicy) string {
	if rp == nil {
		return ""
	}
	if len(rp.Tightened) == 0 {
		return "repo policy " + packs.RepoPolicyPath + ": the policy is as strict already"
	}
	return fmt.Sprintf("repo policy %s: tightened %s (%s)", packs.RepoPolicyPath,
		plural(int64(len(rp.Tightened)), "setting", "settings"), strings.Join(rp.Tightened, ", "))
}
