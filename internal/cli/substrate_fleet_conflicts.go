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
	"errors"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/attach"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/fleet"
)

// errFleetNoSignIn is a DefenseClaw context that could not be opened.
type errFleetNoSignIn struct{ err error }

func (e *errFleetNoSignIn) Error() string { return e.err.Error() }
func (e *errFleetNoSignIn) Unwrap() error { return e.err }

// substrateFleetEveryone lists every person's agents with the DefenseClaw
// sign-in of the --context (default: the last one), for the policy_conflict
// count of verify and status --cluster; tests replace it.
var substrateFleetEveryone = func(cmd *cobra.Command, com *substrateCommon) func(context.Context) ([]api.Actor, error) {
	return func(ctx context.Context) ([]api.Actor, error) {
		s, err := substrateOpen(cmd, com)
		if err != nil {
			return nil, &errFleetNoSignIn{err}
		}
		return s.Client.ListEveryone(ctx)
	}
}

// readPolicyConflicts counts the agents in policy_conflict (GAP-0398). The
// controller marks them on the leader's registrations, which kubectl does
// not read: the count is one list of every person's agents through the
// admin listener, with the administrator's own sign-in. Without one (no
// context, signed out, not an administrator, no answer) the count is
// unknown and says why: a person's list is never counted as the cluster's.
func readPolicyConflicts(ctx context.Context, f *substrateClusterFlags, o *fleet.Observed) {
	if f.everyone == nil {
		o.Conflicts = &fleet.Conflicts{Reason: fleet.ConflictsNotRead}
		return
	}
	actors, err := f.everyone(ctx)
	if err != nil {
		o.Conflicts = &fleet.Conflicts{Reason: conflictsReason(err)}
		return
	}
	c := &fleet.Conflicts{Agents: []fleet.ConflictAgent{}}
	for _, a := range actors {
		if a.Deleted || a.PolicyConflict == nil {
			continue
		}
		c.Agents = append(c.Agents, fleet.ConflictAgent{Atespace: a.Atespace, Name: a.Name, Reverts: a.PolicyConflict.Reverts})
	}
	o.Conflicts = c
}

func conflictsReason(err error) string {
	var noSignIn *errFleetNoSignIn
	switch {
	case errors.As(err, &noSignIn):
		return fleet.ConflictsNoSignIn
	case errors.Is(err, api.ErrNotAdministrator):
		return fleet.ConflictsNotAdministrator
	case errors.Is(err, auth.ErrNotSignedIn), errors.Is(err, attach.ErrNotSignedIn):
		return fleet.ConflictsSignedOut
	}
	if e, ok := api.AsError(err); ok {
		switch e.Status {
		case http.StatusUnauthorized:
			return fleet.ConflictsSignedOut
		case http.StatusForbidden:
			return fleet.ConflictsNotAdministrator
		}
	}
	return fleet.ConflictsUnreachable
}
