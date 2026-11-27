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

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/pushgrant"
)

// B2 2.4: `substrate pull NAME --push-branch BR` asks this route before the
// launcher pushes an actor's work to its origin with the bound token. The
// answer is allow, ask or deny from the profile floor's git_push and
// substrate.git.push_branch. The agent's own git push stays governed by
// hooks and egress url_rules, as before, except while a launcher push holds
// a grant (GAP-1073): an allow to a launcher that asks for one (?grant=1)
// opens a push grant on the leader, and until the launcher closes it
// (DELETE .../push/{grant}) or it expires the egress callout refuses every
// git push of the actor to another repository. So a push the agent
// redirects inside the actor fails outside it.

// SubstratePushGrants is the leader's push grants (pushgrant.Client).
type SubstratePushGrants interface {
	OpenPushGrant(ctx context.Context, in pushgrant.OpenRequest) (pushgrant.Opened, error)
	ClosePushGrant(ctx context.Context, in pushgrant.CloseRequest) (pushgrant.Closed, error)
}

// SubstrateGitPushFor is git_push for an actor of profile: the floor's
// git_push (deny wins between substrate.admin and the profile), else
// substrate.git.push_branch; push_branch deny wins over all. A floor that
// cannot be computed denies.
func SubstrateGitPushFor(cfg *config.Config) func(profile string) string {
	if cfg == nil {
		return nil
	}
	return func(profile string) string {
		floor, err := substrateActorFloor(cfg, profile)
		if err != nil {
			return config.SubstrateGitPushDeny
		}
		return floor.EffectiveGitPush(cfg.Substrate.Git.EffectivePushBranch())
	}
}

// substrateGitPushApproval is how long an approved git_push ask answers the
// launcher's next call for the same push: same branch, repository and
// head (it pushes right after the answer).
const substrateGitPushApproval = 10 * time.Minute

var (
	substrateGitPushHost   = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?$`)
	substrateGitPushHead   = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	substrateGitPushBranch = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)
)

// substrateGitPushBranchOK is a short form of git check-ref-format for a
// branch name the launcher pushes to.
func substrateGitPushBranchOK(b string) bool {
	return substrateGitPushBranch.MatchString(b) && !strings.HasPrefix(b, "-") && !strings.HasPrefix(b, "/") &&
		!strings.HasSuffix(b, "/") && !strings.HasSuffix(b, ".") && !strings.HasSuffix(b, ".lock") &&
		!strings.Contains(b, "..") && !strings.Contains(b, "//") && !strings.Contains(b, "/.") && !strings.HasPrefix(b, ".") && b != "HEAD"
}

func (a *APIServer) substrateGitPush(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if st.cfg.GitPush == nil || st.cfg.Asks == nil {
			writeSubstrateJSONError(w, http.StatusNotImplemented, "push_unavailable")
			return
		}
		raw, ok := readAllLimited(r.Body, 8<<10)
		var in struct {
			Host    string `json:"host"`
			Repo    string `json:"repo"`
			URL     string `json:"url,omitempty"`
			Branch  string `json:"branch"`
			Head    string `json:"head"`
			Commits int    `json:"commits"`
			Files   int    `json:"files"`
			AskID   string `json:"ask_id,omitempty"`
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if !ok || dec.Decode(&in) != nil {
			writeSubstrateJSONError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		in.Host = strings.ToLower(strings.TrimSpace(in.Host))
		in.Repo = strings.Trim(strings.TrimSpace(in.Repo), "/")
		if !substrateGitPushHost.MatchString(in.Host) || in.Repo == "" || len(in.Repo) > 512 || strings.ContainsAny(in.Repo, " \t\r\n\"\\") ||
			!substrateGitPushBranchOK(in.Branch) || !substrateGitPushHead.MatchString(in.Head) || in.Commits < 0 || in.Files < 0 || len(in.AskID) > 64 ||
			in.URL != "" && in.URL != "https://"+in.Host+"/"+in.Repo && in.URL != "https://"+in.Host+"/"+in.Repo+".git" {
			writeSubstrateJSONError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		reg, status, reason := a.substrateFindSession(st, r, r.PathValue("atespace"), r.PathValue("name"))
		if status != http.StatusOK {
			writeSubstrateJSONError(w, status, reason)
			return
		}
		// The ask names the exact address the launcher pushes to.
		target := in.Host + "/" + in.Repo
		if in.URL != "" {
			target = in.URL
		}
		answer := func(decision, why string, extra map[string]any) {
			a.substrateAuditGitPush(r, reg.Atespace+"/"+reg.Name, reg.Person.ID(), target, in.Branch, in.Commits, in.Files, decision, why)
			out := map[string]any{"decision": decision, "reason": why}
			for k, v := range extra {
				out[k] = v
			}
			if decision == config.SubstrateGitPushAllow && r.URL.Query().Get("grant") == "1" {
				// GAP-1073: the grant the callout enforces while the
				// launcher pushes. One that cannot be opened is said, and
				// the launcher warns (an older leader, a full store).
				g, err := a.substrateOpenPushGrant(r.Context(), st, reg.Atespace, reg.Name, reg.UID, in.Host, in.Repo, in.Branch)
				if err != nil {
					out["grant_error"] = err.Error()
				} else {
					out["grant"], out["grant_expires"] = g.ID, g.Expires
				}
			}
			writeSubstrateJSON(w, http.StatusOK, out)
		}
		switch st.cfg.GitPush(reg.Profile) {
		case config.SubstrateGitPushAllow:
			answer(config.SubstrateGitPushAllow, "git_push_allowed", nil)
			return
		case config.SubstrateGitPushAsk:
		default:
			answer(config.SubstrateGitPushDeny, "git_push_denied", map[string]any{"profile": reg.Profile})
			return
		}
		ask := asks.Ask{
			Kind: asks.KindGitPush, Atespace: reg.Atespace, Actor: reg.Name, UID: reg.UID, OwnerID: reg.Person.ID(), Profile: reg.Profile,
			Host: in.Host, Tool: in.Branch, Rule: asks.GitPushRule(in.Repo, in.Head),
			Summary: fmt.Sprintf("Push %s at %s (%d commits, %d files) to %s?", in.Branch, in.Head[:12], in.Commits, in.Files, target),
		}
		mine, err := st.cfg.Asks.List(r.Context(), asks.ListRequest{All: true, OwnerID: ask.OwnerID})
		if err != nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "asks_unavailable")
			return
		}
		now := time.Now()
		for _, o := range mine {
			if o.Kind != asks.KindGitPush || o.UID != reg.UID || o.Host != ask.Host || o.Tool != ask.Tool || o.Rule != ask.Rule {
				continue
			}
			// The launcher reads its own ask again (ask_id); a run started
			// after someone approved the same push in approvals finds that
			// approval for a short while.
			named := in.AskID != "" && o.ID == in.AskID
			switch {
			case o.State == asks.StateApproved && (named || in.AskID == "") && now.Sub(o.DecidedAt) <= substrateGitPushApproval:
				answer(config.SubstrateGitPushAllow, "approved", map[string]any{"ask_id": o.ID, "decided_by": o.DecidedBy})
				return
			case named && o.State == asks.StateDenied:
				answer(config.SubstrateGitPushDeny, "ask_denied", map[string]any{"ask_id": o.ID})
				return
			case named && o.State == asks.StatePending:
				writeSubstrateJSON(w, http.StatusOK, map[string]any{"decision": config.SubstrateGitPushAsk, "ask_id": o.ID, "summary": o.Summary})
				return
			}
		}
		if slices.ContainsFunc(mine, func(o asks.Ask) bool {
			// approve --always: the same person, profile and host.
			return o.Kind == asks.KindGitPush && o.Always && o.State == asks.StateApproved &&
				o.OwnerID == ask.OwnerID && o.Profile == ask.Profile && o.Host == ask.Host
		}) {
			answer(config.SubstrateGitPushAllow, "approved with --always for this person, profile and host", nil)
			return
		}
		opened, err := st.cfg.Asks.OpenAsk(r.Context(), ask)
		if err != nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "asks_unavailable")
			return
		}
		a.substrateAuditGitPush(r, reg.Atespace+"/"+reg.Name, ask.OwnerID, target, in.Branch, in.Commits, in.Files, config.SubstrateGitPushAsk, opened.ID)
		writeSubstrateJSON(w, http.StatusOK, map[string]any{"decision": config.SubstrateGitPushAsk, "ask_id": opened.ID, "summary": opened.Summary})
	}
}

var errSubstrateNoPushGrants = errors.New("push_grants_unavailable")

// substrateOpenPushGrant opens the leader's grant for a push of
// atespace/name to host/repo, refs/heads/branch.
func (a *APIServer) substrateOpenPushGrant(ctx context.Context, st *substrateState, atespace, name, uid, host, repo, branch string) (pushgrant.Opened, error) {
	if st.cfg.PushGrants == nil {
		return pushgrant.Opened{}, errSubstrateNoPushGrants
	}
	g, err := st.cfg.PushGrants.OpenPushGrant(ctx, pushgrant.OpenRequest{Atespace: atespace, Actor: name, UID: uid,
		Host: host, Repo: repo, Ref: "refs/heads/" + branch})
	if err != nil || !pushgrant.ValidID(g.ID) {
		return pushgrant.Opened{}, errSubstrateNoPushGrants
	}
	return g, nil
}

// substrateGitPushClose is DELETE .../push/{grant}: the launcher closes its
// grant after the push. The answer says whether the grant was still open
// and how many pushes to the approved repository egress checked under it.
func (a *APIServer) substrateGitPushClose(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("grant")
		if !pushgrant.ValidID(id) {
			writeSubstrateJSONError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		if st.cfg.PushGrants == nil {
			writeSubstrateJSONError(w, http.StatusNotImplemented, "push_grants_unavailable")
			return
		}
		reg, status, reason := a.substrateFindSession(st, r, r.PathValue("atespace"), r.PathValue("name"))
		if status != http.StatusOK {
			writeSubstrateJSONError(w, status, reason)
			return
		}
		c, err := st.cfg.PushGrants.ClosePushGrant(r.Context(), pushgrant.CloseRequest{Atespace: reg.Atespace, Actor: reg.Name, ID: id})
		if err != nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "push_grants_unavailable")
			return
		}
		writeSubstrateJSON(w, http.StatusOK, map[string]any{"closed": c.Found, "pushes": c.Pushes})
	}
}

// substrateAuditGitPush records a push decision (substrate_git_push): the
// actor, person, host and repository, branch and counts, never content.
func (a *APIServer) substrateAuditGitPush(r *http.Request, actor, person, target, branch string, commits, files int, decision, reason string) {
	if a.logger == nil {
		return
	}
	details := map[string]any{
		"event": "substrate_git_push", "actor": actor, "person": person, "target": target, "branch": branch,
		"commits": commits, "files": files, "decision": decision, "reason": reason,
	}
	_ = a.logger.LogAlertCtx(context.WithoutCancel(r.Context()), "substrate", "INFO",
		fmt.Sprintf("push of agent %s to %s branch %s: %s", actor, target, branch, decision), details)
}
