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

package extproc

import (
	"context"
	"net/url"
	"strings"
)

// PushGrantChecker answers whether actor atespace/actor holds an open
// push grant (internal/substrate/pushgrant, GAP-1073) and whether one is
// host/repo. push marks the receive-pack POST, which the grant counts.
type PushGrantChecker interface {
	CheckPush(ctx context.Context, atespace, actor, host, repo string, push bool) (active, match bool, granted string, err error)
}

const (
	receivePack     = "git-receive-pack"
	infoRefs        = "/info/refs"
	ambiguousRepo   = "\x00"
	pushGrantReason = "While pull --push-branch pushes this actor's work, a git push of this actor may go only to the repository the person approved"
)

// gitReceivePack reports a git smart-HTTP push request and its repository
// path: GET <repo>/info/refs?service=git-receive-pack or POST
// <repo>/git-receive-pack, on the canonical path. post marks the POST. A
// path an origin could read another way that names receive-pack is a push
// to no repository (it never matches a grant).
func gitReceivePack(req *Request) (repo string, post, ok bool) {
	raw, query, _ := strings.Cut(req.Path, "?")
	p, err := canonicalPath(pathOnly(raw))
	if err != nil {
		if strings.Contains(strings.ToLower(req.Path), "receive-pack") {
			return ambiguousRepo, req.Method != "GET" && req.Method != "HEAD", true
		}
		return "", false, false
	}
	lp := strings.ToLower(p)
	switch {
	case strings.HasSuffix(lp, "/"+receivePack):
		return p[:len(p)-len(receivePack)-1], req.Method != "GET" && req.Method != "HEAD", true
	case strings.HasSuffix(lp, infoRefs) && serviceIsReceivePack(query):
		return p[:len(p)-len(infoRefs)], false, true
	}
	return "", false, false
}

// serviceIsReceivePack reads the service parameter of an info/refs query;
// any spelling of it that names receive-pack counts.
func serviceIsReceivePack(query string) bool {
	if query == "" {
		return false
	}
	if q, err := url.ParseQuery(query); err == nil {
		for k, vs := range q {
			if !strings.EqualFold(k, "service") {
				continue
			}
			for _, v := range vs {
				if strings.EqualFold(strings.TrimSpace(v), receivePack) {
					return true
				}
			}
		}
		return false
	}
	return strings.Contains(strings.ToLower(query), "receive-pack")
}

// pushGrantStage enforces an open push grant at egress (GAP-1073): while
// the actor holds one, a git push to any other host/repo is refused
// (push_redirect). With no grant the request is decided as before. A check
// that gets no answer refuses the POST that sends (retryable) and lets the
// info/refs GET through with an alert, as for a chain check (GAP-0601).
func (e *Engine) pushGrantStage(ctx context.Context, v Verdict, req *Request) (Verdict, bool) {
	if e.pushGrants == nil {
		return v, false
	}
	repo, post, ok := gitReceivePack(req)
	if !ok {
		return v, false
	}
	budget := e.cfg.Chain.SendBudget
	if budget <= 0 {
		budget = MessageBudget
	}
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	active, match, granted, err := e.pushGrants.CheckPush(cctx, req.Actor.Atespace, req.Actor.Name, req.Host, repo, post)
	switch {
	case err != nil:
		if post {
			v = deny(v, CategoryPushUnchecked, sourceCallout, "push_grant",
				"DefenseClaw could not check this git push against the repository a person approved for this actor.")
			v.Retryable = true
			return v, true
		}
		v.Alert = true
		v.Findings = append(v.Findings, "push_grant_unchecked")
	case active && !match:
		return deny(v, CategoryPushRedirect, sourceCallout, "push_grant", clip(pushGrantReason+" ("+granted+").", 400)), true
	}
	return v, false
}
