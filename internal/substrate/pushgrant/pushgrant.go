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

// Package pushgrant holds the egress push grants of pull --push-branch
// (GAP-1073). When the gateway allows a push of an actor's work to
// host/repo, it opens a grant on the leader; while the grant is open, the
// egress callout refuses every git push of that actor (smart-HTTP
// receive-pack) to any other repository, on any host. So a push the agent
// redirects inside the actor (git config, a git on PATH) fails at egress,
// outside the actor, and the launcher reports a failure instead of the
// approved repository. The leader keeps the grants in memory, bounded, for
// TTL at most; the launcher closes its grant after the push, and the close
// answer says how many pushes to the approved repository egress saw.
package pushgrant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// Methods. Gateway replicas open and close grants; the callout may only
// check (substrateLeaderPermissions).
const (
	MethodOpen  = "PushGrantOpen"
	MethodClose = "PushGrantClose"
	MethodCheck = "PushGrantCheck"
)

// Methods lists every method of this package.
var Methods = []string{MethodOpen, MethodClose, MethodCheck}

const (
	// TTL is how long a grant lives when nobody closes it: the launcher's
	// push budget (10 min) plus slack.
	TTL = 15 * time.Minute
	// MaxGrants bounds the open grants of the cluster, and MaxPerActor
	// those of one actor (the oldest leaves first).
	MaxGrants   = 1024
	MaxPerActor = 8
)

// OpenRequest opens a grant: actor Atespace/Actor may push to Host/Repo.
type OpenRequest struct {
	Atespace string `json:"atespace"`
	Actor    string `json:"actor"`
	UID      string `json:"uid,omitempty"`
	Host     string `json:"host"`
	Repo     string `json:"repo"`
	// Ref is the approved ref (refs/heads/<branch>), kept for the record.
	Ref string `json:"ref,omitempty"`
}

// Opened names the open grant.
type Opened struct {
	ID      string    `json:"id"`
	Expires time.Time `json:"expires"`
}

// CloseRequest closes the grant ID of the actor.
type CloseRequest struct {
	Atespace string `json:"atespace"`
	Actor    string `json:"actor"`
	ID       string `json:"id"`
}

// Closed is what became of a grant: Found is false for one that expired or
// was lost (a leader change); Pushes counts the receive-pack POSTs to the
// approved repository that egress checked while it was open.
type Closed struct {
	Found  bool `json:"found"`
	Pushes int  `json:"pushes"`
}

// CheckRequest is the callout's question for a git push of the actor to
// Host/Repo; Push marks the receive-pack POST (the one that sends).
type CheckRequest struct {
	Atespace string `json:"atespace"`
	Actor    string `json:"actor"`
	Host     string `json:"host"`
	Repo     string `json:"repo"`
	Push     bool   `json:"push,omitempty"`
}

// CheckAnswer: Active is false when the actor has no open grant (the push
// is decided as before); Match is true when one of them is Host/Repo.
// Granted names an approved host/repo for the refusal text.
type CheckAnswer struct {
	Active  bool   `json:"active"`
	Match   bool   `json:"match,omitempty"`
	Granted string `json:"granted,omitempty"`
}

var idRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidID reports a grant id's form.
func ValidID(id string) bool { return idRE.MatchString(id) }

// Host is the form hosts are compared in: lower case, no trailing dot, no
// brackets and no port (the callout sees no port in the host it decides).
func Host(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h[i:], "]") && strings.Count(h, ":") == 1 {
		h = h[:i]
	}
	h = strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(h, "["), "]"), ".")
	return h
}

// Repo is the form repository paths are compared in: no leading or
// trailing slash, lower case (the git hosts read owner and name without
// case), no .git suffix (both spellings name the same repository).
func Repo(p string) string {
	p = strings.ToLower(strings.Trim(strings.TrimSpace(p), "/"))
	return strings.Trim(strings.TrimSuffix(p, ".git"), "/")
}

type grant struct {
	id, atespace, actor, uid, host, repo, ref string
	opened, expires                           time.Time
	pushes                                    int
}

// Store is the leader's grants, in memory: a leader change drops them,
// and the launcher's close then reports the grant lost.
type Store struct {
	Now func() time.Time

	mu     sync.Mutex
	grants map[string]*grant
}

// NewStore returns an empty store.
func NewStore() *Store { return &Store{grants: map[string]*grant{}} }

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// prune drops expired grants; s.mu is held.
func (s *Store) prune(now time.Time) {
	for id, g := range s.grants {
		if !now.Before(g.expires) {
			delete(s.grants, id)
		}
	}
}

var errFull = &leader.WireError{Code: leader.CodeUnavailable, Message: "too many open push grants"}

// Open implements MethodOpen.
func (s *Store) Open(_ context.Context, in OpenRequest) (Opened, error) {
	host, repo := Host(in.Host), Repo(in.Repo)
	if in.Atespace == "" || in.Actor == "" || host == "" || repo == "" || len(repo) > 512 || len(in.Ref) > 256 {
		return Opened{}, &leader.WireError{Code: leader.CodeBadRequest, Message: "a grant needs an actor, a host and a repository"}
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return Opened{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.grants == nil {
		s.grants = map[string]*grant{}
	}
	now := s.now()
	s.prune(now)
	var mine []*grant
	for _, g := range s.grants {
		if g.atespace == in.Atespace && g.actor == in.Actor {
			mine = append(mine, g)
		}
	}
	for len(mine) >= MaxPerActor {
		old := 0
		for i, g := range mine {
			if g.opened.Before(mine[old].opened) {
				old = i
			}
		}
		delete(s.grants, mine[old].id)
		mine = append(mine[:old], mine[old+1:]...)
	}
	if len(s.grants) >= MaxGrants {
		return Opened{}, errFull
	}
	g := &grant{id: hex.EncodeToString(b), atespace: in.Atespace, actor: in.Actor, uid: in.UID, host: host, repo: repo, ref: in.Ref,
		opened: now, expires: now.Add(TTL)}
	s.grants[g.id] = g
	return Opened{ID: g.id, Expires: g.expires}, nil
}

// Close implements MethodClose: only the grant's own actor closes it.
func (s *Store) Close(_ context.Context, in CloseRequest) (Closed, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(s.now())
	g, ok := s.grants[in.ID]
	if !ok || g.atespace != in.Atespace || g.actor != in.Actor {
		return Closed{}, nil
	}
	delete(s.grants, in.ID)
	return Closed{Found: true, Pushes: g.pushes}, nil
}

// Check implements MethodCheck.
func (s *Store) Check(_ context.Context, in CheckRequest) (CheckAnswer, error) {
	host, repo := Host(in.Host), Repo(in.Repo)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(s.now())
	var out CheckAnswer
	for _, g := range s.grants {
		if g.atespace != in.Atespace || g.actor != in.Actor {
			continue
		}
		if !out.Active {
			out.Active, out.Granted = true, g.host+"/"+g.repo
		}
		if repo != "" && g.host == host && g.repo == repo {
			out.Match, out.Granted = true, g.host+"/"+g.repo
			if in.Push {
				g.pushes++
			}
		}
	}
	return out, nil
}

// Serve registers the grant methods on the leader server.
func Serve(srv *leader.Server, s *Store) {
	srv.Handle(MethodOpen, leader.Typed(s.Open))
	srv.Handle(MethodClose, leader.Typed(s.Close))
	srv.Handle(MethodCheck, leader.Typed(s.Check))
}

// Client calls the grant methods on the leader.
type Client struct {
	Leader *leader.Client
}

func (c *Client) call(ctx context.Context, method string, in, out any) error {
	if c == nil || c.Leader == nil {
		return errors.New("pushgrant: no leader client")
	}
	return c.Leader.Call(ctx, method, leader.NewRequestID(), in, out)
}

// OpenPushGrant opens a grant (gateway replicas).
func (c *Client) OpenPushGrant(ctx context.Context, in OpenRequest) (Opened, error) {
	var out Opened
	err := c.call(ctx, MethodOpen, in, &out)
	return out, err
}

// ClosePushGrant closes a grant (gateway replicas).
func (c *Client) ClosePushGrant(ctx context.Context, in CloseRequest) (Closed, error) {
	var out Closed
	err := c.call(ctx, MethodClose, in, &out)
	return out, err
}

// CheckPush is the callout's check of a git push of atespace/actor to
// host/repo. A leader that predates grants (unknown_method, a rolling
// upgrade) holds none, so the push is decided as before.
func (c *Client) CheckPush(ctx context.Context, atespace, actor, host, repo string, push bool) (active, match bool, granted string, err error) {
	var out CheckAnswer
	err = c.call(ctx, MethodCheck, CheckRequest{Atespace: atespace, Actor: actor, Host: host, Repo: repo, Push: push}, &out)
	var we *leader.WireError
	if errors.As(err, &we) && we.Code == leader.CodeUnknownMethod {
		return false, false, "", nil
	}
	if err != nil {
		return false, false, "", err
	}
	return out.Active, out.Match, out.Granted, nil
}
