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

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// SourceOptions tunes a Source. Workload != nil selects workload mode:
// the token is read fresh on every call and the store is not used.
// Kube != nil (and Workload nil) selects kube mode: the bearer comes from
// the kubeconfig user, is kept until refreshSkew before its expiry (5
// minutes when it states none; a tokenFile is read on every call), and
// the store is not used.
type SourceOptions struct {
	Workload   *WorkloadOptions
	Kube       *KubeOptions
	HTTPClient *http.Client
	Now        func() time.Time
}

// Source hands out the bearer for the admin listener, refreshing the
// person sign-in when it is about to expire. It is safe for concurrent
// use; refreshes are serialized.
type Source struct {
	name  string
	ctx   Context
	store Store
	opts  SourceOptions

	mu   sync.Mutex
	tok  *Token
	disc *discovery
	hc   *http.Client

	kube      *Token
	kubeUntil time.Time
}

// NewSource returns the token source of context name.
func NewSource(name string, c Context, st Store, o SourceOptions) *Source {
	return &Source{name: name, ctx: c, store: st, opts: o}
}

func (s *Source) now() time.Time {
	if s.opts.Now != nil {
		return s.opts.Now()
	}
	return time.Now()
}

// Token returns the bearer for the admin listener. Errors wrap
// ErrNotSignedIn when a new sign-in is needed; network errors are
// returned as they are.
func (s *Source) Token(ctx context.Context) (string, error) {
	if s.opts.Workload != nil {
		return s.workload(ctx)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.opts.Kube != nil {
		t, err := s.kubeLocked(ctx)
		if err != nil {
			return "", err
		}
		return t.AccessToken, nil
	}
	t, err := s.personLocked(ctx)
	if err != nil {
		return "", err
	}
	b, _ := t.pick(s.now())
	return b, nil
}

// Current returns the sign-in in use (refreshed when due). The caller
// must not print its token fields.
func (s *Source) Current(ctx context.Context) (*Token, error) {
	if s.opts.Workload != nil {
		raw, err := s.workload(ctx)
		if err != nil {
			return nil, err
		}
		return workloadToken(raw), nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	get := s.personLocked
	if s.opts.Kube != nil {
		get = s.kubeLocked
	}
	t, err := get(ctx)
	if err != nil {
		return nil, err
	}
	cp := *t
	cp.Groups = append([]string(nil), t.Groups...)
	return &cp, nil
}

func (s *Source) workload(ctx context.Context) (string, error) {
	o := *s.opts.Workload
	if o.HTTPClient == nil {
		o.HTTPClient = s.opts.HTTPClient
	}
	return readWorkload(ctx, s.ctx, o, s.now())
}

// kubeLocked returns the kube bearer, read again when the kept one is
// within refreshSkew of its expiry, older than kubeNoExpiryKeep when it
// states no expiry, or came from a tokenFile. On every call it first
// checks the pin of login --kube (checkKubePin): the admin URL and the
// kubeconfig's cluster must be the verified ones, else no token.
func (s *Source) kubeLocked(ctx context.Context) (*Token, error) {
	o := *s.opts.Kube
	if o.Now == nil {
		o.Now = s.now
	}
	o = o.withDefaults()
	sel, err := checkKubePin(s.ctx, o)
	if err != nil {
		s.kube = nil
		return nil, err
	}
	now := s.now()
	if s.kube != nil && now.Before(s.kubeUntil) {
		return s.kube, nil
	}
	t, fromFile, err := kubeCredential(ctx, o, sel)
	if err != nil {
		s.kube = nil
		return nil, err
	}
	s.kube, s.kubeUntil = t, time.Time{}
	switch {
	case fromFile:
	case t.Expiry.IsZero():
		s.kubeUntil = now.Add(kubeNoExpiryKeep)
	default:
		s.kubeUntil = t.Expiry.Add(-refreshSkew)
	}
	return t, nil
}

func (s *Source) personLocked(ctx context.Context) (*Token, error) {
	if s.tok == nil {
		if s.store == nil {
			return nil, ErrNotSignedIn
		}
		t, err := s.store.Load(s.name)
		if err != nil {
			return nil, err
		}
		if t == nil {
			return nil, ErrNotSignedIn
		}
		if t.Issuer != "" && s.ctx.Issuer != "" && t.Issuer != s.ctx.Issuer {
			return nil, errNotSignedIn("the saved sign-in is for another issuer")
		}
		s.tok = t
	}
	now := s.now()
	if !s.tok.stale(now) {
		return s.tok, nil
	}
	if s.tok.RefreshToken == "" {
		if _, ok := s.tok.pick(now); ok {
			return s.tok, nil
		}
		return nil, errNotSignedIn("the sign-in expired")
	}
	if err := s.refreshLocked(ctx); err != nil {
		return nil, err
	}
	if _, ok := s.tok.pick(s.now()); !ok {
		return nil, errors.New("the issuer returned tokens that are already expired; check this computer's clock")
	}
	return s.tok, nil
}

func (s *Source) client() (*http.Client, error) {
	if s.opts.HTTPClient != nil {
		return s.opts.HTTPClient, nil
	}
	if s.hc == nil {
		hc, err := newHTTPClient(s.ctx.IssuerCAFile)
		if err != nil {
			return nil, fmt.Errorf("issuer_ca_file: %w", err)
		}
		s.hc = hc
	}
	return s.hc, nil
}

// refreshLocked swaps s.tok for a refreshed, saved token.
func (s *Source) refreshLocked(ctx context.Context) error {
	if s.ctx.Issuer == "" || s.ctx.ClientID == "" {
		return errNotSignedIn("the context has no issuer or client_id to refresh the sign-in with")
	}
	hc, err := s.client()
	if err != nil {
		return err
	}
	if s.disc == nil {
		d, err := discover(ctx, hc, s.ctx.Issuer, false)
		if err != nil {
			return err
		}
		s.disc = d
	}
	old := s.tok
	status, body, err := postForm(ctx, hc, s.disc.TokenEndpoint, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {old.RefreshToken},
		"client_id":     {s.ctx.ClientID},
	})
	if err != nil {
		return fmt.Errorf("refresh the sign-in: %w", err)
	}
	if status == http.StatusOK {
		var tr tokenResponse
		if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
			return errors.New("the issuer's refresh answer has no access_token")
		}
		nt := tr.toToken(s.now(), old)
		s.tok = nt
		if s.store != nil {
			if err := s.store.Save(s.name, nt); err != nil {
				return fmt.Errorf("the sign-in was refreshed but could not be saved (%w); the next command may ask you to sign in again", err)
			}
		}
		return nil
	}
	oe := parseOAuthError(body, old.RefreshToken, old.AccessToken, old.IDToken)
	if oe.Code == "invalid_grant" {
		// Another launcher process may have rotated the refresh token.
		if s.store != nil {
			if st, lerr := s.store.Load(s.name); lerr == nil && st != nil && st.RefreshToken != old.RefreshToken {
				if _, ok := st.pick(s.now()); ok {
					s.tok = st
					return nil
				}
			}
		}
		reason := "the issuer ended the sign-in"
		if oe.Description != "" {
			reason += ": " + oe.Description
		}
		return errNotSignedIn(reason)
	}
	return fmt.Errorf("refreshing the sign-in failed (HTTP %d%s)", status, oe.suffix())
}

// Logout revokes the refresh token at the issuer's revocation_endpoint
// when it has one (best effort; failures are ignored) and deletes the
// saved sign-in.
func Logout(ctx context.Context, name string, c Context, st Store, hc *http.Client) error {
	if st == nil {
		return nil
	}
	t, err := st.Load(name)
	if err == nil && t != nil && t.RefreshToken != "" && c.Issuer != "" && c.ClientID != "" {
		revoke(ctx, c, hc, t.RefreshToken)
	}
	return st.Delete(name)
}

func revoke(ctx context.Context, c Context, hc *http.Client, refresh string) {
	if hc == nil {
		var err error
		if hc, err = newHTTPClient(c.IssuerCAFile); err != nil {
			return
		}
	}
	d, err := discover(ctx, hc, c.Issuer, false)
	if err != nil || d.RevocationEndpoint == "" {
		return
	}
	_, _, _ = postForm(ctx, hc, d.RevocationEndpoint, url.Values{
		"token":           {refresh},
		"token_type_hint": {"refresh_token"},
		"client_id":       {c.ClientID},
	})
}
