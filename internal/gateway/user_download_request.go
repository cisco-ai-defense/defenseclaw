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
	"context"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// Bounds of userDownloadRequests.
const (
	// userRequestPrompts is the number of prompts weighed: this turn's and
	// the two before it, so "download X and run it" then "yes, go ahead"
	// counts.
	userRequestPrompts     = 3
	maxUserRequestHosts    = 16
	maxUserRequestSessions = 256
	maxUserRequestScan     = 64 << 10
	userRequestTTL         = 30 * time.Minute
)

// userDownloadRequests remembers, per connector session, the hosts that the
// user's recent prompts ask to download from and run (#1390). It is what
// lets chain.download_then_execute_same_artifact stay quiet on a download the
// user asked for. It keeps host names only, never prompt text, in memory,
// bounded by session count, prompt count and age, and it does not need the
// LLM judge. The hosts are untrusted text: they may only lower that
// detection-only finding, never allow a call.
type userDownloadRequests struct {
	mu       sync.Mutex
	sessions map[string]userDownloadRequestSession
}

type userDownloadRequestSession struct {
	// prompts holds the requested hosts of each recent prompt, newest
	// last. A prompt that asks for nothing still takes a slot.
	prompts  [][]string
	lastSeen time.Time
}

// observeUserDownloadRequest records the hosts the user's prompt asks to
// download from and run, for the session in ctx. Call it on the connector's
// turn-start prompt only: other prompt-shaped events can carry text the
// user did not type.
func (a *APIServer) observeUserDownloadRequest(ctx context.Context, prompt string) {
	if a == nil {
		return
	}
	a.userDownloads.observe(sandboxSessionStateKey(ctx, SessionIDFromContext(ctx)), prompt, time.Now())
}

// resetUserDownloadRequests forgets a session at a lifecycle boundary.
func (a *APIServer) resetUserDownloadRequests(sessionKey string) {
	if a == nil || strings.TrimSpace(sessionKey) == "" {
		return
	}
	a.userDownloads.mu.Lock()
	delete(a.userDownloads.sessions, sessionKey)
	a.userDownloads.mu.Unlock()
}

func (r *userDownloadRequests) observe(sessionKey, prompt string, now time.Time) {
	if sessionKey == "" || strings.TrimSpace(prompt) == "" {
		return
	}
	hosts := userRequestedRunHosts(prompt)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions == nil {
		r.sessions = make(map[string]userDownloadRequestSession)
	}
	session, ok := r.sessions[sessionKey]
	if !ok || now.Sub(session.lastSeen) >= userRequestTTL {
		session = userDownloadRequestSession{}
	}
	if !ok && len(r.sessions) >= maxUserRequestSessions {
		r.pruneLocked(now)
	}
	prompts := append(session.prompts, hosts)
	if len(prompts) > userRequestPrompts {
		prompts = append([][]string(nil), prompts[len(prompts)-userRequestPrompts:]...)
	}
	r.sessions[sessionKey] = userDownloadRequestSession{prompts: prompts, lastSeen: now}
}

// requested reports whether one of the session's recent prompts asked to
// download from host and run what it got.
func (r *userDownloadRequests) requested(sessionKey, host string, now time.Time) bool {
	host = normalizeRequestHost(host)
	if sessionKey == "" || host == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	session, ok := r.sessions[sessionKey]
	if !ok || now.Sub(session.lastSeen) >= userRequestTTL {
		return false
	}
	for _, hosts := range session.prompts {
		for _, candidate := range hosts {
			if candidate == host {
				return true
			}
		}
	}
	return false
}

// pruneLocked drops expired sessions, then the oldest ones, until a new
// session fits.
func (r *userDownloadRequests) pruneLocked(now time.Time) {
	for key, session := range r.sessions {
		if now.Sub(session.lastSeen) >= userRequestTTL {
			delete(r.sessions, key)
		}
	}
	for len(r.sessions) >= maxUserRequestSessions {
		oldestKey, oldest := "", time.Time{}
		for key, session := range r.sessions {
			if oldestKey == "" || session.lastSeen.Before(oldest) {
				oldestKey, oldest = key, session.lastSeen
			}
		}
		delete(r.sessions, oldestKey)
	}
}

var userRequestRunWord = lazyregexp.New(`(?i)\b(run|runs|running|execute|executes|executing|exec|install|installs|installing|launch|launches|launching|invoke|invokes)\b`)

// userRequestedRunHosts returns the host names and IP addresses a prompt
// names when it also asks to run, execute or install something. A name is
// matched whole: "example.net" is not a part of "cdn.example.net".
func userRequestedRunHosts(prompt string) []string {
	if len(prompt) > maxUserRequestScan {
		prompt = prompt[:maxUserRequestScan]
	}
	prompt = strings.ToLower(prompt)
	if !userRequestRunWord.MatchString(prompt) {
		return nil
	}
	var hosts []string
	add := func(host string) {
		host = normalizeRequestHost(host)
		if host == "" || len(hosts) >= maxUserRequestHosts {
			return
		}
		for _, existing := range hosts {
			if existing == host {
				return
			}
		}
		hosts = append(hosts, host)
	}
	nameByte := func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.'
	}
	addrByte := func(c byte) bool {
		return c >= 'a' && c <= 'f' || c >= '0' && c <= '9' || c == ':' || c == '.'
	}
	for start := 0; start < len(prompt); {
		if !nameByte(prompt[start]) && prompt[start] != ':' {
			start++
			continue
		}
		end := start
		for end < len(prompt) && nameByte(prompt[end]) {
			end++
		}
		if name := strings.Trim(prompt[start:end], ".-"); strings.Contains(name, ".") {
			add(name)
		}
		// An IPv6 address, bare or in brackets.
		addrEnd := start
		for addrEnd < len(prompt) && addrByte(prompt[addrEnd]) {
			addrEnd++
		}
		if candidate := prompt[start:addrEnd]; strings.Count(candidate, ":") >= 2 {
			if address, err := netip.ParseAddr(strings.TrimRight(candidate, ".")); err == nil && address.Is6() {
				add(address.String())
			}
		}
		if addrEnd > end {
			end = addrEnd
		}
		if end == start {
			end++
		}
		start = end
	}
	return hosts
}

// normalizeRequestHost lowercases a host, drops IPv6 brackets and a final
// dot, and writes an IP address in its canonical form.
func normalizeRequestHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(host), "[]"), "."))
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Unmap().String()
	}
	return host
}
