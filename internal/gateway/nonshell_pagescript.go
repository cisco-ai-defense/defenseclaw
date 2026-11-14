// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/toolshape"
)

// pageScriptSessionEgressRuleID is the finding of the page-script check
// (experiment EXP-1xx, rel-1-0-10:GAP-0560): a script that a browser-automation
// tool runs in the page reads session state (cookies, web storage, IndexedDB)
// and sends it to a host other than the page's. It is data in the rule packs
// and an alert in every pack, strict and managed included: the tier with a
// literal destination host and a known page origin (proven) was measured by
// unit tests only, because no corpus navigates before a script, so a block in
// strict waits for that measurement (rel-1-0-10:GAP-0560).
const pageScriptSessionEgressRuleID = "PAGE-SCRIPT-SESSION-EGRESS"

// maxPageOriginSessions bounds the sessions whose page the gateway remembers.
const maxPageOriginSessions = 4096

// pageOrigins remembers, per connector session, the host of the last page the
// session navigated to. A session that left that page (back, a tab switch, a
// closed page) or that the gateway has forgotten has no origin: a script that
// sends session state to a literal host is then judged as unknown.
var pageOrigins = &pageOriginStore{hosts: map[string]string{}}

type pageOriginStore struct {
	mu    sync.Mutex
	hosts map[string]string
	order []string
}

func pageOriginKey(connector, session string) string {
	if session == "" {
		return ""
	}
	return connector + "\x00" + session
}

func (s *pageOriginStore) set(key, host string) {
	if key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.hosts[key]; !ok {
		if len(s.order) >= maxPageOriginSessions {
			delete(s.hosts, s.order[0])
			s.order = s.order[1:]
		}
		s.order = append(s.order, key)
	}
	s.hosts[key] = host
}

func (s *pageOriginStore) clear(key string) {
	if key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.hosts[key]; ok {
		s.hosts[key] = ""
	}
}

func (s *pageOriginStore) get(key string) string {
	if key == "" {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hosts[key]
}

// notePageNavigation records what a navigation or page-change call does to the
// session's page.
func notePageNavigation(request trustedActionRequest, mapping toolshape.Mapping) {
	key := pageOriginKey(request.Connector, request.sessionID)
	switch {
	case mapping.PageURL != "":
		pageOrigins.set(key, toolshape.URLHost(mapping.PageURL))
	case mapping.PageLeaves:
		pageOrigins.clear(key)
	}
}

// pageScriptOrigin is the host of the page a script runs in: a URL the same
// call names, a page the script itself opens, or the session's last
// navigation. Empty when none is known.
func pageScriptOrigin(request trustedActionRequest, mapping toolshape.Mapping, flow toolshape.PageFlow) string {
	for _, e := range mapping.Effects {
		if e.Role == toolshape.RoleURL && e.Host != "" {
			return e.Host
		}
	}
	if n := len(flow.Gotos); n > 0 {
		if host := toolshape.URLHost(flow.Gotos[n-1]); host != "" {
			return host
		}
	}
	return pageOrigins.get(pageOriginKey(request.Connector, request.sessionID))
}

// pageScriptEgress reads one page script and returns what it sends session
// state to. proven: a literal destination host that is not the page's host, with
// the page's host known. uncertain: a destination that is not a literal, or a
// literal host with no known page origin. Reading state without a send, a send
// without state, a same-origin send and a loopback or private destination are
// neither.
func pageScriptEgress(request trustedActionRequest, mapping toolshape.Mapping, code string) (proven, uncertain bool, host string, trunc bounded.CapSet) {
	flow := toolshape.AnalyzePageScript(code)
	trunc = flow.Truncated
	if len(flow.Sends) == 0 {
		return false, false, "", trunc
	}
	origin := pageScriptOrigin(request, mapping, flow)
	for _, s := range flow.Sends {
		switch s.Dest {
		case toolshape.DestSameOrigin, toolshape.DestNotNetwork:
			continue
		case toolshape.DestHost:
			if s.Host == origin || toolshape.LocalHost(s.Host) || toolshape.PrivateHost(s.Host) {
				continue
			}
			if origin == "" {
				uncertain = true
				continue
			}
			if !proven {
				proven, host = true, s.Host
			}
		default:
			uncertain = true
		}
	}
	return proven, uncertain, host, trunc
}

// pageScriptNote is the finding's note: what reached what, without the script
// text or any value.
func pageScriptNote(proven bool, host string) string {
	if proven {
		return "page script sends browser session state to " + strings.ToLower(host)
	}
	return "page script sends browser session state; the destination or the page's origin is not known"
}
