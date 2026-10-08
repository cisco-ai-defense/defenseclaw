// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// hermesTaskSessionsMax bounds the remembered Hermes tasks, and the agent
// identities whose last tool call is remembered.
const hermesTaskSessionsMax = 4096

// hermesSessionIDMax bounds a remembered session id; a longer one is not kept.
const hermesSessionIDMax = 256

// hermesLastToolCallTTL bounds how long the session of the last tool call of
// an agent identity is given to its terminal output.
const hermesLastToolCallTTL = 10 * time.Minute

// hermesTaskSessions remembers the session of each Hermes task. Hermes sends
// transform_terminal_output with no session id, while the pre_tool_call of
// that call carries one, so the transform record had no session and no agent
// instance (GAP-0945). A terminal output that names its task (extra.task_id)
// takes the session of that task; Hermes 0.21.5 names none, so it takes the
// session of the last pre_tool_call of the same agent identity. Tasks and
// calls are kept per agent identity (agt-): two users never share one.
type hermesTaskSessions struct {
	mu       sync.Mutex
	sessions map[hermesTaskKey]string
	lastCall map[string]hermesLastToolCall
}

type hermesTaskKey struct{ identity, task string }

type hermesLastToolCall struct {
	session string
	at      time.Time
}

// fill records the session of a Hermes hook that names one, and gives a
// terminal output that names none the session of its task or of the last
// tool call of its agent.
func (m *hermesTaskSessions) fill(req *agentHookRequest) {
	if req == nil || !strings.EqualFold(req.ConnectorName, "hermes") || req.AgentIdentityID == "" ||
		!identityFactsEnabled.Load() {
		return
	}
	extra, _ := req.Payload["extra"].(map[string]interface{})
	task, _ := extra["task_id"].(string)
	task = strings.TrimSpace(task)
	key := hermesTaskKey{identity: req.AgentIdentityID, task: task}
	event := canonicalEvent(req.HookEventName)
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if req.SessionID != "" {
		if len(req.SessionID) > hermesSessionIDMax {
			return
		}
		if event == "pretoolcall" {
			if m.lastCall == nil {
				m.lastCall = make(map[string]hermesLastToolCall)
			}
			if _, known := m.lastCall[req.AgentIdentityID]; !known && len(m.lastCall) >= hermesTaskSessionsMax {
				for old := range m.lastCall {
					delete(m.lastCall, old)
					break
				}
			}
			m.lastCall[req.AgentIdentityID] = hermesLastToolCall{session: req.SessionID, at: now}
		}
		if task == "" {
			return
		}
		if m.sessions == nil {
			m.sessions = make(map[hermesTaskKey]string)
		}
		if _, known := m.sessions[key]; !known && len(m.sessions) >= hermesTaskSessionsMax {
			for old := range m.sessions {
				delete(m.sessions, old)
				break
			}
		}
		m.sessions[key] = req.SessionID
		return
	}
	session := ""
	if task != "" {
		session = m.sessions[key]
	}
	if last, ok := m.lastCall[req.AgentIdentityID]; session == "" && event == "transformterminaloutput" && ok &&
		now.Sub(last.at) <= hermesLastToolCallTTL {
		session = last.session
	}
	if session != "" {
		req.SessionID = session
		appendHookCorrelationValue(req, connector.CorrelationTargetSession, session, connector.CorrelationOriginDerived)
	}
}
