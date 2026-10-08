// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Bound the number of remembered tasks and each retained task and session ID.
const (
	hermesTaskSessionsMax = 4096
	hermesTaskIDMaxBytes  = 4 * 1024
)

// hermesTaskSessions remembers the session of each Hermes task. Hermes sends
// transform_terminal_output with the task id of the terminal call
// (extra.task_id) but no session id, while the pre_tool_call of that call
// carries both, so the transform record had no session and no agent
// instance (GAP-0945). Tasks are kept per agent identity (agt-): two users
// never share a task.
type hermesTaskSessions struct {
	mu       sync.Mutex
	sessions map[hermesTaskKey]string
}

type hermesTaskKey struct{ identity, task string }

// fill records the session of a Hermes hook that names one with its task,
// and gives a hook that names only the task the session of that task.
func (m *hermesTaskSessions) fill(req *agentHookRequest) {
	if req == nil || !strings.EqualFold(req.ConnectorName, "hermes") || req.AgentIdentityID == "" ||
		!identityFactsEnabled.Load() {
		return
	}
	extra, _ := req.Payload["extra"].(map[string]interface{})
	task, _ := extra["task_id"].(string)
	// TrimSpace may leave a short view retaining the original large string.
	if len(task) > hermesTaskIDMaxBytes || len(req.SessionID) > hermesTaskIDMaxBytes {
		return
	}
	if task = strings.TrimSpace(task); task == "" {
		return
	}
	key := hermesTaskKey{identity: req.AgentIdentityID, task: task}
	m.mu.Lock()
	defer m.mu.Unlock()
	if req.SessionID != "" {
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
	if session := m.sessions[key]; session != "" {
		req.SessionID = session
		appendHookCorrelationValue(req, connector.CorrelationTargetSession, session, connector.CorrelationOriginDerived)
	}
}
