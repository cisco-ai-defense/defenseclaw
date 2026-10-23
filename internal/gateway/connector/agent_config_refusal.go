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

package connector

import "errors"

// ErrAgentConfigRefusal marks a Setup refusal caused by the agent's own
// settings: they turn its hooks off (`codex features disable hooks`, Claude
// Code or Copilot disableAllHooks) or cannot be read. Setup refuses before it
// changes anything, so the earlier registration and the user's setting are
// kept. It is that one agent's problem: a gateway start reports it for that
// connector and keeps enforcing every other one (GAP-0578). It also matches
// ErrSetupRefusedUnchanged.
var ErrAgentConfigRefusal = errors.New("the agent's own settings refuse DefenseClaw hooks")

type agentConfigRefusal struct{ err error }

func (e agentConfigRefusal) Error() string { return e.err.Error() }

func (e agentConfigRefusal) Unwrap() []error {
	return []error{ErrAgentConfigRefusal, ErrSetupRefusedUnchanged, e.err}
}

// refuseForAgentConfig marks err as ErrAgentConfigRefusal.
func refuseForAgentConfig(err error) error {
	if err == nil {
		return nil
	}
	return agentConfigRefusal{err: err}
}

// agentSettingsChecker is implemented by the connectors whose Setup refuses
// the agent's own settings (ErrAgentConfigRefusal) before it changes anything.
type agentSettingsChecker interface {
	checkAgentSettings(opts SetupOpts) error
}

// CheckAgentSettings runs the agent-settings refusal conn's Setup starts with,
// and changes nothing. `defenseclaw setup` asks it before it restarts the
// gateway, so settings the gateway would refuse stop setup before the running
// gateway is touched (GAP-0615). It returns nil for a connector without such a
// refusal.
func CheckAgentSettings(conn Connector, opts SetupOpts) error {
	if checker, ok := conn.(agentSettingsChecker); ok {
		return checker.checkAgentSettings(opts)
	}
	return nil
}
