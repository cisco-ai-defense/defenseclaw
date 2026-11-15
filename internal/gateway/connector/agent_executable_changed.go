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

import (
	"errors"
	"fmt"
)

// ErrAgentExecutableChanged marks an executable admission refusal whose cause
// is the agent itself: the version or the bytes of the executable setup
// selected are no longer the ones it sealed, because the agent updated in
// place (npm i -g, a self-update) or was replaced. The gateway never runs or
// trusts bytes it did not admit, so the connector stays refused until setup
// admits the new executable; no DefenseClaw rollback can cure it, so a start
// keeps every other connector (GAP-0249).
var ErrAgentExecutableChanged = errors.New("the agent executable changed since setup")

// agentExecutableChangedError is the refusal of one connector. Its text names
// the setup step that admits the new executable. It unwraps to
// ErrAgentExecutableChanged and also matches ErrExecutableAdmission: every
// check that raises it runs before Setup changes anything. The same evidence
// check also runs when Setup publishes the hook contract lock, after Setup
// wrote the agent files; that one is reported through
// contractPublicationEvidenceError, so the start rolls the connector back.
type agentExecutableChangedError struct{ text string }

func (e *agentExecutableChangedError) Error() string { return e.text }
func (e *agentExecutableChangedError) Unwrap() error { return ErrAgentExecutableChanged }
func (e *agentExecutableChangedError) Is(target error) bool {
	return target == ErrExecutableAdmission
}

func newAgentExecutableChanged(connectorName, product string) error {
	return &agentExecutableChangedError{text: fmt.Sprintf(
		"the %s executable changed since setup (a %s update does this); run: defenseclaw setup %s --yes",
		product, product, connectorName,
	)}
}

var (
	errAmpExecutableChanged      = newAgentExecutableChanged("amp", "Amp")
	errHermesExecutableChanged   = newAgentExecutableChanged("hermes", "Hermes")
	errOpenCodeExecutableChanged = newAgentExecutableChanged("opencode", "OpenCode")
)

// AgentExecutableChangedBeforeChange reports whether err is that refusal,
// reached through single wrappers only. A refusal joined with another failure
// (a rollback that failed) is not the refusal alone: the other failure may
// have left a change behind, and errors.Is would still match.
func AgentExecutableChangedBeforeChange(err error) bool {
	for ; err != nil; err = errors.Unwrap(err) {
		if err == ErrAgentExecutableChanged {
			return true
		}
	}
	return false
}

// contractPublicationEvidenceError reports an executable evidence mismatch
// found while the hook contract lock is published. Setup has already written
// the agent files by then, so the error must not read as a refusal before any
// change (ErrAgentExecutableChanged, ErrExecutableAdmission): the start rolls
// the connector back instead of keeping the files it wrote. The text keeps
// the setup step the refusal names.
func contractPublicationEvidenceError(product string, err error) error {
	return fmt.Errorf("%s contract publication: %s", product, err.Error())
}
