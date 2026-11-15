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

package identity

import (
	"errors"
	"fmt"
)

// Reason is the closed set of refusal reasons a verifier returns. Logs and
// metrics use it; it never carries token bytes or claim values.
type Reason string

const (
	ReasonMissing      Reason = "missing_token"
	ReasonMalformed    Reason = "malformed"
	ReasonAlgorithm    Reason = "algorithm"
	ReasonType         Reason = "token_type"
	ReasonUnknownKey   Reason = "unknown_kid"
	ReasonSignature    Reason = "signature"
	ReasonIssuer       Reason = "issuer"
	ReasonAudience     Reason = "audience"
	ReasonExpired      Reason = "expired"
	ReasonNotYetValid  Reason = "not_yet_valid"
	ReasonLifetime     Reason = "lifetime"
	ReasonWorkerToken  Reason = "worker_token"
	ReasonSubject      Reason = "subject"
	ReasonClaims       Reason = "claims"
	ReasonActorGone    Reason = "actor_gone"
	ReasonActorUID     Reason = "actor_uid_mismatch"
	ReasonActorState   Reason = "actor_not_running"
	ReasonUnavailable  Reason = "verifier_unavailable"
	ReasonKeysetFailed Reason = "keyset_unavailable"
)

// Error is a refusal with its reason. Message never contains token
// material.
type Error struct {
	Reason  Reason
	Message string
}

func (e *Error) Error() string { return string(e.Reason) + ": " + e.Message }

func reasonf(r Reason, format string, args ...any) error {
	return &Error{Reason: r, Message: fmt.Sprintf(format, args...)}
}

// ReasonOf returns the refusal reason of err, or ReasonUnavailable for an
// error that is not a verifier refusal.
func ReasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ReasonUnavailable
}

// Unavailable reports whether err means the verifier could not decide
// (the key set or the control API could not be reached), as opposed to a
// token it refused. Callers apply their fail mode to the first and always
// refuse the second; with no decision there is still no verified caller.
func Unavailable(err error) bool {
	switch ReasonOf(err) {
	case ReasonUnavailable, ReasonKeysetFailed:
		return true
	}
	return false
}
