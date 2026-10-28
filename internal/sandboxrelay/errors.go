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

package sandboxrelay

import (
	"errors"
	"net/http"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// Client-side failures of the relay. Each one fails the sandbox's hook
// closed (the daemon answers the sandbox 502).
var (
	// ErrGatewayUnreachable: the managed gateway's hook socket could not
	// be reached or the call broke.
	ErrGatewayUnreachable = errors.New("sandboxrelay: managed gateway unreachable")
	// ErrSocketUntrusted: the hook socket or its directory failed the
	// owner and mode check (owned by root or the service account, the
	// directory not group- or world-writable).
	ErrSocketUntrusted = errors.New("sandboxrelay: managed gateway socket is not trusted")
	// ErrFilesUnsupported: a relayed call would carry FilesHeader (v1 is
	// copy-only).
	ErrFilesUnsupported = errors.New("sandboxrelay: relayed files are not supported")
	// ErrHeadersTooLarge: the allowlisted headers exceed
	// MaxForwardHeaderBytes.
	ErrHeadersTooLarge = errors.New("sandboxrelay: forwarded headers too large")
)

// InvalidRequestError is a call the client refused before sending it because
// what the caller gave is not valid (a pack name that is a path, a repository
// policy or pack file over its bound). The gateway was never asked and is
// not at fault, so it is not an unreachable gateway (GAP-0579). Message is
// the user text.
type InvalidRequestError struct{ Message string }

func (e *InvalidRequestError) Error() string { return "sandboxrelay: " + e.Message }

// Refusal reasons of the sandbox routes, the "error" of an ErrorBody.
const (
	ReasonRegistrationUnknown = "sandbox_registration_unknown"
	ReasonRegistrationRevoked = "sandbox_registration_revoked"
	ReasonRegistrationExpired = "sandbox_registration_expired"
	// ReasonRegistrationStopped: the registration's sandbox is stopped (its
	// daemon reported it, or stopped reporting it running); a relayed call
	// is refused until the sandbox starts again.
	ReasonRegistrationStopped   = "sandbox_registration_stopped"
	ReasonConnectorMismatch     = "sandbox_connector_mismatch"
	ReasonSubjectChanged        = "sandbox_subject_changed"
	ReasonNotAllowed            = "sandbox_not_allowed"
	ReasonUnavailable           = "sandbox_unavailable"
	ReasonPolicyUnloadable      = "sandbox_policy_unloadable"
	ReasonRelayFilesUnsupported = "sandbox_relay_files_unsupported"
	ReasonDecisionRefused       = "sandbox_decision_refused"
	// ReasonDaemonOutdated: the caller's daemon states a DaemonContract
	// below the managed gateway's, so it cannot carry the complete floor.
	// Its status is 403, which an older daemon treats as transient: it
	// keeps its registrations and does not mark them confirmed.
	ReasonDaemonOutdated = "sandbox_daemon_outdated"
)

// UnavailableSetupChanging is DaemonSettings.Unavailable while the
// organization's change of this computer's sandbox setup (its compute
// driver or OpenShell install mode) is not applied yet: the lifecycle's
// prerequisite record still names the earlier setup (#1203). It is a
// notice that clears by itself, not a refusal to take to IT;
// DetailSetupChanging is the reason code a refusal of it carries.
const (
	UnavailableSetupChanging = sandboxapi.UnavailableSetupChanging
	DetailSetupChanging      = "openshell_setup_changing"
)

// ReasonStatus is the HTTP status each refusal reason answers with; 0 for
// a reason this package does not define.
func ReasonStatus(reason string) int {
	switch reason {
	case ReasonRegistrationUnknown:
		return http.StatusNotFound
	case ReasonRegistrationRevoked, ReasonRegistrationExpired:
		return http.StatusGone
	case ReasonConnectorMismatch, ReasonNotAllowed, ReasonDecisionRefused, ReasonRegistrationStopped, ReasonDaemonOutdated:
		return http.StatusForbidden
	case ReasonSubjectChanged:
		return http.StatusConflict
	case ReasonUnavailable, ReasonPolicyUnloadable, DetailSetupChanging:
		return http.StatusServiceUnavailable
	case ReasonRelayFilesUnsupported:
		return http.StatusBadRequest
	}
	return 0
}

// ErrorBody is the JSON body of every non-2xx sandbox-route answer.
type ErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// Error is a non-2xx answer of the managed gateway as the client returns
// it. RetryAfter is the Retry-After header of a 429, passed through.
type Error struct {
	Status     int
	Reason     string
	Message    string
	RetryAfter string
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	msg := "sandboxrelay: managed gateway answered " + http.StatusText(e.Status)
	if e.Reason != "" {
		msg += " (" + e.Reason + ")"
	}
	return msg
}
