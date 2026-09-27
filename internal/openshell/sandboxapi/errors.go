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

package sandboxapi

import (
	"errors"
	"fmt"
	"net/http"
)

// Error codes. They are stable machine tokens; Message is for people.
const (
	// CodeDisabled: openshell.enabled is false (or the platform has no
	// sandbox support).
	CodeDisabled = "disabled"
	// CodeUnavailable: the daemon is not connected to a supported local
	// OpenShell gateway right now.
	CodeUnavailable = "unavailable"
	CodeInvalid     = "invalid_request"
	CodeNotFound    = "not_found"
	// CodeConflict: the sandbox exists already or is in the wrong phase.
	CodeConflict = "conflict"
	// CodeNeedsCopy: the project cannot be mounted live (a linked worktree,
	// a git directory outside the folder, and the like; Detail says why);
	// it can run in copy mode.
	CodeNeedsCopy = "needs_copy"
	// CodeAdminViolation: openshell.admin refused the request ("blocked by
	// your organization's DefenseClaw policy").
	CodeAdminViolation = "admin_violation"
	// CodePolicyViolation: the pack, profile or a DefenseClaw invariant
	// refused the request.
	CodePolicyViolation = "policy_violation"
	CodePackInvalid     = "pack_invalid"
	// CodeImageUnavailable: no hook-verified overlay image exists (and
	// building one was refused or failed).
	CodeImageUnavailable = "image_unavailable"
	// CodePolicyRejected: OpenShell rejected the sandbox configuration.
	CodePolicyRejected = "policy_rejected"
	// CodeUpstream: an OpenShell call failed.
	CodeUpstream = "upstream_error"
	CodeInternal = "internal"
)

// AdminMessage is the sentence every admin refusal starts with.
const AdminMessage = "blocked by your organization's DefenseClaw policy"

// Error is the JSON error body of every non-2xx sandbox API response.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"error"`
	Detail  string `json:"detail,omitempty"`
	// Violation is the refusing policy decision, when there is one.
	Violation *Violation `json:"violation,omitempty"`
	// Status is the HTTP status; it is not serialized.
	Status int `json:"-"`
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Message
	}
	return e.Message + ": " + e.Detail
}

// HTTPStatus returns the status the gateway answers with.
func (e *Error) HTTPStatus() int {
	if e.Status != 0 {
		return e.Status
	}
	return StatusForCode(e.Code)
}

// StatusForCode maps an error code onto its HTTP status.
func StatusForCode(code string) int {
	switch code {
	case CodeDisabled, CodeUnavailable:
		return http.StatusServiceUnavailable
	case CodeInvalid, CodePackInvalid:
		return http.StatusBadRequest
	case CodeNotFound:
		return http.StatusNotFound
	case CodeConflict, CodeNeedsCopy, CodeImageUnavailable:
		return http.StatusConflict
	case CodeAdminViolation, CodePolicyViolation:
		return http.StatusForbidden
	case CodePolicyRejected:
		return http.StatusUnprocessableEntity
	case CodeUpstream:
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

// Errorf builds an *Error.
func Errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// AsError returns err as an *Error, wrapping anything else as internal.
func AsError(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return &Error{Code: CodeInternal, Message: err.Error()}
}

// IsCode reports whether err is an *Error with code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}
