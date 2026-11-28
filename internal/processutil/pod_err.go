// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package processutil

import "errors"

// ErrPodRestart reports, together with ErrNotContained and
// ErrContainmentUnavailable, that the pod-contained scan worker could not
// clear its container after a job: a process it could not kill and reap, or
// a folder it could not empty (GAP-0875). Only a new container clears that,
// so the scan worker exits and the kubelet starts it again.
var ErrPodRestart = errors.New("processutil: the pod-contained scan worker must be restarted")

// podError is a refusal of the pod-contained scan worker. It is
// ErrNotContained and ErrContainmentUnavailable, so the scan's fail mode
// decides as it does where containment is unavailable, but its text gives
// the pod mode's own reason: no host namespace is involved (GAP-0877).
type podError struct {
	msg     string
	restart bool
}

func (e *podError) Error() string { return "processutil: pod-contained scan worker: " + e.msg }

func (e *podError) Is(target error) bool {
	return target == ErrNotContained || target == ErrContainmentUnavailable || (e.restart && target == ErrPodRestart)
}
