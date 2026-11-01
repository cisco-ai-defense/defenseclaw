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

package sandboxcli

import (
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// CheckIDManagedDockerGroup is the doctor row that tells a managed Linux user
// in the docker group what that membership means.
const CheckIDManagedDockerGroup = "managed-docker-group"

// managedDockerGroupDetail is the row's detail: the docker group, which
// sandboxes on Linux need, is root-equivalent, so the rule that each person
// sees only their own policy does not hold against it (GAP-0498).
const managedDockerGroupDetail = "you are in the docker group, which sandboxes on this computer need " +
	"(the docker driver runs in Docker, and MicroVM agent images are built in Docker for your account); " +
	"Docker access is administrator-equivalent on this computer: it can read and change every file here, " +
	"including your organization's policy and other people's files, so it is not limited to your own policy"

// managedDockerGroupRequiredDetail is what the row adds for an account
// whose organization requires agents to run only in a sandbox here: Docker
// access is also a way to run them outside the sandbox policy, a documented
// limit until a root-owned image and lifecycle service removes the need for
// the group (GAP-0554, GAP-0511).
const managedDockerGroupRequiredDetail = "; your organization requires %s to run only in a sandbox on this computer, " +
	"and Docker access also lets this account run %s in a container outside the sandbox policy, where DefenseClaw does not inspect it " +
	"(a documented limit of sandboxes on Linux)"

// managedDockerGroupCheck is the doctor's Docker access row on a managed
// Linux computer, nil when the account is not in the docker group (the
// runtime row covers an account sandboxes can't run for) or its groups
// can't be read. member is openshell.Doctor.DockerGroup, which the host
// checks set; nil (a test's host report) gives no row. m.RequiredOnHost
// (the agents the managed gateway refuses on the host) adds what the group
// means for them.
func managedDockerGroupCheck(goos string, m *sandboxapi.ManagedStatus, member func() (bool, bool, error)) *openshell.Check {
	if goos != "linux" || m == nil || member == nil {
		return nil
	}
	in, _, err := member()
	if err != nil || !in {
		return nil
	}
	contact := sandboxapi.RequestAccessText(m.RequestAccess)
	if contact != sandboxapi.RequestAccessFallback {
		contact = "ask " + contact
	}
	detail := managedDockerGroupDetail
	if len(m.RequiredOnHost) > 0 {
		names := commandNames(sandboxapi.DisplayTexts(m.RequiredOnHost))
		them := "it"
		if len(names) > 1 {
			them = "them"
		}
		detail += fmt.Sprintf(managedDockerGroupRequiredDetail, andList(names), them)
	}
	return &openshell.Check{ID: CheckIDManagedDockerGroup, Title: "Docker access", Status: openshell.StatusWarn,
		Detail: detail,
		Fix: &openshell.Fix{Summary: "nothing to change for your sandboxes; run only images and containers you trust, " +
			"and if you no longer run sandboxes on this computer, " + contact + " to take you out of the docker group"}}
}
