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

//go:build !windows

package sandboxcli

import (
	"context"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// A managed Linux user in the docker group is told that Docker access is
// administrator-equivalent and so not limited to their own policy; a user
// outside the group, an unreadable group list and other systems get no row
// (GAP-0498).
func TestManagedDoctorExplainsDockerGroupAccess(t *testing.T) {
	withManagedHost(t)
	member := func(in bool, err error) func() (bool, bool, error) {
		return func() (bool, bool, error) { return in, in, err }
	}
	doctor := func(goos string, group func() (bool, bool, error)) *openshell.DoctorReport {
		ta := newTestApp(t, "")
		ta.GOOS = goos
		ta.daemon.status.Managed = managedStatusFixture()
		ta.HostDoctor = func(_ context.Context, d *openshell.Doctor) *openshell.DoctorReport {
			d.DockerGroup = group
			return hostReport(nil)(bg, d)
		}
		return ta.runDoctor(bg)
	}

	rep := doctor("linux", member(true, nil))
	c := rep.Get(CheckIDManagedDockerGroup)
	if c == nil || c.Status != openshell.StatusWarn || c.Fix == nil || c.Fix.Command != "" {
		t.Fatalf("docker group row = %+v", c)
	}
	has(t, c.Detail, "you are in the docker group", "administrator-equivalent", "can read and change every file here", "your organization's policy", "not limited to your own policy")
	has(t, c.Fix.Summary, "run only images and containers you trust", "take you out of the docker group")
	if !rep.OK() {
		t.Fatalf("the advisory blocks sandboxes: %+v", rep.Checks)
	}

	for name, group := range map[string]func() (bool, bool, error){
		"not a member":  member(false, nil),
		"unreadable":    member(true, errors.New("no docker group")),
		"no host check": nil,
	} {
		if c := doctor("linux", group).Get(CheckIDManagedDockerGroup); c != nil {
			t.Errorf("%s: row = %+v", name, c)
		}
	}
	if c := doctor("darwin", member(true, nil)).Get(CheckIDManagedDockerGroup); c != nil {
		t.Errorf("macOS row = %+v", c)
	}
}
