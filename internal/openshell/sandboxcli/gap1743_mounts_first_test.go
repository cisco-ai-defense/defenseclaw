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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// rel-1-0-10:GAP-1743: a Mac moving its gateway to the docker driver was
// told to share its home folder with Docker Desktop (and asked to check
// again) before setup asked whether sandboxes mount the project folder at
// all; file sharing is only for those mounts. Setup asks about the mounts
// first, and a no never names file sharing.
func TestGAP1743MacSetupAsksAboutMountsBeforeFileSharing(t *testing.T) {
	sharingOff := func(r *openshell.DoctorReport) {
		hostNetworking(true)(r)
		c := r.Get(openshell.CheckIDDockerFileSharing)
		c.Status, c.Detail = openshell.StatusFail, "/Users/u is not shared with Docker Desktop"
		c.Fix = &openshell.Fix{Summary: "add /Users/u in Docker Desktop → Settings → Resources → File sharing"}
	}
	newMac := func(t *testing.T, input string) *testApp {
		ta := setupApp(t, input, "", false)
		ta.GOOS = "darwin"
		ta.gateway.state.Env = map[string]string{openshell.EnvTelemetryEnabled: "false"}
		ta.HostDoctor = macVMThenDocker(sharingOff)
		ta.gateway.applyRes = &openshell.GatewayApplyResult{}
		_, _ = useGateway(ta)
		return ta
	}
	const mounts = "Allow sandboxes to mount the project folder you launch from?"
	// No to MicroVMs, no to the mounts, yes to the restart.
	ta := newMac(t, "n\nn\ny\n")
	_ = ta.Setup(bg, SetupOptions{SkipImages: true, NoWrappers: true})
	out := ta.output()
	if strings.Contains(out, "Docker file sharing") || strings.Contains(out, "Check Docker Desktop again?") {
		t.Fatalf("setup named Docker file sharing for a gateway that mounts nothing:\n%s", out)
	}
	// Yes to the mounts: file sharing is named after the question.
	ta = newMac(t, "n\ny\nn\ny\n")
	_ = ta.Setup(bg, SetupOptions{SkipImages: true, NoWrappers: true})
	out = ta.output()
	q, fs := strings.Index(out, mounts), strings.Index(out, "Docker file sharing")
	if q < 0 || fs < 0 || fs < q {
		t.Fatalf("the mounts question (at %d) does not come before Docker file sharing (at %d):\n%s", q, fs, out)
	}
}
