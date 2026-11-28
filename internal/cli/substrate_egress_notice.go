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

package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
)

// substrateEgressInfoWait bounds the /info read status and doctor make for
// the egress callout.
const substrateEgressInfoWait = 5 * time.Second

// substrateEgressInfo asks the cluster's /info who holds Substrate's egress
// callout slot; nil when the cluster does not say (an older gateway, or the
// read failed).
func substrateEgressInfo(ctx context.Context, s *substrateSession) *api.EgressCallout {
	cctx, cancel := context.WithTimeout(ctx, substrateEgressInfoWait)
	defer cancel()
	info, err := s.Client.Info(cctx)
	if err != nil {
		return nil
	}
	return info.EgressCallout
}

// substrateEgressLine is the Egress line status prints while the DefenseClaw
// callout does not hold Substrate's egress slot (GAP-0497), "" while it does
// or the cluster does not say. run, run --task, --batch and connect print it
// too (GAP-0505): in closed mode the agent's other hosts are refused and
// fail to resolve, which a person read as a DNS fault.
func substrateEgressLine(e *api.EgressCallout) string {
	if !e.Replaced() {
		return ""
	}
	return "Egress: " + substrateEgressSummary(e)
}

// substrateEgressAhead reads /info while the launcher does other work (the
// create, the actor lookup), so the Egress line costs a launch no time. The
// returned func waits for that read and prints the line on w; it prints at
// most once.
func substrateEgressAhead(ctx context.Context, s *substrateSession) func(w io.Writer) {
	ch := make(chan *api.EgressCallout, 1)
	go func() { ch <- substrateEgressInfo(ctx, s) }()
	var once sync.Once
	return func(w io.Writer) {
		once.Do(func() {
			if line := substrateEgressLine(<-ch); line != "" {
				fmt.Fprintln(w, line)
			}
		})
	}
}

// substrateEgressSummary says, for a person, that the DefenseClaw callout does
// not hold the slot, which protections are off and what still applies
// (GAP-0497).
func substrateEgressSummary(e *api.EgressCallout) string {
	who := "another egress callout is in place of DefenseClaw's"
	if e.State == "none" {
		who = "no egress callout is registered"
	}
	// The names come from the cluster: shown as one plain line (GAP-0101).
	names := make([]string, 0, len(e.ChecksOff))
	for _, c := range e.ChecksOff {
		names = append(names, safetext.Line(c))
	}
	off := strings.Join(names, ", ")
	if off == "" {
		off = "ask hosts, URL rules, egress feeds, secret and DLP scans, body and MCP inspection"
	}
	var effect string
	switch e.FailMode {
	case "open":
		effect = "your agents keep their egress allow list without these checks, and unattended runs reach only DefenseClaw"
	case "off":
		effect = "your agents keep their egress allow list without these checks (the cluster runs without the DefenseClaw callout)"
	default:
		effect = "your agents reach only DefenseClaw until your administrator fixes it: hooks and model calls work, every other host is refused"
	}
	return who + ", so these protections are off: " + off + ". " + strings.ToUpper(effect[:1]) + effect[1:] +
		". DefenseClaw's hooks and Substrate's default-deny egress still apply"
}

// doctorEgressCallout is the user doctor row for the egress callout.
func doctorEgressCallout(ctx context.Context, s *substrateSession, adminOK bool) substrateCheck {
	const id = "egress_callout"
	if !adminOK {
		return substrateCheck{ID: id, Status: doctorSkip, Summary: "not checked: the admin address does not answer"}
	}
	e := substrateEgressInfo(ctx, s)
	switch {
	case e == nil:
		return substrateCheck{ID: id, Status: doctorSkip, Summary: "the cluster does not report its egress callout"}
	case e.State == "defenseclaw":
		return substrateCheck{ID: id, Status: doctorOK, Summary: "DefenseClaw's egress callout checks your agents' requests"}
	case e.Replaced():
		return substrateCheck{ID: id, Status: doctorFail, Summary: substrateEgressSummary(e),
			Fix: "ask your administrator to register the DefenseClaw callout again (defenseclaw substrate setup, then ate-setup deploy)"}
	}
	return substrateCheck{ID: id, Status: doctorWarn, Summary: "cannot verify the egress callout: the cluster cannot tell which egress callout Substrate uses",
		Fix: "ask your administrator to run: defenseclaw substrate doctor --cluster --install-file FILE"}
}
