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
	"context"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// Destinations is `sandbox destinations NAME`: every host the sandbox
// reached or tried to reach, what kind of destination it is (its model
// provider, its harness's vendor, shadow AI, ...), and the model calls
// OpenShell's inference route reported.
func (a *App) Destinations(ctx context.Context, name string, format OutputFormat) error {
	api, err := a.api()
	if err != nil {
		return err
	}
	d, err := api.Destinations(ctx, name)
	if err != nil {
		return apiError(err)
	}
	if format == OutputJSON {
		if d.Destinations == nil {
			d.Destinations = []sandboxapi.DestinationRow{}
		}
		return writeJSON(a.IO.Out, d)
	}
	if len(d.Destinations) == 0 && len(d.Models) == 0 {
		a.note("sandbox " + name + " has reached no destination yet")
		return nil
	}
	shadow := 0
	rows := make([][]string, 0, len(d.Destinations))
	for _, r := range d.Destinations {
		if sandboxapi.ShadowAIKind(r.Kind) {
			shadow++
		}
		rows = append(rows, []string{
			destinationHost(r), destinationKindText(r.Kind), truncate(firstNonEmpty(r.Provider, r.Category, "-"), 32),
			destinationRequests(r), humanBytes(r.BytesUp) + " / " + humanBytes(r.BytesDown),
			truncate(firstNonEmpty(destinationBinary(r), "-"), 40), r.LastSeen.Local().Format("01-02 15:04"),
		})
	}
	if len(rows) > 0 {
		a.table([]string{"DESTINATION", "KIND", "PROVIDER", "REQUESTS", "UP / DOWN", "BINARY", "LAST SEEN"}, rows)
	}
	if len(d.Models) > 0 {
		models := make([][]string, 0, len(d.Models))
		for _, u := range d.Models {
			calls := strconv.FormatInt(u.Calls, 10)
			if u.Failed > 0 {
				calls += fmt.Sprintf(" (%d failed)", u.Failed)
			}
			models = append(models, []string{firstNonEmpty(u.Provider, "-"), firstNonEmpty(u.Model, "-"), calls, u.LastSeen.Local().Format("01-02 15:04")})
		}
		a.println()
		a.table([]string{"PROVIDER", "MODEL", "CALLS", "LAST SEEN"}, models)
	}
	if shadow > 0 {
		a.warn(fmt.Sprintf("%s the harness does not use (shadow AI); block one with `%s policy block HOST`",
			plural(int64(shadow), "AI destination", "AI destinations"), CommandName))
	}
	if d.Dropped > 0 {
		a.note(fmt.Sprintf("%d older destinations were dropped to keep the view at %d", d.Dropped, sandboxapi.MaxDestinations))
	}
	return nil
}

// destinationHost is a row's host with its ports when they are not just
// 443.
func destinationHost(r sandboxapi.DestinationRow) string {
	if len(r.Ports) == 0 || (len(r.Ports) == 1 && r.Ports[0] == 443) {
		return r.Host
	}
	ports := make([]string, 0, len(r.Ports))
	for _, p := range r.Ports {
		ports = append(ports, strconv.Itoa(p))
	}
	host := r.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return host + ":" + strings.Join(ports, ",")
}

// destinationKindText is how a destination kind reads.
func destinationKindText(kind string) string {
	switch kind {
	case sandboxapi.DestinationModelProvider:
		return "model provider"
	case sandboxapi.DestinationHarnessVendor:
		return "harness vendor"
	case sandboxapi.DestinationOtherAI:
		return "shadow AI"
	case sandboxapi.DestinationUnknownAI:
		return "shadow AI?"
	default:
		return strings.ReplaceAll(kind, "_", " ")
	}
}

// destinationRequests counts a row's requests and refusals.
func destinationRequests(r sandboxapi.DestinationRow) string {
	s := strconv.FormatInt(r.Connections+r.Tunnels, 10)
	if refused := r.Refused + r.Blocked; refused > 0 {
		s += fmt.Sprintf(" (%d refused)", refused)
	}
	if r.ModelTurns > 0 {
		s += fmt.Sprintf(", %d model calls", r.ModelTurns)
	}
	return s
}

// destinationBinary is the program that last connected; with the sandbox's
// process tree on, its lineage: the process, then its parent and theirs.
func destinationBinary(r sandboxapi.DestinationRow) string {
	if len(r.Lineage) < 2 {
		return lastOf(r.Binaries)
	}
	names := make([]string, 0, len(r.Lineage))
	for _, p := range r.Lineage {
		names = append(names, firstNonEmpty(p.Comm, path.Base(p.Exe), strconv.Itoa(p.PID)))
	}
	return strings.Join(names, " ← ")
}

func lastOf(list []string) string {
	if len(list) == 0 {
		return ""
	}
	return list[len(list)-1]
}

// egressAIText is the AI part of a sandbox's Egress status line: "" without
// AI destinations.
func egressAIText(sb *sandboxapi.Sandbox) string {
	if sb.Egress.ModelAPIs == 0 && sb.Egress.ShadowAI == 0 {
		return ""
	}
	parts := []string{plural(int64(sb.Egress.ModelAPIs), "model API", "model APIs")}
	if sb.Egress.ShadowAI > 0 {
		parts = append(parts, fmt.Sprintf("%d shadow AI", sb.Egress.ShadowAI))
	}
	return "; AI: " + strings.Join(parts, ", ") + " (`" + CommandName + " destinations " + sb.Name + "`)"
}
