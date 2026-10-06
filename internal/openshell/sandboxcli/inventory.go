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
	"strings"
)

// DiscoverOptions are `sandbox discover`'s.
type DiscoverOptions struct {
	Name   string
	Output OutputFormat
}

// Discover runs the AI discovery of a ready sandbox now and prints what it
// found: the MCP servers, skills, plugins, CLIs, packages and agents the
// sandbox holds. The gateway's AI inventory (`defenseclaw agent usage
// --sandbox NAME`) takes it in on its next scan.
func (a *App) Discover(ctx context.Context, o DiscoverOptions) error {
	api, err := a.api()
	if err != nil {
		return err
	}
	res, err := api.Discover(ctx, o.Name)
	if err != nil {
		return apiError(err)
	}
	if o.Output == OutputJSON {
		return writeJSON(a.IO.Out, res)
	}
	if len(res.Signals) == 0 {
		a.note(fmt.Sprintf("no AI components found in sandbox %s (%d entries read)", res.Name, res.Entries))
	} else {
		rows := make([][]string, 0, len(res.Signals))
		for _, sig := range res.Signals {
			rows = append(rows, []string{sig.Category, firstNonEmpty(sig.Product, "-"), sig.Detector, discoveryNames(sig.Names)})
		}
		a.table([]string{"CATEGORY", "PRODUCT", "FOUND BY", "NAMES"}, rows)
	}
	if res.Result != "ok" {
		a.warn("the scan was partial: " + strings.Join(res.Problems, "; "))
	}
	a.note(fmt.Sprintf("scanned in %dms; `defenseclaw agent usage --sandbox %s` shows them in the AI inventory after its next scan", res.DurationMs, res.Name))
	return nil
}

// discoveryNames is a signal's names cell: the first few, and how many more.
func discoveryNames(names []string) string {
	const show = 3
	switch {
	case len(names) == 0:
		return "-"
	case len(names) <= show:
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:show], ", ") + fmt.Sprintf(" (+%d)", len(names)-show)
}
