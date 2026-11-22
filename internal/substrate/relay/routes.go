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

package relay

import "strings"

// The relay's routes. This is the one table of them: the relay serves each
// at Prefix + "/" + route, the gateway's attach route serves each at
// <attach prefix>/<route> and proxies it to the relay's path (GAP-0158),
// and every client builds its URLs as RouteBase + "/" + route, where the
// route base is either a relay origin plus Prefix or the gateway's attach
// prefix.
const (
	// Prefix is where the relay's own routes begin.
	Prefix = "/dcrelay/1"

	RouteWS     = "ws"
	RoutePoll   = "poll"
	RouteTask   = "task"
	RouteStatus = "status"
	RouteExec   = "exec"
	RouteFiles  = "files"
)

// AttachRoutes are the first path segments the gateway's attach route
// passes through to the relay (anything below them goes along).
var AttachRoutes = []string{RouteWS, RoutePoll, RouteTask, RouteStatus, RouteExec, RouteFiles}

// Path returns the relay's own path of route (route may carry more
// segments, as "poll/<id>").
func Path(route string) string { return Prefix + "/" + strings.TrimLeft(route, "/") }

// RouteBase returns the route base of a relay reached at its own origin
// (tests, tools, in-cluster callers). Through the gateway the route base is
// the attach prefix itself.
func RouteBase(origin string) string { return strings.TrimRight(origin, "/") + Prefix }

// RouteURL joins a route base and a route.
func RouteURL(base, route string) string {
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(route, "/")
}
