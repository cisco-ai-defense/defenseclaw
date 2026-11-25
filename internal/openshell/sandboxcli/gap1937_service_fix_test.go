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

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// rel-1-0-10:GAP-1937: on a managed computer the sandbox commands start the
// account's sandbox service only under the launcher's name (`defenseclaw`,
// a symlink to defenseclaw-gateway). Run as defenseclaw-gateway by its
// path, a sandbox command said the service does not answer and that
// "every sandbox command starts it", which that command had not done. It
// names the command that does.
func TestGAP1937ServiceFixNamesTheCommandThatStartsIt(t *testing.T) {
	withManagedHost(t)
	err := apiError(&sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Message: "the DefenseClaw daemon is not reachable", Detail: "nothing accepted the connection on its port"})
	if err == nil {
		t.Fatal("no error")
	}
	text := err.Error()
	if strings.Contains(text, "every sandbox command starts it") || !strings.Contains(text, "`defenseclaw sandbox") {
		t.Fatalf("run as defenseclaw-gateway, the service fix = %q; want the defenseclaw command that starts the service, not 'every sandbox command starts it'", text)
	}
	// The launcher's sandbox commands do start it.
	LauncherStartsService = true
	t.Cleanup(func() { LauncherStartsService = false })
	if text := apiError(&sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Message: "the DefenseClaw daemon is not reachable"}).Error(); !strings.Contains(text, "every sandbox command starts it") {
		t.Fatalf("the launcher's service fix = %q", text)
	}
}
