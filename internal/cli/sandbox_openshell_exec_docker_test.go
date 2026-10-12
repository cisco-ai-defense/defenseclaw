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

//go:build unix

package cli

import (
	"errors"
	"testing"
)

// GAP-0613: the account's gateway gets the Docker endpoint its docker CLI
// uses (DOCKER_HOST, else the current context's unix socket), so the
// MicroVM driver finds the images built there.
func TestDockerContextHostFollowsTheAccountsCLI(t *testing.T) {
	noEnv := func(string) (string, bool) { return "", false }
	colima := func() (string, error) { return "unix:///Users/frank/.colima/default/docker.sock\n", nil }
	if got := dockerContextHost(noEnv, colima); got != "unix:///Users/frank/.colima/default/docker.sock" {
		t.Fatalf("context host = %q", got)
	}
	set := func(k string) (string, bool) { return "unix:///tmp/own.sock", k == "DOCKER_HOST" }
	if got := dockerContextHost(set, colima); got != "unix:///tmp/own.sock" {
		t.Fatalf("DOCKER_HOST = %q", got)
	}
	for _, answer := range []func() (string, error){
		func() (string, error) { return "", errors.New("no docker") },
		func() (string, error) { return "tcp://10.0.0.1:2375", nil },
		func() (string, error) { return "", nil },
	} {
		if got := dockerContextHost(noEnv, answer); got != "" {
			t.Fatalf("unusable answer gave %q", got)
		}
	}
}
