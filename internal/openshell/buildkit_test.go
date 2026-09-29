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

package openshell_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// BuildKit is available when `docker buildx version` succeeds and
// DOCKER_BUILDKIT does not turn it off; the problem quotes docker (or,
// without output, the error), and the fix fits the platform.
func TestBuildKitProblem(t *testing.T) {
	ok := []byte("github.com/docker/buildx v0.30.1-desktop.2 c6f062d0eef6a18ae703d0433e2c8a4dd34d4513\n")
	exit1 := errors.New("docker: exit status 1")
	for _, tc := range []struct {
		goos, env string
		out       []byte
		err       error
		problem   string
		fix       string
	}{
		{goos: "darwin", out: ok},
		{goos: "linux", env: " true ", out: ok},
		{goos: "linux", env: "1", out: ok},
		{goos: "darwin", env: "0", out: ok, problem: "DOCKER_BUILDKIT=0 turns BuildKit off", fix: "unset DOCKER_BUILDKIT, or set it to 1"},
		{goos: "linux", env: "yes", out: ok, problem: `DOCKER_BUILDKIT="yes" is not true or false`, fix: "unset DOCKER_BUILDKIT"},
		{goos: "darwin", out: []byte("\ndocker: unknown command: docker buildx\n\nRun 'docker --help'\n"), err: exit1,
			problem: "(`docker buildx version`: docker: unknown command: docker buildx), so docker build would fall back to the legacy builder",
			fix:     "(Docker Desktop provides it)"},
		{goos: "linux", err: exit1, problem: "(`docker buildx version`: docker: exit status 1)", fix: "(the docker-buildx-plugin package from Docker's repository, or Docker Desktop)"},
	} {
		problem, fix := openshell.BuildKitProblem(tc.goos, tc.env, tc.out, tc.err)
		if (tc.problem == "") != (problem == "") || !strings.Contains(problem, tc.problem) || !strings.Contains(fix, tc.fix) || (problem == "") != (fix == "") {
			t.Errorf("BuildKitProblem(%s, %q, %q, %v) = %q, %q; want %q, %q", tc.goos, tc.env, tc.out, tc.err, problem, fix, tc.problem, tc.fix)
		}
	}
	for out, want := range map[string]string{
		string(ok):                              "v0.30.1-desktop.2",
		"github.com/docker/buildx 0.30.1 abc\n": "",
		"":                                      "",
		"  github.com/docker/buildx v0.12.1 abc\nx\n": "v0.12.1",
	} {
		if got := openshell.BuildKitVersion([]byte(out)); got != want {
			t.Errorf("BuildKitVersion(%q) = %q, want %q", out, got, want)
		}
	}
}
