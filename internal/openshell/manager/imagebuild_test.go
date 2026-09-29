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

package manager

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// buildFailingDocker is a Docker daemon without images whose builds print
// output and fail. It has the buildx plugin unless noBuildx is set.
type buildFailingDocker struct {
	output   string
	noBuildx bool
	builds   *int
}

func (d buildFailingDocker) Run(_ context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) error {
	if stdin != nil {
		_, _ = io.Copy(io.Discard, stdin)
	}
	switch args[0] {
	case "buildx":
		if d.noBuildx {
			_, _ = io.WriteString(stderr, "docker: unknown command: docker buildx\n\nRun 'docker --help' for more information\n")
			return &image.CommandError{Args: args, ExitCode: 1}
		}
		_, _ = io.WriteString(stdout, "github.com/docker/buildx v0.30.1 c6f062d\n")
		return nil
	case "build":
		if d.builds != nil {
			*d.builds++
		}
		_, _ = io.WriteString(stderr, d.output)
	}
	return &image.CommandError{Args: args, ExitCode: 1}
}

// TestCreateReportsTheEndOfAFailedImageBuild: the daemon builds without a
// build log, so a create whose image build fails carries the last lines
// docker printed, in its error and in the daemon log.
func TestCreateReportsTheEndOfAFailedImageBuild(t *testing.T) {
	e := newEnv(t, nil)
	var mu sync.Mutex
	var logs []string
	e.m.logf = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		logs = append(logs, fmt.Sprintf(format, args...))
	}
	output := "#1 [internal] load build definition from Dockerfile\n" +
		"#6 [2/9] RUN set -eu; apt-get update\n#6 0.412 E: Could not resolve 'deb.debian.org'\n" +
		"ERROR: failed to build: process \"/bin/sh -c set -eu; apt-get update\" did not complete successfully: exit code: 100\n"
	e.m.opts.Images = BuilderImages{Builder: &image.Builder{
		Docker: buildFailingDocker{output: output}, Store: image.NewStore(e.dataDir), Log: io.Discard,
	}}
	_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "img-box"})
	apiErr := wantCode(t, err, sandboxapi.CodeImageUnavailable)
	tail := "docker build exited 1; the last lines docker printed:\n" +
		"    #1 [internal] load build definition from Dockerfile\n    #6 [2/9] RUN set -eu; apt-get update\n" +
		"    #6 0.412 E: Could not resolve 'deb.debian.org'\n" +
		"    ERROR: failed to build: process \"/bin/sh -c set -eu; apt-get update\" did not complete successfully: exit code: 100"
	if !strings.HasSuffix(apiErr.Detail, tail) || apiErr.Message != "the Claude Code sandbox image is not usable" {
		t.Fatalf("create error = %+v, want the detail to end with\n%s", apiErr, tail)
	}
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, l := range logs {
		found = found || strings.HasPrefix(l, string(gatewaylog.ErrCodeOpenShellImageBuildFailed)+": claudecode: ") && strings.HasSuffix(l, tail)
	}
	if !found {
		t.Fatalf("the daemon log lacks the build's output:\n%s", strings.Join(logs, "\n"))
	}
	assertNothingLeft(t, e)
}

// TestCreateNamesTheMissingBuildxPlugin: a daemon whose docker lacks the
// buildx plugin (another HOME or DOCKER_CONFIG hides it) refuses the image
// build before docker build runs, and the create error says how to fix it.
func TestCreateNamesTheMissingBuildxPlugin(t *testing.T) {
	t.Setenv("DOCKER_BUILDKIT", "")
	e := newEnv(t, nil)
	builds := 0
	e.m.opts.Images = BuilderImages{Builder: &image.Builder{
		Docker: buildFailingDocker{noBuildx: true, builds: &builds}, Store: image.NewStore(e.dataDir), Log: io.Discard,
	}}
	_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "img-box"})
	apiErr := wantCode(t, err, sandboxapi.CodeImageUnavailable)
	for _, want := range []string{"docker's buildx plugin is not available (`docker buildx version`: docker: unknown command: docker buildx)",
		"install Docker's buildx plugin", "DOCKER_CONFIG"} {
		if !strings.Contains(apiErr.Detail, want) {
			t.Fatalf("create error detail = %q, want %q", apiErr.Detail, want)
		}
	}
	if builds != 0 {
		t.Fatalf("docker build ran %d times", builds)
	}
	assertNothingLeft(t, e)
}
