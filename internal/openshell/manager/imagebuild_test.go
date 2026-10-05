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
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// buildFailingDocker is a Docker daemon without images whose builds print
// output and fail. It has the buildx plugin unless noBuildx is set, and
// runs in an empty environment.
type buildFailingDocker struct {
	output   string
	noBuildx bool
	builds   *int
}

func (buildFailingDocker) Getenv(string) string { return "" }

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

// daemonLog collects what the manager of e logs.
func daemonLog(e *harnessEnv) func() []string {
	var mu sync.Mutex
	var logs []string
	e.m.logf = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		logs = append(logs, fmt.Sprintf(format, args...))
	}
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(logs)
	}
}

// assertBuildOutputLoggedOnce: the create of name whose image build failed
// logs docker's output, of which line is one line, once, in the
// OPENSHELL_IMAGE_BUILD_FAILED line whose prefix is buildPrefix. The
// create's OPENSHELL_SANDBOX_FAILED line and its failed sandbox-health
// record, which is exported, carry the failure without the output: it ends
// with docker's exit.
func assertBuildOutputLoggedOnce(t *testing.T, e *harnessEnv, logs []string, name, buildPrefix, line string) {
	t.Helper()
	var withOutput []string
	failedPrefix := string(gatewaylog.ErrCodeOpenShellSandboxFailed) + ": create " + name + ": "
	failed := ""
	for _, l := range logs {
		if strings.Contains(l, line) {
			withOutput = append(withOutput, l)
		}
		if strings.HasPrefix(l, failedPrefix) {
			failed = l
		}
	}
	if len(withOutput) != 1 || !strings.HasPrefix(withOutput[0], buildPrefix) {
		t.Fatalf("docker's output is in %d daemon log lines, want one that starts %q:\n%s", len(withOutput), buildPrefix, strings.Join(logs, "\n"))
	}
	if !strings.HasSuffix(failed, ": docker build exited 1") || strings.Contains(failed, "\n") {
		t.Fatalf("the create's failure line = %q, want it to end with docker's exit and nothing after", failed)
	}
	health := where(&e.tel.mu, &e.tel.health, func(h audit.SandboxHealthEvent) bool {
		return h.Sandbox.Name == name && h.State == audit.SandboxHealthFailed
	})
	if want := strings.TrimPrefix(failed, failedPrefix); len(health) != 1 || health[0].ErrorSummary != want {
		t.Fatalf("failed health records = %+v, want one with the summary %q", health, want)
	}
}

// TestCreateReportsTheEndOfAFailedImageBuild: the daemon builds without a
// build log, so a create whose image build fails carries the last lines
// docker printed in its error and, once, in the daemon log; the create's
// own failure line and telemetry leave them out. DOCKER_BUILDKIT here is
// not the environment the builder's docker runs in.
func TestCreateReportsTheEndOfAFailedImageBuild(t *testing.T) {
	t.Setenv("DOCKER_BUILDKIT", "0")
	e := newEnv(t, nil)
	logs := daemonLog(e)
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
	got := logs()
	if !slices.ContainsFunc(got, func(l string) bool {
		return strings.HasPrefix(l, string(gatewaylog.ErrCodeOpenShellImageBuildFailed)+": claudecode: ") && strings.HasSuffix(l, tail)
	}) {
		t.Fatalf("the daemon log lacks the build's output:\n%s", strings.Join(got, "\n"))
	}
	assertBuildOutputLoggedOnce(t, e, got, "img-box", string(gatewaylog.ErrCodeOpenShellImageBuildFailed)+": claudecode: ", "Could not resolve")
	assertNothingLeft(t, e)
}

// A MicroVM create whose run image build fails is reported the same way:
// the output in the error and in its one OPENSHELL_IMAGE_BUILD_FAILED line,
// not in the create's failure line or telemetry.
func TestCreateReportsTheEndOfAFailedRunImageBuild(t *testing.T) {
	e := newVMEnv(t, nil)
	logs := daemonLog(e)
	output := "#4 [2/3] COPY --chmod=0644 claude.json /etc/claude-code/managed-settings.d/50-run.json\n" +
		"#4 ERROR: failed to compute cache key: \"/claude.json\" not found"
	e.images.runErr = fmt.Errorf("openshell image: docker build defenseclaw.invalid/sandbox-run:claudecode-x: %w",
		&image.BuildError{Err: &image.CommandError{Args: []string{"build"}, ExitCode: 1}, Output: output})
	_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "vm-box", Copy: true, LLM: anthropicLLM, Credentials: stripeCred})
	apiErr := wantCode(t, err, sandboxapi.CodeImageUnavailable)
	if !strings.HasSuffix(apiErr.Detail, "docker build exited 1; the last lines docker printed:\n    "+strings.ReplaceAll(output, "\n", "\n    ")) {
		t.Fatalf("create error = %+v, want docker's output at the end", apiErr)
	}
	assertBuildOutputLoggedOnce(t, e, logs(), "vm-box", string(gatewaylog.ErrCodeOpenShellImageBuildFailed)+": claudecode: run image: ",
		"failed to compute cache key")
	assertNothingLeft(t, e)
}

// TestCreateNamesTheMissingBuildxPlugin: a daemon whose docker lacks the
// buildx plugin (another HOME or DOCKER_CONFIG hides it) refuses the image
// build before docker build runs, and the create error says how to fix it.
func TestCreateNamesTheMissingBuildxPlugin(t *testing.T) {
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

// relabeled is an error that wraps err under a message of its own.
type relabeled struct{ err error }

func (r relabeled) Error() string { return "the build broke" }
func (r relabeled) Unwrap() error { return r.err }

// A build the daemon cannot run for the docker socket's permissions names
// the restart that picks up a docker group joined since (GAP-2137).
func TestImageErrorNamesTheDaemonRestart(t *testing.T) {
	denied := &image.BuildError{Err: &image.CommandError{Args: []string{"build"}, ExitCode: 1},
		Output: "ERROR: permission denied while trying to connect to the docker API at unix:///var/run/docker.sock"}
	e := newImageError("the Claude Code sandbox image is not usable", fmt.Errorf("openshell image: docker build t: %w", denied))
	if !strings.Contains(e.api.Detail, "→ the DefenseClaw daemon cannot reach Docker") || !strings.Contains(e.api.Detail, "defenseclaw-gateway restart") {
		t.Fatalf("detail = %q", e.api.Detail)
	}
	if strings.Contains(e.summary, "restart") {
		t.Fatalf("summary = %q", e.summary)
	}
	other := newImageError("x", errors.New("docker build exited 1"))
	if strings.Contains(other.api.Detail, "restart") {
		t.Fatalf("detail = %q", other.api.Detail)
	}
}

// withoutBuildOutput keeps the whole message but the output of the docker
// build that failed, and never lets the output through.
func TestWithoutBuildOutput(t *testing.T) {
	exited := &image.CommandError{Args: []string{"build"}, ExitCode: 1}
	withOutput := &image.BuildError{Err: exited, Output: "#6 ERROR: boom\nERROR: failed to build"}
	for _, tc := range []struct {
		err  error
		want string
	}{
		{errors.New("docker image inspect x exited 1"), "docker image inspect x exited 1"},
		{fmt.Errorf("openshell image: docker build t: %w", &image.BuildError{Err: exited}), "openshell image: docker build t: docker build exited 1"},
		{fmt.Errorf("openshell image: docker build t: %w", withOutput), "openshell image: docker build t: docker build exited 1"},
		{fmt.Errorf("resolve: %w", relabeled{withOutput}), "docker build exited 1"},
	} {
		if got := withoutBuildOutput(tc.err); got != tc.want {
			t.Errorf("withoutBuildOutput(%q) = %q, want %q", tc.err, got, tc.want)
		}
	}
}
