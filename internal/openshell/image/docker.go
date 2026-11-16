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

package image

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

// Docker runs one docker CLI command. Implementations must not interpret
// args through a shell.
type Docker interface {
	Run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) error
	// Getenv reads the environment the commands run in, which docker also
	// takes settings from (DOCKER_BUILDKIT, see checkBuildKit).
	Getenv(key string) string
}

// SystemDockerHost is the system Docker engine on Linux: the one the
// managed OpenShell gateway's docker and MicroVM drivers ask (the gateway
// starts without DOCKER_HOST), and the one the managed availability checks
// judge by the account's docker group.
const SystemDockerHost = "unix:///var/run/docker.sock"

// CLI runs the docker binary, in this process's environment.
type CLI struct {
	// Binary defaults to "docker".
	Binary string
	// Host, when set, is the engine every command uses (DOCKER_HOST, with
	// DOCKER_CONTEXT dropped), whatever engine the account's current
	// Docker context or environment names.
	Host string
}

// ManagedCLI is the docker CLI that builds, lists and removes the harness
// images on a computer, managed tells whether it is a managed one. A
// managed Linux computer pins the system engine: its OpenShell gateway's
// docker and MicroVM drivers boot the images from there, and an account
// whose Docker context or service environment named another engine
// (rootless Docker, another account's daemon) had its image built where
// the gateway could not find it, which then tried to pull it from the
// reserved registry name (#1195). Everywhere else it is the account's own
// docker CLI, which the managed macOS gateway follows (GAP-0613).
func ManagedCLI(managed bool, goos string) CLI {
	if managed && goos == "linux" {
		return CLI{Host: SystemDockerHost}
	}
	return CLI{}
}

// Getenv implements Docker: docker runs in this process's environment,
// with Host as its DOCKER_HOST when set.
func (c CLI) Getenv(key string) string {
	if c.Host != "" {
		switch key {
		case "DOCKER_HOST":
			return c.Host
		case "DOCKER_CONTEXT":
			return ""
		}
	}
	return os.Getenv(key)
}

// environ is the environment docker runs in ("" when it is this process's
// own): extra on the PATH for docker's plugins, Host as the one engine.
func (c CLI) environ(extra []string) []string {
	if len(extra) == 0 && c.Host == "" {
		return nil
	}
	env := os.Environ()
	if c.Host != "" {
		env = slices.DeleteFunc(env, func(kv string) bool {
			return strings.HasPrefix(kv, "DOCKER_HOST=") || strings.HasPrefix(kv, "DOCKER_CONTEXT=")
		})
		env = append(env, "DOCKER_HOST="+c.Host)
	}
	if len(extra) > 0 {
		// docker runs its plugins and credential helpers (buildx,
		// docker-credential-desktop) from its own folder.
		env = append(env, "PATH="+strings.Join(append([]string{os.Getenv("PATH")}, extra...), string(os.PathListSeparator)))
	}
	return env
}

// Run implements Docker.
func (c CLI) Run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) error {
	binary, extra := c.Binary, []string(nil)
	if binary == "" {
		binary, extra = DockerBinary(runtime.GOOS, exec.LookPath, os.Stat)
	}
	cmd := processutil.CommandContext(ctx, binary, args...)
	cmd.Env = c.environ(extra)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return &CommandError{Args: args, ExitCode: exitErr.ExitCode()}
		}
		return fmt.Errorf("docker %s: %w", firstArg(args), err)
	}
	return nil
}

// dockerInstalls are where docker is installed outside the PATH a service
// runs with. A macOS LaunchAgent's PATH is /usr/bin:/bin:/usr/sbin:/sbin,
// and Docker Desktop links docker into /usr/local/bin. Without these, the
// managed Mac's sandbox daemon could not build a harness image (GAP-0443).
var dockerInstalls = map[string][]string{
	"darwin": {"/usr/local/bin/docker", "/opt/homebrew/bin/docker", "/Applications/Docker.app/Contents/Resources/bin/docker"},
	"linux":  {"/usr/bin/docker", "/usr/local/bin/docker"},
}

// DockerBinary is the docker CLI to run: the PATH's, else the first of
// dockerInstalls that exists, with the folders its plugins and credential
// helpers are in (its own and its link target's) for the PATH it runs with.
// "docker" when there is none, which fails as before.
func DockerBinary(goos string, lookPath func(string) (string, error), stat func(string) (os.FileInfo, error)) (string, []string) {
	if path, err := lookPath("docker"); err == nil {
		return path, nil
	}
	for _, path := range dockerInstalls[goos] {
		info, err := stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		dirs := []string{filepath.Dir(path)}
		if real, err := filepath.EvalSymlinks(path); err == nil && filepath.Dir(real) != dirs[0] {
			dirs = append(dirs, filepath.Dir(real))
		}
		return path, dirs
	}
	return "docker", nil
}

// CommandError reports a docker command that exited non-zero.
type CommandError struct {
	Args     []string
	ExitCode int
	Stderr   string
}

func (e *CommandError) Error() string {
	msg := fmt.Sprintf("docker %s exited %d", firstArg(e.Args), e.ExitCode)
	if s := strings.TrimSpace(e.Stderr); s != "" {
		msg += ": " + lastLines(s, 5)
	}
	return msg
}

func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

// output runs a docker command and returns trimmed stdout; stderr is folded
// into the error.
func output(ctx context.Context, d Docker, stdin io.Reader, args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	if err := d.Run(ctx, stdin, &stdout, &stderr, args...); err != nil {
		var cmdErr *CommandError
		if errors.As(err, &cmdErr) && cmdErr.Stderr == "" {
			cmdErr.Stderr = stderr.String()
		}
		return stdout.String(), err
	}
	return strings.TrimSpace(stdout.String()), nil
}

// buildImage streams files as a build context (writeContextTar) to
// `docker build --pull=false --label k=v ... -t tag -`, the labels sorted,
// with docker's output going to log (nil discards it). A failed build
// returns a *BuildError with the end of that output, unless ctx ended it.
// A docker that would not build with BuildKit is refused first
// (ErrNoBuildKit).
func buildImage(ctx context.Context, d Docker, files []ContextFile, labels map[string]string, tag string, log io.Writer) error {
	if err := checkBuildKit(ctx, d); err != nil {
		return err
	}
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(writeContextTar(pw, files))
	}()
	args := []string{"build", "--pull=false"}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--label", key+"="+labels[key])
	}
	args = append(args, "-t", tag, "-")
	tail := &outputTail{}
	var out io.Writer = tail
	if log != nil {
		// The tail first: a log that fails a write stops the ones after it.
		out = io.MultiWriter(tail, log)
	}
	err := d.Run(ctx, pr, out, out, args...)
	_ = pr.CloseWithError(io.ErrClosedPipe)
	if err != nil && ctx.Err() == nil {
		return &BuildError{Err: err, Output: tail.String()}
	}
	return err
}

// ErrNoBuildKit reports a build refused because docker would build it with
// its legacy builder, which cannot (openshell.BuildKitProblem says why).
var ErrNoBuildKit = errors.New("docker does not build with BuildKit")

type buildKitError struct{ problem, fix string }

func (e *buildKitError) Error() string        { return e.problem + "; " + e.fix }
func (e *buildKitError) Is(target error) bool { return target == ErrNoBuildKit }

// checkBuildKit refuses, with the fix, a docker that would not build with
// BuildKit: DOCKER_BUILDKIT, in the environment d runs docker in, turns it
// off or is not a boolean, or `docker buildx version` fails.
// A legacy build would run every step before the first COPY --chmod (the
// harness install, a download of about 3 GB) and only then stop.
func checkBuildKit(ctx context.Context, d Docker) error {
	var out bytes.Buffer
	err := d.Run(ctx, nil, &out, &out, openshell.BuildKitArgs...)
	var cmdErr *CommandError
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case err != nil && !errors.As(err, &cmdErr):
		// docker did not run at all; the build would fail the same way.
		return err
	}
	if problem, fix := openshell.BuildKitProblem(runtime.GOOS, d.Getenv("DOCKER_BUILDKIT"), out.Bytes(), err); problem != "" {
		return &buildKitError{problem: problem, fix: fix}
	}
	return nil
}

// tagImage gives the image source (an image ID or a name) the name target.
func tagImage(ctx context.Context, d Docker, source, target string) error {
	_, err := output(ctx, d, nil, "tag", source, target)
	return err
}

// imageFacts is what docker reports of a local image: its ID, the diff IDs
// of its layers, bottom first, its labels and its repo digests.
type imageFacts struct {
	ID          string
	Layers      []string
	Labels      map[string]string
	RepoDigests []string
}

// inspectImage reports ref's imageFacts.
func inspectImage(ctx context.Context, d Docker, ref string) (imageFacts, error) {
	out, err := output(ctx, d, nil, "image", "inspect", "--format", "{{json .}}", ref)
	if err != nil {
		return imageFacts{}, fmt.Errorf("openshell image: inspect %s: %w", ref, err)
	}
	var doc struct {
		ID          string   `json:"Id"`
		RepoDigests []string `json:"RepoDigests"`
		RootFS      struct {
			Layers []string `json:"Layers"`
		} `json:"RootFS"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || !imageIDRE.MatchString(doc.ID) {
		return imageFacts{}, fmt.Errorf("openshell image: inspect %s returned no image", ref)
	}
	return imageFacts{ID: doc.ID, Layers: doc.RootFS.Layers, Labels: doc.Config.Labels, RepoDigests: doc.RepoDigests}, nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
