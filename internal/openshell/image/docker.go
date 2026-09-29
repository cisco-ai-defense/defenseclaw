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
	"os/exec"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

// Docker runs one docker CLI command. Implementations must not interpret
// args through a shell.
type Docker interface {
	Run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) error
}

// CLI runs the docker binary.
type CLI struct {
	// Binary defaults to "docker".
	Binary string
}

// Run implements Docker.
func (c CLI) Run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) error {
	binary := c.Binary
	if binary == "" {
		binary = "docker"
	}
	cmd := processutil.CommandContext(ctx, binary, args...)
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
// with docker's output going to log.
func buildImage(ctx context.Context, d Docker, files []ContextFile, labels map[string]string, tag string, log io.Writer) error {
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
	if log == nil {
		log = io.Discard
	}
	err := d.Run(ctx, pr, log, log, args...)
	_ = pr.CloseWithError(io.ErrClosedPipe)
	return err
}

// tagImage gives the image source (an image ID or a name) the name target.
func tagImage(ctx context.Context, d Docker, source, target string) error {
	_, err := output(ctx, d, nil, "tag", source, target)
	return err
}

// imageFacts is what docker reports of a local image: its ID, the diff IDs
// of its layers, bottom first, and its labels.
type imageFacts struct {
	ID     string
	Layers []string
	Labels map[string]string
}

// inspectImage reports ref's imageFacts.
func inspectImage(ctx context.Context, d Docker, ref string) (imageFacts, error) {
	out, err := output(ctx, d, nil, "image", "inspect", "--format", "{{json .}}", ref)
	if err != nil {
		return imageFacts{}, fmt.Errorf("openshell image: inspect %s: %w", ref, err)
	}
	var doc struct {
		ID     string `json:"Id"`
		RootFS struct {
			Layers []string `json:"Layers"`
		} `json:"RootFS"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || !imageIDRE.MatchString(doc.ID) {
		return imageFacts{}, fmt.Errorf("openshell image: inspect %s returned no image", ref)
	}
	return imageFacts{ID: doc.ID, Layers: doc.RootFS.Layers, Labels: doc.Config.Labels}, nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
