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

package openshell

import (
	"fmt"
	"strconv"
	"strings"
)

// BuildKit.
//
// DefenseClaw's image Dockerfiles use BuildKit-only syntax (COPY --chmod),
// and `docker build` builds with BuildKit only through Docker's buildx CLI
// plugin. Without the plugin (docker looks for it in the cli-plugins
// directory of its config, DOCKER_CONFIG or ~/.docker, so another HOME
// hides it), or with DOCKER_BUILDKIT=0, docker falls back to the legacy
// builder: it runs every step before the first COPY --chmod, the harness
// install among them, and then stops with "the --chmod option requires
// BuildKit". The image builder checks first (image.Builder).

// BuildKitArgs is the docker command that succeeds only when docker finds
// its buildx plugin.
var BuildKitArgs = []string{"buildx", "version"}

// BuildKitProblem explains why `docker build` would not use BuildKit, and
// how to fix it on goos; problem is empty when it would. env is the value
// of DOCKER_BUILDKIT docker sees, out and err the outcome of `docker
// BuildKitArgs...`.
func BuildKitProblem(goos, env string, out []byte, err error) (problem, fix string) {
	if v := strings.TrimSpace(env); v != "" {
		on, perr := strconv.ParseBool(v)
		switch {
		case perr != nil:
			return fmt.Sprintf("DOCKER_BUILDKIT=%q is not true or false, and docker build refuses to run with it", v),
				"unset DOCKER_BUILDKIT, or set it to 1"
		case !on:
			return fmt.Sprintf("DOCKER_BUILDKIT=%s turns BuildKit off, and docker's legacy builder cannot build the sandbox images "+
					"(their Dockerfile uses COPY --chmod)", v),
				"unset DOCKER_BUILDKIT, or set it to 1"
		}
	}
	if err == nil {
		return "", ""
	}
	why := firstOutputLine(out)
	if why == "" {
		why = err.Error()
	}
	return fmt.Sprintf("docker's buildx plugin is not available (`docker %s`: %s), so docker build would fall back to the legacy builder, "+
		"which cannot build the sandbox images (their Dockerfile uses COPY --chmod)", strings.Join(BuildKitArgs, " "), why), BuildKitFix(goos)
}

// BuildKitFix is how to give docker its buildx plugin on goos.
func BuildKitFix(goos string) string {
	from := "Docker Desktop provides it"
	if goos == "linux" {
		from = "the docker-buildx-plugin package from Docker's repository, or Docker Desktop"
	}
	return "install Docker's buildx plugin (" + from + "), and make sure DOCKER_CONFIG, or ~/.docker when it is unset, " +
		"is the Docker config whose cli-plugins directory has docker-buildx"
}

func firstOutputLine(out []byte) string {
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
}
