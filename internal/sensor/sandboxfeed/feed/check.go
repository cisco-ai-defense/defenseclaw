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

package feed

import (
	"context"
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/sensor/tetragon"
)

// Check reports whether this host can run the feed: a Tetragon that serves a
// unix socket passing the managed helper's trust checks (root-owned info
// file, socket and directory; SO_PEERCRED uid 0 and the info file's pid; a
// supported release), and a Docker Engine that answers. It is what `sandbox
// kernel-feed install` runs, with the installed binary, before it enables
// the service. It loads nothing and asks Tetragon only for its version.
func Check(ctx context.Context, docker *DockerInspector) (string, error) {
	client, err := tetragon.Dial(ctx, tetragon.DialOptions{Scope: tetragon.ScopeConsume})
	if err != nil {
		return "", err
	}
	version, socket := client.Version().String(), client.Socket()
	_ = client.Close()
	if docker == nil {
		docker = &DockerInspector{}
	}
	if err := docker.Ping(ctx); err != nil {
		return "", fmt.Errorf("the Docker Engine does not answer: %w", err)
	}
	return fmt.Sprintf("Tetragon %s on %s; Docker Engine answers", version, socket), nil
}
