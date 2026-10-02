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

package sandboxcli

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// gitIdentityEnv are the variables withGitIdentity sets, each with the git
// configuration key it takes its value from.
var gitIdentityEnv = [][2]string{
	{"GIT_AUTHOR_NAME", "user.name"}, {"GIT_COMMITTER_NAME", "user.name"},
	{"GIT_AUTHOR_EMAIL", "user.email"}, {"GIT_COMMITTER_EMAIL", "user.email"},
}

// maxGitIdentity bounds one identity value.
const maxGitIdentity = 256

// gitConfigTimeout bounds one read of the host's git configuration.
const gitConfigTimeout = 5 * time.Second

// withGitIdentity gives the sandbox's git the identity the host's git uses
// for the project (user.name and user.email, the repository's own before
// the user's), as the GIT_AUTHOR_* and GIT_COMMITTER_* variables. The
// sandbox has none of the user's git configuration, so without them its
// git refuses to commit, and it looks up the sandbox's host name to make up
// an address, which OpenShell's DNS refuses. What --env sets is kept.
func (a *App) withGitIdentity(ctx context.Context, project string, env map[string]string) map[string]string {
	values := map[string]string{}
	for _, key := range []string{"user.name", "user.email"} {
		values[key] = gitIdentityValue(a.GitConfig(ctx, project, key))
	}
	for _, kv := range gitIdentityEnv {
		v := values[kv[1]]
		if v == "" {
			continue
		}
		if _, set := env[kv[0]]; set {
			continue
		}
		if env == nil {
			env = map[string]string{}
		}
		env[kv[0]] = v
	}
	return env
}

// gitIdentityValue is an identity value fit for the sandbox environment:
// one line of text without control characters, at most maxGitIdentity
// bytes; anything else is dropped.
func gitIdentityValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > maxGitIdentity || strings.IndexFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return ""
	}
	return v
}

// hostGitConfig reads one configuration key with the host's git in dir
// (App.GitConfig). Reading configuration runs no hook or helper; a missing
// git, an unset key or a failure reads as "".
func (a *App) hostGitConfig(ctx context.Context, dir, key string) string {
	git, err := a.LookPath("git")
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, gitConfigTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, git, "-C", dir, "config", "--get", key)
	cmd.Env = append(a.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
