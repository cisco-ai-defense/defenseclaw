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

package sensor

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/sensor/agentchain"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// providerConfig is a credential-adjacent provider configuration file a CLI
// connector's agent reads itself to reach its model provider: the file at
// home below its account's home and, when the agent process started with
// env set, the file env names. suffix is the classifier's indicator for it.
type providerConfig struct {
	suffix, home, env string
}

// agentProviderConfigs are the provider configs per CLI connector. Claude
// Code on Amazon Bedrock loads the AWS shared config at every start, an idle
// TUI session included (GAP-1189). Only files the classifier grades
// credential-adjacent belong here: a secret store (~/.aws/credentials, the
// SSO token cache) is never one.
var agentProviderConfigs = map[string][]providerConfig{
	"claudecode": {{suffix: "/.aws/config", home: ".aws/config", env: "AWS_CONFIG_FILE"}},
}

// providerConfigFacts are what a read is compared with to decide it is the
// agent's own provider config. Seams for tests.
type providerConfigFacts struct {
	// home is the home directory the account database records for uid
	// (never the process's $HOME), "" while it is not known.
	home func(uid int) string
	// env is the value of name in the environment process pid started with.
	env func(pid int, name string) (string, bool)
	// realPath resolves every symbolic link and ".." in a path.
	realPath func(string) (string, error)
	// owner is the uid that owns the file at a resolved path.
	owner func(path string) (int, bool)
}

func defaultProviderConfigFacts() providerConfigFacts {
	return providerConfigFacts{
		home: procprobe.CachedOwnerHome, env: processStartEnv,
		realPath: winpath.EvalLinks, owner: fileOwnerUID,
	}
}

// ownProviderConfigRead reports whether a credential-adjacent file read is
// the agent process itself (depth 0, recognised as a CLI connector by its
// executable, install path or script) reading its own provider config. Such
// a read is the agent starting up, not credential access, and is not
// recorded.
//
// Its own means the file the read resolves to (every link and ".."
// resolved) is the one its account's home or its AWS_CONFIG_FILE resolves
// to, and that file is owned by the process's account. Another account's
// home, /root, a staged copy, a checkout's .aws/config, and an own-home link
// to another account's file all stay credential access (GAP-1592), as does
// the same read by anything the agent started, by a process recognised only
// by a name pattern or argv, of any other file, every high-confidence read,
// and a read whose account or home is not known (Windows, or a directory
// account not resolved yet).
func ownProviderConfigRead(event plane.Event, lineage agentchain.Lineage, match tactics.Match, indicators tactics.IndicatorSet, facts providerConfigFacts) bool {
	if event.Kind != plane.KindFileRead || lineage.Depth != 0 ||
		match.SignalID != "agent_credential_access" || match.Confidence >= 1 {
		return false
	}
	uid := event.UID
	if uid == nil {
		uid = lineage.Root.UID
	}
	if uid == nil {
		return false
	}
	for _, config := range agentProviderConfigs[lineage.Root.Agent.Connector] {
		if match.Detail == config.suffix && hasPathSuffix(event.Path, config.suffix, indicators.CaseInsensitivePaths) &&
			facts.ownFile(event.Path, event.PID, *uid, config) {
			return true
		}
	}
	return false
}

// ownFile reports whether path is config's file for process pid of account
// uid, compared as real paths, and owned by uid.
func (f providerConfigFacts) ownFile(path string, pid, uid int, config providerConfig) bool {
	read, err := f.realPath(path)
	if err != nil {
		return false
	}
	if owner, ok := f.owner(read); !ok || owner != uid {
		return false
	}
	home := f.home(uid)
	if !filepath.IsAbs(home) {
		home = ""
	}
	var candidates []string
	if home != "" {
		candidates = append(candidates, filepath.Join(home, filepath.FromSlash(config.home)))
	}
	if named, ok := f.env(pid, config.env); ok {
		switch {
		case strings.HasPrefix(named, "~/") && home != "":
			// The AWS SDKs expand a leading ~ to the home.
			candidates = append(candidates, filepath.Join(home, named[2:]))
		case filepath.IsAbs(named):
			// A relative name depends on the cwd of the read, which the
			// event does not carry.
			candidates = append(candidates, named)
		}
	}
	for _, candidate := range candidates {
		if real, err := f.realPath(candidate); err == nil && real == read {
			return true
		}
	}
	return false
}

// maxProcessEnv bounds the environment block read for one process.
const maxProcessEnv = 1 << 20

// processStartEnv is the value of name in the environment process pid
// started with, from /proc/<pid>/environ on Linux. Elsewhere there is no such
// file, and only the account's home counts: a /proc folder there is no start
// environment (on Windows \proc at the drive root is a folder any account may
// make), so it is never read.
func processStartEnv(pid int, name string) (string, bool) {
	if runtime.GOOS != "linux" {
		return "", false
	}
	file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "environ"))
	if err != nil {
		return "", false
	}
	defer file.Close()
	block, err := io.ReadAll(io.LimitReader(file, maxProcessEnv))
	if err != nil {
		return "", false
	}
	prefix := []byte(name + "=")
	for _, entry := range bytes.Split(block, []byte{0}) {
		if bytes.HasPrefix(entry, prefix) {
			value := string(entry[len(prefix):])
			return value, value != ""
		}
	}
	return "", false
}

// hasPathSuffix reports whether path ends in suffix, folding case where the
// platform's filesystem does.
func hasPathSuffix(path, suffix string, caseInsensitive bool) bool {
	if len(path) < len(suffix) {
		return false
	}
	tail := path[len(path)-len(suffix):]
	if caseInsensitive {
		return strings.EqualFold(tail, suffix)
	}
	return tail == suffix
}
