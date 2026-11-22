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

package regauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
)

// maxDockerConfigBytes bounds the login file.
const maxDockerConfigBytes = 1 << 20

// Docker Hub's registry and token service: a config.json names Docker Hub
// as https://index.docker.io/v1/, image references reach it as
// registry-1.docker.io, and its Bearer realm is auth.docker.io.
const (
	dockerHubRegistry = "registry-1.docker.io"
	dockerHubTokens   = "auth.docker.io"
)

// DockerConfigFile reads registry logins from a docker config.json (the
// chart mounts a kubernetes.io/dockerconfigjson Secret). It is re-read when
// its size or modification time changes, so a Secret update applies within
// the kubelet's sync period. A missing file is no logins (the Secret is
// optional); a file that does not parse fails every lookup, so a broken
// Secret shows as a registry error instead of a silent anonymous read.
type DockerConfigFile struct {
	Path string

	mu     sync.Mutex
	loaded bool
	mod    time.Time
	size   int64
	logins map[string]attest.Credential
	err    error
}

// Credential implements attest.CredentialSource.
func (d *DockerConfigFile) Credential(_ context.Context, host string) (attest.Credential, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	fi, err := os.Stat(d.Path)
	if errors.Is(err, fs.ErrNotExist) {
		d.loaded, d.logins, d.err = false, nil, nil
		return attest.Credential{}, false, nil
	}
	if err != nil {
		return attest.Credential{}, false, fmt.Errorf("registry login file %s: %w", d.Path, err)
	}
	if !d.loaded || !fi.ModTime().Equal(d.mod) || fi.Size() != d.size {
		d.loaded, d.mod, d.size = true, fi.ModTime(), fi.Size()
		d.logins, d.err = readDockerConfig(d.Path)
	}
	if d.err != nil {
		return attest.Credential{}, false, d.err
	}
	c, ok := d.logins[strings.ToLower(host)]
	return c, ok, nil
}

func readDockerConfig(path string) (map[string]attest.Credential, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("registry login file %s: %w", path, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxDockerConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("registry login file %s: %w", path, err)
	}
	if len(b) > maxDockerConfigBytes {
		return nil, fmt.Errorf("registry login file %s is larger than %d bytes", path, maxDockerConfigBytes)
	}
	logins, err := ParseDockerConfig(b)
	if err != nil {
		return nil, fmt.Errorf("registry login file %s: %w", path, err)
	}
	return logins, nil
}

// ParseDockerConfig reads the auths of a docker config.json into logins by
// registry host (lower case, with the port when the key has one). A key
// may be a host or a URL ("https://host/v1/"); Docker Hub's keys become
// registry-1.docker.io with auth.docker.io as its token service. Entries
// with only an identity token, and credential helpers, are not supported
// and are skipped. When two keys name the same host the first in sorted
// order wins. Errors never quote the file.
func ParseDockerConfig(b []byte) (map[string]attest.Credential, error) {
	var f struct {
		Auths map[string]struct {
			Auth     string `json:"auth"`
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, errors.New("not a docker config.json (want {\"auths\": {...}})")
	}
	keys := make([]string, 0, len(f.Auths))
	for k := range f.Auths {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := map[string]attest.Credential{}
	for _, k := range keys {
		e := f.Auths[k]
		host := registryHost(k)
		if host == "" {
			return nil, errors.New("an auths key is not a registry host")
		}
		if _, dup := out[host]; dup {
			continue
		}
		user, pass := e.Username, e.Password
		if e.Auth != "" {
			raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(e.Auth))
			if err != nil {
				return nil, fmt.Errorf("the auth of %s is not base64", host)
			}
			u, p, ok := strings.Cut(string(raw), ":")
			if !ok {
				return nil, fmt.Errorf("the auth of %s is not user:password", host)
			}
			user, pass = u, p
		}
		if user == "" {
			continue
		}
		c := attest.Credential{Username: user, Password: pass}
		if host == dockerHubRegistry {
			c.TokenHosts = []string{dockerHubTokens}
		}
		out[host] = c
	}
	return out, nil
}

// registryHost turns an auths key into the host image references use.
func registryHost(key string) string {
	h := strings.ToLower(strings.TrimSpace(key))
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	if h == "" || strings.ContainsAny(h, " @?#") {
		return ""
	}
	switch h {
	case "index.docker.io", "docker.io":
		return dockerHubRegistry
	}
	return h
}
