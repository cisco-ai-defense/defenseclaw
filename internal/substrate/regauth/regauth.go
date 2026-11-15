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

// Package regauth gives the template verifier its registry logins
// (substrate.templates.registry_auth, GAP-0190): a mounted docker config,
// Amazon ECR tokens through the AWS SDK default credential chain, or none
// (anonymous, the default). Every login belongs to exactly one registry
// host; attest.Registry sends it only to that host, and only when it asks.
package regauth

import (
	"context"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
)

// FromConfig is the one place the controller and the gateway's create path
// get their template registry logins. nil means anonymous.
func FromConfig(c config.SubstrateRegistryAuthConfig) attest.CredentialSource {
	var srcs Chain
	if len(c.ECRHosts) > 0 {
		srcs = append(srcs, NewECR(c.ECRHosts, nil))
	}
	if p := strings.TrimSpace(c.DockerConfig); p != "" {
		srcs = append(srcs, &DockerConfigFile{Path: p})
	}
	switch len(srcs) {
	case 0:
		return nil
	case 1:
		return srcs[0]
	}
	return srcs
}

// Chain asks each source in turn; the first that has a login for the host,
// or fails for it, answers.
type Chain []attest.CredentialSource

// Credential implements attest.CredentialSource.
func (ch Chain) Credential(ctx context.Context, host string) (attest.Credential, bool, error) {
	for _, s := range ch {
		c, ok, err := s.Credential(ctx, host)
		if err != nil || ok {
			return c, ok, err
		}
	}
	return attest.Credential{}, false, nil
}
