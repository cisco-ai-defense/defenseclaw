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
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// TrustedCAsFor is the BuildSpec.TrustedCAs of an image built under cfg:
// on a managed computer's sandbox daemon the administrator's CAs as the
// managed gateway relayed them (OpenShellConfig.TrustedCAPEM, or the reason
// it could not read them), else the file openshell.trusted_ca_bundle names,
// which in a managed configuration must be administrator-owned. An error
// means no image may be built or used: a sandbox without the CAs the
// operator named would fail every intercepted TLS connection.
func TrustedCAsFor(cfg *config.Config) ([]byte, error) {
	if cfg == nil {
		return nil, nil
	}
	o := cfg.OpenShell
	if e := strings.TrimSpace(o.TrustedCAError); e != "" {
		return nil, fmt.Errorf("your organization's trusted CAs cannot be used: %s", e)
	}
	if o.TrustedCAPEM != "" {
		cas, err := openshell.ParseTrustedCAs([]byte(o.TrustedCAPEM))
		if err != nil {
			return nil, fmt.Errorf("your organization's trusted CAs cannot be used: %w", err)
		}
		return cas.PEM, nil
	}
	cas, err := openshell.LoadTrustedCAs(o.TrustedCABundle, managed.IsManagedEnterprise(cfg.DeploymentMode))
	if err != nil {
		return nil, err
	}
	return cas.PEM, nil
}
