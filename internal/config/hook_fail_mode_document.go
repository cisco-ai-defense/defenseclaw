// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ManagedEnterpriseDocument reports a config.yaml document whose
// deployment_mode is managed_enterprise, without loading the config.
func ManagedEnterpriseDocument(data []byte) bool {
	var doc struct {
		DeploymentMode string `yaml:"deployment_mode"`
	}
	return yaml.Unmarshal(data, &doc) == nil && managed.IsManagedEnterprise(doc.DeploymentMode)
}
