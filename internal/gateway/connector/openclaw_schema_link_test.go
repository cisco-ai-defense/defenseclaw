// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import "github.com/defenseclaw/defenseclaw/internal/gateway/connector/openclawschema"

// The gateway and the CLI register the plugin config check in production;
// this package's own Setup tests register it the same way.
func init() { SetOpenClawPluginConfigMigrator(openclawschema.Migrate) }
