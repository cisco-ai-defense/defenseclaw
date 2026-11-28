// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/openclawschema"
)

// Every connector Setup runs from the gateway or from the CLI, which links
// this package: register the OpenClaw plugin config check here, where the
// hook binary does not link it (see connector.SetOpenClawPluginConfigMigrator).
func init() { connector.SetOpenClawPluginConfigMigrator(openclawschema.Migrate) }
