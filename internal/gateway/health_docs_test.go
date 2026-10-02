// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The gateway API reference must describe what the unauthenticated /health
// document carries on the standalone profile (handleHealth), where /health
// is also served (the Unix hook socket), and the routes that do not take the
// gateway token (tokenAuth): the ACP signed routes and the listener proof.
func TestGatewayAPIDocsDescribeHealthAndAuthExceptions(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs-site", "content", "docs", "reference", "gateway-api.mdx"))
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Join(strings.Fields(string(raw)), " ")
	for _, want := range []string{
		"`inspection`",
		"`user_scoped_credentials.key_ids`",
		"hook socket also answers `GET /health`",
		"`POST /api/v1/acp/evaluate`",
		"`GET " + connector.UserScopedListenerProofPath + "`",
		"`" + connector.UserScopedListenerKeyIDHeader + "`",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("gateway-api.mdx does not mention %s", want)
		}
	}
}
