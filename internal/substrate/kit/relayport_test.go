// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// S2B-4: config.SubstrateRelayPort, the port a forward never reaches, is
// the relay's own listen port.
func TestSubstrateRelayPortIsTheRelayListenPort(t *testing.T) {
	if got := DefaultConfig().Relay.Listen; got != ":"+strconv.Itoa(config.SubstrateRelayPort) {
		t.Fatalf("relay listens on %q, config.SubstrateRelayPort is %d", got, config.SubstrateRelayPort)
	}
}
