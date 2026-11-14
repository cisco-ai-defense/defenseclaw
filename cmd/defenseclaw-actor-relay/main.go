// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// defenseclaw-actor-relay is the terminal relay and headless runner inside an
// Agent Substrate actor (internal/substrate/relay). It is the actor image's
// entrypoint.
package main

import (
	"os"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

func main() {
	os.Exit(relay.Main(os.Args[1:], os.Stdout, os.Stderr))
}
