// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// defenseclaw-actor-hook is the DefenseClaw hook of a connector agent that
// runs as an Agent Substrate actor (internal/substrate/kit). It is a static
// binary in the actor image, registered in the agent's root-owned managed
// settings.
package main

import (
	"os"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

func main() {
	os.Exit(kit.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
