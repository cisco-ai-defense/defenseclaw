// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// a9tool drives the lane A9 live cells on E1: the template commands (build,
// verify, scan, publish, keygen) and the discovery run over the cluster's
// ActorTemplates and Actors.
//
//	a9tool template build|verify|scan|publish|keygen ...
//	a9tool discover --templates F --actors F --anchors F [--managed atespace/name]...
package main

import (
	"context"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/substrate/attest/templatecli"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "discover" {
		os.Exit(discover(context.Background(), args[1:]))
	}
	if len(args) > 0 && args[0] == "template" {
		args = args[1:]
	}
	os.Exit(templatecli.Run(context.Background(), args, os.Stdout, os.Stderr))
}
