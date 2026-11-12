// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package kit is the DefenseClaw actor kit for Agent Substrate: the hook
// binary (defenseclaw-actor-hook) a connector agent runs inside an actor, its
// resident transport helper, and the settings layer of an actor image.
//
// Hooks stay in the sandbox and decisions are made outside it. The hook reads
// the agent's event on stdin, wraps it in a HookEnvelope with the facts the
// gateway cannot see from outside (resolved paths, small file contents, repo
// MCP server files), and POSTs it to the cluster gateway's actor listener
// through Substrate egress, which replaces the x-defenseclaw-actor
// placeholder with the actor's signed JWT. The answer is printed in the
// connector's native hook format by hookexec, the same code the host hooks
// use.
//
// Nothing the kit sends is trusted by the gateway: the envelope, its facts and
// its mode are claims (PLAN 5.2, B1). Only the injected JWT identifies the
// actor.
//
// Golden-snapshot rule (PLAN 6.4, E5): every actor of a template starts from
// the same memory image, so nothing in this package creates an ID, a nonce,
// a cache or a connection before it is first used after a resume. The helper
// is started lazily by the first hook or by the relay, never at image start.
package kit
