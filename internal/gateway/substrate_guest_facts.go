// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// A Substrate actor's gateway has no view of the actor's file system: the
// request has no working directory (copy mode) and the gateway never opens a
// host path for it (TestSandboxIngressCopyModeNeverTouchesHostFS). The
// laptop's gateway resolves a symlink, a symlinked folder or a `..` walk
// against the real file system, so cat key-link, cat a/b/ssh/id_ed25519,
// cat ./a/../key-link, cd a/b/ssh && cat id_ed25519 and Read ./key-link
// block there (PATH-SSH-KEY) and were allowed in an actor (substrate-1
// GAP-0471). The actor's kit, which runs in the actor's file system, makes
// the laptop's proofs there and reports them on the envelope
// (kit.CollectFacts): the private-key read proof and the protected-target
// write decision of a shell command, and the resolved target of each path
// argument of a file tool. Both are claims of
// code that runs as the agent's user, so the gateway uses them only to add
// the finding the laptop makes, never to remove one; a claim that does not
// match the call it came with is ignored.

// maxSubstrateGuestLinkClaims bounds the file-tool link claims one call
// carries (the kit sends at most 32 path facts).
const maxSubstrateGuestLinkClaims = 8

// substrateGuestClaims are the kit's claims of one hook call that change a
// judgment.
type substrateGuestClaims struct {
	// keyReadCommand is the shell command (tool_input.command) the kit
	// proved reads the actor's SSH private key (kit.ProofPrivateKeyRead).
	keyReadCommand string
	// protectedWriteCommand is the shell command the kit's run of the
	// laptop's protected-target decision found writes a protected file
	// (kit.ProofProtectedWrite).
	protectedWriteCommand string
	// links are the file-tool path arguments whose resolved target differs
	// from their spelling.
	links []substrateGuestLinkClaim
}

// substrateGuestLinkClaim is one tool_input.<key> path argument, as the
// call sent it, and its target in the actor's file system.
type substrateGuestLinkClaim struct {
	key, value, resolved string
}

type substrateGuestClaimsKey struct{}

// withSubstrateGuestClaims keeps the claims of env on ctx.
func withSubstrateGuestClaims(ctx context.Context, env substrateEnvelope) context.Context {
	if claims := substrateGuestClaimsOf(env); claims != nil {
		return context.WithValue(ctx, substrateGuestClaimsKey{}, claims)
	}
	return ctx
}

func substrateGuestClaimsFrom(ctx context.Context) *substrateGuestClaims {
	if ctx == nil {
		return nil
	}
	claims, _ := ctx.Value(substrateGuestClaimsKey{}).(*substrateGuestClaims)
	return claims
}

// substrateGuestClaimsOf reads the claims of env that match its payload: a
// proof names the payload's own command, a link the payload's own argument.
func substrateGuestClaimsOf(env substrateEnvelope) *substrateGuestClaims {
	if env.Facts == nil || (len(env.Facts.Proofs) == 0 && len(env.Facts.Paths) == 0) {
		return nil
	}
	var payload struct {
		ToolInput map[string]json.RawMessage `json:"tool_input"`
	}
	if json.Unmarshal(env.Payload, &payload) != nil || len(payload.ToolInput) == 0 {
		return nil
	}
	argument := func(key string) (string, bool) {
		var value string
		raw, found := payload.ToolInput[key]
		if !found || json.Unmarshal(raw, &value) != nil {
			return "", false
		}
		return value, true
	}
	claims := &substrateGuestClaims{}
	if command, ok := argument("command"); ok && strings.TrimSpace(command) != "" {
		if slices.Contains(env.Facts.Proofs, kit.ProofPrivateKeyRead) {
			claims.keyReadCommand = command
		}
		if slices.Contains(env.Facts.Proofs, kit.ProofProtectedWrite) {
			claims.protectedWriteCommand = command
		}
	}
	for _, fact := range env.Facts.Paths {
		key, ok := strings.CutPrefix(fact.Field, "tool_input.")
		if !ok || key == "command" || strings.ContainsAny(key, ".[") ||
			!path.IsAbs(fact.Resolved) || !path.IsAbs(fact.Abs) || path.Clean(fact.Resolved) == path.Clean(fact.Abs) ||
			strings.ContainsAny(fact.Resolved, "\x00\r\n") {
			continue
		}
		value, ok := argument(key)
		if !ok || value != fact.Path || len(claims.links) >= maxSubstrateGuestLinkClaims {
			continue
		}
		claims.links = append(claims.links, substrateGuestLinkClaim{key: key, value: value, resolved: path.Clean(fact.Resolved)})
	}
	if claims.keyReadCommand == "" && claims.protectedWriteCommand == "" && len(claims.links) == 0 {
		return nil
	}
	return claims
}

// substrateGuestLinkTwinRequest is a file-tool call of an actor with each
// path argument the kit resolved through a link replaced by its target: the
// call the laptop's gateway judges once it has followed the link (Read
// ./key-link reads /sandbox/.ssh/id_ed25519). The twin only adds findings.
func substrateGuestLinkTwinRequest(ctx context.Context, request trustedActionRequest) (trustedActionRequest, bool) {
	claims := substrateGuestClaimsFrom(ctx)
	if claims == nil || len(claims.links) == 0 || request.guestLinkTwin || len(request.Input.Args) == 0 {
		return trustedActionRequest{}, false
	}
	var args map[string]json.RawMessage
	if json.Unmarshal(request.Input.Args, &args) != nil {
		return trustedActionRequest{}, false
	}
	changed := false
	for _, link := range claims.links {
		raw, found := args[link.key]
		var value string
		if !found || json.Unmarshal(raw, &value) != nil || value != link.value {
			continue
		}
		resolved, err := json.Marshal(link.resolved)
		if err != nil {
			continue
		}
		args[link.key], changed = resolved, true
	}
	if !changed {
		return trustedActionRequest{}, false
	}
	encoded, err := json.Marshal(args)
	if err != nil {
		return trustedActionRequest{}, false
	}
	twin := request
	twin.Input.Args = encoded
	twin.LegacyText = string(encoded)
	twin.guestLinkTwin = true
	return twin, true
}

// substrateGuestClaimsProveKeyRead reports the kit's private-key read proof
// for command, the command the request judges.
func (request trustedActionRequest) substrateGuestClaimsProveKeyRead(command string) bool {
	return request.guestKeyReadCommand != "" && command == request.guestKeyReadCommand
}
