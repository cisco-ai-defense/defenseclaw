// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
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
// write decision of the call's shell command (for every connector's shell
// tool, GAP-0545), the place of each path word of that command that a link
// moves (GAP-0546, GAP-0547), and the resolved target of each path argument
// of a file tool. All are claims of code that runs as the agent's user, so
// the gateway uses them only to add the finding the laptop makes, never to
// remove one; a claim that does not match the call it came with is ignored.

// The kit sends at most 40 path facts (32 ordinary plus 8 shell-link facts) and two proofs. An
// envelope with more facts, or more than 8 proofs, is not the kit's, and none of
// its claims is read: the call is judged as one with no facts, which is never
// more lenient than with them (substrate-1 GAP-0548). Reading the claims of
// an envelope decodes each argument of its call once, so it is linear in the
// envelope's size.
const (
	maxSubstrateGuestPathFacts = 40
	maxSubstrateGuestProofs    = 8
	// maxSubstrateGuestLinkClaims bounds the file-tool link claims one call
	// carries.
	maxSubstrateGuestLinkClaims = 8
	// maxSubstrateGuestCommandTwins bounds the readings of one shell call
	// whose words the kit placed in more than one folder (cd a || cd b; cat
	// lk): one twin per reading; a word placed in more folders cuts the
	// claims (substrate-1 GAP-0623).
	maxSubstrateGuestCommandTwins = 4
)

// substrateGuestClaims are the kit's claims of one hook call that change a
// judgment.
type substrateGuestClaims struct {
	// keyReadCommand is the shell command (kit.ShellCommandOf) the kit
	// proved reads the actor's SSH private key (kit.ProofPrivateKeyRead).
	keyReadCommand string
	// protectedWriteCommand is the shell command the kit's run of the
	// laptop's protected-target decision found writes a protected file
	// (kit.ProofProtectedWrite).
	protectedWriteCommand string
	// links are the file-tool path arguments whose resolved target differs
	// from their spelling.
	links []substrateGuestLinkClaim
	// words are the places of the shell command's path words that differ
	// from their spelling (kit.CommandWordField), by the word as the command
	// spells it.
	words map[string]hookpaths.CommandWordPlace
	// placedWords are the same places by the word and the path it spells in
	// the folder the kit read it in (hookpaths.PlacedCommandPathWords from
	// wordDir), one per place: cd a && echo x >> lk && cd ../b && echo x >>
	// lk has two (substrate-1 GAP-0623). words then keeps only a spelling
	// with one place.
	placedWords map[hookpaths.CommandWordAt]hookpaths.CommandWordPlace
	// wordDir is the folder the kit placed the words from
	// (kit.ShellCommandDir); empty when it is not known, and the words are
	// read as LinkResolvedCommand reads them.
	wordDir string
	// cut is set when the kit's claims are not complete
	// (kit.ProofClaimsCut): a word or argument past the cut may name a link
	// no claim places (substrate-1 GAP-0622).
	cut bool
	// homePlaces are the places of the command's path words that the kit
	// found private in the actor's home (kit.PathFact.PrivateHome).
	homePlaces map[string]bool
}

// homePlaceView reads the kit's private home places; nil for no claims.
func (claims *substrateGuestClaims) homePlaceView() homePlaceView {
	if claims == nil {
		return nil
	}
	return &homePlaceSet{places: claims.homePlaces}
}

// substrateGuestLinkClaim is one tool_input.<key> path argument, as the
// call sent it, and its target in the actor's file system. A patch claim is
// a file an apply_patch body in that argument adds, updates or moves to.
type substrateGuestLinkClaim struct {
	key, value, resolved string
	patch                bool
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
// proof and a command word name the payload's own shell command, as the
// connector registry reads it (kit.ShellCommandOf, every connector's shell
// tool), a link the payload's own argument.
func substrateGuestClaimsOf(env substrateEnvelope) *substrateGuestClaims {
	facts := env.Facts
	if facts == nil || (len(facts.Proofs) == 0 && len(facts.Paths) == 0) ||
		len(facts.Paths) > maxSubstrateGuestPathFacts || len(facts.Proofs) > maxSubstrateGuestProofs {
		return nil
	}
	claims := &substrateGuestClaims{cut: slices.Contains(facts.Proofs, kit.ProofClaimsCut)}
	if command, _, ok := kit.ShellCommandOf(env.Connector, env.Event, env.Payload); ok {
		claims.wordDir, _ = kit.ShellCommandDir(env.Connector, env.Event, env.Payload)
		places := map[string]int{}
		if slices.Contains(facts.Proofs, kit.ProofPrivateKeyRead) {
			claims.keyReadCommand = command
		}
		if slices.Contains(facts.Proofs, kit.ProofProtectedWrite) {
			claims.protectedWriteCommand = command
		}
		for _, fact := range facts.Paths {
			if fact.Field != kit.CommandWordField || fact.Path == "" || !strings.Contains(command, fact.Path) {
				continue
			}
			place := hookpaths.CommandWordPlace{Followed: substrateGuestPlace(fact.Resolved), Entry: substrateGuestPlace(fact.Entry)}
			if place.Followed != "" || place.Entry != "" {
				if claims.words == nil {
					claims.words = map[string]hookpaths.CommandWordPlace{}
					claims.placedWords = map[hookpaths.CommandWordAt]hookpaths.CommandWordPlace{}
				}
				if places[fact.Path]++; places[fact.Path] == 1 {
					claims.words[fact.Path] = place
				} else {
					delete(claims.words, fact.Path)
				}
				if abs := substrateGuestPlace(fact.Abs); abs != "" {
					claims.placedWords[hookpaths.CommandWordAt{Text: fact.Path, Abs: abs}] = place
				}
			}
			if fact.PrivateHome {
				for _, private := range []string{substrateGuestPlace(fact.Abs), place.Followed, place.Entry} {
					if private == "" {
						continue
					}
					if claims.homePlaces == nil {
						claims.homePlaces = map[string]bool{}
					}
					claims.homePlaces[private] = true
				}
			}
		}
	}
	// The call's arguments as the gateway judges them (kit.ToolArgsOf:
	// tool_input, Copilot's toolArgs, Cursor's beforeReadFile file).
	var toolArgs map[string]json.RawMessage
	_ = json.Unmarshal(kit.ToolArgsOf(env.Connector, env.Event, env.Payload), &toolArgs)
	// Each argument is decoded once, however many facts name it.
	type decoded struct {
		value   string
		patches []string
		ok      bool
	}
	arguments := map[string]decoded{}
	argument := func(key string) decoded {
		if known, seen := arguments[key]; seen {
			return known
		}
		var out decoded
		raw, found := toolArgs[key]
		var argv []string
		switch {
		case !found:
		case json.Unmarshal(raw, &out.value) == nil:
			out.ok = true
			out.patches = substratePatchWriteTargets(out.value)
		case json.Unmarshal(raw, &argv) == nil:
			out.patches = substratePatchWriteTargets(strings.Join(argv, "\n"))
		}
		arguments[key] = out
		return out
	}
	for _, fact := range facts.Paths {
		if len(claims.links) >= maxSubstrateGuestLinkClaims {
			break
		}
		key, ok := strings.CutPrefix(fact.Field, "tool_input.")
		if !ok || strings.ContainsAny(key, ".[") ||
			!path.IsAbs(fact.Resolved) || !path.IsAbs(fact.Abs) || path.Clean(fact.Resolved) == path.Clean(fact.Abs) ||
			strings.ContainsAny(fact.Resolved, "\x00\r\n") {
			continue
		}
		switch value := argument(key); {
		case value.ok && value.value == fact.Path:
			claims.links = append(claims.links, substrateGuestLinkClaim{key: key, value: fact.Path, resolved: path.Clean(fact.Resolved)})
		case slices.Contains(value.patches, fact.Path):
			claims.links = append(claims.links, substrateGuestLinkClaim{key: key, value: fact.Path, resolved: path.Clean(fact.Resolved), patch: true})
		}
	}
	if claims.keyReadCommand == "" && claims.protectedWriteCommand == "" && len(claims.links) == 0 &&
		len(claims.placedWords) == 0 && len(claims.homePlaces) == 0 && !claims.cut {
		return nil
	}
	return claims
}

// substratePatchWriteHeaders are the apply_patch headers whose file the
// patch writes through a link (a deleted file is the entry itself).
var substratePatchWriteHeaders = []string{"*** Add File: ", "*** Update File: ", "*** Move to: "}

// substratePatchWriteTargets are the files an apply_patch body adds, updates
// or moves to, as its headers spell them.
func substratePatchWriteTargets(text string) []string {
	if !strings.Contains(text, "*** Begin Patch") {
		return nil
	}
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		for _, header := range substratePatchWriteHeaders {
			if target, found := strings.CutPrefix(line, header); found && strings.TrimSpace(target) != "" {
				out = append(out, strings.TrimSpace(target))
			}
		}
	}
	return out
}

// substrateRespellPatch spells each header of text that writes target as
// writing resolved.
func substrateRespellPatch(text, target, resolved string) string {
	lines := strings.Split(text, "\n")
	for index, line := range lines {
		body := strings.TrimRight(line, "\r")
		for _, header := range substratePatchWriteHeaders {
			if spelled, found := strings.CutPrefix(body, header); found && strings.TrimSpace(spelled) == target {
				lines[index] = header + resolved + line[len(body):]
			}
		}
	}
	return strings.Join(lines, "\n")
}

// substrateGuestPlace is a kit-claimed place a command word may be spelled
// as: an absolute, clean path of at most hookpaths.MaxWriteTargetPathBytes
// with no NUL or line break; "" for anything else.
func substrateGuestPlace(place string) string {
	if !path.IsAbs(place) || path.Clean(place) != place || len(place) > hookpaths.MaxWriteTargetPathBytes ||
		strings.ContainsAny(place, "\x00\r\n") {
		return ""
	}
	return place
}

// substrateGuestCommandTwinRequests are a shell call of an actor with each
// path word the kit placed through a link spelled as its place, the words of
// an eval or -c body and the words after a static cd chain too, each in its
// folder (hookpaths.PlacedLinkResolvedCommand), one twin per reading of a
// word placed in more than one folder: the command the
// laptop's gateway judges once it has followed the links (cd -P a/b/ssh &&
// cat id_ed25519 reads /sandbox/.ssh/id_ed25519, echo x >> dc-link writes
// /sandbox/.defenseclaw/config.yaml). trustedToolCallFindings judges it with
// every reading of the call; it only adds findings (substrate-1 GAP-0546,
// GAP-0547, GAP-0623). cut is set when a word has places in more folders
// than there are twins.
func substrateGuestCommandTwinRequests(request trustedActionRequest, claims *substrateGuestClaims) (twins []trustedActionRequest, cut bool) {
	if claims == nil || len(claims.placedWords) == 0 || request.guestCommandTwin ||
		request.Input.DialectHint != "" && request.Input.DialectHint != actionfacts.DialectPOSIX {
		return nil, false
	}
	command, ok := trustedBashCommandInput(request.Input)
	if !ok {
		return nil, false
	}
	var spelled []string
	for reading := range maxSubstrateGuestCommandTwins {
		resolved, changed, more := command, false, false
		if claims.wordDir == "" {
			if reading == 0 {
				resolved, changed = hookpaths.LinkResolvedCommand(command, request.Input.ActiveHome, claims.words)
			}
		} else {
			resolved, changed, more = hookpaths.PlacedLinkResolvedCommand(command, claims.wordDir,
				request.Input.ActiveHome, claims.placedWords, claims.words, reading)
		}
		if changed && !slices.Contains(spelled, resolved) {
			spelled = append(spelled, resolved)
			twin := bashReadingRequest(request, command, resolved)
			twin.guestCommandTwin = true
			// Its findings only add to the call's, so the home copy checks
			// read the kit's places there (substrate-1 GAP-0549).
			twin.guestHomePlaces = claims.homePlaceView()
			twins = append(twins, twin)
		}
		if !more {
			return twins, false
		}
	}
	return twins, true
}

// substrateGuestLinkTwinRequest is a file-tool call of an actor with each
// path argument the kit resolved through a link replaced by its target, and
// each file an apply_patch body writes through a link spelled as its target:
// the call the laptop's gateway judges once it has followed the link (Read
// ./key-link reads /sandbox/.ssh/id_ed25519, *** Add File: ak-link writes
// /sandbox/.ssh/authorized_keys). The twin only adds findings.
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
		var argv []string
		var respelled any
		switch {
		case !found:
			continue
		case link.patch && json.Unmarshal(raw, &value) == nil:
			respelled = substrateRespellPatch(value, link.value, link.resolved)
		case link.patch && json.Unmarshal(raw, &argv) == nil:
			for index := range argv {
				argv[index] = substrateRespellPatch(argv[index], link.value, link.resolved)
			}
			respelled = argv
		case !link.patch && json.Unmarshal(raw, &value) == nil && value == link.value:
			respelled = link.resolved
		default:
			continue
		}
		encoded, err := json.Marshal(respelled)
		if err != nil || string(encoded) == string(raw) {
			continue
		}
		args[link.key], changed = encoded, true
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
