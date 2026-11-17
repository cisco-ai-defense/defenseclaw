// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
)

// TestPatchDecoyHeaderNeverWeakerThanTheSinglePatch{Default,Strict,Permissive,Managed,ManagedStrict}:
// an apply_patch envelope that holds a Claude Code Write or Edit target of the
// fixture set next to headers no reader places (a home form the tool does not
// expand, a name the shell expands) is judged at least as its single-header
// patch is, on every patch route: Codex apply_patch command and input,
// OpenCode patch patchText, Hermes V4A patch, and the shell here-document the
// Codex shell tool feeds to apply_patch, with a quoted and an expanding
// delimiter. Each placed header is still read by the path and content rules,
// and the header no reader places only adds the unknown-tier finding, which
// never lowers a proven block (rel-1-0-10:GAP-1055, GAP-1077).
//
// The envelope shapes (patchDecoyShapes) put the unplaced header first, last,
// around the target, several times, among benign files, between two copies
// of the target, as a delete or update before it, beside a delete of the
// target, and as the source or the destination of a move. Every fixture
// target is checked on every route in patchDecoyShapesPerCase of the shapes,
// rotated by case, so each route and shape pair is checked on about a third
// of the targets; the shapes take the unplaced spellings in turn the same way.
//
// Before GAP-1077, the shell routes read an envelope with an unplaced header
// as partial and added no unknown finding: allow in every tier, strict too,
// where the single-header here-document blocks. One top-level test per tier,
// so the -race shards can take them apart.
func TestPatchDecoyHeaderNeverWeakerThanTheSinglePatchDefault(t *testing.T) {
	patchDecoyHeaderNeverWeaker(t, "default")
}

func TestPatchDecoyHeaderNeverWeakerThanTheSinglePatchStrict(t *testing.T) {
	patchDecoyHeaderNeverWeaker(t, "strict")
}

func TestPatchDecoyHeaderNeverWeakerThanTheSinglePatchPermissive(t *testing.T) {
	patchDecoyHeaderNeverWeaker(t, "permissive")
}

func TestPatchDecoyHeaderNeverWeakerThanTheSinglePatchManaged(t *testing.T) {
	patchDecoyHeaderNeverWeaker(t, "managed")
}

func TestPatchDecoyHeaderNeverWeakerThanTheSinglePatchManagedStrict(t *testing.T) {
	patchDecoyHeaderNeverWeaker(t, "managed-strict")
}

// patchDecoyUnplaced are header names no reader places on the host of the
// gateway, on every patch route: home forms, which the patch tool expands on
// no host; and on Windows, a drive-relative and a device name. The shell
// routes add patchDecoyExpanded.
func patchDecoyUnplaced() []string {
	names := []string{"~/zzdecoy1.txt", `~\zzdecoy2.txt`}
	if runtime.GOOS == "windows" {
		names = append(names, `C:zzdecoy3.txt`, `\\.\pipe\zzdecoy4`)
	}
	return names
}

// patchDecoyExpanded is a header name the shell expands in a here-document
// with an unquoted delimiter: no reader knows the file the tool gets. Other
// routes read it as a plain relative name, a benign file.
const patchDecoyExpanded = "$HOME/zzdecoy5.txt"

// patchDecoyShapesPerCase is how many of the patchDecoyShapes each fixture
// target is checked in, on every route.
const patchDecoyShapesPerCase = 4

// patchDecoyShape is one envelope with headers no reader places (envelope),
// and the envelope of the same placed change alone (reference).
type patchDecoyShape struct {
	name                string
	envelope, reference func(target, body, hunk, u, u2 string) string
}

func patchDecoyEnv(parts ...string) string {
	return "*** Begin Patch\n" + strings.Join(parts, "\n") + "\n*** End Patch"
}

func patchDecoyAdd(name string) string { return "*** Add File: " + name + "\n+x" }

// patchDecoyShapes: body is the target's single-header change without the
// envelope lines, hunk its text as an update hunk, u and u2 two unplaced names.
var patchDecoyShapes = func() []patchDecoyShape {
	single := func(_, body, _, _, _ string) string { return patchDecoyEnv(body) }
	return []patchDecoyShape{
		{"first", func(_, b, _, u, _ string) string { return patchDecoyEnv(patchDecoyAdd(u), b) }, single},
		{"last", func(_, b, _, u, _ string) string { return patchDecoyEnv(b, patchDecoyAdd(u)) }, single},
		{"sandwich", func(_, b, _, u, u2 string) string {
			return patchDecoyEnv(patchDecoyAdd(u), b, patchDecoyAdd(u2))
		}, single},
		{"several", func(_, b, _, u, u2 string) string {
			return patchDecoyEnv(patchDecoyAdd(u), patchDecoyAdd(u2), patchDecoyAdd(u+"x"), b,
				patchDecoyAdd(u2+"y"), patchDecoyAdd(u+"z"))
		}, single},
		{"benign-mix", func(_, b, _, u, u2 string) string {
			return patchDecoyEnv("*** Add File: notes1.txt\n+x", patchDecoyAdd(u), b, "*** Add File: notes2.txt\n+x", patchDecoyAdd(u2))
		}, single},
		{"duplicate-target", func(_, b, _, u, _ string) string { return patchDecoyEnv(b, patchDecoyAdd(u), b) }, single},
		{"delete-unplaced-before", func(_, b, _, u, _ string) string {
			return patchDecoyEnv("*** Delete File: "+u, b)
		}, single},
		{"update-unplaced-before", func(_, b, _, u, _ string) string {
			return patchDecoyEnv("*** Update File: "+u+"\n@@\n-a\n+b", b)
		}, single},
		{"delete-target-and-decoy",
			func(target, _, _, u, _ string) string {
				return patchDecoyEnv(patchDecoyAdd(u), "*** Delete File: "+target)
			},
			func(target, _, _, _, _ string) string { return patchDecoyEnv("*** Delete File: " + target) }},
		{"move-unplaced-to-target",
			func(target, _, hunk, u, _ string) string {
				return patchDecoyEnv("*** Update File: " + u + "\n*** Move to: " + target + "\n" + hunk)
			},
			func(target, _, hunk, _, _ string) string {
				return patchDecoyEnv("*** Update File: notes1.txt\n*** Move to: " + target + "\n" + hunk)
			}},
		{"move-target-to-unplaced",
			func(target, _, hunk, u, _ string) string {
				return patchDecoyEnv("*** Update File: " + target + "\n*** Move to: " + u + "\n" + hunk)
			},
			func(target, _, hunk, _, _ string) string {
				return patchDecoyEnv("*** Update File: " + target + "\n*** Move to: notes9.txt\n" + hunk)
			}},
		{"move-target-to-unplaced-and-decoy",
			func(target, _, hunk, u, u2 string) string {
				return patchDecoyEnv(patchDecoyAdd(u2), "*** Update File: "+target+"\n*** Move to: "+u+"\n"+hunk)
			},
			func(target, _, hunk, _, _ string) string {
				return patchDecoyEnv("*** Update File: " + target + "\n*** Move to: notes9.txt\n" + hunk)
			}},
	}
}()

// patchDecoyRoute is one patch route: the call that gives the tool the
// envelope, and the unplaced names it reads.
type patchDecoyRoute struct {
	name     string
	call     func(envelope string) shapeParityCall
	unplaced []string
}

func patchDecoyRoutes(cwd string) []patchDecoyRoute {
	codexHeaders := map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse",
		"X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract}
	codex := func(tool string, input map[string]any) shapeParityCall {
		return shapeParityCall{name: "codex/" + tool, conn: "codex", event: "PreToolUse", headers: codexHeaders,
			body: shapeParityEnvelope("PreToolUse", cwd, tool, input)}
	}
	unplaced := patchDecoyUnplaced()
	shell := append(slices.Clip(unplaced), patchDecoyExpanded)
	return []patchDecoyRoute{
		{"codex/command", func(e string) shapeParityCall { return codex("apply_patch", map[string]any{"command": e}) }, unplaced},
		{"codex/input", func(e string) shapeParityCall { return codex("apply_patch", map[string]any{"input": e}) }, unplaced},
		{"opencode/patchText", func(e string) shapeParityCall {
			return shapeParityCall{name: "opencode/patch", conn: "opencode", event: "tool.execute.before",
				body: shapeParityOpenCode(cwd, "patch", map[string]any{"patchText": e})}
		}, unplaced},
		{"hermes/patch-v4a", func(e string) shapeParityCall {
			return shapeParityCall{name: "hermes/patch", conn: "hermes", event: "pre_tool_call",
				body: shapeParityHermes(cwd, "patch", map[string]any{"mode": "patch", "patch": e})}
		}, unplaced},
		// The Codex shell tool, apply_patch fed by a here-document whose
		// delimiter is quoted: the body reaches the tool byte for byte.
		{"codex/heredoc-quoted", func(e string) shapeParityCall {
			return codex("Bash", map[string]any{"command": "apply_patch <<'PATCH'\n" + e + "\nPATCH"})
		}, shell},
		// The same with an unquoted delimiter and a body the shell expands
		// (the first file's text holds an expansion in every envelope, the
		// single-header one too).
		{"codex/heredoc-expanding", func(e string) shapeParityCall {
			e = strings.Replace(e, "*** Begin Patch\n", "*** Begin Patch\n*** Add File: notes0.txt\n+$PWD\n", 1)
			return codex("Bash", map[string]any{"command": "apply_patch <<PATCH\n" + e + "\nPATCH"})
		}, shell},
	}
}

func patchDecoyHeaderNeverWeaker(t *testing.T, tier string) {
	index := slices.IndexFunc(gap0437Packs, func(p gap0437Pack) bool { return p.name == tier })
	if index < 0 {
		t.Fatalf("no tier %q in gap0437Packs", tier)
	}
	p := gap0437Packs[index]
	all := shapeParityCases(t)
	cases := all[:0]
	for _, c := range all {
		if strings.HasPrefix(c.id, "wincred/") && (c.tool == "Write" || c.tool == "Edit") {
			cases = append(cases, c)
		}
	}
	if len(cases) == 0 {
		t.Fatal("no wincred Write or Edit fixture cases")
	}
	cwd := t.TempDir()
	handlers := shapeParityHandlers(t, p)
	routes := patchDecoyRoutes(cwd)
	var blocked atomic.Int64
	checked := make([]atomic.Int64, len(patchDecoyShapes))
	// The routes are independent; each runs in its own subtest, in
	// parallel, so the -race shards finish in time.
	t.Run("routes", func(t *testing.T) {
		for _, route := range routes {
			t.Run(strings.ReplaceAll(route.name, "/", "-"), func(t *testing.T) {
				t.Parallel()
				verdict := func(envelope string) string {
					call := route.call(envelope)
					return shapeParityHook(t, handlers[call.conn], call, p.managed)
				}
				for n, c := range cases {
					str := func(key string) string { value, _ := c.args[key].(string); return value }
					// The fixture name on Windows; elsewhere the same name
					// with forward slashes, the spelling whose single-header
					// patch a Linux or macOS gateway blocks (there a
					// backslash is a character of a file name).
					target := str("file_path")
					if runtime.GOOS != "windows" {
						target = strings.ReplaceAll(target, `\`, "/")
					}
					single := shapeParityPatch(target, str("content"))
					hunk := "@@\n-a\n+" + strings.ReplaceAll(str("content"), "\n", "\n+")
					if c.tool == "Edit" {
						single = shapeParityUpdatePatch(target, str("old_string"), str("new_string"))
						hunk = "@@\n-" + strings.ReplaceAll(str("old_string"), "\n", "\n-") + "\n+" +
							strings.ReplaceAll(str("new_string"), "\n", "\n+")
					}
					body := strings.TrimSuffix(strings.TrimPrefix(single, "*** Begin Patch\n"), "\n*** End Patch")
					references := map[string]string{}
					for k := range patchDecoyShapesPerCase {
						s := (n + k*len(patchDecoyShapes)/patchDecoyShapesPerCase) % len(patchDecoyShapes)
						shape := patchDecoyShapes[s]
						u := route.unplaced[(n+s)%len(route.unplaced)]
						u2 := route.unplaced[(n+s+1)%len(route.unplaced)]
						reference := shape.reference(target, body, hunk, u, u2)
						want, ok := references[reference]
						if !ok {
							want = verdict(reference)
							references[reference] = want
							if want == "block" {
								blocked.Add(1)
							}
						}
						got := verdict(shape.envelope(target, body, hunk, u, u2))
						checked[s].Add(1)
						if shapeParityRank[got] < shapeParityRank[want] {
							t.Errorf("%s %s %s %s (%s): %q, the single-header patch %q", c.id, c.tool, route.name,
								shape.name, u, got, want)
						}
					}
				}
			})
		}
	})
	var missing []string
	for s, shape := range patchDecoyShapes {
		if checked[s].Load() == 0 {
			missing = append(missing, shape.name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("envelope shapes never checked: %v", missing)
	}
	if blocked.Load() == 0 {
		t.Fatal("no single-header patch of the fixture targets blocks: the test no longer pins a placed block")
	}
}
