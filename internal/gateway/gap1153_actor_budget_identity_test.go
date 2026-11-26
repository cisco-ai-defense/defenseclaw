// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// gap1153Config is one rule pack and guardrail mode the identity corpus is
// judged in.
type gap1153Config struct{ pack, mode string }

func gap1153Configs() []gap1153Config {
	return []gap1153Config{{"default", "action"}, {"strict", "action"}, {"permissive", "action"}, {"default", "observe"}}
}

// gap1153Fit repeats unit ({k} counts up) between prefix and suffix up to
// about size bytes, as the BISECT-1153 S1..S8 shapes are made.
func gap1153Fit(prefix, unit, suffix string, size int) string {
	var out strings.Builder
	out.WriteString(prefix)
	for k := 0; ; k++ {
		piece := strings.ReplaceAll(unit, "{k}", fmt.Sprint(k))
		if out.Len()+len(piece)+len(suffix) > size {
			break
		}
		out.WriteString(piece)
	}
	return out.String() + suffix
}

// gap1153Corpus is the generated identity corpus: shell commands of 2 B to
// 32 KB in the gap0471 layout (key, authorized_keys, state and rc links, a
// private backup folder), under, at and over the statement budget, with the
// RKGUESTRES rows (link reads and writes, cd through links, eval and sh -c
// bodies, an own SSH folder copy) at the start, in the middle or at the end
// of padding of every BISECT-1153 form.
func gap1153Corpus(n int) []string {
	r := rand.New(rand.NewSource(1153))
	rows := []string{
		"cat key-link", "cat key-link2", "cat a/b/ssh/id_ed25519", "cd a/b/ssh && cat id_ed25519", "cd -P sshdir && cat id_ed25519",
		"cat ./a/../key-link", "echo k >> ak-link", "echo x >> dc-link", "echo x >> rc-link", "cp -r ~/.ssh ~/bak/sshcopy",
		"cat readme-link", "ls docs-link", "eval \"cat key-link\"", "sh -c 'echo x >> dc-link'", "cd claude-dir && echo x > settings.json",
		"cat aws-link", "cp key-link /tmp/k", "echo hi > out.txt", "git status", "ls", "cd docs && ls", "cat README.md",
		"mv readme-link r2", "ln -sf ~/.ssh/authorized_keys ak3", "f() { cat key-link; }; f", "g() { echo k >> ak-link; }; cd /tmp; g",
		"echo k >> ~/.ssh/authorized_keys", "cat ~/.ssh/id_ed25519", "echo x >> ~/.defenseclaw/config.yaml", "cp /tmp/x ~/.ssh/authorized_keys",
		"tee -a ~/.ssh/authorized_keys < /dev/null", "cd ~/.ssh && echo k >> authorized_keys",
	}
	units := []string{"$C;f{k}(){ :;};", "$C;f{k}(){ :;};f{k};", "true;", ": {k};", "x{k}=1;", "echo {k} >/dev/null;", "ls\n", "test -e f{k} && :;"}
	// Deeply nested loops are read in time exponential in the depth by
	// every build, the gateway's split included (substrate-1 GAP-1152): the
	// S5 form is the one nested shape, judged as BISECT-1153 sent it.
	wraps := [][2]string{{"", ""}, {"for i in 1; do ", "done"}, {"if true; then ", "fi"}, {"for i in 1; do for j in 1; do ", "done; done"}, {"w() { ", "}; w"}}
	corpus := []string{
		gap1153Fit("for i in 1; do ", "$C;f{k}(){ :;};", "done", 8190),
		gap1153Fit("", "$C;f{k}(){ :;};", "true", 8190),
		gap1153Fit(strings.Repeat("for i in 1; do ", 20), "$C;f{k}(){ :;};", strings.Repeat("done; ", 20)+"true", 8190),
		gap1153Fit("for i in 1; do ", "$C;f{k}(){ :;};f{k};", "done", 8190),
	}
	sizes := []int{16, 60, 200, 255, 256, 300, 600, 1024, 1500, 2600, 4096, 8190, 12000, 20000, 32000}
	for len(corpus) < n {
		wrap := wraps[r.Intn(len(wraps))]
		unit := units[r.Intn(len(units))]
		size := sizes[r.Intn(len(sizes))]
		padding := gap1153Fit("", unit, "", size)
		var picked []string
		for k := r.Intn(4); k > 0; k-- {
			picked = append(picked, rows[r.Intn(len(rows))])
		}
		body := padding
		switch r.Intn(3) {
		case 0:
			body = strings.Join(append(picked, padding), "; ")
		case 1:
			half := strings.LastIndex(padding[:len(padding)/2], ";") + 1
			body = padding[:half] + strings.Join(append(picked, ""), "; ") + padding[half:]
		default:
			body = strings.Join(append([]string{padding}, picked...), "; ")
		}
		body = strings.TrimSpace(strings.Trim(strings.TrimSpace(body), ";"))
		if body == "" {
			body = "true"
		}
		corpus = append(corpus, wrap[0]+body+"; "+wrap[1])
	}
	return corpus
}

// gap1153API is gap0545API for one pack and mode in the home of a first
// gap0545API call, so every configuration reads the same kit facts.
func gap1153API(t *testing.T, connectorName string, c gap1153Config) *APIServer {
	t.Helper()
	installToolCallCorpusProfileConnector(t, connectorName, c.pack)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = c.mode
	cfg.Guardrail.Connector = connectorName
	cfg.Guardrail.RulePack = c.pack
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), c.pack)
	return &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
}

// gap1153Facts are the kit facts of a call with rel/1.0.11 dfb6d9c707's
// whole-command proofs on calls over the statement budget (rel) and without
// them (head), in the guest's namespace.
func gap1153Facts(t *testing.T, s gap0545Shape, host []byte, home string) (rel, head *SubstrateFacts) {
	t.Helper()
	restore := kit.SetOverBudgetShellProofsForTest(true)
	rel = gap0545KitFacts(t, s.connector, s.event, host, home)
	restore()
	head = gap0545KitFacts(t, s.connector, s.event, host, home)
	return rel, head
}

// TestGAP1153ActorOverBudgetVerdictIdentity: the kit makes no whole-command
// proof (private-key read, protected-target decision) for a shell command
// over the statement budget (substrate-1 GAP-1153). On a generated corpus
// of 2,400 commands of every BISECT-1153 form, in three connector shell
// shapes, the kit's facts are byte-identical to rel's (the same envelope,
// so the same request to the gateway) on every call under the budget and
// on every call over it where rel's proofs found nothing; every call whose
// facts differ is over the budget, and the gateway answers it (action and
// rules) with head's facts as with rel's, in the default, strict and
// permissive packs and in observe mode, refusing it at the budget
// (ACTION-COMPOUND-LIMIT).
func TestGAP1153ActorOverBudgetVerdictIdentity(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	n := 2400
	if testing.Short() {
		n = 240
	}
	if v, err := strconv.Atoi(os.Getenv("GAP1153_CORPUS_N")); err == nil && v > 0 {
		n = v
	}
	corpus := gap1153Corpus(n)
	// GAP1153_SHARD=k/N judges only the commands i with i%N == k, so one
	// run can be split across processes.
	shard, shards := 0, 1
	if k, total, ok := strings.Cut(os.Getenv("GAP1153_SHARD"), "/"); ok {
		shard, _ = strconv.Atoi(k)
		shards, _ = strconv.Atoi(total)
		shards = max(shards, 1)
	}
	began := time.Now()
	seen := 0
	shapes := gap0545Shapes()
	shapes = []gap0545Shape{shapes[0], shapes[1], shapes[5]} // claude Bash, codex exec_command, cursor
	var gated, withProofs, judged, limited, same, skipped int
	for si, s := range shapes {
		_, actor, home, app := gap0545API(t, s.connector, "default")
		// Half the calls run in an open folder outside the home, as the
		// BISECT-1153 calls ran in /work: their words are no private places,
		// so the kit makes no decision past the budget unless a link moves one.
		open := gap1153OpenFolder(t, home)
		apis := map[gap1153Config]*APIServer{}
		for _, c := range gap1153Configs() {
			apis[c] = gap1153API(t, s.connector, c)
		}
		for i, command := range corpus {
			if i%len(shapes) != si || i%shards != shard {
				continue
			}
			if seen++; seen%100 == 0 {
				t.Logf("progress: %d commands in %v", seen, time.Since(began))
			}
			hostCWD, guestCWD := app, sandboxauth.SandboxHome+"/app"
			if i%2 == 0 {
				hostCWD, guestCWD = open, open
			}
			host, _ := json.Marshal(s.body(command, hostCWD))
			guest, _ := json.Marshal(s.body(command, guestCWD))
			rel, head := gap1153Facts(t, s, host, home)
			relRaw, _ := json.Marshal(rel)
			headRaw, _ := json.Marshal(head)
			over := len(command) >= 256 && actionfacts.ShellStatementsOverBudget(command)
			if over {
				gated++
				if rel != nil && slices.Contains(rel.Proofs, kit.ProofProtectedWrite) {
					withProofs++
				}
			}
			if !bytes.Equal(relRaw, headRaw) {
				// Only an over-budget call may lose rel's protected-write
				// proof, and nothing else of its facts.
				if !over {
					t.Fatalf("%s #%d (%d B, under the budget): kit facts differ\nrel  %s\nhead %s", s.name, i, len(command), relRaw, headRaw)
				}
				skipped++
				if want := gap1153JSON(t, gap1153WithoutWriteProof(rel)); !bytes.Equal(want, headRaw) {
					t.Fatalf("%s #%d (%d B, over the budget): head facts %s, want rel's less the protected-write proof %s", s.name, i, len(command), headRaw, want)
				}
			}
			if bytes.Equal(relRaw, headRaw) {
				// The same envelope: the gateway reads the same request.
				same++
				continue
			}
			for _, c := range gap1153Configs() {
				judging := time.Now()
				ra, rr := gap0545Verdict(t, apis[c], gap0545Actor(actor, s.connector, s.event, guest, rel), s, guest)
				ha, hr := gap0545Verdict(t, apis[c], gap0545Actor(actor, s.connector, s.event, guest, head), s, guest)
				if took := time.Since(judging); took > 2*time.Second {
					t.Logf("slow: %s #%d (%d B) %s/%s took %v", s.name, i, len(command), c.pack, c.mode, took)
				}
				judged++
				if ha != ra || !slices.Equal(hr, rr) {
					t.Errorf("%s #%d (%d B) %s/%s: head %s %v, rel %s %v\ncommand %.300q", s.name, i, len(command), c.pack, c.mode, ha, hr, ra, rr, command)
				}
				if !slices.Contains(hr, "ACTION-COMPOUND-LIMIT") {
					t.Errorf("%s #%d (%d B) %s/%s: facts differ on a call the gateway did not refuse at the budget: %s %v", s.name, i, len(command), c.pack, c.mode, ha, hr)
				}
				limited++
			}
		}
	}
	t.Logf("GAP-1153 identity: %d commands, %d over the budget (%d with rel's protected-write proof, %d of them without it at head), %d with byte-identical facts, %d facts-differ calls judged twice in %d configurations (%d answers, all ACTION-COMPOUND-LIMIT)", len(corpus), gated, withProofs, skipped, same, judged/len(gap1153Configs()), len(gap1153Configs()), limited)
	if shards == 1 && !testing.Short() && (gated < 800 || withProofs < 100 || skipped < 50) {
		t.Fatalf("corpus too thin: %d over the budget, %d with a rel proof, %d without it at head", gated, withProofs, skipped)
	}
}

// TestGAP1153ActorHomeCopyCornerKeepsCallAnswer: the GAP-0549 corner of an
// over-budget call. Rel's protected-write proof of the whole command (echo
// k >> ak-link) made the kit mark the private backup folder, and that view
// lowers the gateway's authorized_keys block of the cap-floor piece cp -r
// ~/.ssh ~/bak/sshcopy to the laptop's alert (default pack). Those words are
// claims the gateway reads, so the kit keeps the decision for them: head's
// facts are rel's and the call's answer is the same in every pack and mode
// (substrate-1 GAP-1153; design (a), which dropped the proof, blocked here).
func TestGAP1153ActorHomeCopyCornerKeepsCallAnswer(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	s := gap0545Shapes()[0]
	_, actor, home, app := gap0545API(t, s.connector, "default")
	for _, command := range []string{
		"echo k >> ak-link; cp -r ~/.ssh ~/bak/sshcopy; " + gap1153Fit("", "true;", "true", 4096),
		gap1153Fit("", "true;", "", 4096) + "cp -r ~/.ssh ~/bak/sshcopy; echo k >> ak-link",
		"cat key-link; cp -r ~/.ssh ~/bak/sshcopy; " + gap1153Fit("for i in 1; do ", "$C;f{k}(){ :;};", "done", 8190),
		gap1153Fit("", "test -e f{k} && :;", "", 1500) + "echo k >> ak-link; cp -r ~/.ssh ~/bak/sshcopy",
	} {
		host, _ := json.Marshal(s.body(command, app))
		guest, _ := json.Marshal(s.body(command, sandboxauth.SandboxHome+"/app"))
		rel, head := gap1153Facts(t, s, host, home)
		if rel == nil || len(rel.Proofs) == 0 || !slices.ContainsFunc(rel.Paths, func(p SubstratePathFact) bool { return p.PrivateHome }) {
			t.Fatalf("%.60q: rel facts %+v: want a proof and a private home place (the corner is not reached)", command, rel)
		}
		if relRaw, headRaw := gap1153JSON(t, rel), gap1153JSON(t, head); !bytes.Equal(relRaw, headRaw) {
			t.Fatalf("%.60q: head facts %s, rel %s: want rel's", command, headRaw, relRaw)
		}
		for _, c := range gap1153Configs() {
			api := gap1153API(t, s.connector, c)
			ra, rr := gap0545Verdict(t, api, gap0545Actor(actor, s.connector, s.event, guest, rel), s, guest)
			ha, hr := gap0545Verdict(t, api, gap0545Actor(actor, s.connector, s.event, guest, head), s, guest)
			t.Logf("%.40q %s/%s: rel %s %v, head %s %v", command, c.pack, c.mode, ra, rr, ha, hr)
			if ha != ra {
				t.Errorf("%.60q %s/%s: head %s %v, rel %s %v", command, c.pack, c.mode, ha, hr, ra, rr)
			}
		}
	}
}

func gap1153JSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// gap1153WithoutWriteProof is facts without the protected-write proof, as
// the kit sends them when it makes no decision (nil when nothing is left).
func gap1153WithoutWriteProof(facts *SubstrateFacts) *SubstrateFacts {
	if facts == nil {
		return nil
	}
	out := *facts
	out.Proofs = slices.DeleteFunc(slices.Clone(facts.Proofs), func(p string) bool { return p == kit.ProofProtectedWrite })
	if len(out.Proofs) == 0 {
		out.Proofs = nil
	}
	if len(out.Paths) == 0 && len(out.Files) == 0 && len(out.Skills) == 0 && len(out.ProjectHooks) == 0 && len(out.Proofs) == 0 && !out.Truncated {
		return nil
	}
	return &out
}

// gap1153OpenFolder is a world-readable working folder outside home with
// the gap0471 links into it (key, authorized_keys, state, the SSH folder).
func gap1153OpenFolder(t *testing.T, home string) string {
	t.Helper()
	open := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(filepath.Join(open, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		"key-link": filepath.Join(home, ".ssh", "id_ed25519"), "key-link2": "key-link", "a/b/ssh": filepath.Join(home, ".ssh"),
		"sshdir": "a/b/ssh", "ak-link": filepath.Join(home, ".ssh", "authorized_keys"), "dc-link": filepath.Join(home, ".defenseclaw", "config.yaml"),
		"rc-link": filepath.Join(home, ".bashrc"), "aws-link": filepath.Join(home, ".aws", "credentials"), "claude-dir": filepath.Join(home, ".claude"),
	} {
		if err := os.Symlink(target, filepath.Join(open, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"README.md", "docs/README.md"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(open, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(open, name), []byte("readme\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"readme-link": "README.md", "docs-link": "docs"} {
		if err := os.Symlink(target, filepath.Join(open, name)); err != nil {
			t.Fatal(err)
		}
	}
	return open
}
