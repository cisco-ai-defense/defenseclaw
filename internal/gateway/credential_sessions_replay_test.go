// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// A session-level view of the secret-read-then-egress code (GAP-0724): the
// hook-path decisions on every session of a session corpus (CB_CORPUS, the
// chainbench-v1 case file) whose shell calls touch a credentials file, in the
// default and the strict pack. The unit and lane A/B corpora hold single
// calls and so never reach the chain or the sender reader; a real session
// does. The test prints one SESS row per session and pack (the session id,
// the strongest action, whether a chain.* rule fired) and a TOTAL row per
// pack, to compare two trees by session id. It skips without CB_CORPUS.
var credentialSessionPattern = regexp.MustCompile(`(?i)(^|[\s/"'=:<>])(\.env(\.[a-z0-9_-]+)?|\.aws/credentials|id_(rsa|ed25519|ecdsa|dsa)[a-z0-9_.-]*|\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.kube/config)($|[\s/"'<>;|&)])`)

func TestCredentialSessionsReplayGAP0724(t *testing.T) {
	path := os.Getenv("CB_CORPUS")
	if path == "" {
		t.Skip("CB_CORPUS (a chainbench case file) is not set")
	}
	type event struct {
		Tool    string          `json:"tool_name"`
		Command string          `json:"command"`
		Args    json.RawMessage `json:"args"`
		Outcome string          `json:"outcome"`
	}
	type session struct {
		ID       string
		Commands []string
		Failed   []bool
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var sessions []session
	reader := bufio.NewReaderSize(file, 1<<20)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 && len(line) < 8<<20 {
			var c struct {
				ID      string `json:"id"`
				Payload struct {
					Events []event `json:"events"`
				} `json:"payload"`
			}
			if json.Unmarshal(line, &c) == nil {
				s := session{ID: c.ID}
				touches := false
				for _, e := range c.Payload.Events {
					command := e.Command
					if command == "" && len(e.Args) > 0 {
						var a struct {
							Command string `json:"command"`
						}
						_ = json.Unmarshal(e.Args, &a)
						command = a.Command
					}
					if command == "" || len(command) > 4000 {
						continue
					}
					if credentialSessionPattern.MatchString(command) {
						touches = true
					}
					s.Commands = append(s.Commands, command)
					s.Failed = append(s.Failed, e.Outcome == "failed")
				}
				if touches && len(s.Commands) > 0 {
					sessions = append(sessions, s)
				}
			}
		}
		if err != nil {
			break
		}
	}
	// a stable sample by session id when there are more than CB_MAX (450)
	if len(sessions) > 450 {
		keep := sessions[:0]
		for _, s := range sessions {
			h := 0
			for _, c := range s.ID {
				h = (h*31 + int(c)) % 1000003
			}
			if h%100 < 100*450/len(sessions)+1 {
				keep = append(keep, s)
			}
		}
		sessions = keep
	}
	fmt.Printf("SESSIONS credential-touching=%d\n", len(sessions))
	installCorrelationHMACForTest()
	policiesRoot := guardrailPoliciesRoot(t)
	for _, pack := range []string{"default", "strict"} {
		installDefaultProfileConnector(t, "claudecode")
		store, logger := testStoreAndV8Logger(t)
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = "claudecode"
		cfg.Guardrail.RulePackDir = filepath.Join(policiesRoot, pack)
		api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
		handler := http.HandlerFunc(api.handleAgentHook("claudecode"))
		var blocks, alerts, chains int
		for _, s := range sessions {
			worst, chain := "allow", false
			for i, command := range s.Commands {
				id := fmt.Sprintf("t%d", i)
				pre := claudeToolEvent("PreToolUse", s.ID, id, command)
				pre["cwd"] = "/work/proj"
				got := callAgentHookForTest(t, handler, pre)
				if got.Action == guardrailActionBlock {
					worst = "block"
				} else if (got.Action == "alert" || got.RawAction == "alert") && worst == "allow" {
					worst = "alert"
				}
				if slices.ContainsFunc(got.RuleIDs, func(r string) bool { return strings.HasPrefix(r, "chain.") }) {
					chain = true
				}
				if got.Action == guardrailActionBlock {
					break
				}
				if !s.Failed[i] {
					post := claudeToolResult("PostToolUse", s.ID, id)
					post["cwd"] = "/work/proj"
					callAgentHookForTest(t, handler, post)
				}
			}
			switch worst {
			case "block":
				blocks++
			case "alert":
				alerts++
			}
			if chain {
				chains++
			}
			if worst != "allow" || chain {
				fmt.Printf("SESS %s %s %s chain=%t\n", pack, s.ID, worst, chain)
			}
			_ = guardrail.ToolChainSecretReadThenEgress
		}
		fmt.Printf("TOTAL pack=%s sessions=%d blockSessions=%d alertSessions=%d chainSessions=%d\n", pack, len(sessions), blocks, alerts, chains)
	}
}
