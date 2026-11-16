// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func gap0341ProbeCommands() []string {
	return []string{
		"cat .env", "head .env", "less .env", "base64 .env", "xxd .env", "strings .env", "dd if=.env", "cp .env /tmp/x",
		"grep . .env", "grep -r KEY .", "awk 1 .env", "sed -n p .env", "bat .env", "gzip -c .env",
		`python3 -c "print(open('.env').read())"`, `node -e "console.log(require('fs').readFileSync('.env','utf8'))"`,
		`perl -ne print .env`, "(cat .env)", `bash -c "cat .env"`, "F=.env; cat $F", "cat .en?", "cat .env*",
		"while read l; do echo $l; done < .env", "ln -s .env notes.txt && cat notes.txt", "source .env; echo $API_KEY",
		"cat ~/.aws/credentials", "cat ~/.aws/config", "cat ~/.ssh/id_rsa", "cat /proc/self/environ",
		"cat /var/run/secrets/kubernetes.io/serviceaccount/token", "cat ~/.codex/auth.json", "cat ~/.claude/.credentials.json",
		"cat ~/.config/gh/hosts.yml", "cat ~/.vault-token", "cat ~/.pgpass", "cat ~/.terraform.d/credentials.tfrc.json",
		"sed p .env", "sed '' .env", "cat ./.env*", "grep -rn KEY .", "jq . ~/.docker/config.json",
	}
}

func TestGAP0341CredentialPathProbeRows(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(t.Name()), 0600); err != nil {
		t.Fatal(err)
	}
	for i, command := range gap0341ProbeCommands() {
		t.Run(fmt.Sprintf("probe-%02d", i), func(t *testing.T) {
			facts := Analyze(Input{Tool: "exec", Command: command, CWD: dir, ActiveHome: dir})
			field := reflect.ValueOf(facts).FieldByName("CredentialPathReads")
			got := field.IsValid() && field.Len() > 0
			want := command != "cat ~/.aws/config" && command != "cat /proc/self/environ" && command != "cat /var/run/secrets/kubernetes.io/serviceaccount/token"
			if got != want {
				t.Fatalf("private read=%v want=%v", got, want)
			}
			raw, err := json.Marshal(facts)
			if err != nil {
				t.Fatal(err)
			}
			var projected map[string]any
			if err = json.Unmarshal(raw, &projected); err != nil {
				t.Fatal(err)
			}
			if _, ok := projected["CredentialPathReads"]; ok {
				t.Fatal("private evidence serialized")
			}
		})
	}
}
func TestGAP0341CredentialPathScope(t *testing.T) {
	for i, command := range []string{"grep -rn KEY .", "cat ~/.aws/config", "cat .env.example", "unused() { cat .env; }", "sh -n -c 'cat .env'", "ssh -i ~/.ssh/id_rsa server.invalid", "cat https://example.invalid/.env"} {
		t.Run(fmt.Sprintf("negative-%02d", i), func(t *testing.T) {
			facts := Analyze(Input{Tool: "exec", Command: command, CWD: t.TempDir()})
			field := reflect.ValueOf(facts).FieldByName("CredentialPathReads")
			if field.IsValid() && field.Len() != 0 {
				t.Fatal("unexpected private read")
			}
		})
	}
}
func TestGAP0341CredentialPathLocalSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, ".env")
	if err := os.WriteFile(target, []byte(t.Name()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "notes.txt")); err != nil {
		t.Skip("symlink unavailable")
	}
	facts := Analyze(Input{Tool: "exec", Command: "cat notes.txt", CWD: dir})
	field := reflect.ValueOf(facts).FieldByName("CredentialPathReads")
	if !field.IsValid() || field.Len() == 0 {
		t.Fatal("missing local link read")
	}
}

func TestGAP0341CredentialPathIdentity(t *testing.T) {
	for i, row := range []struct {
		command string
		unknown bool
	}{
		{"sed -n p .env", false}, {"cat .en?", true}, {"cat .env*", true},
	} {
		t.Run(fmt.Sprintf("identity-%02d", i), func(t *testing.T) {
			facts := Analyze(Input{Tool: "exec", Command: row.command, CWD: "/work"})
			field := reflect.ValueOf(facts).FieldByName("CredentialPathReads")
			if !field.IsValid() || field.Len() == 0 {
				t.Fatal("missing private read")
			}
			reads := field.Interface().([]PathFact)
			unknown := false
			for _, read := range reads {
				if read.Value == "" {
					unknown = true
				}
			}
			if unknown != row.unknown {
				t.Fatalf("unknown=%v want=%v", unknown, row.unknown)
			}
			if i == 0 && len(facts.Paths) != 0 {
				t.Fatal("ordinary path projection widened")
			}
		})
	}
}
