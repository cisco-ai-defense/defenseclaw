// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

// A managed gateway cannot read the home of the user, so it has no working
// directory for a relative file-tool path and follows no link there. The hook
// client placed the path as the user; the content proofs read its answer, and
// place the path in the client directory lexically when it gave none.
const clientProject = "/home/user/proj"

func clientPlacedCall(t *testing.T, tool string, args map[string]any, resolved map[string]string) (Input, Facts) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	input := Input{
		Tool: tool, Args: raw,
		ClientResolvedTargets:    resolved,
		ClientWorkingDirectories: []string{clientProject},
	}
	return input, Analyze(input)
}

func TestContentProofsPlaceARelativeTargetByTheHookClient(t *testing.T) {
	const (
		library  = "/usr/local/lib/liblogger.so\n"
		export   = "export LD_PRELOAD=/usr/local/lib/liblogger.so\n"
		insecure = `{"insecure-registries":["http://registry.example.test:5000"]}` + "\n"
	)
	pamEdit := func(name string) map[string]any {
		return map[string]any{"file_path": name, "old_string": "account    required     pam_nologin.so",
			"new_string": pamPermitAll + "\naccount    required     pam_nologin.so"}
	}
	write := func(name, content string) map[string]any {
		return map[string]any{"file_path": name, "content": content}
	}
	for _, row := range []struct {
		name     string
		tool     string
		args     map[string]any
		resolved map[string]string
		proof    func(Input, Facts) bool
		want     bool
	}{
		{"loader link name", "Write", write("lnk-preload", library), map[string]string{clientProject + "/lnk-preload": "/etc/ld.so.preload"}, loaderProof, true},
		{"loader dot-slash link name", "Write", write("./lnk-preload", library), map[string]string{clientProject + "/lnk-preload": "/etc/ld.so.preload"}, loaderProof, true},
		{"loader two-hop link answer", "Write", write("lnk-preload2", library), map[string]string{clientProject + "/lnk-preload2": "/etc/ld.so.preload"}, loaderProof, true},
		{"loader dot-dot path, client answer", "Write", write("../../../etc/ld.so.preload", library), map[string]string{clientProject + "/../../../etc/ld.so.preload": "/etc/ld.so.preload"}, loaderProof, true},
		{"loader dot-dot path, no answer", "Write", write("../../../etc/ld.so.preload", library), nil, loaderProof, true},
		{"loader profile.d link into the directory", "Write", write("lnk-profd/r109.sh", export), map[string]string{clientProject + "/lnk-profd/r109.sh": "/etc/profile.d/r109.sh"}, loaderProof, true},
		{"loader link to an ordinary file", "Write", write("lnk-ok", library), map[string]string{clientProject + "/lnk-ok": clientProject + "/ok.txt"}, loaderProof, false},
		{"loader path that lands in the home", "Write", write("../../etc/ld.so.preload", library), nil, loaderProof, false},
		{"loader ordinary text through the link", "Write", write("lnk-preload", "# nothing\n"), map[string]string{clientProject + "/lnk-preload": "/etc/ld.so.preload"}, loaderProof, false},
		{"loader plain project file", "Write", write("lib.txt", library), nil, loaderProof, false},
		{"pam edit by link name", "Edit", pamEdit("lnk-sshd"), map[string]string{clientProject + "/lnk-sshd": "/etc/pam.d/sshd"}, pamProof, true},
		{"pam edit by dot-slash link name", "Edit", pamEdit("./lnk-sshd"), map[string]string{clientProject + "/lnk-sshd": "/etc/pam.d/sshd"}, pamProof, true},
		{"pam write by link name", "Write", write("lnk-sshd", pamPermitAll+"\n"), map[string]string{clientProject + "/lnk-sshd": "/etc/pam.d/sshd"}, pamProof, true},
		{"pam edit dot-dot path", "Edit", pamEdit("../../../etc/pam.d/sshd"), nil, pamProof, true},
		{"pam edit of a comment by link name", "Edit", map[string]any{"file_path": "lnk-sshd", "old_string": "# old", "new_string": "# new"}, map[string]string{clientProject + "/lnk-sshd": "/etc/pam.d/sshd"}, pamProof, false},
		{"pam edit by link to an ordinary file", "Edit", pamEdit("lnk-ok"), map[string]string{clientProject + "/lnk-ok": clientProject + "/ok.txt"}, pamProof, false},
		{"docker write by link name", "Write", write("lnk-docker", insecure), map[string]string{clientProject + "/lnk-docker": "/etc/docker/daemon.json"}, dockerProof, true},
		{"docker benign document by link name", "Write", write("lnk-docker", `{"log-level":"warn"}`+"\n"), map[string]string{clientProject + "/lnk-docker": "/etc/docker/daemon.json"}, dockerProof, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			input, facts := clientPlacedCall(t, row.tool, row.args, row.resolved)
			if got := row.proof(input, facts); got != row.want {
				t.Fatalf("proof = %t, want %t", got, row.want)
			}
		})
	}
}

// TestContentProofsLeaveARelativeTargetWithoutAnyDirectoryUnplaced: a relative
// name that no gateway or client directory places names no file.
func TestContentProofsLeaveARelativeTargetWithoutAnyDirectoryUnplaced(t *testing.T) {
	for name, args := range map[string]map[string]any{
		"loader": {"file_path": "ld.so.preload", "content": "/usr/local/lib/liblogger.so\n"},
		"docker": {"file_path": "daemon.json", "content": `{"insecure-registries":["http://registry.example.test:5000"]}` + "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			input, _ := clientPlacedCall(t, "Write", args, nil)
			input.ClientWorkingDirectories = nil
			facts := Analyze(input)
			if loaderProof(input, facts) || dockerProof(input, facts) {
				t.Fatal("a relative name with no directory was placed")
			}
		})
	}
}

func loaderProof(input Input, facts Facts) bool { return ExactGlobalLDPreloadFileWrite(input, facts) }

func pamProof(input Input, facts Facts) bool {
	_, ok := ExactPAMAuthenticationBypass(input, facts)
	return ok
}

func dockerProof(input Input, facts Facts) bool {
	return ExactDockerInsecureRegistryWrite(input, facts)
}
