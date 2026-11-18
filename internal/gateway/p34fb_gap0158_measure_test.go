package gateway

import (
	"fmt"
	"sort"
	"strings"
	"testing"

)

// Measurement only (not committed): what each pack does today for a
// credential-file sibling, per tool route and platform.
func TestP34fbMeasureCredentialSiblings(t *testing.T) {
	type platform struct{ name, home, sep string }
	platforms := []platform{{"linux", "/home/alice", "/"}, {"windows", `C:\Users\alice`, `\`}}
	files := []string{".aws/credentials", ".git-credentials", ".netrc", ".ssh/id_rsa", ".docker/config.json", ".npmrc"}
	suffixes := []string{"", ".bak", ".orig", ".old", ".example", ".template"}
	var lines []string
	for _, profile := range []string{"default", "strict", "permissive"} {
		judges := map[string]hookConfigJudge{"claudecode": newHookConfigJudge(t, "claudecode", profile), "codex": newHookConfigJudge(t, "codex", profile)}
		for _, pf := range platforms {
			for _, file := range files {
				for _, suffix := range suffixes {
					full := pf.home + pf.sep + strings.ReplaceAll(file, "/", pf.sep) + suffix
					homeRel := "~/" + file + suffix
					if pf.name == "windows" {
						homeRel = `$HOME\` + strings.ReplaceAll(file, "/", `\`) + suffix
					}
					type route struct {
						route, conn, tool string
						args              map[string]any
					}
					routes := []route{
						{"Write", "claudecode", "Write", map[string]any{"file_path": full, "content": "x"}},
						{"Edit", "claudecode", "Edit", map[string]any{"file_path": full, "old_string": "a", "new_string": "b"}},
						{"apply_patch-add", "codex", "apply_patch", map[string]any{"command": "*** Begin Patch\n*** Add File: " + full + "\n+x\n*** End Patch"}},
						{"apply_patch-update", "codex", "apply_patch", map[string]any{"command": "*** Begin Patch\n*** Update File: " + full + "\n@@\n-a\n+b\n*** End Patch"}},
						{"apply_patch-delete", "codex", "apply_patch", map[string]any{"command": "*** Begin Patch\n*** Delete File: " + full + "\n*** End Patch"}},
						{"Read", "claudecode", "Read", map[string]any{"file_path": full}},
						{"sh-read", "claudecode", "Bash", map[string]any{"command": "cat " + homeRel}},
						{"sh-write", "claudecode", "Bash", map[string]any{"command": "echo x > " + homeRel}},
						{"sh-cp-into", "claudecode", "Bash", map[string]any{"command": "cp /tmp/x " + homeRel}},
						{"codex-sh-write", "codex", "exec_command", map[string]any{"cmd": "echo x > " + homeRel}},
					}
					if pf.name == "windows" {
						routes = append(routes,
							route{"ps-read", "claudecode", "PowerShell", map[string]any{"command": "Get-Content " + homeRel}},
							route{"ps-write", "claudecode", "PowerShell", map[string]any{"command": "Set-Content " + homeRel + " x"}})
					}
					for _, r := range routes {
						got := judges[r.conn](pf.home+pf.sep+"project", false, r.tool, r.args)
						ids := []string{}
						for _, id := range []string{"PATH-AWS-CREDS", "PATH-WIN-AWS-CREDS", "PATH-GIT-CREDS", "PATH-NETRC", "PATH-SSH-KEY", "PATH-DOCKER", "PATH-NPMRC"} {
							if strings.Contains(got, id) {
								ids = append(ids, id)
							}
						}
						sort.Strings(ids)
						lines = append(lines, fmt.Sprintf("M\t%s\t%s\t%s\t%s\t%s\t%s\t%s", profile, pf.name, file, suffix, r.route, hookConfigAction(got), strings.Join(ids, ",")))
					}
				}
			}
		}
	}
	for _, l := range lines {
		t.Log(l)
	}
}
