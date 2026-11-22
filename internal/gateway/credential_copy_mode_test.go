//go:build !windows

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"
)

// TestCredentialCopyMadeReadableAlerts is rel-1-0-10:GAP-0950: a copy of a
// credential file that the same call makes group or world readable (a
// numeric chmod of the copy, install -m) is a permission widening of that
// credential, alerted as CMD-CHMOD-WORLD in every tier, as the symbolic
// spellings (go+r, a+r) already are. A copy kept private and a readable mode
// on an ordinary file add nothing.
func TestCredentialCopyMadeReadableAlerts(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home", "alice")
	other := filepath.Join(root, "home", "bob")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(project, ".git"), filepath.Join(home, ".aws"), filepath.Join(home, ".kube")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	type row struct {
		id, command string
		widens      bool
	}
	var rows []row
	for homeName, base := range map[string]string{"own": home, "other": other} {
		for _, rel := range []string{".netrc", ".git-credentials", ".pgpass", ".aws/credentials", ".kube/config"} {
			f := filepath.Join(base, rel)
			id := homeName + "-" + rel
			rows = append(rows,
				row{"W1-" + id, "cp " + f + " /tmp/n && chmod 644 /tmp/n", true},
				row{"W3-" + id, "cp " + f + " /tmp/n; chmod 0640 /tmp/n", true},
				row{"W4-" + id, "cp -p " + f + " " + filepath.Join(home, "n.bak") + " && chmod 755 " + filepath.Join(home, "n.bak"), true},
				row{"X1-" + id, "install -m 644 " + f + " /tmp/n", true},
				row{"X5-" + id, "install -m 0644 " + f + " /tmp/n", true},
				row{"keep-" + id, "cp " + f + " /tmp/n && chmod 600 /tmp/n", false},
				row{"keep-install-" + id, "install -m 600 " + f + " /tmp/n", false},
				row{"keep-other-" + id, "cp " + f + " /tmp/n && chmod 644 /tmp/other", false},
			)
		}
	}
	benign := []row{
		{"benign-cp-chmod", "cp config.json /tmp/n && chmod 644 /tmp/n", false},
		{"benign-install", "install -m 644 build/app.conf /tmp/app.conf", false},
		{"benign-chmod", "chmod 644 README.md", false},
	}
	rows = append(rows, benign...)
	for _, pack := range gap0437Packs {
		a := gap0437Server(t, pack, "claudecode", "action")
		for index, r := range rows {
			action, severity, rules := credCopyVerdict(gap0437Hook(t, a, project, fmt.Sprintf("g0950-%s-%d", pack.name, index), r.command))
			name := pack.name + "/" + r.id
			t.Logf("ROW %s %s/%s/%v", name, action, severity, rules)
			widened := slices.Contains(rules, "CMD-CHMOD-WORLD")
			if r.widens && (!widened || credCopyActionRank(action) < credCopyActionRank("alert")) {
				t.Errorf("%s: readable copy of a credential answered %s %s %v, want CMD-CHMOD-WORLD at least alert", name, action, severity, rules)
			}
			if !r.widens && widened {
				t.Errorf("%s: no widening, yet CMD-CHMOD-WORLD (%s %v)", name, action, rules)
			}
			if pack.name == "default" && slices.Contains(benign, r) && action != "allow" {
				t.Errorf("%s: benign twin answered %s %s %v in default", name, action, severity, rules)
			}
		}
	}
}

// credCopyVerdict is action, severity and the sorted rule ids of a hook
// answer.
func credCopyVerdict(out map[string]any) (action, severity string, rules []string) {
	action, _ = out["action"].(string)
	if action == "" {
		action = "allow"
	}
	severity, _ = out["severity"].(string)
	if raw, ok := out["rule_ids"].([]any); ok {
		for _, rule := range raw {
			rules = append(rules, fmt.Sprint(rule))
		}
	}
	sort.Strings(rules)
	return action, severity, rules
}

func credCopyActionRank(action string) int {
	return map[string]int{"allow": 0, "alert": 1, "confirm": 2, "ask": 2, "block": 3, "deny": 3}[action]
}
