//go:build !windows

package workspace

import (
	"strings"
	"testing"
)

// RV6-6: the branch commit lists the sandbox's own commits, starting after
// the commit its HEAD began at: the placeholder commit of a copy that
// replaced credentials is not listed, and an agent commit is, whatever its
// subject says.
func TestRV7BranchListsOnlyTheAgentsCommits(t *testing.T) {
	e, fs, _ := s9aCopy(t, "rv7b")
	fs.write(remoteRepo+"/agent.txt", "agent work\n")
	fs.agent(remoteRepo, "add", "agent.txt")
	fs.agent(remoteRepo, "commit", "-q", "-m", "defenseclaw: tidy up")
	pull(t, e, fs, "rv7b")
	if _, err := apply(e, "rv7b", ApplyBranch, func(o *ApplyOptions) { o.AcceptSensitive = true }); err != nil {
		t.Fatal(err)
	}
	msg := e.git(e.project, "log", "-1", "--format=%B", "dc/rv7b")
	if !strings.Contains(msg, "- defenseclaw: tidy up") {
		t.Errorf("branch message lacks the agent's commit:\n%s", msg)
	}
	if strings.Contains(msg, "credentials replaced with placeholders") {
		t.Errorf("branch message lists the placeholder commit:\n%s", msg)
	}
}

// RV7-4: the run warning says the pre-push hook is an accident guard.
func TestRV7WarningNamesTheHookAsAnAccidentGuard(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, "config.py", "TOKEN = \""+b1Key(0)+"\"\n")
	e.git(e.project, "add", "config.py")
	e.commit("config")
	rec, _ := launchCopy(t, e, "rv7w", func(o *StageOptions) { o.RewriteSecrets = PlaceholderToken })
	if w := strings.Join(rec.Warnings, "\n"); !strings.Contains(w, "an accident guard: the agent can skip or remove it") {
		t.Errorf("the run warning does not call the hook an accident guard: %q", w)
	}
}
