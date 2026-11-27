package gateway

import (
	"path/filepath"
	"testing"
)

func TestGAP1087InlineHookConfigDeletionFiveTiers(t *testing.T) {
	home := hardP5Home(t)
	member := ".claude/settings.json"
	project := filepath.Join(home, "proj", "notes.txt")
	cases := map[string][]string{
		"rm " + member: {
			"python3 -c 'import os; os.remove(\"" + member + "\")'",
			"node -e 'require(\"fs\").unlinkSync(\"" + member + "\")'",
			"ruby -e 'File.delete(\"" + member + "\")'",
		},
		"mv " + member + " .claude/x.json": {
			"python3 -c 'import os; os.rename(\"" + member + "\", \".claude/x.json\")'",
		},
	}
	benign := []string{
		"python3 -c 'import os; os.remove(\"" + project + "\")'",
		"python3 -c 'import os; os.rename(\"" + project + "\", \"" + filepath.Join(home, "proj", "moved.txt") + "\")'",
		"node -e 'require(\"fs\").unlinkSync(\"" + project + "\")'",
		"ruby -e 'File.delete(\"" + project + "\")'",
	}
	hardP5Parity(t, home, cases, benign)
}
