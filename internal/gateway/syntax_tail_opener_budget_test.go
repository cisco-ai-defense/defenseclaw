package gateway

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// gap0930GatewayShape is a script passed as one quoted argument with n
// openers of one delimiter that a single late line closes, and a syntax error
// in its body.
func gap0930GatewayShape(n int) string {
	var b strings.Builder
	b.WriteString("tool '")
	for i := 0; i < n; i++ {
		b.WriteString("cat <<'\"'\"'E'\"'\"'\n")
	}
	b.WriteString("E\nit's (x)\necho after'")
	return b.String()
}

// rel-1-0-10:GAP-0930. The same broken shape is the unknown tier at 9, 18,
// 36 and 72 KB in every pack: alert in default, permissive and the managed
// default pack, block in strict and managed-strict, never allow LOW.
func TestGAP0930ManyOpenersAreTheUnknownTierAtEverySize(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	for _, p := range gap0437Packs {
		hook := gap0437Server(t, p, "claudecode", "action")
		cwd := t.TempDir()
		for _, n := range []int{500, 1000, 2000, 4000} {
			command := gap0930GatewayShape(n)
			out := gap0437Hook(t, hook, cwd, fmt.Sprintf("g930%s%d", p.name, n), command)
			want := "alert"
			if strings.Contains(p.name, "strict") {
				want = "block"
			}
			if out["action"] != want {
				t.Errorf("%s %d bytes: action %v severity %v, want %s", p.name, len(command), out["action"], out["severity"], want)
			}
		}
	}
}
