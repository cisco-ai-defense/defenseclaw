package psparse

import "testing"

// TT1 code-close test for rel-1-0-10:GAP-0194 (fix 5f7287490c): the host
// words of a pwsh or cmd call must be the native argv, so the Static script
// text is what runs. Rows are the review 9 probe ids (Q06, Q41, V1..V5). A
// row may be NotStatic; if it is Static the text must be the native one.
// Without a pwsh binary this pins the source-text expectations the native
// oracle (TestHostArgvOracle) was run against.
func TestFU12GAP0194HostWordsReproduceTheNativeArgv(t *testing.T) {
	rows := []struct {
		id, src string
		static  []string // texts a Static answer may carry; empty: must be NotStatic
	}{
		{"Q06", `pwsh -c'Write-Output a'`, nil},
		{"Q41", `pwsh -nop -c Write-Output 1e3 0x10 1kb`, []string{"Write-Output 1e3 0x10 1kb"}},
		{"V1", `pwsh -c -:'Write-Output "x"'`, []string{`-:Write-Output "x"`}},
		{"V2", `pwsh -c a'Write-Output "x"'`, []string{`aWrite-Output "x"`}},
		{"V3", `cmd /c del a'"C:\a b"'`, []string{`del a"C:\a b"`}},
		{"V4", `cmd /c -:'"C:\a b"'`, []string{`-:"C:\a b"`}},
		{"V5", `pwsh -c --:'"q"'`, []string{`--:"q"`}},
	}
	for _, r := range rows {
		for _, d := range []Dialect{DialectUnknown, DialectWindowsPS51, DialectPwsh7} {
			ns, ok := firstHostNested(r.src, d)
			if !ok || !ns.Static {
				continue
			}
			allowed := false
			for _, want := range r.static {
				allowed = allowed || ns.Text == want
			}
			if !allowed {
				t.Errorf("%s dialect=%d: Static text %q, want NotStatic or one of %q", r.id, d, ns.Text, r.static)
			}
		}
	}
}
