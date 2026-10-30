package hookpaths

import "testing"

// TestDirectoryStackPathExpandsLikeBash pins the bash directory-stack tilde
// expansion the link walk uses for copy and archive sources (GAP-2586):
// ~N and ~+N count from the current directory, ~-N from the bottom, ~- and
// an index outside the stack stay unexpanded.
func TestDirectoryStackPathExpandsLikeBash(t *testing.T) {
	stack := []string{"/h/p/src", "/h/p", "/h"}
	rows := []struct {
		word, want string
		ok         bool
	}{
		{"~1/ordinary", "/h/p/ordinary", true},
		{"~+1/ordinary", "/h/p/ordinary", true},
		{"~0", "/h/p/src", true},
		{"~+", "/h/p/src", true},
		{"~+/x", "/h/p/src/x", true},
		{"~2", "/h", true},
		{"~-0/a", "/h/a", true},
		{"~-2", "/h/p/src", true},
		{"~3/x", "", false},
		{"~-3", "", false},
		{"~-", "", false},
		{"~-/x", "", false},
		{"~user/x", "", false},
	}
	for _, row := range rows {
		got, ok := directoryStackPath(row.word, stack)
		if got != row.want || ok != row.ok {
			t.Errorf("%q: got %q %t, want %q %t", row.word, got, ok, row.want, row.ok)
		}
	}
	if _, ok := directoryStackPath("~1", nil); ok {
		t.Error("an unknown stack expanded a word")
	}
}
