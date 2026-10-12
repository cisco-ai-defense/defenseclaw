package managed

import "testing"

func TestWindowsPathWithinProfileRoots(t *testing.T) {
	roots := []string{`C:\Users`, `D:\Profiles\sample`}
	tests := []struct {
		name, path string
		want       bool
	}{
		{"Users root", `C:\Users`, true},
		{"profile", `D:\Profiles\sample\project`, true},
		{"mixed case", `c:\uSeRs\Sample\project`, true},
		{"short child name", `C:\Users\SAMPLE~1\project`, true},
		{"trailing dots and slashes", `C:\Users.\sample.\project..\`, true},
		{"extended prefix", `\\?\C:\Users\sample`, true},
		{"forward slashes", `C:/Users/sample/project`, true},
		{"prefix is not a boundary", `C:\Users2\sample`, false},
		{"outside", `C:\src\project`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := windowsPathWithinProfileRoots(tt.path, roots); got != tt.want {
				t.Fatalf("windowsPathWithinProfileRoots(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
