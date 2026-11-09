package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// A command that names a registered hook file and holds any flow construct is
// read as reaching it, whatever values the shell would carry; a single simple
// command with literal words keeps the precise reading.
func TestRegistrationWriteReachFlowConstructs(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	bin := filepath.Join(home, ".local", "bin")
	hook := filepath.Join(bin, "defenseclaw-hook-user")
	named := filepath.Join(root, "source", "defenseclaw-hook-user")
	ordinary := filepath.Join(root, "ordinary")
	for _, path := range []string{hook, named} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(ordinary, 0o700); err != nil {
		t.Fatal(err)
	}
	link := func(folder string) string { return "ln -sf " + named + " " + folder + "/" }
	rows := []struct {
		name, command string
		want          bool
	}{
		// The reviewer's conditional-join and pipeline-state forms.
		{"conditional join keeps the protected arm", "src=" + named + "; dest=" + ordinary + "; eval ':'; if [ -n \"$src\" ]; then dest=" + bin + "; else dest=" + ordinary + "; fi; ln -sf \"$src\" \"$dest\"/", true},
		{"conditional join after a shadowed exit", "src=" + named + "; dest=" + ordinary + "; exit() { :; }; exit; if [ -n \"$src\" ]; then dest=" + bin + "; else dest=" + ordinary + "; fi; ln -sf \"$src\" \"$dest\"/", true},
		{"conditional join after a stateful pipeline", "src=" + named + "; dest=" + ordinary + "; echo x | read y; if [ -n \"$src\" ]; then dest=" + bin + "; else dest=" + ordinary + "; fi; ln -sf \"$src\" \"$dest\"/", true},
		{"printf -v in the last pipe stage with lastpipe", "shopt -s lastpipe; src=" + named + "; dest=" + ordinary + "; echo x | printf -v dest %s " + bin + "; ln -sf \"$src\" \"$dest\"/", true},
		{"conditional join with ordinary arms", "src=" + named + "; dest=" + ordinary + "; eval ':'; if [ -n \"$src\" ]; then dest=" + ordinary + "/a; else dest=" + ordinary + "/b; fi; ln -sf \"$src\" \"$dest\"/", false},
		{"printf -v with an ordinary value", "shopt -s lastpipe; src=" + named + "; dest=" + bin + "; echo x | printf -v dest %s " + ordinary + "; ln -sf \"$src\" \"$dest\"/", true},
		{"printf -v of an ordinary link", "shopt -s lastpipe; src=" + ordinary + "/tool; dest=" + ordinary + "; echo x | printf -v dest %s " + ordinary + "/b; ln -sf \"$src\" \"$dest\"/", false},
		// Each construct, around a link that names the hook through its folder.
		{"pipe", "echo x | " + link(bin), true},
		{"and", "true && " + link(bin), true},
		{"or", "false || " + link(bin), true},
		{"list", "echo a; " + link(bin), true},
		{"subshell", "( " + link(bin) + " )", true},
		{"group", "{ " + link(bin) + "; }", true},
		{"if", "if [ -n \"$x\" ]; then " + link(bin) + "; fi", true},
		{"case", "case x in x) " + link(bin) + ";; esac", true},
		{"for", "for i in 1; do " + link(bin) + "; done", true},
		{"while", "while false; do " + link(bin) + "; done", true},
		{"until", "until true; do " + link(bin) + "; done", true},
		{"select", "select i in 1; do " + link(bin) + "; done", true},
		{"function", "f() { :; }; " + link(bin), true},
		{"eval", "eval :; " + link(bin), true},
		{"source", "source /dev/null; " + link(bin), true},
		{"dot", ". /dev/null; " + link(bin), true},
		{"background", link(bin) + " &", true},
		{"here-document", "cat <<EOF\nx\nEOF\n" + link(bin), true},
		{"here-string", "cat <<< x; " + link(bin), true},
		{"process substitution", "cat <(echo x); " + link(bin), true},
		{"command substitution", "x=$(echo a); " + link(bin), true},
		{"link inside a here-document body of a shell", "bash <<EOF\n" + link(bin) + "\nEOF", true},
		// The same constructs around an ordinary link name no registered file.
		{"ordinary pipe", "echo x | " + link(ordinary), false},
		{"ordinary and", "true && " + link(ordinary), false},
		{"ordinary list", "echo a; " + link(ordinary), false},
		{"ordinary if", "if [ -n \"$x\" ]; then " + link(ordinary) + "; fi", false},
		{"ordinary eval", "eval :; " + link(ordinary), false},
		{"ordinary function", "f() { :; }; " + link(ordinary), false},
		// Reads of the hook are not writes.
		{"checksum in a list", "sha256sum " + hook + " && echo ok", false},
		{"loop prints the hook", "for f in " + hook + "; do cat \"$f\"; done", false},
		{"sed prints the hook in a list", "sed -n 1p " + hook + "; echo done", false},
		{"redirect to the null device", "cat " + hook + " > /dev/null; echo done", false},
		{"folder named in a list for ordinary work", "cd " + bin + " && cp " + ordinary + "/tool tool", false},
		{"install into the folder in a list", "cp " + ordinary + "/tool " + bin + "/tool && chmod +x " + bin + "/tool", false},
		// A single simple command keeps the precise reading.
		{"simple link into the hook folder", link(bin), true},
		{"simple link into an ordinary folder", link(ordinary), false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got := len(RegistrationWriteReached(row.command, root, home, []string{hook, bin})) > 0
			if got != row.want {
				t.Errorf("reached %v, want %v for %q", got, row.want, row.command)
			}
		})
	}
}

func TestRegistrationWriteReachFlowLinkedName(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	bin := filepath.Join(home, ".local", "bin")
	hook := filepath.Join(bin, "defenseclaw-hook-user")
	alias := filepath.Join(root, "alias")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hook, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(hook, alias); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	for command, want := range map[string]bool{
		"echo a; cp /tmp/x " + alias:           true,
		"echo a; cp /tmp/x " + root + "/other": false,
	} {
		if got := len(RegistrationWriteReached(command, root, home, []string{hook, bin})) > 0; got != want {
			t.Errorf("%q reached %v, want %v", command, got, want)
		}
	}
}

func TestRegistrationFlowConstructReaders(t *testing.T) {
	flow := []string{
		"eval :", "source /dev/null", ". /dev/null", "shopt -s lastpipe", "set -e", "printf -v x %s y",
		"read x", "declare x=1", "typeset x=1", "local x=1", "export x=1", "readonly x=1",
		"mapfile -t x", "readarray -t x", "alias a=b", "unset x", "command -v x", "builtin echo",
		"enable -n echo", "trap : EXIT", "exec true", "cat <<< x", "cat <(true)", "x=$(true)",
		"echo a | cat", "true && true", "f() { :; }", "$cmd a b", "echo $other",
	}
	for _, command := range flow {
		file, ok := parseShell(command)
		if !ok {
			t.Fatalf("%q does not parse", command)
		}
		if !registrationHasFlow(file, "/home/u") {
			t.Errorf("%q is not read as flow", command)
		}
	}
	for _, command := range []string{
		"ln -sf /a/b /c/", "cp -r a b", "FOO=1 ln a b", "echo hi", "cat \"$HOME/x\"",
		"printf %s x", "printf -- -v", "sed -n 1p x", "ln -sf a b > /dev/null",
	} {
		file, ok := parseShell(command)
		if !ok {
			t.Fatalf("%q does not parse", command)
		}
		if registrationHasFlow(file, "/home/u") {
			t.Errorf("%q is read as flow", command)
		}
	}
}

// A registered folder that does not exist yet is still a folder: ordinary
// work in it, in a list, does not name the hook it will hold.
func TestRegistrationWriteReachFlowMissingFolder(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	bin := filepath.Join(home, ".local", "bin")
	hook := filepath.Join(bin, "defenseclaw-hook-user")
	names := []string{hook, bin, filepath.Dir(bin)}
	rows := []struct {
		command string
		want    bool
	}{
		{"mkdir -p " + bin + "\nln -sf /usr/local/bin/httpie " + bin + "/http", false},
		{"cat > ~/.xprofile <<'EOF'\necho $HOME/.local/bin\nEOF", false},
		{"cd " + bin + " && cp /tmp/tool tool", false},
		{"mkdir -p " + bin + "\nln -sf /tmp/defenseclaw-hook-user " + bin + "/", true},
		{"mkdir -p " + bin + "\nln -sf /tmp/tool " + hook, true},
	}
	for _, row := range rows {
		if got := len(RegistrationWriteReached(row.command, root, home, names)) > 0; got != row.want {
			t.Errorf("%q reached %v, want %v", row.command, got, row.want)
		}
	}
}
