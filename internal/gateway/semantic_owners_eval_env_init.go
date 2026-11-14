// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// CMD-EVAL claims that the shell runs text the call does not show. The
// environment-setup idiom eval "$(tool args)" runs the text one known tool
// prints to configure the current shell (opam env, ssh-agent -s, brew
// shellenv, pyenv init -); the tool itself is visible in the call and is
// judged by every other rule. Such an eval is kept as audit telemetry and
// does not alert. Every other eval (a variable, a downloader or interpreter
// behind the substitution, a tool or argument not on the list, any eval whose
// substitution is not one plain command) stays an alert
// (rel-1-0-10:GAP-0018).

// evalEnvInitTools maps a program to the argument vectors (after the program)
// whose output configures the shell. Arguments are compared exactly.
var evalEnvInitTools = map[string][][]string{
	"opam":      {{"env"}, {"env", "--switch=default"}, {"env", "--set-switch"}},
	"ssh-agent": {{"-s"}, {"-c"}, {}},
	"brew":      {{"shellenv"}},
	"pyenv":     {{"init", "-"}, {"init", "--path"}, {"virtualenv-init", "-"}},
	"rbenv":     {{"init", "-"}},
	"nodenv":    {{"init", "-"}},
	"goenv":     {{"init", "-"}},
	"jenv":      {{"init", "-"}},
	"direnv":    {{"hook", "bash"}, {"hook", "zsh"}, {"export", "bash"}, {"export", "zsh"}},
	"fnm":       {{"env"}, {"env", "--use-on-cd"}},
	"mise":      {{"activate", "bash"}, {"activate", "zsh"}},
	"zoxide":    {{"init", "bash"}, {"init", "zsh"}},
	"starship":  {{"init", "bash"}, {"init", "zsh"}},
	"dircolors": {{"-b"}, {"-b", "~/.dircolors"}, {"-b", "/etc/DIR_COLORS"}},
	"luarocks":  {{"path"}, {"path", "--bin"}},
	"keychain":  {{"--eval", "--quiet"}, {"--eval"}},
	"gpg-agent": {{"--daemon"}},
	"minikube":  {{"docker-env"}, {"-p", "minikube", "docker-env"}},
}

// evalCommandText is the shell text of the call: the command of a shell tool
// call, or the input's own command.
func evalCommandText(input actionfacts.Input) string {
	if strings.TrimSpace(input.Command) != "" {
		return input.Command
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(input.Args, &fields) != nil {
		return ""
	}
	for _, key := range []string{"command", "cmd"} {
		var text string
		if raw, ok := fields[key]; ok && json.Unmarshal(raw, &text) == nil {
			return text
		}
	}
	return ""
}

// evalPattern is the CMD-EVAL rule's own pattern, for the text left once the
// known environment-setup evals are taken out.
var evalPattern = regexp.MustCompile(`(?i)(?:^|[;&|\r\n"]\s*)eval\s+\\?["'\$\(]`)

// evalEnvInitOnly reports a call whose every eval runs the output of one known
// environment-setup command, as the whole of the eval's operand, and in which
// no other command is left undecided.
func evalEnvInitOnly(input actionfacts.Input, facts actionfacts.Facts) bool {
	text := evalCommandText(input)
	if text == "" {
		return false
	}
	children := map[int64][]actionfacts.CommandFact{}
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 {
			children[command.ParentCommandID] = append(children[command.ParentCommandID], command)
		}
	}
	evals := 0
	var forms []string
	for _, command := range facts.Commands {
		if !oneOfFold(path.Base(command.Program), "eval") {
			continue
		}
		evals++
		kids := children[command.ID]
		if len(kids) != 1 || !evalEnvInitChild(kids[0]) || len(children[kids[0].ID]) != 0 || len(kids[0].Redirects) > 0 {
			return false
		}
		forms = append(forms, strings.Join(kids[0].Argv, " "))
	}
	if evals == 0 {
		return false
	}
	for _, command := range facts.Commands {
		if !command.ArgvComplete && !oneOfFold(path.Base(command.Program), "eval") {
			return false
		}
	}
	// The eval's operand must be the substitution and nothing else: take each
	// exact eval "$(tool args)" form out of the text, and what is left must
	// hold no eval the rule would match.
	for _, form := range forms {
		quoted := regexp.QuoteMeta(form)
		exact := regexp.MustCompile(`(^|[;&|\n]\s*|\s)eval\s+(?:"\$\(` + quoted + `\)"|\$\(` + quoted + `\))(\s*(?:$|[;&|\n]))`)
		for {
			next := exact.ReplaceAllString(text, "$1$3")
			if next == text {
				break
			}
			text = next
		}
	}
	return !evalPattern.MatchString(text)
}

func evalEnvInitChild(command actionfacts.CommandFact) bool {
	if !command.ArgvComplete || len(command.Argv) == 0 {
		return false
	}
	program := command.Argv[0]
	if strings.Contains(program, "/") && !strings.HasPrefix(program, "/usr/") && !strings.HasPrefix(program, "/opt/") {
		return false
	}
	allowed, ok := evalEnvInitTools[path.Base(program)]
	if !ok {
		return false
	}
	args := command.Argv[1:]
	for _, want := range allowed {
		if len(want) == len(args) {
			equal := true
			for i := range want {
				if want[i] != args[i] {
					equal = false
					break
				}
			}
			if equal {
				return true
			}
		}
	}
	return false
}
