// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookcli"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func init() {
	var connectorName, hookDir string
	var installWindow, toolPayloadStdin bool
	cmd := &cobra.Command{
		Use:    "hook-outage-mode",
		Short:  "Print the gateway-outage mode the config gives a per-user connector's hooks now",
		Hidden: true,
		// A hook runs it while the gateway is down: no daemon bootstrap,
		// no audit store, only a read of config.yaml.
		Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		Args:        cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mode := hookcli.HookOutageFailModeFor(connectorName, hookDir, installWindow)
			if mode == "open" && toolPayloadStdin {
				mode = outageToolDecision(cmd.InOrStdin(), filepath.Dir(hookDir))
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), mode)
			return err
		},
	}
	cmd.Flags().StringVar(&connectorName, "connector", "", "connector name")
	cmd.Flags().StringVar(&hookDir, "hook-dir", "", "absolute hooks folder of the hook runtime asking")
	cmd.Flags().BoolVar(&installWindow, "install-window", false, "print the mode for a call the gateway answered while an installer holds the data directory")
	cmd.Flags().BoolVar(&toolPayloadStdin, "tool-payload-stdin", false, "check the tool payload before an open outage answer")
	_ = cmd.MarkFlagRequired("connector")
	rootCmd.AddCommand(cmd)
}

type outageToolPayload struct {
	Name string                 `json:"name"`
	Args map[string]interface{} `json:"args"`
	CWD  string                 `json:"cwd"`
}

// outageToolDecision checks concrete protected targets on the rare path where
// the gateway is unavailable. The saved tier chooses whether ordinary calls
// may proceed.
func outageToolDecision(input io.Reader, dataDir string) string {
	const maxPayload = 256 << 10
	raw, err := io.ReadAll(io.LimitReader(input, maxPayload+1))
	if err != nil || len(raw) > maxPayload {
		return "closed"
	}
	var payload outageToolPayload
	if err := json.Unmarshal(raw, &payload); err != nil || payload.Name == "" || payload.Args == nil {
		return "closed"
	}
	home := hookcli.OutageAccountHome()
	if home == "" || !filepath.IsAbs(home) {
		return "closed"
	}
	cwd := payload.CWD
	if !filepath.IsAbs(cwd) {
		return "closed"
	}
	if workdir, ok := payload.Args["workdir"].(string); ok && workdir != "" {
		if workdir == "~" {
			cwd = home
		} else if strings.HasPrefix(workdir, "~/") {
			cwd = filepath.Join(home, workdir[2:])
		} else if filepath.IsAbs(workdir) {
			cwd = filepath.Clean(workdir)
		} else {
			cwd = filepath.Join(cwd, workdir)
		}
	}
	if strings.EqualFold(payload.Name, "apply_patch") {
		args, err := json.Marshal(payload.Args)
		if err != nil {
			return "closed"
		}
		targets, known := hookpaths.ApplyPatchWriteTargets(payload.Name, args, "", cwd, home)
		if !known {
			return "closed"
		}
		for _, target := range targets {
			if outagePathProtected(target, cwd, home, dataDir) {
				return "protected"
			}
		}
	}
	if outagePayloadNamesProtected(payload.Args, cwd, home, dataDir) {
		return "protected"
	}
	return "open"
}

func outagePayloadNamesProtected(args map[string]interface{}, cwd, home, dataDir string) bool {
	type field struct {
		key         string
		value       interface{}
		environment map[string]string
	}
	stack := []field{{value: args, environment: map[string]string{"HOME": home, "DEFENSECLAW_HOME": dataDir}}}
	for len(stack) != 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch item := current.value.(type) {
		case map[string]interface{}:
			environment := current.environment
			if raw, ok := item["env"].(map[string]interface{}); ok {
				environment = outageKnownEnvironment(raw, environment)
			}
			for key, value := range item {
				if !strings.EqualFold(key, "env") {
					stack = append(stack, field{key: key, value: value, environment: environment})
				}
			}
		case []interface{}:
			for _, value := range item {
				stack = append(stack, field{key: current.key, value: value, environment: current.environment})
			}
		case string:
			if item == "" {
				continue
			}
			switch strings.ToLower(current.key) {
			case "command", "cmd", "script", "command_line", "commandline":
				if outageCommandNamesProtected(item, cwd, home, dataDir, current.environment) {
					return true
				}
			case "path", "file", "filepath", "file_path", "target", "destination", "dest", "output", "output_path", "filename":
				path := strings.ReplaceAll(strings.ReplaceAll(item, "${HOME}", home), "$HOME", home)
				if path == "~" {
					path = home
				} else if strings.HasPrefix(path, "~/") {
					path = filepath.Join(home, path[2:])
				}
				if !filepath.IsAbs(path) {
					path = filepath.Join(cwd, path)
				}
				if outagePathProtected(path, cwd, home, dataDir) {
					return true
				}
			}
		}
	}
	return false
}

func outageKnownEnvironment(raw map[string]interface{}, inherited map[string]string) map[string]string {
	known := make(map[string]string, len(raw)+len(inherited))
	for key, value := range inherited {
		known[key] = value
	}
	for key, value := range raw {
		if text, ok := value.(string); ok && outageEnvironmentName(key) && !strings.ContainsRune(text, 0) {
			known[key] = text
		}
	}
	return known
}

func outageEnvironmentName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		char := name[i]
		if char != '_' && (char < 'A' || char > 'Z') && (char < 'a' || char > 'z') &&
			(i == 0 || char < '0' || char > '9') {
			return false
		}
	}
	return true
}

// The shared hookpaths writer returns known write targets, including values
// from the tool environment. ActionFacts retains the named path reading for
// commands that identify a protected file without a writer operand.
func outageCommandNamesProtected(command, cwd, home, dataDir string, environment map[string]string) bool {
	if hookpaths.KnownProtectedWriteTarget(command, cwd, home, environment, func(path string) bool {
		return outagePathProtected(path, cwd, home, dataDir)
	}) {
		return true
	}
	facts := actionfacts.Analyze(actionfacts.Input{Tool: "exec", Command: command, CWD: cwd, ActiveHome: home})
	for _, path := range facts.Paths {
		target := path.Resolved
		if target == "" {
			target = path.Normalized
		}
		if target == "" {
			target = path.Value
		}
		if target != "" {
			if !filepath.IsAbs(target) {
				target = filepath.Join(cwd, target)
			}
			if outagePathProtected(target, cwd, home, dataDir) {
				return true
			}
		}
	}
	return false
}

func outagePathProtected(path, cwd, home, dataDir string) bool {
	quoted := "'" + strings.ReplaceAll(path, "'", "'\\''") + "'"
	if runtime.GOOS == "windows" {
		quoted = `"` + path + `"`
	}
	command := "printf x > " + quoted
	return hookpaths.ActionStateTargetMention(command, cwd, home) ||
		hookpaths.ActionCommandDecision(command, cwd, home) == "protected-target" ||
		outageTargetInDataRoot(path, home, dataDir)
}

func outageTargetInDataRoot(target, home, dataDir string) bool {
	if dataDir == "" || filepath.Clean(dataDir) == filepath.Join(home, ".defenseclaw") {
		return false
	}
	root, rootOK := hookpaths.ResolveWriteTarget(dataDir)
	resolved, targetOK := hookpaths.ResolveWriteTarget(target)
	if !rootOK {
		return true
	}
	if !targetOK {
		resolved = filepath.Clean(target)
	}
	relative, err := filepath.Rel(root, resolved)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) &&
		!strings.HasPrefix(relative, "logs"+string(filepath.Separator)) {
		return true
	}
	return false
}
