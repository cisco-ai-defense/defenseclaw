// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// The agent's MCP entry for a bridged server (B3.3, T6 ruling 1): written in
// the agent's user-scope configuration inside the actor when the stream
// opens and removed when it ends, never in the managed settings (those are
// the kit's hooks). An entry of the same name that is not the relay's is
// left as it is and the bridge is not configured.

// mcpEntryWriter adds (add) or removes the entry NAME -> argv in file.
type mcpEntryWriter func(file, name string, argv []string, add bool) error

// mcpConnectorConfig is the user-scope MCP configuration of each connector
// with a bridge entry: its file under the agent's home and its writer.
var mcpConnectorConfig = map[string]struct {
	file  func(s *Server, home string) string
	write mcpEntryWriter
}{
	"claudecode": {func(s *Server, home string) string {
		if f := s.opts.Config.Relay.ClaudeStateFile; f != "" {
			return f
		}
		return filepath.Join(home, ".claude.json")
	}, jsonMCPEntry("mcpServers", func(argv []string) any {
		return map[string]any{"type": "stdio", "command": argv[0], "args": toAny(argv[1:])}
	})},
	"opencode": {func(_ *Server, home string) string {
		return filepath.Join(home, ".config", "opencode", "opencode.json")
	}, jsonMCPEntry("mcp", func(argv []string) any {
		return map[string]any{"type": "local", "command": toAny(argv), "enabled": true}
	})},
	"codex": {func(_ *Server, home string) string {
		return filepath.Join(home, ".codex", "config.toml")
	}, codexMCPEntry},
}

// mcpConfigure writes (add) or removes the agent's entry for name, with the
// agent's file permissions. Edits are serialised: two bridges share a file.
func (s *Server) mcpConfigure(home, name string, add bool) error {
	cc, ok := mcpConnectorConfig[s.opts.Config.Relay.Connector]
	if !ok {
		return fmt.Errorf("no MCP configuration is written for connector %q", s.opts.Config.Relay.Connector)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	argv := []string{exe, "mcp-stdio", name}
	s.mcpCfgMu.Lock()
	defer s.mcpCfgMu.Unlock()
	file := cc.file(s, home)
	run := func() { err = cc.write(file, name, argv, add) }
	if !s.opts.sep.withAgentFS(run) {
		return errors.New("relay: the agent's identity could not be taken")
	}
	return err
}

func toAny(v []string) []any {
	out := make([]any, len(v))
	for i, s := range v {
		out[i] = s
	}
	return out
}

// jsonMCPEntry edits the object key of a JSON configuration file.
func jsonMCPEntry(key string, entry func(argv []string) any) mcpEntryWriter {
	return func(file, name string, argv []string, add bool) error {
		return editJSONDoc(file, "mcp config", func(doc map[string]any) bool {
			servers, _ := doc[key].(map[string]any)
			cur, exists := servers[name]
			ours := exists && isRelayMCPEntry(cur, argv)
			if !add {
				if !ours {
					return false
				}
				delete(servers, name)
				if len(servers) == 0 {
					delete(doc, key)
				}
				return true
			}
			if exists && !ours {
				return false
			}
			if servers == nil {
				servers = map[string]any{}
			}
			servers[name] = entry(argv)
			doc[key] = servers
			return !ours
		})
	}
}

// isRelayMCPEntry reports whether v is the entry the relay writes for argv
// (the argv strings appear in order under command/args).
func isRelayMCPEntry(v any, argv []string) bool {
	m, _ := v.(map[string]any)
	if m == nil {
		return false
	}
	var got []string
	add := func(x any) {
		switch t := x.(type) {
		case string:
			got = append(got, t)
		case []any:
			for _, e := range t {
				s, _ := e.(string)
				got = append(got, s)
			}
		}
	}
	add(m["command"])
	add(m["args"])
	return slices.Equal(got, argv)
}

// codexMCPEntry edits [mcp_servers.NAME] in Codex's config.toml as one
// marked block of lines, so the rest of the file stays byte for byte.
func codexMCPEntry(file, name string, argv []string, add bool) error {
	raw, err := readConfigFile(file)
	if err != nil {
		return err
	}
	begin := "# defenseclaw mcp bridge " + name + " (begin)\n"
	end := "# defenseclaw mcp bridge " + name + " (end)\n"
	i := bytes.Index(raw, []byte(begin))
	j := -1
	if i >= 0 {
		if k := bytes.Index(raw[i:], []byte(end)); k >= 0 {
			j = i + k + len(end)
		}
	}
	if !add {
		if i < 0 || j < 0 {
			return nil
		}
		return writeConfigFile(file, append(raw[:i:i], raw[j:]...))
	}
	if i >= 0 && j >= 0 {
		return nil
	}
	header := "[mcp_servers." + name + "]"
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.ReplaceAll(strings.TrimSpace(l), " ", "") == header {
			return fmt.Errorf("mcp config: %s already has %s", file, header)
		}
	}
	args := make([]string, len(argv)-1)
	for k, a := range argv[1:] {
		args[k] = strconv.Quote(a)
	}
	var b bytes.Buffer
	b.Write(raw)
	if len(raw) > 0 && !bytes.HasSuffix(raw, []byte("\n")) {
		b.WriteByte('\n')
	}
	b.WriteString(begin + header + "\ncommand = " + strconv.Quote(argv[0]) + "\nargs = [" + strings.Join(args, ", ") + "]\n" + end)
	return writeConfigFile(file, b.Bytes())
}

// readConfigFile reads a regular file of at most claudeStateMaxBytes; a
// missing file is empty.
func readConfigFile(file string) ([]byte, error) {
	fi, err := os.Lstat(file)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, err
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("%s is not a regular file", file)
	case fi.Size() > claudeStateMaxBytes:
		return nil, fmt.Errorf("%s is larger than %d bytes", file, claudeStateMaxBytes)
	}
	return os.ReadFile(file)
}

// writeConfigFile replaces file (0600) through a temporary file beside it.
func writeConfigFile(file string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), "."+filepath.Base(file)+".dc-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), file)
}
