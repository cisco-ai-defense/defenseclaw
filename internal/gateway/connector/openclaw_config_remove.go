// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"reflect"

	"github.com/defenseclaw/defenseclaw/internal/jsonc"
)

// openClawRemoval says which of DefenseClaw's settings to take out of
// openclaw.json: its plugin registration (allow list, entry, load path)
// and/or the approvals.plugin block an earlier setup --human-approval wrote.
type openClawRemoval struct {
	registration bool
	approvals    bool
	// conversationGrant also takes hooks.allowConversationAccess (when it is
	// true) out of the defenseclaw entry: setup wrote it, the operator did not
	// (GAP-0986). keepEmptyHooks leaves an emptied hooks object in place
	// because the operator had one before setup.
	conversationGrant bool
	keepEmptyHooks    bool
}

// removeDefenseClawFromConfig takes the settings in scope out of a parsed
// openclaw.json. It touches only keys that are already there.
func removeDefenseClawFromConfig(cfg map[string]interface{}, scope openClawRemoval) {
	if scope.registration {
		if plugins, ok := cfg["plugins"].(map[string]interface{}); ok {
			if _, ok := plugins["allow"].([]interface{}); ok {
				plugins["allow"] = removeString(plugins["allow"], "defenseclaw")
			}
			if entries, ok := plugins["entries"].(map[string]interface{}); ok {
				removeDefenseClawEntryKeys(entries, scope)
			}
			if load, ok := plugins["load"].(map[string]interface{}); ok {
				if _, ok := load["paths"].([]interface{}); ok {
					load["paths"] = removeDefenseClawLoadPaths(load["paths"])
				}
			}
		}
	}
	if scope.approvals {
		dropDefenseClawPluginApprovals(cfg)
	}
}

// removeFromOpenClawConfig returns the text of openclaw.json with the
// DefenseClaw settings in scope taken out, or nil when none of them is there.
// openclaw.json is the operator's JSON5 file: a teardown that removes nothing
// leaves it byte for byte, and one that removes something cuts only those
// members out of the text, so comments, quoting and key order stay
// (GAP-0937). The cut text is read back and must equal the parsed file with
// the settings removed; if it does not, no byte is written and the error
// names the file and the keys to remove by hand.
func removeFromOpenClawConfig(configPath string, data []byte, scope openClawRemoval) ([]byte, error) {
	before, err := parseOpenClawConfig(configPath, data)
	if err != nil {
		return nil, err
	}
	want, err := parseOpenClawConfig(configPath, data)
	if err != nil {
		return nil, err
	}
	removeDefenseClawFromConfig(want, scope)
	if reflect.DeepEqual(before, want) {
		return nil, nil
	}
	out := data
	for {
		doc, err := jsonc.Parse(out)
		if err != nil {
			return nil, openClawEditError(configPath, err)
		}
		spans := nextDefenseClawRemoval(doc, out, scope)
		if spans == nil {
			break
		}
		out = jsonc.Apply(out, spans)
	}
	got, err := parseOpenClawConfig(configPath, out)
	if err != nil || !reflect.DeepEqual(got, want) {
		return nil, openClawEditError(configPath, err)
	}
	return out, nil
}

func openClawEditError(configPath string, cause error) error {
	msg := fmt.Sprintf("%s: could not take the DefenseClaw settings out without rewriting the file; "+
		"remove \"defenseclaw\" from plugins.allow, plugins.entries and plugins.load.paths (and approvals.plugin if you set up human approval) by hand",
		configPath)
	if cause != nil {
		return fmt.Errorf("%s: %w", msg, cause)
	}
	return fmt.Errorf("%s", msg)
}

// nextDefenseClawRemoval returns the text ranges that drop the first
// DefenseClaw setting still in the document, or nil when none is left. It
// mirrors removeDefenseClawFromConfig on the located text; the caller repeats
// it until nothing is left and then checks the two agree.
func nextDefenseClawRemoval(doc *jsonc.Value, data []byte, scope openClawRemoval) []jsonc.Span {
	if scope.registration {
		if plugins := childValue(doc, "plugins"); plugins != nil && plugins.Object {
			if allow := childValue(plugins, "allow"); allow != nil && allow.Array {
				for i, el := range allow.Children {
					var s string
					if jsonc.UnmarshalJSON5(data[el.Value.Start:el.Value.End], &s) == nil && s == "defenseclaw" {
						return allow.RemoveChild(data, i)
					}
				}
			}
			if entries := childValue(plugins, "entries"); entries != nil && entries.Object {
				if i, ok := entries.Lookup("defenseclaw"); ok {
					entry := entries.Children[i].Value
					switch {
					case !entry.Object || len(entry.Children) == 0:
						return entries.RemoveChild(data, i)
					default:
						if j, ok := entry.Lookup("enabled"); ok {
							return entry.RemoveChild(data, j)
						}
						if spans := removeHookModeSpans(entry, data); spans != nil {
							return spans
						}
						if scope.conversationGrant {
							if spans := removeConversationGrantSpans(entry, data, scope.keepEmptyHooks); spans != nil {
								return spans
							}
						}
					}
				}
			}
			if load := childValue(plugins, "load"); load != nil && load.Object {
				if paths := childValue(load, "paths"); paths != nil && paths.Array {
					for i, el := range paths.Children {
						var v interface{}
						if jsonc.UnmarshalJSON5(data[el.Value.Start:el.Value.End], &v) == nil && isDefenseClawLoadPath(v) {
							return paths.RemoveChild(data, i)
						}
					}
				}
			}
		}
	}
	if scope.approvals {
		if approvals := childValue(doc, "approvals"); approvals != nil && approvals.Object {
			if i, ok := approvals.Lookup("plugin"); ok {
				var plugin map[string]interface{}
				if jsonc.UnmarshalJSON5(data[approvals.Children[i].Value.Start:approvals.Children[i].Value.End], &plugin) == nil && isDefenseClawPluginApprovals(plugin) {
					var all map[string]interface{}
					if jsonc.UnmarshalJSON5(data[approvals.Start:approvals.End], &all) == nil && len(all) == 1 {
						k, _ := doc.Lookup("approvals")
						return doc.RemoveChild(data, k)
					}
					return approvals.RemoveChild(data, i)
				}
			}
		}
	}
	return nil
}

// removeConversationGrantSpans returns the text ranges that drop
// hooks.allowConversationAccess from a defenseclaw entry when it is true, and
// the hooks object with it when nothing else is in it (unless keepEmptyHooks).
// It mirrors removeDefenseClawConversationGrant on the located text.
func removeConversationGrantSpans(entry *jsonc.Value, data []byte, keepEmptyHooks bool) []jsonc.Span {
	hooks := childValue(entry, "hooks")
	if hooks == nil || !hooks.Object {
		return nil
	}
	g, ok := hooks.Lookup("allowConversationAccess")
	if !ok {
		return nil
	}
	var granted bool
	value := hooks.Children[g].Value
	if jsonc.UnmarshalJSON5(data[value.Start:value.End], &granted) != nil || !granted {
		return nil
	}
	if len(hooks.Children) == 1 && !keepEmptyHooks {
		k, _ := entry.Lookup("hooks")
		return entry.RemoveChild(data, k)
	}
	return hooks.RemoveChild(data, g)
}

// childValue is the value of the member of obj named key, or nil.
func childValue(obj *jsonc.Value, key string) *jsonc.Value {
	if i, ok := obj.Lookup(key); ok {
		return obj.Children[i].Value
	}
	return nil
}

// removeHookModeSpans returns the text ranges that drop config.hookMode
// (setup writes it) from a defenseclaw entry, and the config object with it
// when nothing else is in it. It mirrors removeDefenseClawHookMode.
func removeHookModeSpans(entry *jsonc.Value, data []byte) []jsonc.Span {
	cfg := childValue(entry, "config")
	if cfg == nil || !cfg.Object {
		return nil
	}
	i, ok := cfg.Lookup(openClawHookModeKey)
	if !ok {
		return nil
	}
	if len(cfg.Children) == 1 {
		k, _ := entry.Lookup("config")
		return entry.RemoveChild(data, k)
	}
	return cfg.RemoveChild(data, i)
}
