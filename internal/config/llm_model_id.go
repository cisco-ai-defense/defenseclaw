// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"
)

// Full ids of the Bedrock models the setup llm short names stand for
// (cli/defenseclaw/commands/cmd_setup.py _BEDROCK_SHORT_MODEL_NAMES).
const (
	bedrockHaiku45ModelID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
	bedrockLunaModelID    = "us.openai.gpt-5.6-luna"
)

var bedrockShortModelNames = map[string]string{
	"haiku-4.5": bedrockHaiku45ModelID, "haiku-4-5": bedrockHaiku45ModelID,
	"claude-haiku-4.5": bedrockHaiku45ModelID, "claude-haiku-4-5": bedrockHaiku45ModelID,
	"luna": bedrockLunaModelID, "gpt-5.6-luna": bedrockLunaModelID,
}

// unprefixedOpenAIModelPrefixes are the OpenAI model names the gateway
// routes to OpenAI by default (inferProvider: an unprefixed model that is
// not a Bedrock id, claude* or gemini*).
var unprefixedOpenAIModelPrefixes = []string{"gpt-", "o1", "o3", "o4", "chatgpt-", "text-", "codex-", "computer-use-"}

// ModelIDProblem says why the model of l, read at key (for example
// "llm.model"), is not a model id the gateway can route, or "" when it is
// empty, names a custom-providers instance, or looks routable (GAP-0172).
// setup llm refuses such a value before it saves it (GAP-2638); a managed
// config arrives from an MDM or a file, so the lifecycle warns instead and
// the judge falls back to the rules on every call until it is fixed.
//
// It flags only what the gateway is known to get wrong: a model for
// Bedrock (llm.provider bedrock or a bedrock/ prefix) that is not a Bedrock
// id, an ARN or a deployment alias, and an unprefixed model with no
// llm.provider that the gateway would send to OpenAI although it is no
// OpenAI model name (a nickname such as "luna", or "not-a-model").
func (l LLMConfig) ModelIDProblem(key string) string {
	model := strings.TrimSpace(l.Model)
	if model == "" || strings.TrimSpace(l.InstanceName) != "" {
		return ""
	}
	provider := strings.ToLower(strings.TrimSpace(l.Provider))
	bare := model
	// An ARN carries slashes of its own and no provider prefix.
	if prefix, rest, found := strings.Cut(model, "/"); found && prefix != "" && !strings.HasPrefix(model, "arn:") {
		if provider == "" {
			provider = strings.ToLower(prefix)
		}
		bare = rest
	}
	expected := "write it as provider/model or a full Amazon Bedrock id, for example bedrock/" + bedrockHaiku45ModelID +
		", " + bedrockLunaModelID + " or anthropic/" + "claude-sonnet-5-5"
	hint := ""
	if full, ok := bedrockShortModelNames[strings.ToLower(strings.TrimSpace(bare))]; ok {
		hint = fmt.Sprintf(" (%q is the short name of %s)", bare, full)
	}
	switch provider {
	case "bedrock", "amazon-bedrock":
		if IsBedrockModelID(bare) || strings.HasPrefix(bare, "arn:") {
			return ""
		}
		if l.Bedrock != nil {
			if _, ok := l.Bedrock.DeploymentAliases[bare]; ok {
				return ""
			}
		}
		return fmt.Sprintf("%s %q is not an Amazon Bedrock model id%s, so the LLM judge cannot call it and falls back to the rules on every call; "+
			"give the full model id or inference profile, for example %s or %s", key, model, hint, bedrockHaiku45ModelID, bedrockLunaModelID)
	case "":
		lower := strings.ToLower(bare)
		if IsBedrockModelID(bare) || strings.HasPrefix(lower, "claude") || strings.HasPrefix(lower, "gemini") {
			return ""
		}
		for _, prefix := range unprefixedOpenAIModelPrefixes {
			if strings.HasPrefix(lower, prefix) {
				return ""
			}
		}
		return fmt.Sprintf("%s %q names no provider and is not a model id DefenseClaw recognizes%s; the gateway sends it to OpenAI as written, "+
			"so the LLM judge falls back to the rules on every call; %s", key, model, hint, expected)
	}
	return ""
}
