// internal/training/grpo_reward.go
package training

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DispatchReward computes the weighted sum of all reward functions.
func DispatchReward(completion string, metadata map[string]string, specs []RewardSpec) float64 {
	if len(specs) == 0 {
		return 0.0
	}
	totalWeight := 0.0
	weightedSum := 0.0
	for _, spec := range specs {
		score := evaluateReward(completion, metadata, spec)
		weightedSum += score * spec.Weight
		totalWeight += spec.Weight
	}
	if totalWeight == 0 {
		return 0.0
	}
	return weightedSum / totalWeight
}

func evaluateReward(completion string, metadata map[string]string, spec RewardSpec) float64 {
	switch spec.Type {
	case "format":
		return rewardFormat(completion, spec.Params)
	case "regex":
		return rewardRegex(completion, spec.Params)
	case "contains":
		return rewardContains(completion, spec.Params)
	case "length":
		return rewardLength(completion, spec.Params)
	case "ground_truth":
		return rewardGroundTruth(completion, metadata, spec.Params)
	case "exec":
		return rewardExec(completion, spec.Params)
	default:
		return 0.0
	}
}

func rewardFormat(completion string, params map[string]string) float64 {
	switch params["type"] {
	case "json":
		var v interface{}
		if json.Unmarshal([]byte(completion), &v) == nil {
			return 1.0
		}
		return 0.0
	case "yaml":
		// Simple heuristic: no JSON parse error alternative
		if strings.Contains(completion, ":") && !strings.HasPrefix(completion, "{") {
			return 1.0
		}
		return 0.0
	}
	return 0.0
}

func rewardRegex(completion string, params map[string]string) float64 {
	pattern := params["pattern"]
	if pattern == "" {
		return 0.0
	}
	matched, err := regexp.MatchString(pattern, completion)
	if err != nil || !matched {
		return 0.0
	}
	return 1.0
}

func rewardContains(completion string, params map[string]string) float64 {
	required := strings.Split(params["required"], ",")
	if len(required) == 0 {
		return 0.0
	}
	found := 0
	for _, term := range required {
		if strings.Contains(completion, strings.TrimSpace(term)) {
			found++
		}
	}
	return float64(found) / float64(len(required))
}

func rewardLength(completion string, params map[string]string) float64 {
	words := len(strings.Fields(completion))
	minLen, _ := strconv.Atoi(params["min"])
	maxLen, _ := strconv.Atoi(params["max"])
	if maxLen == 0 {
		maxLen = 10000
	}
	if words >= minLen && words <= maxLen {
		return 1.0
	}
	if words < minLen {
		return float64(words) / float64(minLen)
	}
	// Over max: linear penalty
	over := float64(words-maxLen) / float64(maxLen)
	r := 1.0 - over
	if r < 0 {
		return 0.0
	}
	return r
}

func rewardGroundTruth(completion string, metadata map[string]string, params map[string]string) float64 {
	field := params["field"]
	if field == "" {
		field = "ground_truth"
	}
	expected := ""
	if metadata != nil {
		expected = metadata[field]
	}
	if expected == "" {
		return 0.0
	}
	if strings.TrimSpace(completion) == strings.TrimSpace(expected) {
		return 1.0
	}
	if strings.Contains(completion, expected) {
		return 0.5
	}
	return 0.0
}

func rewardExec(completion string, params map[string]string) float64 {
	timeout := 10
	if t, err := strconv.Atoi(params["timeout"]); err == nil {
		timeout = t
	}
	lang := params["lang"]
	if lang == "" {
		lang = "python"
	}

	var cmd *exec.Cmd
	switch lang {
	case "python":
		cmd = exec.Command("python3", "-c", completion)
	case "bash":
		cmd = exec.Command("bash", "-c", completion)
	default:
		return 0.0
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case err := <-done:
		if err == nil {
			return 1.0
		}
		return 0.0
	case <-time.After(time.Duration(timeout) * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return 0.0
	}
}

// FormatProgress returns a human-readable progress string.
func (s GrpoStats) FormatProgress(totalSteps int) string {
	return fmt.Sprintf("step %d/%d, reward=%.3f, loss=%.4f",
		s.Steps, totalSteps, s.LastRewardMean, s.LastLoss)
}
