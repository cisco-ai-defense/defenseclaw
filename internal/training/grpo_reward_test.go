// internal/training/grpo_reward_test.go
package training

import "testing"

func TestRewardFormat_ValidJSON(t *testing.T) {
	specs := []RewardSpec{{Type: "format", Params: map[string]string{"type": "json"}, Weight: 1.0}}
	r := DispatchReward(`{"name": "test"}`, nil, specs)
	if r != 1.0 {
		t.Errorf("expected 1.0, got %f", r)
	}
}

func TestRewardFormat_InvalidJSON(t *testing.T) {
	specs := []RewardSpec{{Type: "format", Params: map[string]string{"type": "json"}, Weight: 1.0}}
	r := DispatchReward(`{invalid`, nil, specs)
	if r != 0.0 {
		t.Errorf("expected 0.0, got %f", r)
	}
}

func TestRewardContains(t *testing.T) {
	specs := []RewardSpec{{Type: "contains", Params: map[string]string{"required": "hello,world"}, Weight: 1.0}}
	r := DispatchReward("hello there", nil, specs)
	if r != 0.5 { // 1 of 2 terms found
		t.Errorf("expected 0.5, got %f", r)
	}
}

func TestRewardComposition(t *testing.T) {
	specs := []RewardSpec{
		{Type: "format", Params: map[string]string{"type": "json"}, Weight: 0.5},
		{Type: "length", Params: map[string]string{"max": "100"}, Weight: 0.5},
	}
	r := DispatchReward(`{"x":1}`, nil, specs)
	// JSON valid (1.0 × 0.5) + length OK (1.0 × 0.5) = 1.0
	if r != 1.0 {
		t.Errorf("expected 1.0, got %f", r)
	}
}
