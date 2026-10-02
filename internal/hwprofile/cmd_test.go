package hwprofile

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestDetectAll(t *testing.T) {
	p := DetectAll()
	data, _ := json.MarshalIndent(p, "", "  ")
	fmt.Println(string(data))

	if p.Platform == "" {
		t.Error("platform not detected")
	}
	if p.CPUCores == 0 {
		t.Error("CPU cores not detected")
	}
	if p.TotalRAMGB == 0 {
		t.Error("RAM not detected")
	}
	if p.HardwareTier == "" {
		t.Error("hardware tier not classified")
	}
	t.Logf("Tier: %s, RAM: %.0fGB, GPU VRAM: %.0fGB, Unified: %v",
		p.HardwareTier, p.TotalRAMGB, p.TotalGPUVRAMGB, p.UnifiedMemory)
}
