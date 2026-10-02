package hwprofile

import (
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// DetectAll probes hardware and returns a classified SystemProfile.
func DetectAll() *SystemProfile {
	p := &SystemProfile{
		Platform: runtime.GOOS,
		Arch:     runtime.GOARCH,
	}
	detectCPU(p)
	detectRAM(p)
	detectGPUs(p)
	classifyTier(p)
	return p
}

func detectGPUs(p *SystemProfile) {
	var mu sync.Mutex
	var wg sync.WaitGroup

	type detector struct {
		name string
		fn   func() []GpuInfo
	}
	detectors := []detector{
		{"nvidia", detectNVIDIA},
		{"amd", detectAMD},
		{"apple", detectAppleSilicon},
		{"intel", detectIntel},
	}

	for _, d := range detectors {
		wg.Add(1)
		go func(det detector) {
			defer wg.Done()
			gpus := det.fn()
			mu.Lock()
			p.GPUs = append(p.GPUs, gpus...)
			mu.Unlock()
		}(d)
	}
	wg.Wait()

	// Deduplicate and sort by VRAM descending
	seen := map[string]bool{}
	var unique []GpuInfo
	for _, g := range p.GPUs {
		key := g.Name + g.Backend
		if seen[key] {
			continue
		}
		seen[key] = true
		if g.VRAMTotalGB == 0 {
			g.VRAMTotalGB = estimateVRAMFromName(g.Name)
		}
		unique = append(unique, g)
	}
	sort.Slice(unique, func(i, j int) bool {
		return unique[i].VRAMTotalGB > unique[j].VRAMTotalGB
	})
	p.GPUs = unique
	p.HasGPU = len(p.GPUs) > 0
	for _, g := range p.GPUs {
		if g.UnifiedMemory {
			p.UnifiedMemory = true
		}
		p.TotalGPUVRAMGB += g.VRAMTotalGB
	}
}

// detectNVIDIA uses nvidia-smi to query NVIDIA GPUs.
func detectNVIDIA() []GpuInfo {
	out, err := exec.Command("nvidia-smi",
		"--query-gpu=name,memory.total",
		"--format=csv,noheader,nounits").Output()
	if err != nil {
		return nil
	}
	var gpus []GpuInfo
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.SplitN(line, ",", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		vramMB, _ := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		gpus = append(gpus, GpuInfo{
			Name:        name,
			VRAMTotalGB: vramMB / 1024.0,
			Backend:     "cuda",
		})
	}
	return gpus
}

// detectAMD uses rocm-smi to query AMD GPUs.
func detectAMD() []GpuInfo {
	out, err := exec.Command("rocm-smi", "--showmeminfo", "vram", "--csv").Output()
	if err != nil {
		return nil
	}
	nameOut, _ := exec.Command("rocm-smi", "--showproductname", "--csv").Output()
	names := parseCSVColumn(string(nameOut), "Card Series")

	var gpus []GpuInfo
	vrams := parseCSVColumn(string(out), "VRAM Total Memory (B)")
	for i, vStr := range vrams {
		vBytes, _ := strconv.ParseFloat(vStr, 64)
		name := "AMD GPU"
		if i < len(names) {
			name = names[i]
		}
		gpus = append(gpus, GpuInfo{
			Name:        name,
			VRAMTotalGB: vBytes / (1024 * 1024 * 1024),
			Backend:     "rocm",
		})
	}
	return gpus
}

// detectIntel checks lspci for Intel Arc GPUs.
func detectIntel() []GpuInfo {
	out, err := exec.Command("lspci").Output()
	if err != nil {
		return nil
	}
	var gpus []GpuInfo
	for _, line := range strings.Split(string(out), "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "vga") && strings.Contains(lower, "intel") && strings.Contains(lower, "arc") {
			name := extractAfter(line, ":")
			gpus = append(gpus, GpuInfo{
				Name:    strings.TrimSpace(name),
				Backend: "vulkan",
			})
		}
	}
	return gpus
}

func parseCSVColumn(csv, colName string) []string {
	lines := strings.Split(strings.TrimSpace(csv), "\n")
	if len(lines) < 2 {
		return nil
	}
	headers := strings.Split(lines[0], ",")
	idx := -1
	for i, h := range headers {
		if strings.TrimSpace(h) == colName {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil
	}
	var values []string
	for _, line := range lines[1:] {
		cols := strings.Split(line, ",")
		if idx < len(cols) {
			values = append(values, strings.TrimSpace(cols[idx]))
		}
	}
	return values
}

func extractAfter(s, sep string) string {
	if idx := strings.Index(s, sep); idx >= 0 {
		return s[idx+len(sep):]
	}
	return s
}
