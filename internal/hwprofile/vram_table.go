package hwprofile

import "strings"

// vramTable maps GPU name substrings (lowercase) to known VRAM in GB.
// Used as a fallback when the driver doesn't report memory.
var vramTable = map[string]float64{
	// NVIDIA Consumer
	"rtx 4060":     8, "rtx 4060 ti": 8, "rtx 4070": 12, "rtx 4070 ti": 12,
	"rtx 4080":     16, "rtx 4090": 24,
	"rtx 5060":     12, "rtx 5070": 12, "rtx 5070 ti": 16,
	"rtx 5080":     16, "rtx 5090": 32,
	"rtx 3060":     12, "rtx 3070": 8, "rtx 3080": 10, "rtx 3090": 24,
	"rtx 2060":     6, "rtx 2070": 8, "rtx 2080": 8, "rtx 2080 ti": 11,
	"gtx 1660":     6, "gtx 1070": 8, "gtx 1080": 8, "gtx 1080 ti": 11,
	// NVIDIA Professional
	"a6000":  48, "a5000": 24, "a4000": 16, "a2000": 6,
	"a100":   80, "a100 40gb": 40, "a30": 24, "a10": 24, "a16": 16,
	"h100":   80, "h200": 141, "h20": 96, "b100": 192, "b200": 192,
	"t4":     16, "l4": 24, "l40": 48, "l40s": 48,
	"v100":   16, "v100 32gb": 32, "p100": 16, "p40": 24,
	"rtx 6000 ada": 48, "rtx 5880 ada": 48, "rtx 4000 ada": 20,
	// AMD
	"rx 7900 xtx": 24, "rx 7900 xt": 20, "rx 7800 xt": 16, "rx 7600": 8,
	"rx 9070 xt":  16, "rx 9070": 12,
	"mi300x":      192, "mi250x": 128, "mi210": 64, "mi100": 32,
	"w7900":       48, "w7800": 32, "w6800": 32,
	// Intel
	"arc a770": 16, "arc a750": 8, "arc a580": 8,
	"arc b580": 12, "arc b570": 10,
	// Apple Silicon (unified memory — these are the GPU chip names)
	"apple m1":       16, "apple m1 pro": 16, "apple m1 max": 32, "apple m1 ultra": 64,
	"apple m2":       24, "apple m2 pro": 32, "apple m2 max": 96, "apple m2 ultra": 192,
	"apple m3":       24, "apple m3 pro": 36, "apple m3 max": 128, "apple m3 ultra": 192,
	"apple m4":       32, "apple m4 pro": 48, "apple m4 max": 128, "apple m4 ultra": 256,
	// NVIDIA Jetson
	"jetson orin nano": 4, "jetson orin nx": 8, "jetson agx orin": 32,
}

// estimateVRAMFromName returns estimated VRAM for a GPU name using the lookup table.
// Returns 0 if no match found.
func estimateVRAMFromName(name string) float64 {
	lower := strings.ToLower(name)
	// Try exact substring matches, longest first for specificity
	var bestMatch string
	var bestVRAM float64
	for pattern, vram := range vramTable {
		if strings.Contains(lower, pattern) && len(pattern) > len(bestMatch) {
			bestMatch = pattern
			bestVRAM = vram
		}
	}
	return bestVRAM
}
