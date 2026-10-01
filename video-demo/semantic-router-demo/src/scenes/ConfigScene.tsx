import React from "react";
import { useCurrentFrame, interpolate } from "remotion";
import { SceneWrap } from "../components/SceneWrap";
import { Terminal } from "../components/Terminal";

export const ConfigScene: React.FC = () => {
  const frame = useCurrentFrame();
  const durationInFrames = 1200; // frames 450-1649

  // YAML config lines - advanced v0.3 config with signals and decisions
  const yamlLines = [
    { text: "cat defenseclaw.yaml", isCommand: true, delay: 10, color: "#e6edf3" },
    { text: "", delay: 30 },
    { text: "routing:", delay: 35, color: "#f97583" },
    { text: "  enabled: true", delay: 40, color: "#e6edf3" },
    { text: "  version: v0.3", delay: 45, color: "#79c0ff" },
    { text: "  signals:", delay: 52, color: "#f97583" },
    { text: "    embedding:", delay: 58, color: "#d2a8ff" },
    { text: "      - name: intent_classifier", delay: 64, color: "#79c0ff" },
    { text: "        threshold: 0.82", delay: 70, color: "#79c0ff" },
    { text: "        aggregation_method: weighted_mean", delay: 76, color: "#79c0ff" },
    { text: "    domain:", delay: 84, color: "#d2a8ff" },
    { text: "      - name: code_domain", delay: 90, color: "#79c0ff" },
    { text: "        categories: [programming, devops, database]", delay: 96, color: "#79c0ff" },
    { text: "    complexity:", delay: 104, color: "#d2a8ff" },
    { text: "      - name: task_complexity", delay: 110, color: "#79c0ff" },
    { text: "        method: token_analysis", delay: 116, color: "#79c0ff" },
    { text: "    keywords:", delay: 124, color: "#d2a8ff" },
    { text: "      - name: reasoning_cue", delay: 130, color: "#79c0ff" },
    { text: "        keywords: [compare, analyze, tradeoffs]", delay: 136, color: "#79c0ff" },
    { text: "  decisions:", delay: 146, color: "#f97583" },
    { text: "    - name: code_route", delay: 152, color: "#3fb950" },
    { text: "      priority: 100", delay: 158, color: "#79c0ff" },
    { text: "      rules:", delay: 164, color: "#f97583" },
    { text: "        operator: OR", delay: 170, color: "#d29922" },
    { text: "        conditions:", delay: 176, color: "#f97583" },
    { text: "          - type: embedding", delay: 182, color: "#79c0ff" },
    { text: "            name: intent_classifier", delay: 188, color: "#79c0ff" },
    { text: "          - type: domain", delay: 194, color: "#79c0ff" },
    { text: "            name: code_domain", delay: 200, color: "#79c0ff" },
    { text: "      model_refs: [qwen3:4b]", delay: 208, color: "#d2a8ff" },
    { text: "      plugins: [lora:code-adapter]", delay: 214, color: "#d2a8ff" },
    { text: "    - name: reasoning_route", delay: 224, color: "#3fb950" },
    { text: "      priority: 90", delay: 230, color: "#79c0ff" },
    { text: "      rules:", delay: 236, color: "#f97583" },
    { text: "        operator: AND", delay: 242, color: "#d29922" },
    { text: "        conditions:", delay: 248, color: "#f97583" },
    { text: "          - type: keyword", delay: 254, color: "#79c0ff" },
    { text: "            name: reasoning_cue", delay: 260, color: "#79c0ff" },
    { text: "          - type: complexity", delay: 266, color: "#79c0ff" },
    { text: "            name: task_complexity", delay: 272, color: "#79c0ff" },
    { text: "      model_refs: [qwen3:8b]", delay: 280, color: "#d2a8ff" },
    { text: "      plugins: [system_prompt:chain-of-thought]", delay: 286, color: "#d2a8ff" },
    { text: "    - name: cache_hit", delay: 296, color: "#3fb950" },
    { text: "      priority: 200", delay: 302, color: "#79c0ff" },
    { text: "      plugins: [semantic_cache]", delay: 308, color: "#d2a8ff" },
  ];

  // Second terminal: start command (appears after config is shown)
  const startLines = [
    { text: "defenseclaw start", isCommand: true, delay: 0, color: "#e6edf3" },
    { text: "", delay: 25 },
    { text: "[INFO] Loading config v0.3", delay: 35, color: "#8b949e" },
    { text: "[INFO] Semantic Router: 3 signals loaded (embedding, domain, complexity)", delay: 55, color: "#79c0ff" },
    { text: "[INFO] Decision engine: 3 rules (code_route, reasoning_route, cache_hit)", delay: 80, color: "#79c0ff" },
    { text: "[INFO] Plugins: lora, system_prompt, semantic_cache", delay: 105, color: "#d2a8ff" },
    { text: "[INFO] SR sidecar healthy ✓  (classify-only mode)", delay: 135, color: "#3fb950" },
  ];

  // Show start terminal after frame 550 (relative)
  const startTerminalOpacity = interpolate(frame, [550, 570], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  // Label for config section
  const configLabelOpacity = interpolate(frame, [5, 20], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  return (
    <SceneWrap durationInFrames={durationInFrames}>
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          height: "100%",
          padding: "40px 80px",
          gap: 24,
        }}
      >
        {/* Section label */}
        <div
          style={{
            opacity: configLabelOpacity,
            fontFamily: "'Inter', system-ui, sans-serif",
            fontSize: 28,
            fontWeight: 600,
            color: "#58a6ff",
            marginBottom: 8,
          }}
        >
          Configuration — v0.3 Signal Fusion
        </div>

        {/* YAML Config Terminal */}
        <Terminal
          lines={yamlLines}
          title="defenseclaw.yaml"
          startFrame={0}
          typingSpeed={1}
          style={{ flex: 1, maxHeight: frame > 550 ? "55%" : "85%" }}
        />

        {/* Start Command Terminal */}
        <div style={{ opacity: startTerminalOpacity, flex: 1 }}>
          <Terminal
            lines={startLines}
            title="terminal"
            startFrame={570}
            typingSpeed={2}
            style={{ height: "100%" }}
          />
        </div>
      </div>
    </SceneWrap>
  );
};
