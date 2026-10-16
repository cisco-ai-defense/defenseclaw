import React from "react";
import { useCurrentFrame, interpolate, spring, useVideoConfig } from "remotion";
import { SceneWrap } from "../components/SceneWrap";
import { Terminal } from "../components/Terminal";

const Badge: React.FC<{
  text: string;
  color: string;
  opacity: number;
  scale: number;
}> = ({ text, color, opacity, scale }) => (
  <div
    style={{
      opacity,
      transform: `scale(${scale})`,
      display: "inline-block",
      padding: "6px 16px",
      borderRadius: 20,
      backgroundColor: `${color}22`,
      border: `1px solid ${color}`,
      color,
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: 14,
      fontWeight: 600,
      marginTop: 8,
    }}
  >
    {text}
  </div>
);

export const LiveRoutingScene: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const durationInFrames = 2700; // frames 1650-4349

  // --- Request 1: Embedding-based routing (frames 0-900 relative) ---
  const req1Lines = [
    {
      text: 'curl -s http://localhost/v1/chat/completions \\',
      isCommand: true,
      delay: 30,
      color: "#e6edf3",
    },
    {
      text: '  -H "Content-Type: application/json" \\',
      delay: 60,
      color: "#8b949e",
    },
    {
      text: '  -d \'{"model":"auto","messages":[{"role":"user",',
      delay: 90,
      color: "#8b949e",
    },
    {
      text: '  "content":"optimize this SQL query with better indexing"}]}\'',
      delay: 120,
      color: "#79c0ff",
    },
    { text: "", delay: 200 },
    { text: "HTTP/1.1 200 OK", delay: 220, color: "#3fb950" },
    { text: "X-Semantic-Router: routed", delay: 240, color: "#58a6ff" },
    { text: "X-SR-Signal: embedding/intent_classifier (score: 0.91)", delay: 260, color: "#58a6ff" },
    { text: "X-SR-Decision: code_route", delay: 280, color: "#58a6ff" },
    { text: "X-SR-Model: qwen3:4b", delay: 300, color: "#d2a8ff" },
    { text: "X-SR-Plugin: lora:code-adapter activated", delay: 320, color: "#bc8cff" },
    { text: "", delay: 350 },
    { text: '{"choices":[{"message":{"content":"To optimize your query..."}}]}', delay: 370, color: "#e6edf3" },
  ];

  // --- Request 2: Multi-signal fusion (frames 900-1800 relative) ---
  const req2Lines = [
    {
      text: 'curl -s http://localhost/v1/chat/completions \\',
      isCommand: true,
      delay: 30,
      color: "#e6edf3",
    },
    {
      text: '  -d \'{"model":"auto","messages":[{"role":"user",',
      delay: 60,
      color: "#8b949e",
    },
    {
      text: '  "content":"step by step, compare React vs Vue for a large',
      delay: 90,
      color: "#79c0ff",
    },
    {
      text: '  SaaS dashboard with 50+ components"}]}\'',
      delay: 120,
      color: "#79c0ff",
    },
    { text: "", delay: 200 },
    { text: "HTTP/1.1 200 OK", delay: 220, color: "#3fb950" },
    { text: "X-Semantic-Router: routed", delay: 240, color: "#d29922" },
    { text: "X-SR-Signal: keyword/reasoning_cue + complexity/high (AND)", delay: 260, color: "#d29922" },
    { text: "X-SR-Decision: reasoning_route", delay: 280, color: "#d29922" },
    { text: "X-SR-Model: qwen3:8b", delay: 300, color: "#d2a8ff" },
    { text: "X-SR-Plugin: system_prompt:chain-of-thought injected", delay: 320, color: "#d29922" },
    { text: "", delay: 350 },
    { text: '{"choices":[{"message":{"content":"<think>Let me analyze..."}}]}', delay: 370, color: "#e6edf3" },
  ];

  // --- Request 3: Semantic cache hit (frames 1800-2700 relative) ---
  const req3Lines = [
    {
      text: 'curl -s http://localhost/v1/chat/completions \\',
      isCommand: true,
      delay: 30,
      color: "#e6edf3",
    },
    {
      text: '  -d \'{"model":"auto","messages":[{"role":"user",',
      delay: 60,
      color: "#8b949e",
    },
    {
      text: '  "content":"optimize this SQL query with better indexing"}]}\'',
      delay: 90,
      color: "#79c0ff",
    },
    { text: "", delay: 170 },
    { text: "HTTP/1.1 200 OK", delay: 190, color: "#3fb950" },
    { text: "X-Semantic-Router: cache-hit", delay: 210, color: "#3fb950" },
    { text: "X-SR-Signal: semantic_cache (similarity: 0.98)", delay: 230, color: "#3fb950" },
    { text: "X-SR-Latency: 2ms (vs avg 1200ms)", delay: 250, color: "#3fb950" },
    { text: "", delay: 280 },
    { text: '{"choices":[{"message":{"content":"To optimize your query..."}}]}', delay: 300, color: "#e6edf3" },
  ];

  // Badge animations for Request 1 (appear after response shown ~frame 420)
  const badge1Opacity = interpolate(frame, [420, 440], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const badge1Scale = Math.max(
    0,
    spring({ frame: frame - 420, fps, config: { damping: 12 } })
  );

  // Badge animations for Request 2 (appear after response ~frame 1320)
  const badge2Opacity = interpolate(frame, [1320, 1340], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const badge2Scale = Math.max(
    0,
    spring({ frame: frame - 1320, fps, config: { damping: 12 } })
  );

  // Badge animations for Request 3 (appear after response ~frame 2150)
  const badge3Opacity = interpolate(frame, [2150, 2170], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const badge3Scale = Math.max(
    0,
    spring({ frame: frame - 2150, fps, config: { damping: 12 } })
  );

  // Section transitions
  const req1Opacity = interpolate(frame, [0, 15, 850, 900], [0, 1, 1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const req2Opacity = interpolate(frame, [900, 950, 1750, 1800], [0, 1, 1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const req3Opacity = interpolate(frame, [1800, 1850, 2650, 2700], [0, 1, 1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  // Section label
  const labelOpacity = interpolate(frame, [0, 15], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  // Request number indicator
  const getRequestLabel = (): string => {
    if (frame < 900) return "Request 1 of 3 — Embedding Match";
    if (frame < 1800) return "Request 2 of 3 — Multi-Signal Fusion";
    return "Request 3 of 3 — Semantic Cache Hit";
  };

  return (
    <SceneWrap durationInFrames={durationInFrames}>
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          height: "100%",
          padding: "40px 80px",
        }}
      >
        {/* Section label */}
        <div
          style={{
            opacity: labelOpacity,
            fontFamily: "'Inter', system-ui, sans-serif",
            fontSize: 28,
            fontWeight: 600,
            color: "#58a6ff",
            marginBottom: 8,
          }}
        >
          Live Routing Demo
        </div>

        {/* Request progress indicator */}
        <div
          style={{
            opacity: labelOpacity,
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 16,
            color: "#8b949e",
            marginBottom: 16,
          }}
        >
          {getRequestLabel()}
        </div>

        {/* Request 1: Embedding-based routing */}
        <div
          style={{
            opacity: req1Opacity,
            position: "absolute",
            top: 130,
            left: 80,
            right: 80,
            bottom: 40,
            display: frame < 900 ? "flex" : "none",
            flexDirection: "column",
          }}
        >
          <Terminal
            lines={req1Lines}
            title="request 1 — embedding-based routing"
            startFrame={0}
            typingSpeed={1.5}
            style={{ flex: 1 }}
          />
          <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
            <Badge
              text="EMBEDDING MATCH"
              color="#58a6ff"
              opacity={badge1Opacity}
              scale={badge1Scale}
            />
            <Badge
              text="LoRA: code-adapter"
              color="#bc8cff"
              opacity={badge1Opacity}
              scale={badge1Scale}
            />
          </div>
        </div>

        {/* Request 2: Multi-signal fusion */}
        <div
          style={{
            opacity: req2Opacity,
            position: "absolute",
            top: 130,
            left: 80,
            right: 80,
            bottom: 40,
            display: frame >= 900 && frame < 1800 ? "flex" : "none",
            flexDirection: "column",
          }}
        >
          <Terminal
            lines={req2Lines}
            title="request 2 — multi-signal fusion"
            startFrame={950}
            typingSpeed={1.5}
            style={{ flex: 1 }}
          />
          <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
            <Badge
              text="MULTI-SIGNAL FUSION"
              color="#d29922"
              opacity={badge2Opacity}
              scale={badge2Scale}
            />
            <Badge
              text="Chain-of-thought injected"
              color="#d29922"
              opacity={badge2Opacity}
              scale={badge2Scale}
            />
          </div>
        </div>

        {/* Request 3: Semantic cache hit */}
        <div
          style={{
            opacity: req3Opacity,
            position: "absolute",
            top: 130,
            left: 80,
            right: 80,
            bottom: 40,
            display: frame >= 1800 ? "flex" : "none",
            flexDirection: "column",
          }}
        >
          <Terminal
            lines={req3Lines}
            title="request 3 — semantic cache hit"
            startFrame={1850}
            typingSpeed={1.5}
            style={{ flex: 1 }}
          />
          <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
            <Badge
              text="CACHE HIT"
              color="#3fb950"
              opacity={badge3Opacity}
              scale={badge3Scale}
            />
            <Badge
              text="2ms response"
              color="#3fb950"
              opacity={badge3Opacity}
              scale={badge3Scale}
            />
          </div>
        </div>
      </div>
    </SceneWrap>
  );
};
