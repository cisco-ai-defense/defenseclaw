import React from "react";
import {
  useCurrentFrame,
  interpolate,
  spring,
  useVideoConfig,
} from "remotion";
import { SceneWrap } from "../components/SceneWrap";

interface BoxProps {
  label: string;
  sublabel?: string;
  subItems?: string[];
  x: number;
  y: number;
  width: number;
  height: number;
  color: string;
  opacity: number;
  scale: number;
  pulse?: boolean;
  frame: number;
}

const ArchBox: React.FC<BoxProps> = ({
  label,
  sublabel,
  subItems,
  x,
  y,
  width,
  height,
  color,
  opacity,
  scale,
  pulse,
  frame,
}) => {
  const pulseScale = pulse
    ? 1 + 0.03 * Math.sin((frame / 15) * Math.PI)
    : 1;

  return (
    <div
      style={{
        position: "absolute",
        left: x - width / 2,
        top: y - height / 2,
        width,
        height,
        opacity,
        transform: `scale(${scale * pulseScale})`,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        backgroundColor: `${color}15`,
        border: `2px solid ${color}`,
        borderRadius: 12,
        boxShadow: pulse ? `0 0 20px ${color}44` : "none",
        padding: "8px 12px",
      }}
    >
      <span
        style={{
          fontFamily: "'Inter', system-ui, sans-serif",
          fontSize: 16,
          fontWeight: 600,
          color,
        }}
      >
        {label}
      </span>
      {sublabel && (
        <span
          style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 11,
            color: "#8b949e",
            marginTop: 4,
            textAlign: "center",
          }}
        >
          {sublabel}
        </span>
      )}
      {subItems && (
        <div style={{ marginTop: 6, display: "flex", flexDirection: "column", alignItems: "center", gap: 2 }}>
          {subItems.map((item, i) => (
            <span
              key={i}
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 10,
                color: "#8b949e",
                backgroundColor: `${color}20`,
                padding: "2px 8px",
                borderRadius: 4,
              }}
            >
              {item}
            </span>
          ))}
        </div>
      )}
    </div>
  );
};

interface ArrowProps {
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  opacity: number;
  color?: string;
  animated?: boolean;
  frame?: number;
}

const Arrow: React.FC<ArrowProps> = ({
  x1,
  y1,
  x2,
  y2,
  opacity,
  color = "#8b949e",
  animated,
  frame = 0,
}) => {
  const dashOffset = animated ? -(frame * 2) : 0;

  return (
    <svg
      style={{
        position: "absolute",
        left: 0,
        top: 0,
        width: "100%",
        height: "100%",
        pointerEvents: "none",
        opacity,
      }}
    >
      <defs>
        <marker
          id={`arrowhead-${x1}-${y1}`}
          markerWidth="10"
          markerHeight="7"
          refX="9"
          refY="3.5"
          orient="auto"
        >
          <polygon points="0 0, 10 3.5, 0 7" fill={color} />
        </marker>
      </defs>
      <line
        x1={x1}
        y1={y1}
        x2={x2}
        y2={y2}
        stroke={color}
        strokeWidth={2}
        strokeDasharray={animated ? "8 4" : "none"}
        strokeDashoffset={dashOffset}
        markerEnd={`url(#arrowhead-${x1}-${y1})`}
      />
    </svg>
  );
};

export const ArchitectureScene: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const durationInFrames = 1050; // frames 4350-5399

  // Staggered box appearances (5 boxes now)
  const box1Opacity = interpolate(frame, [30, 50], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const box1Scale = Math.max(
    0,
    spring({ frame: frame - 30, fps, config: { damping: 14 } })
  );

  const box2Opacity = interpolate(frame, [80, 100], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const box2Scale = Math.max(
    0,
    spring({ frame: frame - 80, fps, config: { damping: 14 } })
  );

  const box3Opacity = interpolate(frame, [130, 150], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const box3Scale = Math.max(
    0,
    spring({ frame: frame - 130, fps, config: { damping: 14 } })
  );

  const box4Opacity = interpolate(frame, [180, 200], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const box4Scale = Math.max(
    0,
    spring({ frame: frame - 180, fps, config: { damping: 14 } })
  );

  const box5Opacity = interpolate(frame, [230, 250], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const box5Scale = Math.max(
    0,
    spring({ frame: frame - 230, fps, config: { damping: 14 } })
  );

  // Arrow appearances
  const arrow1Opacity = interpolate(frame, [60, 75], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const arrow2Opacity = interpolate(frame, [110, 125], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const arrow3Opacity = interpolate(frame, [160, 175], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const arrow4Opacity = interpolate(frame, [210, 225], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  // Annotation below pipeline (appears after all boxes)
  const annotationOpacity = interpolate(frame, [300, 330], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  // Architecture label
  const labelOpacity = interpolate(frame, [0, 15], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  // Closing slide transition (~frame 550)
  const closingOpacity = interpolate(frame, [550, 600], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const diagramOpacity = interpolate(frame, [550, 600], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  // Closing title animation
  const closingScale = Math.max(
    0,
    spring({ frame: frame - 600, fps, config: { damping: 12 } })
  );

  // Layout constants - 5 boxes spread across 1920px width with padding
  const centerY = 340;
  const startX = 160;
  const spacing = 220;

  return (
    <SceneWrap durationInFrames={durationInFrames}>
      <div
        style={{
          position: "relative",
          width: "100%",
          height: "100%",
          padding: "40px 80px",
        }}
      >
        {/* Architecture Diagram */}
        <div style={{ opacity: diagramOpacity }}>
          {/* Section label */}
          <div
            style={{
              opacity: labelOpacity,
              fontFamily: "'Inter', system-ui, sans-serif",
              fontSize: 28,
              fontWeight: 600,
              color: "#58a6ff",
              marginBottom: 16,
            }}
          >
            Architecture — Routing Pipeline
          </div>

          {/* Arrows between boxes */}
          <Arrow
            x1={startX + 75}
            y1={centerY}
            x2={startX + spacing - 90}
            y2={centerY}
            opacity={arrow1Opacity}
            color="#8b949e"
            animated
            frame={frame}
          />
          <Arrow
            x1={startX + spacing + 90}
            y1={centerY}
            x2={startX + spacing * 2 - 90}
            y2={centerY}
            opacity={arrow2Opacity}
            color="#d29922"
            animated
            frame={frame}
          />
          <Arrow
            x1={startX + spacing * 2 + 90}
            y1={centerY}
            x2={startX + spacing * 3 - 90}
            y2={centerY}
            opacity={arrow3Opacity}
            color="#58a6ff"
            animated
            frame={frame}
          />
          <Arrow
            x1={startX + spacing * 3 + 90}
            y1={centerY}
            x2={startX + spacing * 4 - 75}
            y2={centerY}
            opacity={arrow4Opacity}
            color="#3fb950"
            animated
            frame={frame}
          />

          {/* Box 1: Request */}
          <ArchBox
            label="Request"
            sublabel="POST /v1/chat/completions"
            x={startX}
            y={centerY}
            width={150}
            height={80}
            color="#8b949e"
            opacity={box1Opacity}
            scale={box1Scale}
            frame={frame}
          />

          {/* Box 2: Signal Extraction */}
          <ArchBox
            label="Signal Extraction"
            subItems={["Embeddings", "Domain", "Complexity"]}
            x={startX + spacing}
            y={centerY}
            width={170}
            height={120}
            color="#d29922"
            opacity={box2Opacity}
            scale={box2Scale}
            frame={frame}
          />

          {/* Box 3: Decision Engine */}
          <ArchBox
            label="Decision Engine"
            sublabel="Multi-signal fusion / AND|OR rules"
            x={startX + spacing * 2}
            y={centerY}
            width={180}
            height={90}
            color="#58a6ff"
            opacity={box3Opacity}
            scale={box3Scale}
            pulse={frame > 200}
            frame={frame}
          />

          {/* Box 4: Plugin Enrichment */}
          <ArchBox
            label="Plugin Enrichment"
            sublabel="LoRA / Cache / Prompts"
            x={startX + spacing * 3}
            y={centerY}
            width={170}
            height={90}
            color="#bc8cff"
            opacity={box4Opacity}
            scale={box4Scale}
            frame={frame}
          />

          {/* Box 5: Forward */}
          <ArchBox
            label="Forward"
            sublabel="→ optimal model"
            x={startX + spacing * 4}
            y={centerY}
            width={140}
            height={80}
            color="#3fb950"
            opacity={box5Opacity}
            scale={box5Scale}
            frame={frame}
          />

          {/* Annotation below pipeline */}
          <div
            style={{
              position: "absolute",
              left: startX + spacing - 40,
              top: centerY + 100,
              opacity: annotationOpacity,
              textAlign: "center",
              width: spacing * 3,
            }}
          >
            <div
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 14,
                color: "#8b949e",
                backgroundColor: "#161b22",
                border: "1px solid #30363d",
                borderRadius: 8,
                padding: "10px 20px",
                display: "inline-block",
              }}
            >
              classify-only{" "}
              <span style={{ color: "#58a6ff" }}>•</span>{" "}
              no double-hop{" "}
              <span style={{ color: "#58a6ff" }}>•</span>{" "}
              graceful fallback
            </div>
          </div>
        </div>

        {/* Closing Slide */}
        <div
          style={{
            position: "absolute",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            opacity: closingOpacity,
          }}
        >
          <div style={{ transform: `scale(${closingScale})` }}>
            <h1
              style={{
                fontFamily: "'Inter', system-ui, sans-serif",
                fontSize: 48,
                fontWeight: 800,
                color: "#e6edf3",
                margin: 0,
                textAlign: "center",
              }}
            >
              Defense
              <span style={{ color: "#58a6ff" }}>Claw</span>
              {" + vLLM Semantic Router"}
            </h1>
          </div>
          <div
            style={{
              opacity: interpolate(frame, [650, 690], [0, 1], {
                extrapolateLeft: "clamp",
                extrapolateRight: "clamp",
              }),
              marginTop: 32,
              display: "flex",
              gap: 16,
              flexWrap: "wrap",
              justifyContent: "center",
              maxWidth: 900,
            }}
          >
            {[
              { text: "Embedding similarity", color: "#58a6ff" },
              { text: "Multi-signal fusion", color: "#d29922" },
              { text: "Plugin enrichment", color: "#bc8cff" },
              { text: "Semantic caching", color: "#3fb950" },
            ].map((item, i) => (
              <div
                key={i}
                style={{
                  opacity: interpolate(
                    frame,
                    [660 + i * 30, 680 + i * 30],
                    [0, 1],
                    { extrapolateLeft: "clamp", extrapolateRight: "clamp" }
                  ),
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 18,
                  color: item.color,
                  backgroundColor: `${item.color}15`,
                  border: `1px solid ${item.color}`,
                  borderRadius: 8,
                  padding: "8px 20px",
                }}
              >
                {item.text}
              </div>
            ))}
          </div>
        </div>
      </div>
    </SceneWrap>
  );
};
