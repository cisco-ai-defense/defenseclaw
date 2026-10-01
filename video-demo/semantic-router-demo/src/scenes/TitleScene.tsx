import React from "react";
import {
  useCurrentFrame,
  interpolate,
  spring,
  useVideoConfig,
} from "remotion";
import { SceneWrap } from "../components/SceneWrap";

export const TitleScene: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const durationInFrames = 450;

  // Logo animation
  const logoScale = spring({ frame, fps, config: { damping: 12 } });
  const logoOpacity = interpolate(frame, [0, 20], [0, 1], {
    extrapolateRight: "clamp",
  });

  // Subtitle animation
  const subtitleOpacity = interpolate(frame, [30, 50], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const subtitleY = interpolate(frame, [30, 50], [20, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  // Problem arrow animation (starts at frame 90)
  const problemOpacity = interpolate(frame, [90, 110], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  // Solution arrow animation (starts at frame 250)
  const solutionOpacity = interpolate(frame, [250, 270], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  // Red X animation
  const redXScale = spring({
    frame: frame - 150,
    fps,
    config: { damping: 10 },
  });
  const redXOpacity = interpolate(frame, [150, 160], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  // Green check animation
  const greenCheckScale = spring({
    frame: frame - 320,
    fps,
    config: { damping: 10 },
  });
  const greenCheckOpacity = interpolate(frame, [320, 330], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  // Arrow pulse for problem
  const arrowPulse = interpolate(frame % 60, [0, 30, 60], [1, 1.05, 1]);

  return (
    <SceneWrap durationInFrames={durationInFrames}>
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          padding: 80,
        }}
      >
        {/* Logo */}
        <div
          style={{
            opacity: logoOpacity,
            transform: `scale(${logoScale})`,
            marginBottom: 16,
          }}
        >
          <h1
            style={{
              fontFamily: "'Inter', system-ui, sans-serif",
              fontSize: 72,
              fontWeight: 800,
              color: "#e6edf3",
              margin: 0,
              letterSpacing: -2,
            }}
          >
            Defense
            <span style={{ color: "#58a6ff" }}>Claw</span>
          </h1>
        </div>

        {/* Subtitle */}
        <div
          style={{
            opacity: subtitleOpacity,
            transform: `translateY(${subtitleY}px)`,
            marginBottom: 80,
          }}
        >
          <h2
            style={{
              fontFamily: "'Inter', system-ui, sans-serif",
              fontSize: 36,
              fontWeight: 400,
              color: "#8b949e",
              margin: 0,
            }}
          >
            Intelligent Model Routing
          </h2>
        </div>

        {/* Problem: Same model for everything */}
        <div
          style={{
            opacity: problemOpacity,
            marginBottom: 40,
            display: "flex",
            alignItems: "center",
            gap: 24,
            transform: `scale(${arrowPulse})`,
          }}
        >
          <div
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 22,
              color: "#8b949e",
              backgroundColor: "#21262d",
              padding: "12px 24px",
              borderRadius: 8,
              border: "1px solid #30363d",
            }}
          >
            Same model for everything
          </div>
          <div
            style={{
              opacity: redXOpacity,
              transform: `scale(${Math.max(0, redXScale)})`,
              fontSize: 40,
              color: "#f85149",
              fontWeight: 800,
              marginLeft: 16,
            }}
          >
            ✕
          </div>
        </div>

        {/* Solution: AI-powered signal fusion -> Optimal model */}
        <div
          style={{
            opacity: solutionOpacity,
            display: "flex",
            alignItems: "center",
            gap: 24,
          }}
        >
          <div
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 22,
              color: "#e6edf3",
              backgroundColor: "#0d2d1a",
              padding: "12px 24px",
              borderRadius: 8,
              border: "1px solid #238636",
            }}
          >
            AI-powered signal fusion
          </div>
          <svg width="80" height="24" viewBox="0 0 80 24">
            <line
              x1="0"
              y1="12"
              x2="60"
              y2="12"
              stroke="#3fb950"
              strokeWidth="2"
            />
            <polygon points="60,6 76,12 60,18" fill="#3fb950" />
          </svg>
          <div
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 22,
              color: "#e6edf3",
              backgroundColor: "#0d2d1a",
              padding: "12px 24px",
              borderRadius: 8,
              border: "1px solid #238636",
            }}
          >
            Optimal model
          </div>
          <div
            style={{
              opacity: greenCheckOpacity,
              transform: `scale(${Math.max(0, greenCheckScale)})`,
              fontSize: 40,
              color: "#3fb950",
              fontWeight: 800,
              marginLeft: 16,
            }}
          >
            ✓
          </div>
        </div>
      </div>
    </SceneWrap>
  );
};
