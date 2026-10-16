import React from "react";
import { useCurrentFrame, interpolate } from "remotion";

interface TerminalLine {
  text: string;
  color?: string;
  isCommand?: boolean;
  delay?: number; // frame at which this line starts typing
}

interface TerminalProps {
  lines: TerminalLine[];
  title?: string;
  startFrame?: number;
  typingSpeed?: number; // characters per frame
  style?: React.CSSProperties;
}

export const Terminal: React.FC<TerminalProps> = ({
  lines,
  title = "terminal",
  startFrame = 0,
  typingSpeed = 1.5,
  style,
}) => {
  const frame = useCurrentFrame();
  const relativeFrame = frame - startFrame;

  const getVisibleText = (text: string, lineDelay: number): string => {
    const elapsed = relativeFrame - lineDelay;
    if (elapsed <= 0) return "";
    const chars = Math.floor(elapsed * typingSpeed);
    return text.substring(0, chars);
  };

  const isLineVisible = (lineDelay: number): boolean => {
    return relativeFrame >= lineDelay;
  };

  return (
    <div
      style={{
        backgroundColor: "#161b22",
        borderRadius: 12,
        border: "1px solid #30363d",
        overflow: "hidden",
        fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
        fontSize: 16,
        lineHeight: 1.6,
        ...style,
      }}
    >
      {/* Title bar */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          padding: "10px 16px",
          backgroundColor: "#21262d",
          borderBottom: "1px solid #30363d",
          gap: 8,
        }}
      >
        <div
          style={{
            width: 12,
            height: 12,
            borderRadius: "50%",
            backgroundColor: "#f85149",
          }}
        />
        <div
          style={{
            width: 12,
            height: 12,
            borderRadius: "50%",
            backgroundColor: "#d29922",
          }}
        />
        <div
          style={{
            width: 12,
            height: 12,
            borderRadius: "50%",
            backgroundColor: "#3fb950",
          }}
        />
        <span
          style={{
            color: "#8b949e",
            fontSize: 13,
            marginLeft: 8,
          }}
        >
          {title}
        </span>
      </div>

      {/* Terminal content */}
      <div style={{ padding: "16px 20px" }}>
        {lines.map((line, i) => {
          const delay = line.delay ?? i * 20;
          if (!isLineVisible(delay)) return null;

          const visibleText = line.isCommand
            ? getVisibleText(line.text, delay)
            : relativeFrame >= delay + (line.text.length / typingSpeed)
              ? line.text
              : getVisibleText(line.text, delay);

          const showCursor =
            line.isCommand &&
            visibleText.length < line.text.length &&
            visibleText.length > 0;

          return (
            <div key={i} style={{ minHeight: "1.6em" }}>
              {line.isCommand && (
                <span style={{ color: "#3fb950" }}>$ </span>
              )}
              <span style={{ color: line.color || "#e6edf3" }}>
                {visibleText}
              </span>
              {showCursor && (
                <span
                  style={{
                    color: "#58a6ff",
                    opacity: interpolate(
                      frame % 30,
                      [0, 15, 30],
                      [1, 0, 1]
                    ),
                  }}
                >
                  |
                </span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
