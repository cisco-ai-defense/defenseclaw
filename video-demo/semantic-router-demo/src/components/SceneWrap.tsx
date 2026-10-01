import React from "react";
import { useCurrentFrame, interpolate } from "remotion";

interface SceneWrapProps {
  children: React.ReactNode;
  fadeInFrames?: number;
  fadeOutFrames?: number;
  durationInFrames: number;
}

export const SceneWrap: React.FC<SceneWrapProps> = ({
  children,
  fadeInFrames = 15,
  fadeOutFrames = 15,
  durationInFrames,
}) => {
  const frame = useCurrentFrame();

  const opacity = interpolate(
    frame,
    [0, fadeInFrames, durationInFrames - fadeOutFrames, durationInFrames],
    [0, 1, 1, 0],
    { extrapolateLeft: "clamp", extrapolateRight: "clamp" }
  );

  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        opacity,
        backgroundColor: "#0d1117",
      }}
    >
      {children}
    </div>
  );
};
