import React from "react";
import { Composition } from "remotion";
import { Sequence, AbsoluteFill } from "remotion";
import { TitleScene } from "./scenes/TitleScene";
import { ConfigScene } from "./scenes/ConfigScene";
import { LiveRoutingScene } from "./scenes/LiveRoutingScene";
import { ArchitectureScene } from "./scenes/ArchitectureScene";

const SemanticRouterDemo: React.FC = () => {
  return (
    <AbsoluteFill style={{ backgroundColor: "#0d1117" }}>
      {/* Scene 1: Title + Problem (0:00-0:15, frames 0-449) */}
      <Sequence from={0} durationInFrames={450}>
        <TitleScene />
      </Sequence>

      {/* Scene 2: Config + Start (0:15-0:55, frames 450-1649) */}
      <Sequence from={450} durationInFrames={1200}>
        <ConfigScene />
      </Sequence>

      {/* Scene 3: Live Routing (0:55-2:25, frames 1650-4349) */}
      <Sequence from={1650} durationInFrames={2700}>
        <LiveRoutingScene />
      </Sequence>

      {/* Scene 4: Architecture + Close (2:25-3:00, frames 4350-5399) */}
      <Sequence from={4350} durationInFrames={1050}>
        <ArchitectureScene />
      </Sequence>
    </AbsoluteFill>
  );
};

export const RemotionRoot: React.FC = () => {
  return (
    <>
      <Composition
        id="SemanticRouterDemo"
        component={SemanticRouterDemo}
        durationInFrames={5400}
        fps={30}
        width={1920}
        height={1080}
      />
    </>
  );
};
