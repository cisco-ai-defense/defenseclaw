# MyAgent — 3-Minute Demo Script

> Recording guide with slide cues, live demo segments, and voiceover narration.
> Record in 3 passes: (1) screen capture, (2) voiceover, (3) combine in iMovie.

---

## Recording Setup

**Screen capture**: QuickTime Player → File → New Screen Recording (Retina, 60fps)
**Audio**: Voice Memos or QuickTime audio (record separately for clean audio)
**Resolution**: 2560×1440 or 1920×1080
**Terminal font**: 16pt, dark theme
**Tip**: Pre-run the setup once so Hermes/Docker are cached — then uninstall and re-record at 2x speed for the install segment.

---

## [0:00–0:15] SLIDE 1: Title

**[Show: Slide 1 — "MyAgent" title slide]**

> "Today I want to show you MyAgent — a new way to bring AI agents to every employee's machine, with enterprise security built in from day one.
>
> One command installs everything. The agent runs in a hardened sandbox. And the user gets a native experience — right from their menu bar."

---

## [0:15–0:22] SLIDE 2: The Challenge

**[Show: Slide 2 — "The Challenge" with 5 bullet points]**

> "Today's AI agents have unrestricted system access. API keys are scattered. Each integration is configured separately. Installation is complex. And there's no visibility into what the agent is doing."

---

## [0:22–0:45] LIVE DEMO: Installation

**[Switch to: Terminal — clean, dark theme]**

> "Let me show you how MyAgent solves this. Starting from a clean machine — one command:"

**[Type and run:]**
```
defenseclaw setup it-governed --yes
```

**[Speed up to 2x as prompts flow — show credentials being entered, JWT auto-fetch, Hermes install, Docker pull, skills install]**

> "The setup walks through credentials — Circuit API for LLM access, Atlassian for Jira and Confluence, Microsoft Graph for Outlook. Each one is validated and stored securely.
>
> Behind the scenes — Hermes agent framework installed, hardened Docker image pulled, seventy-eight enterprise skills deployed, full routing config with five LLM models written automatically.
>
> For IT teams — this same command runs via MDM. Jamf, Intune, Kandji — pre-seed the credentials in a config profile. Zero user interaction."

---

## [0:45–0:50] SLIDE 3: One Command Summary

**[Show: Slide 3 — "One Command. Everything Installed." with checkmarks]**

> "One command — credentials, agent, sandbox, skills, guardrails — all configured."

---

## [0:50–1:10] LIVE DEMO: Starting the Stack

**[Switch to: Terminal]**

**[Type and run:]**
```
defenseclaw-gateway start
```

**[Show the log output with services starting]**

> "One more command starts the entire stack. The DefenseClaw gateway boots four services automatically."

**[Point to each log line as it appears:]**

> "LiteLLM — our LLM proxy with semantic routing across five Circuit API models.
>
> The Semantic Router — analyzes every query, picks the best model. Coding goes to GPT-5.5. Reasoning to O3. Simple queries to 4o-mini.
>
> Hermes — the agent framework — starts on port ninety-one nineteen.
>
> And the MCP gateway — Jira, Confluence, Outlook — all managed centrally. User tokens never leave this machine."

---

## [1:10–1:18] SLIDE 4: Architecture

**[Show: Slide 4 — Architecture block diagram]**

> "Here's the full architecture. MyAgent at the top — sandboxed. Hermes in Docker — sandboxed. The gateway managing everything below — LiteLLM, Semantic Router, MCP servers, Hermes serve."

---

## [1:18–1:55] LIVE DEMO: User Experience

**[Switch to: macOS desktop with other apps visible (Slack, browser, etc.)]**

> "Now — what the user sees."

**[Press Option+Space — command bar appears]**

> "Option-Space from anywhere. A floating command bar — like Spotlight, but for your AI agent."

**[Type: "What are my priority emails today?"]**
**[Hit Enter — response starts streaming]**

> "I ask about priority emails. Hermes routes through the Outlook MCP tool, queries my inbox through Microsoft Graph — using my credentials, on my machine."

**[Response appears with email list]**

> "Response streams in real-time."

**[Press Option+Space again — panel expands to full window]**

> "Option-Space again — full resizable window. Syntax highlighting, tool results, session history."

**[Click on Slack to switch away — wait for response to complete — notification banner appears in top right]**

> "Switch to another app while it's working — a native macOS notification when it's done. Click it — right back in the conversation."

**[Click notification — MyAgent window opens]**

**[Now show routing in action — type a coding query:]**

> "Watch the routing. A coding question —"

**[Type: "Write a Python function to merge two sorted lists"]**

> "The Semantic Router detects this is a coding task —"

**[Show gateway log in a small terminal: `[SR] 'Write a Python function...' → route_coding → coding-model (gpt-5-5)`]**

> "— and routes it to GPT-5.5, our strongest coding model."

**[Response streams in with code]**

> "Now a completely different domain —"

**[Type: "Compare the tradeoffs of microservices vs monolith for our platform"]**

**[Show gateway log: `[SR] 'Compare the tradeoffs...' → embed_reasoning → reasoning-model (o3)`]**

> "The router detects a reasoning question — routes to O3, the best model for analysis. Same interface, same agent — different model underneath, chosen automatically."

---

## [1:55–2:00] SLIDE 5: UX Summary

**[Show: Slide 5 — "User Experience" with 6 features]**

> "Native. Fast. Non-intrusive. Smart routing picks the right model for every query."

---

## [2:00–2:25] SLIDE 6: Three-Layer Security

**[Show: Slide 6 — "Three-Layer Security Model"]**

> "Now — what makes this secure for enterprise.
>
> Three layers. First — MyAgent itself is macOS sandboxed. Cannot read files, spawn processes, or access other apps. It can only talk to Hermes over a local WebSocket.
>
> Second — the Hermes agent runs inside a hardened Docker container. No host filesystem. No network from the container. All Linux capabilities dropped. Every command contained.
>
> Third — DefenseClaw's guardrail engine. Two hundred forty-six security rules. Every tool call inspected in real-time. Prompt injection — blocked. Sandbox escape — blocked and logged as critical.
>
> And the key insight —"

**[Pause for emphasis, point to the blue box at bottom of slide]**

> "All integrations authenticate on the user's own machine, using their own SSO session. Tokens never leave the device. No cloud relay. No third-party proxy. The MCP gateway runs locally on the same Cisco-managed device."

---

## [2:25–2:35] SLIDE 7: MCP Gateway

**[Show: Slide 7 — "MCP Gateway — Local Integration Hub"]**

> "Confluence, Jira, Outlook, Webex — all connected through one local gateway. Seventy-eight PulseClaw skills pre-installed. Outlook inbox, meeting prep, weekly digests, Jira sprint reports, Workday time-off — ready out of the box."

---

## [2:35–2:48] SLIDE 8: MDM Deployment

**[Show: Slide 8 — "Enterprise Deployment — MDM Ready"]**

> "For IT teams rolling this out — push a config profile via Jamf or Intune. The setup command reads it, installs everything, starts automatically. Users get a menu bar icon and a hotkey. No manual configuration. No training needed.
>
> IT controls which models are available, which integrations are enabled, the enforcement level, and the audit trail."

---

## [2:48–3:00] SLIDE 9: Closing

**[Show: Slide 9 — Closing slide]**

> "One command installs everything. One gateway runs all services. One hotkey for the user. Three layers of security. Zero tokens exposed to the agent. Seventy-eight enterprise skills out of the box.
>
> This is MyAgent — enterprise AI, sandboxed and secure, one Option-Space away.
>
> Thank you."

---

## Post-Production Notes

**Recording order:**
1. Record live demo segments first (terminal + MyAgent interaction)
2. Record slide segments (screen share the PPTX in presentation mode)
3. Record voiceover audio as one continuous take
4. Combine in iMovie: drag clips in order, overlay audio, trim to 3 min

**iMovie assembly:**
- Import all screen recordings + audio
- Drag slide clips and demo clips onto timeline in order
- Add audio track on top
- Use "Ken Burns" off for slides (static)
- Add 0.3s cross-dissolve transitions between slides and demos
- Export as 1080p H.264

**Alternative — Keynote with screen recordings:**
- Import demo screen recordings as videos into Keynote slides
- Set "Play automatically" on video slides
- Record narration in Keynote: Play → Record Slideshow
- Export as movie (File → Export To → Movie)
- This gives you slide transitions + embedded videos + audio in one pass

**Tips:**
- Use 2x speed for the install segment (30s real → 15s on screen)
- Keep terminal font large (16pt+) for readability
- Close notification center before recording to avoid random alerts
- Turn on Do Not Disturb except for MyAgent notifications
