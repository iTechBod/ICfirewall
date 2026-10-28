# 🛡️ ICfirewall
> Zero-Trust On-Chain AI Security Relay & Command Center on the Internet Computer

ICfirewall is a privacy-first, decentralized firewall and command center designed to sit between external client interfaces (web dashboards, iOS Shortcuts, hardware triggers) and local AI inference pipelines.  
Running natively as a smart contract canister on the Internet Computer (ICP), ICfirewall inspects, sanitizes, and controls prompt traffic in real time before passing payloads to local inference engines, ensuring zero-trust boundary enforcement and full threat telemetry.

## 📌 Features

- **3-Stage Real-Time Security Engine**  
  Dynamic runtime switching between Off, Medium, and On boundary modes with a multi-layer on-chain threat engine.

- **Advanced On-Chain Threat Engine**  
  Full-width character folding, zero-width / invisible character stripping, whitespace normalization, shell-view deobfuscation, leetspeak decoding, and multi-pattern matching against injection, destructive command, and privilege escalation attempts.

- **Live Threat Telemetry & Vault**  
  Real-time tracking of processed prompts, blocked attacks, queue density, and a circular on-chain threat log.

- **Apple Glass Dark-Mode UI**  
  Minimalist, translucent glassmorphism command center built with native CSS/JS and responsive layout.

- **Multi-Client Access (iOS & Web)**  
  Execute prompts from native Apple iOS Shortcuts or the integrated web terminal.

- **Local Daemon Bridge (`poll_llm.py`)**  
  Asynchronous Python daemon that safely polls the canister, runs local model inference (Odysseus / Ollama / compatible), and writes results back on-chain.

- **Strong Access Control**  
  Master / Admin / Daemon principal model with fail-closed authorization, anonymous principal rejection, and queue capacity limits.

## 🗂️ Project Structure

```text
.
├── src/
│   ├── relay_backend/
│   │   └── main.mo       # Backend Motoko Canister (State, Security Rules, Threat Engine, API)
│   └── relay_frontend/
│       ├── index.html    # Apple Glass UI Layout
│       ├── main.js       # @dfinity/agent, Auth, Polling & Actor Calls
│       └── styles.css    # Glassmorphism Dark Mode Styling
├── mac_daemon/
│   └── poll_llm.py       # Local Python Daemon + Setup Wizard
├── dfx.json
├── requirements.txt
└── README.md