🛡️ ICfirewall
> Zero-Trust On-Chain AI Security Relay & Command Center on the Internet Computer
> 
<p align="left">
<img src="[https://github.com/user-attachments/assets/34ca1631-e1b7-4c42-8ff3-8952baf19064](https://github.com/user-attachments/assets/34ca1631-e1b7-4c42-8ff3-8952baf19064)" alt="Internet Computer" />
<img src="[https://github.com/user-attachments/assets/577c08d5-74e0-41a3-a19e-754bfccf8f40](https://github.com/user-attachments/assets/577c08d5-74e0-41a3-a19e-754bfccf8f40)" alt="Motoko" />
<img src="[https://github.com/user-attachments/assets/b11dce54-35e6-4537-8bcf-85b25bcb2c6a](https://github.com/user-attachments/assets/b11dce54-35e6-4537-8bcf-85b25bcb2c6a)" alt="Python" />
</p>
ICfirewall is a privacy-first, decentralized firewall and command center designed to sit between external client interfaces (web dashboards, iOS Shortcuts, hardware triggers) and local AI inference pipelines.
Running natively as a smart contract canister on the Internet Computer (ICP), ICfirewall inspects, sanitizes, and controls prompt traffic in real time before passing payloads to local inference engines, ensuring zero-trust boundary enforcement and full threat telemetry.
📌 Features
 * 3-Stage Real-Time Security Engine
   Dynamic runtime switching between Off, Medium, and On boundary modes with a multi-layer on-chain threat engine.
 * Advanced On-Chain Threat Engine
   Full-width character folding, zero-width / invisible character stripping, whitespace normalization, shell-view deobfuscation, leetspeak decoding (deleet), and multi-pattern matching against prompt injection, destructive commands, and privilege escalation attempts.
 * Live Threat Telemetry & Vault
   Real-time tracking of processed prompts, blocked attacks, queue density, and a circular on-chain threat log.
 * Apple Glass Dark-Mode UI
   Minimalist, translucent glassmorphism command center built with native CSS/JS and responsive layout.
 * Multi-Client Access (iOS & Web)
   Execute prompts from native Apple iOS Shortcuts or the integrated web terminal.
 * Local Daemon Bridge (poll_llm.py)
   Asynchronous Python daemon that safely polls the canister, runs local model inference (Odysseus / Ollama / compatible), and writes results back on-chain.
 * Strong Access Control & Fail-Closed Security
   Master / Admin / Daemon principal model featuring a secure bootstrap mechanism, fail-closed queue access, anonymous principal rejection, and strict queue capacity limits.
🗂️ Project Structure
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

⚙️ Architecture & Execution Flow
[ iOS Shortcut / Web UI ]
         │
         │ (Authenticated call via Internet Identity)
         ▼
[ ICP Canister: ICfirewall ]
  ├── 1. Verify Principal (Master / Admin / Daemon)
  ├── 2. Apply Boundary Mode + Multi-layer Threat Scan
  └── 3. Queue validated prompt (or reject)
         │
         │ (Daemon polls getPendingPrompt securely)
         ▼
[ Local Python Daemon (poll_llm.py) ]
  ├── 1. Fetch pending prompt
  ├── 2. Send to local LLM / Odysseus
  └── 3. Write result back via saveResult

🛠️ Quick Start & Setup
Prerequisites
 * dfx (v0.24.3 or higher)
 * Python 3.10+ (pip install requests)
 * Local LLM runner (Odysseus, Ollama, LM Studio, etc.)
 * Internet Identity (for master/admin access)
1. Deploy the Canister
git clone https://github.com/iTechBod/ICfirewall.git
cd ICfirewall

# Local development
dfx start --background
dfx deploy

# Mainnet deployment
dfx deploy --network ic

> Critical first steps after deploy:
> # Claim master ownership immediately (race condition protection)
> dfx canister call relay_backend claimMasterPID '("YOUR_PRINCIPAL_ID")'
> 
> # Authorize your daemon identity securely
> dfx canister call relay_backend setDaemonPrincipal '("DAEMON_PRINCIPAL_ID")'
> 
> 
2. Configure & Run the Local Daemon
Create odysseus_config.json in the project root (or let the setup wizard create it automatically):
{
  "url": "http://127.0.0.1:7860",
  "username": "",
  "password": "",
  "session_id": "YOUR_SESSION_ID"
}

Start the daemon:
python3 mac_daemon/poll_llm.py

The interactive setup wizard will guide you through canister ID and identity configuration.
🛡️ Security Boundary Modes
| Mode | Visual Indicator | Filtering Rigor | Best Used For |
|---|---|---|---|
| OFF | Cyan | None | Local testing / raw model evaluation |
| MEDIUM | Emerald | Balanced multi-layer heuristics | Daily use, good security/speed balance |
| ON | Crimson | Strict + deobfuscation + extra patterns | High-security / untrusted inputs |
Mode Details
 * OFF
   No scanning. Everything is queued. Use only in trusted local environments.
 * MEDIUM
   Full normalization pipeline + pattern matching against injection, destructive commands, and privilege escalation. Suitable for everyday use.
 * ON
   Everything in Medium plus:
   * Harder character limits (max 4,000 chars)
   * Extra strict injection patterns
   * Full leetspeak (deleet) + shell-view scanning
   * Additional destructive patterns
📡 Security Model
 * Master Claim: First non-anonymous principal to call claimMasterPID becomes immutable master. Anonymous principals are strictly rejected.
 * Daemon Authorization: getPendingPrompt and saveResult are fail-closed. Only the authorized daemon principal (or verified Master/Admin) can access them.
 * Queue Protection: Hard limit of 200 pending prompts (MAX_QUEUE_LIMIT).
 * Prompt Size Caps: Absolute maximum 20,000 characters (forced down to 4,000 in ON mode).
 * HTTP Lockdown: Raw HTTP endpoints return 404. All interaction goes through authenticated actor methods.
 * Threat Engine: Multi-stage normalization (full-width folding, zero-width stripping, whitespace collapsing, shell-view) + pattern matching + leetspeak deobfuscation.
☕ Support & Community
 * Official Creator Hub: https://2n2uw-uaaaa-aaaag-at2hq-cai.icp.net
 * Built with ♥ on the Internet Computer Protocol
Disclaimer
This is a personal project and has not been professionally security-audited. Review the authorization model, threat engine, and upgrade path carefully before deploying to mainnet or using with sensitive data.
