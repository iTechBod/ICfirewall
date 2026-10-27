# 🛡️ ICfirewall
> Zero-Trust On-Chain AI Security Relay & Command Center on the Internet Computer

ICfirewall is a privacy-first, decentralized firewall and command center designed to sit between external client interfaces (web dashboards, iOS Shortcuts, hardware triggers) and local AI inference pipelines.
Running natively as a smart contract canister on the Internet Computer (ICP), ICfirewall inspects, sanitizes, and controls prompt traffic in real time before passing payloads to local inference engines, ensuring zero-trust boundary enforcement and full threat telemetry.

## 📌 Features
* **3-Stage Real-Time Security Engine:** Dynamic runtime switching between Off, Medium, and On boundary containment modes with fully customizable heuristics.
* **Live Threat Telemetry & Vault:** Real-time tracking of processed prompts, blocked injections, queue density, and dynamic logging of suspicious payloads in an on-chain threat vault.
* **Apple Glass Dark-Mode UI:** Minimalist, translucent glassmorphism command center built with native CSS/JS and responsive layout components.
* **Multi-Client Access (iOS & Web):** Execute prompts directly from native Apple iOS Shortcuts or via the integrated web terminal.
* **Local Daemon Bridge (`poll_llm.py`):** Asynchronous local Python daemon script that polls the ICP canister safely, executes local model inference via Odysseus/Ollama, and returns sanitized outputs back on-chain.
* **Decentralized Support:** Integrated ICP tip jar, direct developer links, and fully client-side execution.

## 🗂️ Project Structure
```text
.
├── src/
│   ├── relay_backend/
│   │   └── main.mo       # Backend Motoko Canister (State, Security Rules, API Endpoints)
│   └── relay_frontend/
│       ├── index.html    # Apple Glass UI Layout & Component Definitions
│       ├── main.js       # @dfinity/agent Connection, Actor Calls, & Real-time State Polling
│       └── styles.css    # Minimalist Glassmorphism Styling, Glows, & Dark Mode Aesthetics
├── mac_daemon/
│   └── poll_llm.py       # Local Python Daemon for Polling Canister & Executing Local LLMs
├── dfx.json              # Dfinity Project Configuration
├── requirements.txt      # Python Dependencies
└── README.md             # Project Documentation

⚙️ Architecture & Execution Flow
[ iOS Shortcut / Web UI ]
         │
         │ (HTTP POST / API call via Internet Identity Authentication)
         ▼
[ ICP Canister: ICfirewall ]
  ├── 1. Verify Cryptographic Principal / Admin Authorization
  ├── 2. Apply Boundary Mode Sanitization (OFF / MEDIUM / ON)
  └── 3. Queue Validated Payload in On-Chain Memory State
         │
         │ (Polls Canister Queue)
         ▼
[ Local Python Daemon (poll_llm.py) ]
  ├── 1. Fetches Pending Prompts via HttpAgent / Requests
  ├── 2. Sends Payload to Local LLM / Odysseus Instance
  └── 3. Writes Model Response / Threat Telemetry Back to Canister

🛠️ Quick Start & Setup
Prerequisites
 * [suspicious link removed] (v0.24.3 or higher)
 * Python 3.10+ with requests installed (pip install requests)
 * Local LLM Runner or Odysseus instance running on http://127.0.0.1:7860
 * Internet Identity (for master/admin access)
1. Deploying the Canister to Local Replica / Mainnet
 * Clone the repository:
   git clone [https://github.com/iTechBod/ICfirewall.git](https://github.com/iTechBod/ICfirewall.git)
cd ICfirewall

 * Start the local ICP network & deploy:
   dfx start --background
dfx deploy

 * Deploy to Mainnet (Optional):
   dfx deploy --network ic

 * CRITICAL: Claim master immediately. Run the following command within seconds of your first deploy, before anyone else can race you (master defaults to null in this template):
   dfx canister call relay_backend claimMasterPID '("YOUR_PRINCIPAL_ID")'

 * Authorize your local daemon principal:
   dfx canister call relay_backend setDaemonPrincipal '("DAEMON_PRINCIPAL_ID")'

2. Configuring the Local Python Daemon
 * Copy or create your odysseus_config.json file in the project root:
   {
  "url": "[http://127.0.0.1:7860](http://127.0.0.1:7860)",
  "username": "",
  "password": "",
  "session_id": "YOUR_ODYSSEUS_SESSION_ID_HERE"
}

 * Start the daemon:
   python3 mac_daemon/poll_llm.py

   (The script will walk through the setup wizard to verify your backend canister ID and identity).
🛡️ Security Boundary Modes & Limitations
ICfirewall implements three dynamic boundary modes to manage incoming prompts and outgoing model responses.
| Mode | Visual Indicator | Filtering Rigor | Target Latency | Best Used For |
|---|---|---|---|---|
| OFF | Cyan Neutral | No Sanitization | ~0ms overhead | Unrestricted local testing & raw model evaluation |
| MEDIUM | Emerald Glow | Balanced Pattern Matching | ~50–150ms | Daily operational usage, balance of security & speed |
| ON | Crimson Warning | Strict Containment | ~150–300ms | High-security execution, untrusted third-party inputs |
Detailed Mode Breakdown
 * Boundary OFF (orb-off)
   * Zero Input/Output Sanitization: Bypasses prompt-injection checks, system prompt extraction protections, and character validation.
   * Increased Vulnerability: Leaves downstream AI processing pipelines exposed to adversarial jailbreak attempts.
 * Boundary MEDIUM (orb-medium)
   * Balanced Filtering: Intercepts known injection vectors, command execution strings, and common jailbreak structures.
   * Partial Redaction: Strips unsafe formatting or high-risk sub-strings while retaining core semantic response context.
 * Boundary ON (orb-on)
   * Strict Containment: Enforces strict regular expressions, character set limits, and semantic entropy checks.
   * Response Truncation: Dynamically terminates response streams if output token entropy crosses high-risk safety thresholds.
📡 API Specification & Security Model
 * Deployer-Only Master Claim: Once claimed, master ownership is immutable.
 * Daemon Authorization: Dedicated daemon principals gate getPendingPrompt and saveResult.
 * HTTP Lockdown: Raw HTTP canister endpoints return 404 by default; all data interaction occurs strictly through authenticated canister actor methods.
 * Substring Matching Note: The current threat rule engine uses substring matching (Text.contains) for heuristics rather than full PCRE regex.
☕ Support & Community
 * Official Creator Hub: https://2n2uw-uaaaa-aaaag-at2hq-cai.icp.net
 * Built with <3 on the Internet Computer Protocol.
Disclaimer: This is a personal project, not security-audited. Do not deploy to mainnet without reviewing the auth model yourself.

