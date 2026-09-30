🛡️ ICfirewall
> Zero-Trust On-Chain AI Security Relay & Command Center on the Internet Computer
> 
ICfirewall is a privacy-first, decentralized firewall and command center designed to sit between external client interfaces (web dashboards, iOS Shortcuts, hardware triggers) and local AI inference pipelines.
Running natively as a smart contract canister on the Internet Computer (ICP), ICfirewall inspects, sanitizes, and controls prompt traffic in real time before passing payloads to local inference engines, ensuring zero-trust boundary enforcement and full threat telemetry.
📌 Features
 * 3-Stage Real-Time Security Engine: Dynamic runtime switching between Off, Medium, and On boundary containment modes.
 * Live Threat Telemetry & Vault: Real-time tracking of processed prompts, blocked injections, queue density, and dynamic logging of suspicious payloads in an on-chain threat vault.
 * Apple Glass Dark-Mode UI: Minimalist, translucent glassmorphism command center built with native CSS/JS and responsive layout components.
 * Multi-Client Access (iOS & Web): Execute prompts directly from native Apple iOS Shortcuts using encrypted Bearer tokens or via the integrated web terminal.
 * Local Daemon Bridge (poll_llm.py): Asynchronous local daemon script that polls the ICP canister safely, executes local model inference, and returns sanitized outputs back on-chain.
 * Decentralized Support: Integrated ICP tip jar, direct developer links, and fully client-side execution.
🗂️ Project Structure
.
├── src/
│   ├── main.mo           # Backend Motoko Canister (State, Security Rules, API Endpoints)
│   ├── index.html        # Apple Glass UI Layout & Component Definitions
│   ├── main.js           # @dfinity/agent Connection, Actor Calls, & Real-time State Polling
│   └── styles.css        # Minimalist Glassmorphism Styling, Glows, & Dark Mode Aesthetics
├── scripts/
│   └── poll_llm.py       # Local Python Daemon for Polling Canister & Executing Local LLMs
└── README.md             # Project Documentation

⚙️ Architecture & Execution Flow
[ iOS Shortcut / Web UI ]
         │
         │ (HTTP POST / API call with Bearer Auth)
         ▼
[ ICP Canister: ICfirewall ]
  ├── 1. Verify Authorization Token
  ├── 2. Apply Boundary Mode Sanitization (OFF / MEDIUM / ON)
  └── 3. Queue Validated Payload in On-Chain Memory State
         │
         │ (Polls Canister Queue)
         ▼
[ Local Python Daemon (poll_llm.py) ]
  ├── 1. Fetches Pending Prompts via HttpAgent / Requests
  ├── 2. Sends Payload to Local LLM (e.g., Ollama / Dolphin 3 Cyber)
  └── 3. Writes Model Response / Threat Telemetry Back to Canister

🛠️ Quick Start & Setup
Prerequisites
 * [suspicious link removed] (v0.15.0 or higher)
 * Python 3.10+ with requests installed (pip install requests)
 * Local LLM Runner (e.g., Ollama, LM Studio, or local API daemon)
1. Deploying the Canister to Local Replica / Mainnet
 * Clone the repository:
   git clone https://github.com/iTechBod/ICfirewall.git
cd ICfirewall

 * Start the local ICP network & deploy:
   dfx start --background
dfx deploy

 * Deploy to Mainnet (Optional):
   dfx deploy --network ic

2. Linking the Frontend Command Center
 * Open main.js.
 * Set your deployed Canister ID:
   const CANISTER_ID = isLocalReplica
  ? 'YOUR-LOCAL-CANISTER-ID'
  : 'YOUR-PRODUCTION-CANISTER-ID';

 * Open index.html in any browser or host it via ICP Asset Canister.
3. Running the Local Python Daemon
 * Set your backend session environment variable and start the daemon:
   export ODYSSEUS_SESSION_ID="YOUR-SESSION-UUID"
python3 scripts/poll_llm.py

 * The script will securely poll the canister for queued prompts, execute them against your local model, and return responses back to the canister pipeline.
📱 Apple iOS Shortcut Setup
You can trigger your on-chain firewall directly from an iPhone using native Apple Shortcuts.
 * Ready-to-use Shortcut: Download iOS Shortcut Template
Manual Shortcut Configuration
 * Add an action: Ask for Input (Prompt text).
 * Add an action: Get Contents of URL:
   * URL: https://<YOUR-CANISTER-ID>.raw.icp0.io/api/prompt
   * Method: POST
   * Headers:
     * Key: Authorization
     * Value: Bearer cyber-dolphin-2026
   * Request Body: File or Text passing the provided input.
🛡️ Security Boundary Modes & Limitations
ICfirewall implements three dynamic boundary modes to manage incoming prompts and outgoing model responses.
| Mode | Visual Indicator | Filtering Rigor | Target Latency | Best Used For |
|---|---|---|---|---|
| OFF | Cyan Neutral | No Sanitization | ~0ms overhead | Unrestricted local testing & raw model evaluation |
| MEDIUM | Emerald Glow | Balanced Pattern Matching | ~50–150ms | Daily operational usage, balance of security & speed |
| ON | Crimson Warning | Strict Regex & Containment | ~150–300ms | High-security execution, untrusted third-party inputs |
Detailed Mode Breakdown
1. Boundary OFF (orb-off)
 * Zero Input/Output Sanitization: Bypasses prompt-injection checks, system prompt extraction protections, and character validation.
 * Increased Vulnerability: Leaves downstream AI processing pipelines exposed to adversarial jailbreak attempts.
 * No Defensive Masking: Model outputs containing raw system leaks or malicious code render unformatted into client interfaces.
2. Boundary MEDIUM (orb-medium)
 * Balanced Filtering: Intercepts known injection vectors, command execution strings, and common jailbreak structures.
 * Occasional False Positives: May flag complex technical jargon, reverse-engineering code snippets, or system logs that mimic exploit payloads.
 * Partial Redaction: Strips unsafe formatting or high-risk sub-strings while retaining core semantic response context.
3. Boundary ON (orb-on)
 * Strict Containment: Enforces strict regular expressions, character set limits, and semantic entropy checks.
 * High Strictness Impact: May block valid developer queries, nested Markdown code blocks, or raw exploit samples.
 * Response Truncation: Dynamically terminates response streams if output token entropy crosses high-risk safety thresholds.
📡 API Specification
Submit Prompt Payload
POST /api/prompt HTTP/1.1
Host: <CANISTER_ID>.raw.icp0.io
Authorization: Bearer cyber-dolphin-2026
Content-Type: application/json

{
  "prompt": "Analyze this smart contract function for reentrancy vulnerabilities."
}

Response
{
  "status": "queued",
  "prompt_id": "8f9a2b1c",
  "mode_applied": "MEDIUM",
  "sanitized": true
}

☕ Support & Community
 * Developer Profile: GitHub @iTechBod
 * Official Creator Hub: 2n2uw-uaaaa-aaaag-at2hq-cai.icp.net
 * Telegram Channel: https://t.me/techbod
Built on the Internet Computer Protocol.
