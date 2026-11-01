# 🛡️ ICfirewall

> On-chain AI prompt firewall, Full Identity-Based Encryption (IBE) vault, and command center for the Internet Computer

ICfirewall is an advanced decentralized perimeter canister that sits between client interfaces (web UI, iOS Shortcuts, etc.) and a local AI inference engine. It inspects incoming prompts, enforces heuristic security guardrails, manages cryptographic keys via **vetKDS (Verifiable Encrypted Threshold Key Derivation)**, secures message channels with **Full Identity-Based Encryption (IBE)**, and queues safe payloads for a local background daemon to execute.

It is an experimental personal project and has **not** been formally security-audited.

---

## Key Features & Updates

- **Full Identity-Based Encryption (IBE) & vetKDS**: Messages and prompt results are encrypted directly against ticket identities (`identity = kind || ticketId`) using the ICP canister's threshold master public key (`vetkd_public_key`). No client public keys are stored on-chain.
- **Two-Step Master Principal Bootstrap**: Prevents front-running during deployment. The installer controller proposes a master principal (`proposeMaster`), which must then be claimed explicitly by that II user (`claimMasterPID`).
- **Cryptographic Separation of Duties**: 
  - `deriveDaemonKey`: Only the authorized `icf-daemon` principal can derive prompt-decryption keys for active leased tasks.
  - `deriveResultKey`: Only the ticket submitter principal can derive decryption keys for their completed private results.
- **Dynamic Runtime Security Modes** (`Off` / `Medium` / `On` Lockdown):
  - In `#On` (Lockdown) mode, private (unscannable) tickets are strictly refused, forcing all inputs through on-chain heuristic scanning.
- **On-chain Heuristic Threat Scanner**:
  - Zero-width character & unicode bidi stripping (`NFKC` normalization)
  - Whitespace collapsing & token-aware leetspeak deobfuscation
  - Pattern matching for prompt injections, destructive commands (`rm -rf`, `mkfs`), and privilege escalation (`sudo`, `chmod 777`).
- **Saturating Accounting & Resource Protection**:
  - Non-trapping saturating reservation math for bytes and queue slots.
  - Cycles floor guards (`60_000_000_000` cycles) and hard per-ticket derivation limits (`MAX_DERIVES_PER_TICKET = 4`) to eliminate cycles-drain vulnerabilities.
- **Local Python Daemon (`mac_daemon/poll_llm.py`)**:
  - Interactive startup wizard that retrieves active `dfx` principals, prompts for canister controller setup, saves `canister_ids.json`, and handles native Odysseus session authentication.

---

## Project Architecture & Flow

```text
.
├── src/
│   ├── relay_backend/
│   │   └── main.mo          # v8.8 Motoko canister (IBE, vetKDS, state preservation)
│   └── relay_frontend/
│       ├── index.html       # Web UI command center & vetKDS vault panel
│       ├── main.ts          # TypeScript client (AuthClient, IBE decryption, polling)
│       ├── crypto.ts        # Client-side IBE & Transport Secret Key primitives
│       └── styles.css       # Dynamic glassmorphism dark theme styles
├── mac_daemon/
│   ├── poll_llm.py          # Python background daemon + automated setup wizard
│   └── vetkeys_helper/
│       └── crypto_helper.mjs# Node.js BLS12-381 / vetKeys crypto helper bridge
├── mops.toml                # Motoko package manager dependencies
├── mops.lock                # Locked Motoko dependency manifest
├── dfx.json                 # DFX deployment configuration (assets build pipeline)
├── requirements.txt         # Python daemon dependencies
└── README.md

Data Flow
[ Web UI / Client ] ──(IBE Encrypted Ciphertext)──> [ ICP Canister (relay_backend) ]
                                                            │
                                              1. Validate role & rate limit
                                              2. Check mode (Off/Medium/On)
                                              3. Heuristic threat inspection
                                              4. Queue task & lease state
                                                            │
                                                            ▼
[ Local Python Daemon ] <──(Poll & IBE Key Derive)── [ Canister Queue ]
         │
         ▼
[ Native Odysseus / Ollama LLM ]
         │
         ▼
[ Local Python Daemon ] ──(Sealed IBE Result)──> [ ICP Canister ] ──> [ Client Decrypts via vetKDS ]
```
Quick Start & Setup Guide
1. Prerequisites
 * DFX SDK (0.24.3+)
 * Node.js (v18+) & npm
 * Mops (Motoko package manager)
 * Python 3.10+
 * A local LLM engine (Odysseus, Ollama, etc.)
 * Internet Identity (for Master / Admin authentication)
2. Initialize Dependencies
Install Motoko and Python packages:
# Install Motoko dependencies
```text
mops install
```
# Install Python daemon dependencies
```text
pip install -r requirements.txt
```
3. Deploy Canisters
Local Replica Deployment
```text
dfx start --background --clean
dfx deploy
```

Internet Computer Mainnet Deployment
```text
dfx deploy --network ic
```

Access Control & Master Ownership
ICfirewall uses a two-step claim process to prevent identity hijacking upon canister initialization:
 * Propose Master (Executed via DFX controller identity):
 ```text
   dfx canister call relay_backend proposeMaster '("YOUR_INTERNET_IDENTITY_PRINCIPAL")'
```

 * Claim Master PID (Executed from the Web UI or via the proposed identity):
   Log in to the Web UI using Internet Identity and click "Claim Master PID Now" in the initialization panel.
 * Authorize Daemon Principal:
   In the Master Admin Studio panel on the Web UI (or via DFX), authorize your daemon's principal:
```text
   dfx canister call relay_backend setDaemonPrincipal '("DAEMON_PRINCIPAL_ID")'
```

vetKDS & Full IBE Operations
ICfirewall leverages the Internet Computer's native threshold key derivation system (aaaaa-aa management canister):
 * Key Retrieval: Click "Fetch vetKDS Public Key" in the Web UI Cryptographic Vault panel to cache the system master public key (BLS12-381 G2).
 * Identity-Based Encryption:
   * Prompts and results are encrypted against a deterministic 9-byte identity: kind (1 byte) || ticketId (8 bytes BE).
   * Private prompts use kind = 1.
   * Sealed prompt results use kind = 2.
 * Derivation Restrictions: Key derivation requires a minimum canister balance floor (60_000_000_000 cycles) and is capped at 4 derivations per ticket.
Running the Local Daemon
The local daemon (mac_daemon/poll_llm.py) coordinates background polling, prompt decryption, model inference, and encrypted result saving:
```text
python3 mac_daemon/poll_llm.py
```

Interactive Setup Wizard
On startup, poll_llm.py automatically:
 * Runs dfx identity get-principal for the configured identity (icf-daemon).
 * Prompts you to enter your Backend and Frontend canister IDs.
 * Automatically updates and persists canister_ids.json in the project root.
 * Authenticates against your local Odysseus/Ollama LLM instance and stores configuration in odysseus_config.json.
Security Modes
| Mode | Behavior & Security Posture |
|---|---|
| Off | Uncensored. Heuristic checks are bypassed. Queues all incoming prompts immediately. |
| Medium | Guarded (Default). Performs normalization, zero-width stripping, and pattern checks for prompt injections, destructive system commands, and privilege escalation. |
| On | Lockdown. Strict inspection enabled. Private (unscannable) tickets are strictly disabled, forcing all inputs through canister-side inspection. |
Support & Links
 * Creator Hub: https://2n2uw-uaaaa-aaaag-at2hq-cai.icp.net
Disclaimer
This is a personal experimental project featuring cutting-edge Identity-Based Encryption and threshold cryptography elements. Do not use it as a standalone security boundary for critical production workloads without an independent formal security audit.

Built with <3 on the Internet Computer Protocol $ICP.
