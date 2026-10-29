# 🛡️ ICfirewall

> On-chain AI prompt firewall, end-to-end encryption vault, and command center for the Internet Computer

ICfirewall is an advanced decentralized perimeter canister that sits between client interfaces (web UI, iOS Shortcuts, etc.) and a local AI inference engine. It inspects incoming prompts, enforces heuristic security guardrails, manages cryptographic keys via **vetKDS (Verifiable Encrypted Threshold Key Derivation)**, secures message channels with client-side **AES-GCM End-to-End Encryption (E2EE)**, and queues safe payloads for a local background daemon to execute.

It is a personal project and has **not** been formally security-audited.

---

## Key Features & v7.0 Updates

- **End-to-End Encryption (E2EE)**: Prompts are encrypted client-side using Web Crypto AES-GCM session keys before crossing the network boundary, ensuring complete transport privacy.
- **vetKDS (Verifiable Encrypted Threshold Key Derivation) Integration**: Leverages ICP’s native subnet threshold system API (`vet_keys_public_key`) to manage decentralized master key derivation on-chain.
- **Mops Package Manager Support**: Integrated via `mops.toml` and `dfx.json` packtool rules for robust Motoko dependency resolution.
- **Three Runtime Security Modes** (`Off` / `Medium` / `On`) with dynamic state-switching.
- **On-chain Heuristic Threat Scanning**:
  - Full-width character folding & zero-width character stripping
  - Whitespace normalization & shell-view deobfuscation
  - Basic leetspeak decoding & pattern detection for prompt injection, destructive commands, and privilege escalation strings.
- **Granular Access Control**: Managed via Master, Admin, and Daemon principals.
- **Fail-Closed Queue & Sizing Caps**: 200 pending prompt queue limit with hard character constraints (2,0000 char max, forced to 4,000 in `On` mode).
- **Local Python Daemon (`poll_llm.py`)**: Automatically unpacks E2EE payloads, coordinates with local LLMs (Odysseus, Ollama, etc.), and securely saves encrypted results back to the canister.

---

## Project Structure

```text
.
├── src/
│   ├── relay_backend/
│   │   └── main.mo          # Motoko canister (with vetKDS & threat inspection)
│   └── relay_frontend/
│       ├── index.html       # Web UI command center & vetKDS vault card
│       ├── main.js          # E2EE session cryptography & canister connector
│       └── styles.css       # Dark glass-style UI styles
├── mac_daemon/
│   └── poll_llm.py          # Local Python E2EE poller + Setup Wizard
├── mops.toml                # Motoko package manager dependency config
├── mops.lock                # Locked dependency versions
├── dfx.json                 # DFX configuration with Mops packtool integration
├── requirements.txt         # Python dependencies
└── README.md

Architecture Flow
[ Web UI / Client ] ──(AES-GCM E2EE Ciphertext)──> [ ICP Canister ]
                                                          │
                                            1. Check caller permissions
                                            2. Inspect threat patterns
                                            3. Queue or reject payload
                                                          │
                                                          ▼
[ Local Python Daemon ] <──(Polls & Decrypts)── [ Canister Queue ]
         │
         ▼
  [ Local AI LLM ]
```
Quick Start & Setup Guide
1. Prerequisites
 * DFX SDK (0.24.3+)
 * Mops (Motoko package manager)
 * Python 3.10+
 * A local LLM or agent endpoint (Odysseus, Ollama, etc.)
 * Internet Identity (for Master / Admin actions)
2. Initialize Packages (Mops)
Ensure your Motoko dependencies are synchronized locally using Mops:
mops i

(This downloads required dependencies and sets up the project based on mops.toml).
3. Deploy the Canister
Start your local replica or target the Internet Computer mainnet:
# Local replica deployment
```text
dfx start --background --clean
dfx deploy
```
# Mainnet deployment
```text
dfx deploy --network ic
```
4. Claim Master Ownership & Set Daemon Principal
After deploying, authorize your principal as the Master Owner:
dfx canister call relay_backend claimMasterPID '("YOUR_PRINCIPAL_ID")'

Configure your local daemon principal so it has permissions to pull tasks:
dfx canister call relay_backend setDaemonPrincipal '("DAEMON_PRINCIPAL_ID")'

Setting Up and Using vetKDS (Threshold Keys)
ICfirewall integrates with Internet Computer's vetKDS feature to derive threshold cryptographic parameters directly from the subnet:
 * Subnet Support: Ensure your network/subnet supports the vet_keys_public_key management canister binding (test_key_1 is typically enabled on local replicas and supported subnets).
 * Web UI Vault Card: In the Web UI Command Center, navigate to the AES-GCM & vetKDS Cryptographic Vault panel.
 * Fetching Public Keys: Click "Fetch vetKDS Public Key". The frontend queries the backend canister, which securely communicates with the system management canister (aaaaa-aa) to retrieve the threshold public key.
 * Verification: The hex-encoded public key is displayed directly in your dashboard vault card for cryptographic operations and secure payload routing.
Running the Local Daemon
The local daemon (mac_daemon/poll_llm.py) manages background polling, client-side cryptographic decryption/encryption, and local LLM completions:
 * Install Python dependencies:
```text
   pip install -r requirements.txt
```
 * Run the daemon setup wizard:
 ```text
   python3 mac_daemon/poll_llm.py
```
 * Follow the interactive setup prompts to link your backend canister ID, active DFX identity, and local LLM endpoint configuration (odysseus_config.json).
Security Modes
| Mode | Behavior Description |
|---|---|
| Off | No security filtering. All incoming encrypted prompts are queued immediately. |
| Medium | Normalization, character folding, and pattern checks against injection, destructive commands, and privilege escalation strings. |
| On | Maximum security: strict character limits (max 4,000), advanced leetspeak filters, shell-view verification, and full heuristics blockades. |
Support & Links
 * Creator Hub: https://2n2uw-uaaaa-aaaag-at2hq-cai.icp.net
Disclaimer
This is a personal experimental project featuring cutting-edge E2EE and threshold cryptography elements. Do not use it as a standalone security boundary for critical production workloads without an independent formal security audit.

