```markdown
# 🛡️ ICfirewall

> On-chain AI prompt firewall and command center for the Internet Computer

ICfirewall is a canister that sits between client interfaces (web UI, iOS Shortcuts, etc.) and a local AI inference engine. It inspects incoming prompts, applies filtering rules based on the selected security mode, and queues allowed prompts for a local daemon to process.

It is a personal project. It has **not** been security-audited.

## Features

- **Three security modes** (Off / Medium / On) that can be switched at runtime
- **On-chain threat detection** with:
  - Full-width character folding
  - Zero-width and invisible character stripping
  - Whitespace normalization
  - Shell-view deobfuscation
  - Basic leetspeak decoding
  - Pattern matching against common prompt injection, destructive commands, and privilege escalation strings
- **Access control** using Master / Admin / Daemon principals
- **Fail-closed queue access** (only the authorized daemon or admins can pull prompts / write results)
- **Queue capacity limit** (200 pending prompts)
- **Prompt size limits** (hard cap 20,000 characters, forced to 4,000 in On mode)
- **Small circular threat log** (last 10 blocked events)
- Web UI with dark glass-style design
- Local Python daemon (`poll_llm.py`) that polls the canister and talks to a local model (Odysseus, Ollama, or compatible)

## Project Structure

```text
.
├── src/
│   ├── relay_backend/
│   │   └── main.mo          # Motoko canister
│   └── relay_frontend/
│       ├── index.html
│       ├── main.js
│       └── styles.css
├── mac_daemon/
│   └── poll_llm.py          # Local daemon + setup wizard
├── dfx.json
├── requirements.txt
└── README.md
```

## How it works

```
[ Web UI / iOS Shortcut ]
          │
          ▼
[ ICP Canister ]
  1. Check caller permissions
  2. Run threat scan according to current mode
  3. Queue the prompt or reject it
          │
          ▼
[ Local Daemon ]
  1. Poll getPendingPrompt
  2. Send prompt to local LLM
  3. Call saveResult with the response
```

## Quick Start

### Prerequisites

- dfx (0.24.3+)
- Python 3.10+
- A local LLM endpoint (Odysseus, Ollama, LM Studio, etc.)
- Internet Identity (for Master/Admin actions)

### Deploy

```bash
git clone https://github.com/iTechBod/ICfirewall.git
cd ICfirewall

dfx start --background
dfx deploy

# Mainnet
dfx deploy --network ic
```

**Important after first deploy:**

```bash
# Claim master (first non-anonymous principal wins)
dfx canister call relay_backend claimMasterPID '("YOUR_PRINCIPAL_ID")'

# Set the daemon principal
dfx canister call relay_backend setDaemonPrincipal '("DAEMON_PRINCIPAL_ID")'
```

### Run the daemon

```bash
python3 mac_daemon/poll_llm.py
```

The script will walk you through configuration if needed.

## Security Modes

|Mode      |Behavior                                                                                                        |
|----------|----------------------------------------------------------------------------------------------------------------|
|**Off**   |No scanning. All prompts are queued.                                                                            |
|**Medium**|Normalization + pattern matching against injection, destructive commands, and privilege escalation.             |
|**On**    |Everything in Medium + stricter character limit (max 4,000) + extra patterns + full leetspeak/shell-view checks.|

## Security Model (Current Reality)

- **Master**: First non-anonymous principal to call `claimMasterPID` becomes master. This is a race on first deploy.
- **Daemon**: `getPendingPrompt` and `saveResult` only accept the configured daemon principal (or Master/Admin). If no daemon is set, only Master/Admin can access the queue.
- **Queue limit**: Maximum 200 pending prompts.
- **Prompt size**: Hard limit of 20,000 characters (4,000 in On mode).
- **Threat log**: Only the last 10 blocked events are kept.
- **HTTP endpoints**: Return 404. All interaction goes through candid methods.
- **No response filtering**: The model output is not scanned or sanitized.
- **No result cleanup**: Old results stay in the canister until manually cleared or the canister is reinstalled.

## Limitations

- Not security-audited
- Master claim is first-come-first-served
- Threat detection is pattern-based (can be bypassed with novel obfuscation)
- Only 10 threat events are retained
- No automatic cleanup of old results
- Rate limiting is global (one shared timestamp)
- No base64 or high-entropy payload detection

## Support

Creator hub: <https://2n2uw-uaaaa-aaaag-at2hq-cai.icp.net>

-----

**Disclaimer**  
This is a personal experimental project. Do not use it as a security boundary for sensitive or high-risk workloads without a proper audit and hardening.

```

```
