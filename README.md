# ICfirewall
a firewall for local llm on odysseus built on the Internet Computer blockchain
🛡️ ICfirewall Command Center
Zero-Trust Relay & Security Dashboard on the Internet Computer
ICfirewall is a lightweight, privacy-first command center designed to monitor local AI prompt traffic, enforce security boundaries, and display threat telemetry—all running on the Internet Computer (ICP).
📌 Project Features
⚬	Real-time Boundary Toggles: Switch seamlessly between Off, Medium, and On security modes.
⚬	Live Telemetry: Monitor processed prompts, blocked threats, active queue length, and overall system health.
⚬	Threat Vault: View recent security events and payload snippets in a dynamic dashboard table.
⚬	On-Chain Coffee Support: Quickly copy the developer’s Principal ID to send ICP tips.
⚬	Dev Link: Direct external link to the hosted developer site on IC boundary nodes.

🗂️ Project Structure

.
├── index.html    # Main user interface & component layout
├── main.js       # Frontend logic, Canister actor connection, & event listeners
├── styles.css    # Dark-mode glassmorphism styling & animations
└── README.md     # Project documentation

🛠️ How to Customize & Update the Code
If you want to edit or add new features without breaking existing functionality, follow these step-by-step instructions.
1. Connecting Your Own Canister Backend
When you deploy your smart contract (canister), you need to link main.js to it:
	1.	Open main.js.
	2.	Find CANISTER_ID:
const CANISTER_ID = isLocalReplica
  ? 'YOUR-LOCAL-CANISTER-ID'
  : 'YOUR-PRODUCTION-CANISTER-ID';

	2.	Paste your generated Canister IDs inside the single quotes.
🤖 How to Prompt AI for Code Changes
When working with ChatGPT, Claude, or Gemini to modify this project, use clear, precise instructions. Here are exact templates you can use:
Example 1: Adding a New Button
"I have an existing index.html and main.js web project. Add a new button in the header topbar named 'Documentation' that opens 'https://docs.example.com' in a new tab when clicked. Ensure event listeners are bound properly in main.js and styled consistently with existing buttons."
Example 2: Changing Styles or Layout
"Modify styles.css to change the main highlight color from cyan (#67e8f9) to emerald green (#10b981). Update all gradients and glows accordingly."
Example 3: Modifying Dashboard Data Fields
"Update index.html and main.js to add a new statistics card called 'Tokens Analyzed' next to 'Processed Prompts'. Handle fetching and displaying this value from the canister actor."
⚙️ How It Works Under the Hood
	1.	Initialization: When index.html loads, main.js instantiates an @dfinity/agent HttpAgent.
	2.	Environment Detection: The app checks window.location.hostname. If running locally (localhost or 127.0.0.1), it connects to the local replica at http://localhost:4943 and calls fetchRootKey(). If deployed live, it routes through [https://icp0.io](https://icp0.io).
	3.	Actor Interface: It builds an Actor interface using idlFactory, matching the canister methods (getStats, getThreats, setMode).
	4.	Polling Cycle: The app initiates a 3-second polling interval via startLiveRefresh() to continually sync backend data with the frontend UI without requiring manual refreshes.
🚀 Local Development Setup
	1.	Clone the repository:
git clone https://github.com/iTechBod/ICfirewall.git
cd icfirewall

	2.	Start local replica & deploy canister (DFX required):
dfx start --background
dfx deploy

	3.	Serve frontend:
Run any standard local web server or open index.html directly in a browser connected to your local agent.


    4.Make a shortcut on your iPhone
	here's a ready to use one (add backend canister id) https://www.icloud.com/shortcuts/f4dd4bd3ffd04ff4a19e82f5a7113ba8
	if you wanna make it manually:
	add an action named ask for input,then in the next action add get contents of url, in the url type [https://YOUR BACKEND CANISTER ID.raw.icp0.io/api/prompt] and click the arrow to expand on the action, select method as post, add headers and in key type Authorization, in value type Bearer cyber-dolphin-2026 and change file to privded input

	and if you don't got iPhone just use the inside web prompt chat, have fun!


off,medium and on boundry button limitations:
## Security Boundary Modes & Limitations

The application uses three boundary modes to manage incoming/outgoing AI prompts and model responses. Below are the functional and performance limitations for each mode.

---

### 1. Boundary OFF (`orb-off`)
*Disables active filtering and safety interventions.*

* **Zero Input/Output Sanitization:** Bypasses all prompt-injection checks, strict content filtering, and structural validation.
* **Increased System Vulnerability:** Leaves the downstream AI processing pipeline exposed to adversarial prompt injections, system prompt leaking, and jailbreak payloads.
* **Visual Ambiguity:** In the default UI, selecting "Off" highlights the active button in cyan, which can visually misrepresent an insecure state as an active safety feature.
* **No Safety Fallbacks:** Failures or malicious outputs from model responses will render directly into the user interface without defensive masking.

---

### 2. Boundary MEDIUM (`orb-medium`)
*Balanced filtering designed for general use and basic abuse prevention.*

* **False Positives on Technical Jargon:** May accidentally flag or block legitimate technical terms, security code snippets, or system logs that resemble exploit payloads.
* **Latency Overhead:** Introduces slight processing delay (roughly 50–150ms) to inspect payloads before forwarding them to the execution layer.
* **Heuristic Blind Spots:** Relies on lightweight pattern matching and static heuristics, which can miss complex, multi-turn, or deeply obfuscated prompt injections.
* **Partial Output Redaction:** May strip formatting or partial context out of model outputs when suspicious patterns are detected.

---

### 3. Boundary ON (`orb-on`)
*Strict validation mode for high-security environments.*

* **High Strictness & Reduced Utility:** Frequently blocks edge-case inputs, developer queries, and raw code snippets due to aggressive regex and semantic containment.
* **Noticeable Processing Latency:** Runs full validation passes on both input queries and output responses, increasing end-to-end response times.
* **Potential Response Truncation:** Outputs with high entropy, dynamic formatting, or uncommon characters may trigger automated safety blocks mid-generation.
* **Strict Character Limits:** Restricts allowable payload length and character sets, limiting long-form inputs or complex markdown structures.
