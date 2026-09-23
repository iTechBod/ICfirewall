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
