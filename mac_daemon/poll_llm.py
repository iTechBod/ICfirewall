import json
import os
import re
import shutil
import subprocess
import time
import uuid
import getpass
import requests
from pathlib import Path

# --- Path Configurations ---
DAEMON_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = DAEMON_DIR.parent
CANISTER_IDS_PATH = PROJECT_ROOT / "canister_ids.json"

DEFAULT_IC_CANISTER_ID = "aaaaa-aa"

# Matches standard ICP Principal/Canister ID format
CANISTER_ID_REGEX = re.compile(r"\b[a-z0-9]{5}(?:-[a-z0-9]{5}){4}\b", re.IGNORECASE)


def run_cmd(cmd: list[str]) -> str:
    """Helper to run system/dfx commands safely."""
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Command failed ({' '.join(cmd)}): {res.stderr.strip()}")
    return res.stdout.strip()


def extract_canister_id(raw_input: str) -> str | None:
    """Extracts a valid ICP canister ID from raw bash or dfx deploy stdout."""
    match = CANISTER_ID_REGEX.search(raw_input)
    return match.group(0) if match else None


def setup_wizard() -> tuple[str, str, dict]:
    """
    Interactive wizard that:
    1. Auto-parses canister IDs from raw bash/dfx deploy logs.
    2. Prompts for Odysseus instance credentials & session parameters.
    3. Provisions controller access via dfx.
    """
    print("==================================================")
    print("         🛡️ ICfirewall Setup Wizard              ")
    print("==================================================")

    # 1. Load existing canister_ids.json if present
    data = {}
    if CANISTER_IDS_PATH.exists():
        try:
            with open(CANISTER_IDS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"⚠️ Warning reading canister_ids.json: {e}")

    if "relay_backend" not in data:
        data["relay_backend"] = {}

    current_ic_id = data["relay_backend"].get("ic", DEFAULT_IC_CANISTER_ID)

    # 2. Parse Canister ID from bash output
    print(f"\nCurrent configured IC Backend Canister ID: {current_ic_id}")
    print("Paste raw bash / dfx deploy output (or press Enter to keep current):")
    user_input = input("Canister Output > ").strip()

    parsed_id = extract_canister_id(user_input)
    if parsed_id:
        selected_ic_id = parsed_id
        print(f"✅ Auto-detected Canister ID: {selected_ic_id}")
    else:
        selected_ic_id = current_ic_id
        print(f"📌 Using default/existing Canister ID: {selected_ic_id}")

    # Save updated canister_ids.json
    data["relay_backend"]["ic"] = selected_ic_id
    try:
        with open(CANISTER_IDS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"💾 Updated {CANISTER_IDS_PATH.name} successfully.")
    except Exception as e:
        print(f"⚠️ Could not write to canister_ids.json: {e}")

    # 3. Configure Odysseus Credentials
    print("\n--------------------------------------------------")
    print("         🧠 Odysseus Agent Configuration         ")
    print("--------------------------------------------------")
    print("💡 Tip: Create a dedicated user on your Odysseus workspace (https://github.com/odysseus-dev/odysseus) for daemon execution.")

    env_url = os.getenv("ODYSSEUS_URL", "http://127.0.0.1:7000")
    odysseus_url = input(f"Odysseus URL [{env_url}]: ").strip() or env_url

    env_user = os.getenv("ODYSSEUS_USERNAME", "")
    prompt_user = f" [{env_user}]" if env_user else ""
    odysseus_user = input(f"Odysseus Username{prompt_user}: ").strip() or env_user

    env_pass = os.getenv("ODYSSEUS_PASSWORD", "")
    odysseus_pass = getpass.getpass("Odysseus Password: ").strip() or env_pass

    env_session = os.getenv("ODYSSEUS_SESSION_ID", "")
    default_session = env_session if env_session else str(uuid.uuid4())
    odysseus_session = input(f"Odysseus Session ID [{default_session}]: ").strip() or default_session

    odysseus_config = {
        "url": odysseus_url.rstrip("/"),
        "username": odysseus_user,
        "password": odysseus_pass,
        "session_id": odysseus_session
    }

    # 4. Target Network & Controller Registration
    network = os.getenv("DFX_NETWORK", "ic").lower()
    active_canister_id = selected_ic_id

    if network == "local":
        local_id = data["relay_backend"].get("local")
        if local_id:
            print(f"\n📌 Local replica detected. Using local canister ID: {local_id}")
            active_canister_id = local_id

    dfx_bin = shutil.which("dfx") or os.path.expanduser("~/.cache/dfinity/versions/0.24.3/dfx")
    if os.path.exists(dfx_bin):
        try:
            principal = run_cmd([dfx_bin, "identity", "get-principal"])
            print(f"🔑 Detected User Principal: {principal}")
            print(f"⚡ Adding principal as controller for {active_canister_id}...")
            
            cmd = [dfx_bin, "wallet", "add-controller", principal, "--network", network]
            run_cmd(cmd)
            print("✅ Principal controller successfully registered.")
        except Exception as err:
            print(f"⚠️ Note on controller update: {err}")
    else:
        print("⚠️ 'dfx' binary not found in standard PATH. Skipping controller registration.")

    print("==================================================\n")
    return active_canister_id, network, odysseus_config


# Execute Setup Wizard
BACKEND_CANISTER_ID, DFX_NETWORK, ODYSSEUS_CONFIG = setup_wizard()

# --- System Executable & Path Setup ---
DFX_BIN = os.getenv("DFX_BIN", shutil.which("dfx") or os.path.expanduser("~/.cache/dfinity/versions/0.24.3/dfx"))
ODYSSEUS_LOG_PATH = os.path.expanduser(os.getenv("ODYSSEUS_LOG_PATH", "~/Desktop/Odysseus_Remote_Log.md"))


class OdysseusClient:
    def __init__(self, config: dict):
        self.url = config["url"]
        self.username = config["username"]
        self.password = config["password"]
        self.session_id = config["session_id"]

        if not self.username or not self.password:
            raise RuntimeError("Odysseus credentials (username/password) are required.")
        
        self.session = requests.Session()
        print("🔐 Authenticating with Odysseus Agent Backend...")
        
        try:
            login = self.session.post(
                f"{self.url}/api/auth/login",
                data={"username": self.username, "password": self.password},
                timeout=15,
            )
            login.raise_for_status()
        except requests.RequestException:
            login = self.session.post(
                f"{self.url}/api/auth/login",
                json={"username": self.username, "password": self.password, "remember": True},
                timeout=15,
            )
            login.raise_for_status()

        models = self.session.get(f"{self.url}/api/models", timeout=15)
        models.raise_for_status()
        items = models.json().get("items", [])
        
        if not items or not items[0].get("models"):
            raise RuntimeError("Odysseus has no active model endpoints configured.")
            
        endpoint = items[0]
        self.endpoint_url = endpoint.get("url", "")
        self.model = endpoint["models"][0]
        
        self._sync_session_mode()

    def _sync_session_mode(self):
        sync_endpoints = [
            f"{self.url}/api/session/{self.session_id}/mode",
            f"{self.url}/api/sessions/{self.session_id}/mode",
            f"{self.url}/api/session/{self.session_id}/config"
        ]
        payload = {"mode": "agent", "terminal": True, "auto_execute": True}
        for ep in sync_endpoints:
            try:
                res = self.session.post(ep, json=payload, timeout=5)
                if res.status_code in [200, 204]:
                    print(f"🎯 Bound session {self.session_id} to agent/terminal mode")
                    break
            except Exception:
                continue

    def complete(self, prompt: str) -> str:
        headers = {"X-Tz-Offset": "0", "X-Tz-Name": "UTC"}

        payload = {
            "message": prompt,
            "session": self.session_id,
            "session_id": self.session_id,
            "mode": "agent",
            "agent_mode": "true",
            "allow_bash": "true",
            "allow_web_search": "true",
            "web_search": "true",
            "deep_search": "true",
            "use_rag": "true",
            "auto_execute": "true",
            "tools_enabled": "true",
            "enable_tools": "true",
            "enable_skills": "true",
            "brain": "active",
            "brain_mode": "active",
            "temperature": 0.1
        }

        response = self.session.post(
            f"{self.url}/api/chat_stream",
            data=payload,
            headers=headers,
            timeout=300,
            stream=True
        )
        response.raise_for_status()

        text_parts = []
        raw_events = []
        for line in response.iter_lines(decode_unicode=True):
            if not line or not line.startswith("data:"):
                continue
            data_str = line[5:].strip()
            if data_str == "[DONE]":
                break
            try:
                event = json.loads(data_str)
                raw_events.append(event)
                content = ""
                if isinstance(event, dict):
                    content = (
                        event.get("content") or 
                        event.get("text") or 
                        event.get("delta") or 
                        event.get("message", {}).get("content", "")
                    )
                    if isinstance(content, dict):
                        content = content.get("content", "") or content.get("text", "")
                elif isinstance(event, str):
                    content = event

                if content:
                    text_parts.append(str(content))
            except json.JSONDecodeError:
                if data_str:
                    text_parts.append(data_str)

        out = "".join(text_parts).strip()
        if not out and raw_events:
            print(f"⚠️ Stream returned raw events without text delta: {raw_events[-1]}")
            return "Agent executed command sequence."
        return out if out else "Task completed by Odysseus Agent."


def call_canister(method: str, argument: str | None = None) -> str:
    command = [
        DFX_BIN, "canister", "call", 
        "--network", DFX_NETWORK, 
        "--output", "json", 
        "--quiet", BACKEND_CANISTER_ID, 
        method
    ]
    if argument is not None:
        command.append(argument)
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def _apple_script_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def notify_odysseus(prompt: str, response: str):
    try:
        title = _apple_script_text(f"Odysseus: {prompt[:30]}...")
        apple_script = f'display notification "Response sent to remote client" with title "{title}"'
        subprocess.run(["osascript", "-e", apple_script], check=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass

    try:
        os.makedirs(os.path.dirname(ODYSSEUS_LOG_PATH), exist_ok=True)
        with open(ODYSSEUS_LOG_PATH, "a", encoding="utf-8") as file:
            file.write(f"### Prompt:\n{prompt}\n\n### Agent Output:\n{response}\n\n---\n")
    except OSError:
        pass


def main():
    print("🛡️ ICfirewall Daemon Active.")
    print(f"Target Canister: {BACKEND_CANISTER_ID} ({DFX_NETWORK})")
    
    try:
        odysseus_client = OdysseusClient(ODYSSEUS_CONFIG)
        print(f"✅ Connected to Odysseus Agent (Model: {odysseus_client.model}, Session: {odysseus_client.session_id})")
    except Exception as err:
        print(f"❌ Odysseus client start failed: {err}")
        raise SystemExit(1)

    last_idle_log = 0.0

    while True:
        try:
            raw_output = call_canister("getPendingPrompt")
            prompt = json.loads(raw_output)

            if prompt and str(prompt).strip() != "":
                clean_prompt = str(prompt).strip()
                print(f"\n📩 Incoming Prompt from Canister: {clean_prompt[:220]}...")
                
                try:
                    reply = odysseus_client.complete(clean_prompt)
                except Exception as err:
                    print(f"Error executing request in Odysseus: {err}")
                    time.sleep(3)
                    continue

                if reply:
                    clean_reply = reply.replace('\\', '\\\\').replace('"', '\\"').replace('\n', ' ')
                    candid_arg = f'("{clean_reply}")'
                    
                    call_canister("saveResult", candid_arg)
                    print("⚡ Result saved back to canister.")
                    notify_odysseus(clean_prompt, reply)

            elif time.time() - last_idle_log >= 30:
                print(f"Polling canister {BACKEND_CANISTER_ID} for prompts...", flush=True)
                last_idle_log = time.time()

        except Exception as error:
            print(f"Poller Warning: {type(error).__name__}: {error}", flush=True)
        
        time.sleep(3)


if __name__ == "__main__":
    main()
