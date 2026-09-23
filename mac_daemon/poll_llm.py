import json
import os
import re
import shutil
import subprocess
import time
import getpass
import requests
from pathlib import Path

# --- Path Configurations ---
DAEMON_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = DAEMON_DIR.parent
CANISTER_IDS_PATH = PROJECT_ROOT / "canister_ids.json"
ODYSSEUS_CONFIG_PATH = PROJECT_ROOT / "odysseus_config.json"

DEFAULT_IC_CANISTER_ID = ""

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
    1. Parses canister IDs from canister_ids.json or prompt logs.
    2. Reads and persists Odysseus credentials into odysseus_config.json.
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

    print(f"\nCurrent configured IC Backend Canister ID: {current_ic_id}")
    print("Paste raw bash / dfx deploy output (or press Enter to keep current):")
    user_input = input("Canister Output > ").strip()

    parsed_id = extract_canister_id(user_input)
    selected_ic_id = parsed_id if parsed_id else current_ic_id

    data["relay_backend"]["ic"] = selected_ic_id
    try:
        with open(CANISTER_IDS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"💾 Updated {CANISTER_IDS_PATH.name} successfully.")
    except Exception as e:
        print(f"⚠️ Could not write to canister_ids.json: {e}")

    # 2. Load or Configure Odysseus Credentials
    print("\n--------------------------------------------------")
    print("         🧠 Odysseus Agent Configuration         ")
    print("--------------------------------------------------")

    saved_config = {}
    if ODYSSEUS_CONFIG_PATH.exists():
        try:
            with open(ODYSSEUS_CONFIG_PATH, "r", encoding="utf-8") as f:
                saved_config = json.load(f)
        except Exception:
            pass

    env_url = saved_config.get("url", os.getenv("ODYSSEUS_URL", "http://127.0.0.1:7860"))
    odysseus_url = input(f"Odysseus URL [{env_url}]: ").strip() or env_url

    env_user = saved_config.get("username", os.getenv("ODYSSEUS_USERNAME", ""))
    prompt_user = f" [{env_user}]" if env_user else " (leave blank if local auth is disabled)"
    odysseus_user = input(f"Odysseus Username{prompt_user}: ").strip() or env_user

    env_pass = saved_config.get("password", os.getenv("ODYSSEUS_PASSWORD", ""))
    prompt_pass = " [****]" if env_pass else " (leave blank if local auth is disabled)"
    odysseus_pass = getpass.getpass(f"Odysseus Password{prompt_pass}: ").strip() or env_pass

    env_session = saved_config.get("session_id", os.getenv("ODYSSEUS_SESSION_ID", "53c98808-7af3-4098-80a1-8b74911d6e54"))
    odysseus_session = input(f"Odysseus Session ID [{env_session}]: ").strip() or env_session

    odysseus_config = {
        "url": odysseus_url.rstrip("/"),
        "username": odysseus_user,
        "password": odysseus_pass,
        "session_id": odysseus_session
    }

    try:
        with open(ODYSSEUS_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(odysseus_config, f, indent=2)
        print(f"💾 Saved configuration to {ODYSSEUS_CONFIG_PATH.name}")
    except Exception as e:
        print(f"⚠️ Could not write to odysseus_config.json: {e}")

    # 3. Target Network & Controller Registration
    network = os.getenv("DFX_NETWORK", "ic").lower()
    active_canister_id = selected_ic_id

    if network == "local":
        local_id = data["relay_backend"].get("local")
        if local_id:
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
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.session_id = config["session_id"]

        self.session = requests.Session()
        
        # Authenticate if credentials are provided
        if self.username and self.password:
            print("🔐 Authenticating with Odysseus Agent Backend...")
            auth_attempts = [
                (f"{self.url}/api/v1/auths/signin", {"email": self.username, "password": self.password}),
                (f"{self.url}/api/v1/auths/signin", {"username": self.username, "password": self.password}),
                (f"{self.url}/api/auth/login", {"username": self.username, "password": self.password})
            ]

            authenticated = False
            for endpoint, payload in auth_attempts:
                try:
                    res = self.session.post(endpoint, json=payload, timeout=10)
                    if res.status_code == 200:
                        token = res.json().get("token") or res.json().get("access_token")
                        if token:
                            self.session.headers.update({"Authorization": f"Bearer {token}"})
                        authenticated = True
                        break
                except Exception:
                    continue

            if not authenticated:
                print("⚠️ Authentication skipped/failed. Proceeding unauthenticated (local mode).")

        try:
            models = self.session.get(f"{self.url}/api/models", timeout=15)
            if models.status_code == 200:
                res_json = models.json()
                items = res_json.get("items", res_json.get("data", []))
                if items:
                    first_item = items[0]
                    if isinstance(first_item, dict):
                        self.model = first_item.get("id") or first_item.get("models", ["default"])[0]
                    else:
                        self.model = str(first_item)
                else:
                    self.model = "default"
            else:
                self.model = "default"
        except Exception:
            self.model = "default"

    def complete(self, prompt: str) -> str:
        headers = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream, application/json",
            "X-Tz-Offset": "0", 
            "X-Tz-Name": "UTC"
        }

        # Step 1: Broadcast prompt to open browser tab session UI
        msg_endpoints = [
            f"{self.url}/api/v1/chats/{self.session_id}/messages",
            f"{self.url}/api/session/{self.session_id}/messages"
        ]
        for msg_ep in msg_endpoints:
            try:
                self.session.post(
                    msg_ep,
                    json={"role": "user", "content": prompt, "session_id": self.session_id, "chat_id": self.session_id},
                    timeout=3
                )
                break
            except Exception:
                pass

        # Step 2: Stream agent response payload
        chat_payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "chat_id": self.session_id,
            "session_id": self.session_id,
            "session": self.session_id,
            "message": prompt,
            "prompt": prompt,
            "stream": True,
            "mode": "agent",
            "agent_mode": True,
            "allow_bash": True,
            "allow_web_search": True,
            "web_search": True,
            "auto_execute": True,
            "tools_enabled": True
        }

        stream_endpoints = [
            f"{self.url}/api/chat/completions",
            f"{self.url}/api/v1/chat/completions",
            f"{self.url}/api/chat_stream"
        ]

        response = None
        for ep in stream_endpoints:
            try:
                res = self.session.post(ep, json=chat_payload, headers=headers, timeout=300, stream=True)
                if res.status_code == 200:
                    response = res
                    break
            except Exception:
                continue

        if not response:
            fallback_payload = {
                "message": prompt,
                "session_id": self.session_id,
                "mode": "agent",
                "auto_execute": "true"
            }
            response = self.session.post(
                f"{self.url}/api/chat_stream",
                data=fallback_payload,
                headers={"X-Tz-Offset": "0"},
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
                    choices = event.get("choices", [])
                    if choices and "delta" in choices[0]:
                        content = choices[0]["delta"].get("content", "")
                    else:
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
        
        # Step 3: Broadcast assistant reply back to browser UI
        if out:
            for msg_ep in msg_endpoints:
                try:
                    self.session.post(
                        msg_ep,
                        json={"role": "assistant", "content": out, "session_id": self.session_id, "chat_id": self.session_id},
                        timeout=3
                    )
                    break
                except Exception:
                    pass

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
                    clean_reply = json.dumps(reply)
                    call_canister("saveResult", f"({clean_reply})")
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
