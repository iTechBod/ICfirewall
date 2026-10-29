#!/usr/bin/env python3
"""
ICfirewall Agentic Daemon (Public Release v7.0 E2EE & Setup Wizard)
"""

import json
import os
import re
import shutil
import subprocess
import time
import getpass
import tempfile
import signal
import base64
import requests
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Path Configurations ---
DAEMON_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = DAEMON_DIR.parent
CANISTER_IDS_PATH = PROJECT_ROOT / "canister_ids.json"
ODYSSEUS_CONFIG_PATH = PROJECT_ROOT / "odysseus_config.json"

DEFAULT_IC_CANISTER_ID = os.getenv("ICF_CANISTER_ID", "")
CANISTER_ID_REGEX = re.compile(r"\b[a-z0-9]{5}(?:-[a-z0-9]{5}){4}\b", re.IGNORECASE)
MAX_PAYLOAD_SIZE_BYTES = 64 * 1024

DFX_BIN = os.getenv(
    "DFX_BIN",
    shutil.which("dfx") or os.path.expanduser("~/.cache/dfinity/versions/0.24.3/dfx")
)
ODYSSEUS_LOG_PATH = os.path.expanduser(
    os.getenv("ODYSSEUS_LOG_PATH", "~/Desktop/Odysseus_Remote_Log.md")
)

BACKEND_CANISTER_ID = DEFAULT_IC_CANISTER_ID
DFX_NETWORK = os.getenv("DFX_NETWORK", "ic")
ACTIVE_IDENTITY = os.getenv("ICF_IDENTITY", "default")

should_exit = False

def handle_exit_signal(sig, frame):
    global should_exit
    print("\n🛑 Graceful shutdown requested...")
    should_exit = True

signal.signal(signal.SIGINT, handle_exit_signal)
signal.signal(signal.SIGTERM, handle_exit_signal)


def run_cmd(cmd: list[str]) -> str:
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Command failed ({' '.join(cmd)}): {res.stderr.strip()}")
    return res.stdout.strip()


def extract_canister_id(raw_input: str) -> str | None:
    match = CANISTER_ID_REGEX.search(raw_input)
    return match.group(0) if match else None


def decrypt_payload(cipher_base64: str) -> str:
    raw_key = os.getenv("ICF_E2EE_RAW_KEY")
    if not raw_key:
        return cipher_base64
    try:
        key_bytes = bytes([int(x) for x in raw_key.split(",")])
        raw_data = base64.b64decode(cipher_base64)
        iv = raw_data[:12]
        ciphertext = raw_data[12:]
        aesgcm = AESGCM(key_bytes)
        decrypted = aesgcm.decrypt(iv, ciphertext, None)
        return decrypted.decode("utf-8")
    except Exception:
        return cipher_base64


def encrypt_payload(text: str) -> str:
    raw_key = os.getenv("ICF_E2EE_RAW_KEY")
    if not raw_key:
        return text
    try:
        key_bytes = bytes([int(x) for x in raw_key.split(",")])
        iv = os.urandom(12)
        aesgcm = AESGCM(key_bytes)
        ciphertext = aesgcm.encrypt(iv, text.encode("utf-8"), None)
        return base64.b64encode(iv + ciphertext).decode("utf-8")
    except Exception:
        return text


def parse_candid_pending_task(raw_output: str) -> dict | None:
    if not raw_output or raw_output in ("null", "()", "[]", '""'):
        return None

    if len(raw_output.encode("utf-8", errors="ignore")) > MAX_PAYLOAD_SIZE_BYTES:
        print("⚠️ Warning: Received canister payload exceeds safety size limits.")
        return None

    try:
        data = json.loads(raw_output)
        
        def parse_nat(val):
            if isinstance(val, (int, float)):
                return int(val)
            if isinstance(val, str) and val.isdigit():
                return int(val)
            if isinstance(val, dict):
                for k, v in val.items():
                    if "nat" in k.lower() or k == "__nat__":
                        return int(v)
            return None

        items = data if isinstance(data, list) else [data]

        for item in items:
            if not isinstance(item, dict):
                continue
            
            task_node = item
            if "Some" in item and isinstance(item["Some"], dict):
                task_node = item["Some"]
            elif "opt" in item and isinstance(item["opt"], dict):
                task_node = item["opt"]

            t_id = None
            p_text = None

            for k, v in task_node.items():
                k_lower = k.lower()
                if "ticket" in k_lower:
                    t_id = parse_nat(v)
                elif "prompt" in k_lower or "text" in k_lower:
                    p_text = str(v)

            if t_id is not None and p_text is not None:
                return {"ticketId": t_id, "prompt": decrypt_payload(p_text)}
    except json.JSONDecodeError:
        pass

    ticket_match = re.search(r'ticketId\s*=\s*([0-9]+)', raw_output)
    prompt_match = re.search(r'prompt\s*=\s*"([^"]*(?:\\.[^"]*)*)"', raw_output, re.DOTALL)
    
    if ticket_match and prompt_match:
        try:
            raw_p = prompt_match.group(1).encode().decode('unicode-escape')
            return {
                "ticketId": int(ticket_match.group(1)),
                "prompt": decrypt_payload(raw_p)
            }
        except Exception:
            pass

    return None


def clean_model_output(raw_text: str) -> str:
    if not raw_text:
        return ""
    cleaned = re.sub(r'<think>.*?</think>', '', raw_text, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r'<thought>.*?</thought>', '', cleaned, flags=re.DOTALL | re.IGNORECASE)
    
    lines = cleaned.split('\n')
    filtered_lines = []
    is_answering = False
    
    preamble_triggers = (
        "analyze the user input", "analyze the preceding context", "determine intent", 
        "safety check", "formulate a response", "self-correction", "final output generation"
    )
    
    for line in lines:
        stripped_lower = line.lower().strip()
        is_preamble = any(stripped_lower.startswith(trig) for trig in preamble_triggers)
        
        if is_preamble:
            is_answering = False
            continue
            
        if not is_preamble and stripped_lower:
            if stripped_lower.startswith("i'm sorry") or stripped_lower.startswith("here is") or not is_answering:
                is_answering = True
                
        if is_answering:
            filtered_lines.append(line)
            
    result = '\n'.join(filtered_lines).strip()
    return result if result else cleaned.strip()


def escape_candid_text(text: str) -> str:
    escaped = text.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
    return f'"{escaped}"'


def call_canister(method: str, argument: str | None = None, timeout: int = 45) -> str:
    command = [
        DFX_BIN, "canister", "call", "--network", DFX_NETWORK,
        "--identity", ACTIVE_IDENTITY, "--output", "json", "--quiet",
    ]

    tf_path = None
    if argument is not None:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as tf:
            tf.write(argument)
            tf_path = tf.name
        command.extend(["--argument-file", tf_path, BACKEND_CANISTER_ID, method])
    else:
        command.extend([BACKEND_CANISTER_ID, method])

    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Canister call '{method}' timed out after {timeout}s.")
    finally:
        if tf_path and os.path.exists(tf_path):
            try:
                os.unlink(tf_path)
            except Exception:
                pass


def setup_wizard() -> tuple[str, str, str, dict]:
    global BACKEND_CANISTER_ID, DFX_NETWORK, ACTIVE_IDENTITY
    print("==================================================")
    print("         🛡️ ICfirewall Setup Wizard              ")
    print("==================================================")

    data = {}
    if CANISTER_IDS_PATH.exists():
        try:
            with open(CANISTER_IDS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            pass

    if "relay_backend" not in data:
        data["relay_backend"] = {}

    current_backend_id = data["relay_backend"].get("ic", DEFAULT_IC_CANISTER_ID)
    backend_input = input(f"Backend Canister ID [{current_backend_id}]: ").strip()
    parsed_backend_id = extract_canister_id(backend_input)
    BACKEND_CANISTER_ID = parsed_backend_id if parsed_backend_id else (backend_input if backend_input else current_backend_id)
    data["relay_backend"]["ic"] = BACKEND_CANISTER_ID

    try:
        with open(CANISTER_IDS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

    if os.path.exists(DFX_BIN):
        try:
            ACTIVE_IDENTITY = os.getenv("ICF_IDENTITY", run_cmd([DFX_BIN, "identity", "whoami"]))
            daemon_principal = run_cmd([DFX_BIN, "identity", "get-principal", "--identity", ACTIVE_IDENTITY])
            call_canister("setDaemonPrincipal", f'("{daemon_principal}")')
        except Exception:
            pass

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
    odysseus_user = input(f"Odysseus Username [{env_user}]: ").strip() or env_user

    env_pass = saved_config.get("password", os.getenv("ODYSSEUS_PASSWORD", ""))
    odysseus_pass = getpass.getpass("Odysseus Password [****]: ").strip() or env_pass

    env_session = saved_config.get("session_id", os.getenv("ODYSSEUS_SESSION_ID", ""))
    odysseus_session = input(f"Odysseus Session ID [{env_session}]: ").strip() or env_session

    odysseus_config = {
        "url": odysseus_url.rstrip("/"),
        "username": odysseus_user,
        "password": odysseus_pass,
        "session_id": odysseus_session,
    }

    try:
        with open(ODYSSEUS_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(odysseus_config, f, indent=2)
    except Exception:
        pass

    return BACKEND_CANISTER_ID, DFX_NETWORK, ACTIVE_IDENTITY, odysseus_config


class OdysseusClient:
    def __init__(self, config: dict):
        self.url = config["url"]
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.session_id = config["session_id"]
        self.session = requests.Session()

        if self.username and self.password:
            try:
                self.session.post(f"{self.url}/api/v1/auths/signin", json={"email": self.username, "password": self.password}, timeout=10)
            except Exception:
                pass

        try:
            models = self.session.get(f"{self.url}/api/models", timeout=15)
            if models.status_code == 200:
                res_json = models.json()
                items = res_json.get("items", res_json.get("data", []))
                self.model = items[0].get("id", "default") if items else "default"
            else:
                self.model = "default"
        except Exception:
            self.model = "default"

    def complete(self, prompt: str) -> str:
        chat_payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "chat_id": self.session_id,
            "session_id": self.session_id,
            "stream": False,
        }
        try:
            res = self.session.post(f"{self.url}/api/chat/completions", json=chat_payload, timeout=300)
            if res.status_code == 200:
                data = res.json()
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                return clean_model_output(content)
        except Exception:
            pass
        return "Task completed by Odysseus Agent."


def notify_odysseus(prompt: str, response: str):
    try:
        title = prompt[:30].replace('"', '\\"') + "..."
        apple_script = f'display notification "Response sent to remote client" with title "Odysseus: {title}"'
        subprocess.run(["osascript", "-e", apple_script], check=True, timeout=10)
    except Exception:
        pass


def main():
    global BACKEND_CANISTER_ID, DFX_NETWORK, ACTIVE_IDENTITY
    BACKEND_CANISTER_ID, DFX_NETWORK, ACTIVE_IDENTITY, odysseus_config = setup_wizard()

    if not BACKEND_CANISTER_ID:
        print("❌ Error: No Backend Canister ID configured.")
        raise SystemExit(1)

    odysseus_client = OdysseusClient(odysseus_config)
    print("🛡️ ICfirewall Daemon v7.0 Active and Polling...")

    poll_error_count = 0
    base_sleep_time = 3.0
    max_sleep_time = 30.0

    while not should_exit:
        try:
            raw_output = call_canister("getPendingPrompt")
            task = parse_candid_pending_task(raw_output)

            if poll_error_count > 0:
                poll_error_count = 0

            if task and task.get("prompt"):
                ticket_id = task.get("ticketId")
                prompt_text = task.get("prompt")
                print(f"\n📩 Incoming Prompt [Ticket #{ticket_id}]: {prompt_text[:100]}...")

                reply = odysseus_client.complete(prompt_text)
                encrypted_reply = encrypt_payload(reply)
                
                clean_ticket_id = int(ticket_id)
                candid_arg = f"({clean_ticket_id} : nat, {escape_candid_text(encrypted_reply)})"
                
                call_canister("saveResult", candid_arg)
                print(f"⚡ Result saved for Ticket #{clean_ticket_id}.")
                notify_odysseus(prompt_text, reply)

            time.sleep(base_sleep_time)
        except Exception as error:
            poll_error_count += 1
            backoff_delay = min(max_sleep_time, base_sleep_time * (1.5 ** (poll_error_count - 1)))
            print(f"⚠️ Poller Warning (Attempt {poll_error_count}): {error}. Backing off for {backoff_delay:.1f}s...")
            time.sleep(backoff_delay)

    print("Daemon stopped cleanly.")


if __name__ == "__main__":
    main()
