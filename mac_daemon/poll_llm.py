import json
import os
import re
import shutil
import subprocess
import time
import getpass
import tempfile
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

# Payload size safety caps (64 KB limit for prompt/response strings)
MAX_PAYLOAD_SIZE_BYTES = 64 * 1024

# System Executable & Path Setup
DFX_BIN = os.getenv(
    "DFX_BIN",
    shutil.which("dfx") or os.path.expanduser("~/.cache/dfinity/versions/0.24.3/dfx")
)
ODYSSEUS_LOG_PATH = os.path.expanduser(
    os.getenv("ODYSSEUS_LOG_PATH", "~/Desktop/Odysseus_Remote_Log.md")
)

# Global runtime variables set during setup wizard
BACKEND_CANISTER_ID = DEFAULT_IC_CANISTER_ID
DFX_NETWORK = "ic"
ACTIVE_IDENTITY = "default"


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


def parse_candid_pending_task(raw_output: str) -> dict | None:
    """
    Robustly parses Candid variant/record structure for getPendingPrompt().
    Handles dfx JSON output quirks for Nat (ticketId) and Text (prompt).
    """
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

        items = []
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = [data]

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
                return {"ticketId": t_id, "prompt": p_text}

    except json.JSONDecodeError:
        pass

    # Regex fallback for raw text candid output (e.g. opt record { ticketId = 123 : nat; prompt = "..." })
    ticket_match = re.search(r'ticketId\s*=\s*([0-9]+)', raw_output)
    prompt_match = re.search(r'prompt\s*=\s*"([^"]*(?:\\.[^"]*)*)"', raw_output, re.DOTALL)
    
    if ticket_match and prompt_match:
        try:
            return {
                "ticketId": int(ticket_match.group(1)),
                "prompt": prompt_match.group(1).encode().decode('unicode-escape')
            }
        except Exception:
            pass

    return None


def clean_model_output(raw_text: str) -> str:
    """Strips out internal model reasoning monologues, tags, and analysis preambles."""
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
    if not result:
        return cleaned.strip()
        
    return result


def escape_candid_text(text: str) -> str:
    """Properly escapes strings for Candid text arguments."""
    escaped = text.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
    return f'"{escaped}"'


def call_canister(method: str, argument: str | None = None, timeout: int = 45) -> str:
    """Executes a canister call via dfx using an argument file to prevent shell escaping or quote breakages."""
    command = [
        DFX_BIN,
        "canister",
        "call",
        "--network",
        DFX_NETWORK,
        "--identity",
        ACTIVE_IDENTITY,
        "--output",
        "json",
        "--quiet",
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
        raise RuntimeError(f"Canister call '{method}' timed out after {timeout}s (Mainnet unreachable).")
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
        except Exception as e:
            print(f"⚠️️ Warning reading canister_ids.json: {e}")

    if "relay_backend" not in data:
        data["relay_backend"] = {}

    current_ic_id = data["relay_backend"].get("ic", DEFAULT_IC_CANISTER_ID)

    print(f"\nCurrent configured IC Backend Canister ID: {current_ic_id}")
    print("Paste raw bash / dfx deploy output (or press Enter to keep current):")
    user_input = input("Canister Output > ").strip()

    parsed_id = extract_canister_id(user_input)
    selected_ic_id = parsed_id if parsed_id else current_ic_id
    BACKEND_CANISTER_ID = selected_ic_id

    data["relay_backend"]["ic"] = selected_ic_id
    try:
        with open(CANISTER_IDS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"💾 Updated {CANISTER_IDS_PATH.name} successfully.")
    except Exception as e:
        print(f"⚠ Could not write to canister_ids.json: {e}")

    DFX_NETWORK = os.getenv("DFX_NETWORK", "ic").lower()

    # --- Identity Configuration ---
    print("\n--------------------------------------------------")
    print("         👑 Master Principal ID Setup            ")
    print("--------------------------------------------------")
    detected_principal = ""
    if os.path.exists(DFX_BIN):
        try:
            ACTIVE_IDENTITY = run_cmd([DFX_BIN, "identity", "whoami"])
            detected_principal = run_cmd([DFX_BIN, "identity", "get-principal"])
            print(f"🔑 Detected Dfx Identity: '{ACTIVE_IDENTITY}' ({detected_principal})")
        except Exception:
            pass

    saved_master_pid = data["relay_backend"].get("master_pid", detected_principal)
    master_pid_prompt = f"Master Principal ID (II or Dfx PID) [{saved_master_pid}]: "
    master_pid_input = input(master_pid_prompt).strip()
    master_pid = master_pid_input if master_pid_input else saved_master_pid

    if master_pid:
        data["relay_backend"]["master_pid"] = master_pid
        try:
            with open(CANISTER_IDS_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

        if os.path.exists(DFX_BIN):
            try:
                current_remote_master = call_canister("getMasterPID")
                current_remote_master = current_remote_master.strip('()-" ')

                if current_remote_master and current_remote_master != "Unassigned":
                    print(f"ℹ️ Master PID already claimed on-chain as: {current_remote_master}")
                else:
                    print(f"⚡ Registering Master PID ({master_pid}) on canister {BACKEND_CANISTER_ID}...")
                    res = call_canister("claimMasterPID", f'("{master_pid}")')
                    print(f"✅ Canister response: {res}")
            except Exception as e:
                print(f"ℹ Skipped remote claimMasterPID registration (Canister already initialized or restricted): {e}")

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

    env_session = saved_config.get(
        "session_id", os.getenv("ODYSSEUS_SESSION_ID", "53c98808-7af3-4098-80a1-8b74911d6e54")
    )
    odysseus_session_input = input(f"Odysseus Session ID [{env_session}]: ").strip()
    odysseus_session = odysseus_session_input if odysseus_session_input else env_session

    odysseus_config = {
        "url": odysseus_url.rstrip("/"),
        "username": odysseus_user,
        "password": odysseus_pass,
        "session_id": odysseus_session,
    }

    try:
        with open(ODYSSEUS_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(odysseus_config, f, indent=2)
        print(f"💾 Saved configuration to {ODYSSEUS_CONFIG_PATH.name}")
    except Exception as e:
        print(f"⚠ Could not write to odysseus_config.json: {e}")

    print("==================================================\n")
    return BACKEND_CANISTER_ID, DFX_NETWORK, ACTIVE_IDENTITY, odysseus_config


class OdysseusClient:
    def __init__(self, config: dict):
        self.url = config["url"]
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.session_id = config["session_id"]

        self.session = requests.Session()

        if self.username and self.password:
            print("🔐 Authenticating with Odysseus Agent Backend...")
            auth_attempts = [
                (f"{self.url}/api/v1/auths/signin", {"email": self.username, "password": self.password}),
                (f"{self.url}/api/v1/auths/signin", {"username": self.username, "password": self.password}),
                (f"{self.url}/api/auth/login", {"username": self.username, "password": self.password}),
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
            "X-Tz-Name": "UTC",
        }

        msg_endpoints = [
            f"{self.url}/api/v1/chats/{self.session_id}/messages",
            f"{self.url}/api/session/{self.session_id}/messages",
        ]
        for msg_ep in msg_endpoints:
            try:
                self.session.post(
                    msg_ep,
                    json={"role": "user", "content": prompt, "session_id": self.session_id, "chat_id": self.session_id},
                    timeout=3,
                )
                break
            except Exception:
                pass

        chat_payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": f"User request: {prompt}"}],
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
            "tools_enabled": True,
            "self_improve": True,
            "meta_cognition": False,
        }

        stream_endpoints = [
            f"{self.url}/api/chat/completions",
            f"{self.url}/api/v1/chat/completions",
            f"{self.url}/api/chat_stream",
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
            try:
                fallback_payload = {
                    "message": prompt,
                    "session_id": self.session_id,
                    "mode": "agent",
                    "auto_execute": "true",
                }
                response = self.session.post(
                    f"{self.url}/api/chat_stream",
                    data=fallback_payload,
                    headers={"X-Tz-Offset": "0"},
                    timeout=300,
                    stream=True,
                )
                response.raise_for_status()
            except Exception as stream_err:
                raise RuntimeError(f"All Odysseus stream endpoints failed: {stream_err}")

        text_parts = []
        try:
            for line in response.iter_lines(decode_unicode=True):
                if not line or not line.startswith("data:"):
                    continue
                data_str = line[5:].strip()
                if data_str == "[DONE]":
                    break
                try:
                    event = json.loads(data_str)
                    content = ""
                    if isinstance(event, dict):
                        choices = event.get("choices", [])
                        if choices and "delta" in choices[0]:
                            content = choices[0]["delta"].get("content", "")
                        else:
                            content = (
                                event.get("content")
                                or event.get("text")
                                or event.get("delta")
                                or event.get("message", {}).get("content", "")
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
        except Exception as parse_chunk_err:
            print(f"⚠️ Warning during stream chunk consumption: {parse_chunk_err}")

        raw_out = "".join(text_parts).strip()
        out = clean_model_output(raw_out)

        if len(out.encode("utf-8", errors="ignore")) > MAX_PAYLOAD_SIZE_BYTES:
            out = out[:MAX_PAYLOAD_SIZE_BYTES] + "\n[Output truncated due to safety size limit]"

        if out:
            for msg_ep in msg_endpoints:
                try:
                    self.session.post(
                        msg_ep,
                        json={"role": "assistant", "content": out, "session_id": self.session_id, "chat_id": self.session_id},
                        timeout=3,
                    )
                    break
                except Exception:
                    pass

        return out if out else "Task completed by Odysseus Agent."


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
    global BACKEND_CANISTER_ID, DFX_NETWORK, ACTIVE_IDENTITY
    
    BACKEND_CANISTER_ID, DFX_NETWORK, ACTIVE_IDENTITY, odysseus_config = setup_wizard()

    print("🛡️ ICfirewall Daemon Active.")
    print(f"Target Canister: {BACKEND_CANISTER_ID} ({DFX_NETWORK} via identity '{ACTIVE_IDENTITY}')")

    try:
        odysseus_client = OdysseusClient(odysseus_config)
        print(f"✅ Connected to Odysseus Agent (Model: {odysseus_client.model}, Session: {odysseus_client.session_id})")
    except Exception as err:
        print(f"❌ Odysseus client start failed: {err}")
        raise SystemExit(1)

    last_idle_log = 0.0
    poll_error_count = 0
    base_sleep_time = 3.0
    max_sleep_time = 30.0

    while True:
        try:
            raw_output = call_canister("getPendingPrompt")
            task = parse_candid_pending_task(raw_output)

            if poll_error_count > 0:
                poll_error_count = 0

            if task and task.get("prompt"):
                ticket_id = task.get("ticketId")
                prompt_text = task.get("prompt")
                print(f"\n📩 Incoming Prompt [Ticket #{ticket_id}]: {prompt_text[:220]}...")

                try:
                    reply = odysseus_client.complete(prompt_text)
                except Exception as err:
                    print(f"⚠️ Error executing request in Odysseus: {err}")
                    time.sleep(3)
                    continue

                # Safeguard: Never leave reply empty on safety/refusal blocks so frontend ticket clears
                if not reply:
                    reply = "I cannot fulfill this request due to safety policies."

                clean_ticket_id = int(ticket_id)
                candid_arg = f"({clean_ticket_id} : nat, {escape_candid_text(reply)})"
                
                res = call_canister("saveResult", candid_arg)
                print(f"⚡ Result saved for Ticket #{clean_ticket_id}. Canister response: {res}")
                notify_odysseus(prompt_text, reply)

            elif time.time() - last_idle_log >= 30:
                print(f"Polling canister {BACKEND_CANISTER_ID} for prompts...", flush=True)
                last_idle_log = time.time()

            time.sleep(base_sleep_time)

        except Exception as error:
            poll_error_count += 1
            backoff_delay = min(max_sleep_time, base_sleep_time * (1.5 ** (poll_error_count - 1)))
            print(f"⚠️ Poller Warning (Attempt {poll_error_count}): {type(error).__name__}: {error}. Backing off for {backoff_delay:.1f}s...", flush=True)
            time.sleep(backoff_delay)


if __name__ == "__main__":
    main()
