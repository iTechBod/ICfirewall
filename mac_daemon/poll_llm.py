#!/usr/bin/env python3
"""
ICfirewall daemon v8.45 (Native Odysseus Session Field Fix, IBE Support & Auto Canister Config)
"""
import base64
import getpass
import json
import os
import re
import signal
import subprocess
import sys
import time
import unicodedata
from pathlib import Path

import requests

DAEMON_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = DAEMON_DIR.parent
HELPER = DAEMON_DIR / "vetkeys_helper" / "crypto_helper.mjs"
ODYSSEUS_CONFIG_PATH = PROJECT_ROOT / "odysseus_config.json"
CANISTER_IDS_PATH = PROJECT_ROOT / "canister_ids.json"

CANISTER_ID = os.getenv("ICF_CANISTER_ID", "v7c4r-xqaaa-aaaam-ad2ga-cai")
DFX_BIN = os.getenv("DFX_BIN", "dfx")
DFX_NETWORK = os.getenv("DFX_NETWORK", "ic")
IDENTITY = os.getenv("ICF_IDENTITY", "icf-daemon")
NODE_BIN = os.getenv("NODE_BIN", "node")
DAEMON_SCAN = os.getenv("ICF_DAEMON_SCAN", "1") != "0"
MAX_REPLY_CHARS = 30000

should_exit = False


def _on_signal(sig, frame):
    global should_exit
    print("\n🛑 Graceful shutdown requested...")
    should_exit = True


signal.signal(signal.SIGINT, _on_signal)
signal.signal(signal.SIGTERM, _on_signal)

# ----------------------------------------------------------------------------- candid text helpers
def idl_hash(name: str) -> int:
    h = 0
    for b in name.encode():
        h = (h * 223 + b) & 0xFFFFFFFF
    return h


_KNOWN_FIELDS = ["ticketId", "taskType", "leaseToken", "attemptCount", "Inspected", "Private"]
_HASH_TO_NAME = {idl_hash(n): n for n in _KNOWN_FIELDS}


def _field_name(raw: str) -> str:
    digits = raw.replace("_", "")
    if digits.isdigit():
        return _HASH_TO_NAME.get(int(digits), raw)
    return raw


def _read_literal(s: str, i: int):
    assert s[i] == '"'
    i += 1
    out = bytearray()
    while i < len(s):
        c = s[i]
        if c == '"':
            return bytes(out), i + 1
        if c == "\\":
            i += 1
            n = s[i]
            if n in '"\\\'':
                out += n.encode()
                i += 1
            elif n == "n":
                out += b"\n"; i += 1
            elif n == "r":
                out += b"\r"; i += 1
            elif n == "t":
                out += b"\t"; i += 1
            elif n == "u" and s[i + 1] == "{":
                j = s.index("}", i)
                out += chr(int(s[i + 2:j].replace("_", ""), 16)).encode("utf-8")
                i = j + 1
            else:
                out.append(int(s[i:i + 2], 16))
                i += 2
        else:
            out += c.encode("utf-8")
            i += 1
    raise ValueError("unterminated candid literal")


def _split_literals(text: str):
    skeleton, literals, i = [], [], 0
    while i < len(text):
        if text[i] == '"':
            data, i = _read_literal(text, i)
            literals.append(data)
            skeleton.append('""')
        else:
            skeleton.append(text[i])
            i += 1
    return "".join(skeleton), literals


def parse_blob_reply(out: str) -> bytes:
    m = re.search(r'blob\s+"', out)
    if not m:
        raise ValueError(f"no blob in reply: {out[:120]!r}")
    data, _ = _read_literal(out, m.end() - 1)
    return data


def blob_literal(data: bytes) -> str:
    return 'blob "' + "".join(f"\\{b:02x}" for b in data) + '"'


def text_literal(s: str) -> str:
    esc = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f'"{esc}"'


def parse_pending_task(out: str):
    out = out.strip()
    if not re.match(r"\(\s*opt\b", out):
        return None
    skeleton, literals = _split_literals(out)
    nums = {}
    for m in re.finditer(r"([\w]+)\s*=\s*([\d_]+)\s*:\s*nat\b", skeleton):
        nums[_field_name(m.group(1))] = int(m.group(2).replace("_", ""))
    tag = re.search(r"([\w]+)\s*=\s*(blob\s+)?\"\"", skeleton)
    if "ticketId" not in nums or "leaseToken" not in nums or not tag or not literals:
        raise ValueError(f"unrecognised PendingTask reply: {skeleton[:200]!r}")
    kind = _field_name(tag.group(1))
    task = {"ticket": nums["ticketId"], "lease": nums["leaseToken"], "attempt": nums.get("attemptCount", 1)}
    if kind == "Private" or tag.group(2):
        task.update(kind="Private", blob=literals[0])
    else:
        task.update(kind="Inspected", text=literals[0].decode("utf-8", "replace"))
    return task


# ----------------------------------------------------------------------------- scanner
_FORMAT_CATS = {"Cf", "Cc", "Co", "Cn"}
_INJECTION = ["ignore previous instructions", "ignore all previous", "ignore the above", "ignore prior instructions",
              "disregard previous", "disregard all prior", "disregard your instructions", "forget your instructions",
              "forget all previous", "reveal your system prompt", "print your system prompt", "developer mode",
              "jailbreak", "do anything now", "you are now", "pretend to be", "system override"]
_DESTRUCTIVE = ["rm -rf", "rm -fr", "rm -r -f", "drop database", "drop table", "truncate table", "mkfs", "dd if=",
                "format c:", "> /dev/sda", ":(){", "shred -", "del /f /s"]
_PRIVILEGE = ["chmod 777", "chmod -r 777", "su root", "su -", "chown root", "setuid", "visudo", "/etc/sudoers"]
_WORDS = {"sudo", "doas", "mkfs"}


def normalize(text: str) -> str:
    t = unicodedata.normalize("NFKC", text).lower()
    t = "".join(" " if ch.isspace() else ch for ch in t if unicodedata.category(ch) not in _FORMAT_CATS or ch.isspace())
    return re.sub(r"\s+", " ", t).strip()


def _scan_one(norm: str):
    for group, pats in (("prompt injection", _INJECTION), ("destructive command", _DESTRUCTIVE), ("privilege escalation", _PRIVILEGE)):
        for p in pats:
            if p in norm:
                return group
    if _WORDS & set(re.findall(r"[a-z0-9]+", norm)):
        return "privilege escalation"
    return None


def scan(text: str):
    norm = normalize(text)
    hit = _scan_one(norm)
    if hit:
        return hit
    for m in re.finditer(r"[A-Za-z0-9+/]{24,}={0,2}", text):
        try:
            hit = _scan_one(normalize(base64.b64decode(m.group(0) + "===", validate=False).decode("utf-8", "ignore")))
        except Exception:
            continue
        if hit:
            return f"{hit} (base64-encoded)"
    for m in re.finditer(r"(?:[0-9a-fA-F]{2}){12,}", text):
        try:
            hit = _scan_one(normalize(bytes.fromhex(m.group(0)).decode("utf-8", "ignore")))
        except Exception:
            continue
        if hit:
            return f"{hit} (hex-encoded)"
    return None


# ----------------------------------------------------------------------------- canister + plumbing
def run(cmd, timeout=60, stdin=None):
    res = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout, cwd=str(PROJECT_ROOT))
    if res.returncode != 0:
        raise RuntimeError(f"{cmd[0]} failed: {res.stderr.strip()[:400]}")
    return res.stdout.strip()


def call_canister(method: str, arg: str | None = None, timeout: int = 90) -> str:
    cmd = [DFX_BIN, "canister", "call", "--network", DFX_NETWORK, "--identity", IDENTITY,
           "--output", "idl", "--quiet", CANISTER_ID, method]
    if arg is not None:
        cmd.append(arg)
    return run(cmd, timeout=timeout)


def helper(payload: dict) -> dict:
    out = run([NODE_BIN, str(HELPER)], timeout=60, stdin=json.dumps(payload))
    return json.loads(out)


_public_key: bytes | None = None


def get_public_key() -> bytes:
    global _public_key
    if _public_key is None:
        _public_key = parse_blob_reply(call_canister("getVetKeyPublicKey"))
    return _public_key


def decrypt_private_prompt(task: dict) -> str:
    seed = os.urandom(32)
    tpk = bytes.fromhex(helper({"cmd": "tpk", "seed": seed.hex()})["tpk"])
    enc_key = parse_blob_reply(call_canister(
        "deriveDaemonKey", f"({task['ticket']} : nat, {task['lease']} : nat, {blob_literal(tpk)})"))
    res = helper({"cmd": "decrypt", "seed": seed.hex(), "ticket": str(task["ticket"]),
                  "publicKey": get_public_key().hex(), "encryptedKey": enc_key.hex(),
                  "ciphertext": task["blob"].hex()})
    return res["plaintext"]


def seal_result(ticket: int, text: str) -> str:
    return helper({"cmd": "encrypt", "publicKey": get_public_key().hex(), "ticket": str(ticket), "plaintext": text})["ciphertext"]


# ----------------------------------------------------------------------------- Setup Wizard
def setup_wizard() -> dict:
    print("==================================================")
    print("         🛡️ ICfirewall Setup Wizard              ")
    print("==================================================")

    # 1. Retrieve dfx principal and prompt user to configure controllers/canisters
    try:
        current_principal = run([DFX_BIN, "identity", "get-principal", "--identity", IDENTITY])
        print(f"🆔 Current active DFX identity ({IDENTITY}) principal:")
        print(f"   👉 {current_principal}")
        print("\n[!] Please ensure this principal is added as a controller/master to your canisters if required.")
    except Exception as e:
        print(f"⚠️ Could not fetch DFX principal automatically: {e}")

    # 2. Canister IDs prompt and persistence to canister_ids.json
    saved_canister_ids = {}
    if CANISTER_IDS_PATH.exists():
        try:
            saved_canister_ids = json.loads(CANISTER_IDS_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass

    # Extract defaults from existing canister_ids.json or environment
    default_backend = CANISTER_ID
    for net_key in [DFX_NETWORK, "local", "ic"]:
        if net_key in saved_canister_ids and isinstance(saved_canister_ids[net_key], dict):
            if saved_canister_ids[net_key].get("relay_backend"):
                default_backend = saved_canister_ids[net_key]["relay_backend"]
                break

    print("\n--- Canister Configuration ---")
    entered_backend = input(f"Enter Backend Canister ID [{default_backend}]: ").strip() or default_backend
    entered_frontend = input(f"Enter Frontend Canister ID [optional]: ").strip()

    # Update global runtime canister ID
    global CANISTER_ID
    CANISTER_ID = entered_backend

    # Save to canister_ids.json in standard DFX multi-network schema format
    canister_data = saved_canister_ids if isinstance(saved_canister_ids, dict) else {}
    if DFX_NETWORK not in canister_data or not isinstance(canister_data[DFX_NETWORK], dict):
        canister_data[DFX_NETWORK] = {}
    
    canister_data[DFX_NETWORK]["relay_backend"] = entered_backend
    if entered_frontend:
        canister_data[DFX_NETWORK]["relay_frontend"] = entered_frontend

    try:
        CANISTER_IDS_PATH.write_text(json.dumps(canister_data, indent=2), encoding="utf-8")
        print(f"✅ Saved canister IDs to {CANISTER_IDS_PATH.name}")
    except Exception as e:
        print(f"⚠️ Warning: Could not save canister_ids.json: {e}")

    # 3. Odysseus Config Setup
    saved_config = {}
    if ODYSSEUS_CONFIG_PATH.exists():
        try:
            saved_config = json.loads(ODYSSEUS_CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass

    default_url = "http://127.0.0.1:7860"
    saved_url = saved_config.get("url", default_url)
    if not saved_url or "/" in saved_url and not saved_url.startswith("http"):
        saved_url = default_url
    
    print("\n--- Odysseus LLM Configuration ---")
    odysseus_url = input(f"Odysseus URL [{saved_url}]: ").strip() or saved_url

    saved_user = saved_config.get("username", "ai")
    if not saved_user or "/" in saved_user:
        saved_user = "ai"
    odysseus_user = input(f"Odysseus Username [{saved_user}]: ").strip() or saved_user

    raw_saved_pass = saved_config.get("password", "bruh1234")
    if not raw_saved_pass or "/" in raw_saved_pass or raw_saved_pass in ("****", "===="):
        raw_saved_pass = "bruh1234"

    entered_pass = getpass.getpass(f"Odysseus Password [saved]: ").strip()
    odysseus_pass = entered_pass if entered_pass else raw_saved_pass

    saved_session = saved_config.get("session_id", "0f51d438-50d7-4847-b74a-c64ca7c722cf")
    if not saved_session or "/" in saved_session:
        saved_session = "0f51d438-50d7-4847-b74a-c64ca7c722cf"
    odysseus_session = input(f"Odysseus Session ID / Chat ID [{saved_session}]: ").strip() or saved_session

    config = {
        "url": odysseus_url.rstrip("/"),
        "username": odysseus_user,
        "password": odysseus_pass,
        "session_id": odysseus_session
    }

    try:
        ODYSSEUS_CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
        print("✅ Saved configuration to odysseus_config.json")
    except Exception as e:
        print(f"⚠️ Warning: Could not save config file: {e}")

    return config


# ----------------------------------------------------------------------------- LLM Client
def clean_model_output(raw_text: str) -> str:
    if not raw_text:
        return ""
    cleaned = re.sub(r'<think>.*?</think>', '', raw_text, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r'<thought>.*?</thought>', '', cleaned, flags=re.DOTALL | re.IGNORECASE)
    return cleaned.strip()


class OdysseusClient:
    """
    Native Odysseus client with required session field in payload.
    """
    LOGIN_PATH = "/api/auth/login"
    MODELS_PATH = "/api/models"
    COMPLETION_ROUTES = ["/api/chat", "/api/v1/chat/completions", "/api/chat/completions"]

    def __init__(self, config: dict):
        self.url = (config.get("url") or "http://127.0.0.1:7860").strip().rstrip("/")
        self.username = (config.get("username") or "ai").strip()
        self.password = (config.get("password") or "").strip()
        self.session_id = (config.get("session_id") or "").strip()
        self.model = ""
        self.active_completion_route = ""
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "ICfirewall-Daemon/8.45"
        })

        self._authenticate()
        self._discover_model()
        print(f"✅ Native Odysseus ready: {self.url} | user={self.username} | model={self.model} | chat={self.session_id or '(none)'}")

    def _authenticate(self) -> None:
        login_url = f"{self.url}{self.LOGIN_PATH}"
        payload = {"username": self.username, "password": self.password}
        try:
            res = self.session.post(login_url, json=payload, timeout=15)
            if res.status_code == 200:
                data = res.json()
                if data.get("ok"):
                    print(f"✅ Odysseus session established for user '{self.username}'")
                    return
            raise RuntimeError(f"Login failed HTTP {res.status_code}: {res.text[:200]}")
        except Exception as e:
            raise RuntimeError(f"Cannot authenticate with Odysseus at {login_url}: {e}") from e

    def _discover_model(self) -> None:
        try:
            res = self.session.get(f"{self.url}{self.MODELS_PATH}", timeout=15)
            if res.status_code == 200:
                data = res.json()
                items = data.get("items") or data.get("data") or []
                extracted_models = []
                for entry in items:
                    if isinstance(entry, dict):
                        models_list = entry.get("models") or []
                        if isinstance(models_list, list):
                            extracted_models.extend(models_list)
                        elif isinstance(entry.get("id"), str):
                            extracted_models.append(entry["id"])

                override = os.getenv("ICF_MODEL_OVERRIDE", "").strip()
                if override and override in extracted_models:
                    self.model = override
                elif extracted_models:
                    self.model = extracted_models[0]
                else:
                    self.model = "default"
                print(f"✅ Selected model: {self.model}")
                return
        except Exception as e:
            print(f"⚠️ Model discovery warning: {e}")
        self.model = os.getenv("ICF_MODEL_OVERRIDE", "default")

    def complete(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "message": prompt,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }
        if self.session_id:
            payload["session"] = self.session_id
            payload["chat_id"] = self.session_id
            payload["session_id"] = self.session_id

        routes = [self.active_completion_route] if self.active_completion_route else self.COMPLETION_ROUTES
        
        last_error = None
        for route in routes:
            if not route:
                continue
            url = f"{self.url}{route}"
            try:
                res = self.session.post(url, json=payload, timeout=300)
                if res.status_code == 401:
                    print("⚠️ 401 Session expired — re-authenticating...")
                    self._authenticate()
                    res = self.session.post(url, json=payload, timeout=300)
                
                if res.status_code == 200:
                    self.active_completion_route = route
                    data = res.json()
                    content = self._extract_content(data)
                    reply = clean_model_output(content)
                    if reply:
                        return reply[:MAX_REPLY_CHARS]
                elif res.status_code != 404:
                    last_error = f"HTTP {res.status_code}: {res.text[:300]}"
            except Exception as e:
                last_error = str(e)

        raise RuntimeError(f"Completion failed across all routes. Last error: {last_error}")

    @staticmethod
    def _extract_content(data: dict) -> str:
        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            msg = choices[0].get("message") or {}
            if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                return msg["content"]
            if isinstance(choices[0].get("content"), str):
                return choices[0]["content"]
        for key in ("response", "content", "output", "text"):
            v = data.get(key)
            if isinstance(v, str) and v:
                return v
        if isinstance(data.get("message"), dict) and isinstance(data["message"].get("content"), str):
            return data["message"]["content"]
        return ""


# ----------------------------------------------------------------------------- main loop
def handle(task: dict, llm: OdysseusClient):
    ticket, lease, private = task["ticket"], task["lease"], task["kind"] == "Private"
    print(f"Task #{ticket} ({task['kind']}, lease {lease}, attempt {task['attempt']})")
    try:
        prompt = decrypt_private_prompt(task) if private else task["text"]
        reason = scan(prompt) if DAEMON_SCAN else None
        
        if reason:
            print(f"🚨 Blocked threat on task #{ticket}: {reason}")
            reply = f"BLOCKED: Security violation detected ({reason})"
        else:
            print(f"🤖 Processing prompt for task #{ticket}...")
            reply = llm.complete(prompt)

        if private:
            sealed = seal_result(ticket, reply)
            call_canister("savePrivateResult", f"({ticket} : nat, {lease} : nat, {text_literal(sealed)})")
        else:
            call_canister("saveInspectedResult", f"({ticket} : nat, {lease} : nat, {text_literal(reply)})")
        print(f"✅ Completed task #{ticket}")

    except Exception as e:
        print(f"❌ Error handling task #{ticket}: {e}")
        try:
            call_canister("reportFailure", f"({ticket} : nat, {lease} : nat, {text_literal(str(e))})")
        except Exception as inner:
            print(f"⚠️ Failed to report failure to canister: {inner}")


def main():
    config = setup_wizard()
    llm = OdysseusClient(config)

    print(f"\n🚀 ICfirewall daemon polling active. Canister: {CANISTER_ID}, Identity: {IDENTITY}, Network: {DFX_NETWORK}")
    while not should_exit:
        try:
            out = call_canister("getPendingPrompt", timeout=30)
            task = parse_pending_task(out)
            if task:
                handle(task, llm)
            else:
                time.sleep(2)
        except Exception as e:
            if not should_exit:
                print(f"⚠️ Polling error: {e}")
                time.sleep(5)

    print("👋 Daemon exited cleanly.")


if __name__ == "__main__":
    main()
