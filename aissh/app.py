import base64
import io
import json
import os
import functools
import re
import requests as _requests
import shutil
import subprocess
import threading
import time as _time
import uuid
import zipfile
from datetime import datetime
from pathlib import Path
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    jsonify,
    flash,
    Response,
    stream_with_context,
)
from flask_sock import Sock
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

import paramiko

load_dotenv()


# ---------------------------------------------------------------------------
# PEM key loader
# ---------------------------------------------------------------------------


def _load_pkey(key_str: str) -> paramiko.PKey:
    """Try parsing a PEM private key across all common key types."""
    key_classes = [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey]
    # DSSKey was removed in paramiko 4.x
    if hasattr(paramiko, "DSSKey"):
        key_classes.append(paramiko.DSSKey)
    for cls in key_classes:
        try:
            return cls.from_private_key(io.StringIO(key_str))
        except Exception:
            continue
    raise ValueError(
        "Could not load private key — unsupported format or requires passphrase"
    )


def _ssh_connect(client: paramiko.SSHClient, server: dict, timeout: int = 10):
    """Connect a paramiko client using password or PEM key from server dict."""
    conn = dict(
        hostname=server["host"],
        port=server.get("port", 22),
        username=server["user"],
        timeout=timeout,
    )
    pem = server.get("pem_key", "")
    if pem:
        conn["pkey"] = _load_pkey(pem)
    else:
        conn["password"] = server.get("password", "")
    client.connect(**conn)


# ---------------------------------------------------------------------------
# Persistent SSH connection pool for stats polling
# ---------------------------------------------------------------------------
_stats_pool: dict = {}  # (user_id, server_name) → paramiko.SSHClient
_stats_pool_lock = threading.Lock()


def _get_stats_conn(user_id: str, server: dict) -> paramiko.SSHClient:
    """Return a live SSH connection for stats, reusing existing one if healthy."""
    key = (user_id, server["name"])
    client = _stats_pool.get(key)
    if client:
        transport = client.get_transport()
        if transport and transport.is_active():
            return client
        try:
            client.close()
        except Exception:
            pass
        del _stats_pool[key]
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    _ssh_connect(client, server, timeout=5)
    _stats_pool[key] = client
    return client


def _ssh_exec(uid: str, server: dict, cmd: str, timeout: int = 15) -> dict:
    """Run a command on a server, return {stdout, stderr, exit_code}."""
    try:
        client = _get_stats_conn(uid, server)
        _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        return {
            "stdout": stdout.read().decode("utf-8", errors="replace").strip(),
            "stderr": stderr.read().decode("utf-8", errors="replace").strip(),
            "exit_code": exit_code,
        }
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "exit_code": -1}


# ---------------------------------------------------------------------------
# Persistent stats stream — one SSH loop per server, cached in memory
# ---------------------------------------------------------------------------
_stats_cache: dict = {}  # (uid, server_name) → latest parsed dict
_stats_threads: dict = {}  # (uid, server_name) → threading.Thread
_stats_stop: dict = {}  # (uid, server_name) → threading.Event
_stats_lock = threading.Lock()  # protects _stats_cache, _stats_threads, _stats_stop

_STATS_LOOP_SCRIPT = (
    "import time,shutil,json,os,sys\n"
    "while True:\n"
    "  try:\n"
    "    s=open('/proc/stat').readline().split();c=[int(x)for x in s[1:]]\n"
    "    t1,i1=sum(c),c[3]\n"
    "    n1={p[0].rstrip(':'):(int(p[1]),int(p[9]))for p in[l.split()for l in open('/proc/net/dev').readlines()[2:]]if len(p)>=10 and p[0].rstrip(':')!='lo'}\n"
    "    time.sleep(2)\n"
    "    s=open('/proc/stat').readline().split();c=[int(x)for x in s[1:]]\n"
    "    t2,i2=sum(c),c[3]\n"
    "    n2={p[0].rstrip(':'):(int(p[1]),int(p[9]))for p in[l.split()for l in open('/proc/net/dev').readlines()[2:]]if len(p)>=10 and p[0].rstrip(':')!='lo'}\n"
    "    cpu=round(100*(1-(i2-i1)/(t2-t1)))\n"
    "    net={k:{'rx_speed':round((n2[k][0]-n1[k][0])/2048,1),'tx_speed':round((n2[k][1]-n1[k][1])/2048,1)}for k in n2 if k in n1}\n"
    "    m={l.split(':')[0].strip():int(l.split()[1])for l in open('/proc/meminfo')if len(l.split())>=2}\n"
    "    used=(m['MemTotal']-m['MemAvailable'])//1024\n"
    "    total=m['MemTotal']//1024\n"
    "    swap_used=(m.get('SwapTotal',0)-m.get('SwapFree',0))//1024\n"
    "    swap_total=m.get('SwapTotal',0)//1024\n"
    "    load=open('/proc/loadavg').read().split()[0]\n"
    "    d=shutil.disk_usage('/');disk_used=d.used//1048576;disk_total=d.total//1048576\n"
    "    cores=os.cpu_count()\n"
    "    uptime=int(float(open('/proc/uptime').read().split()[0]))\n"
    "    conns=len(open('/proc/net/tcp').readlines())-1+len(open('/proc/net/tcp6').readlines())-1\n"
    "    print(json.dumps({'cpu':cpu,'ram_used':used,'ram_total':total,'swap_used':swap_used,'swap_total':swap_total,'load':load,'disk_used':disk_used,'disk_total':disk_total,'cores':cores,'uptime':uptime,'network':net,'connections':conns}),flush=True)\n"
    "  except Exception as e:\n"
    "    print(json.dumps({'error':str(e)}),flush=True)\n"
    "    time.sleep(2)\n"
)


def _stats_stream_worker(uid: str, server: dict, stop_event: threading.Event):
    """Background thread: run a looping stats script on the remote, cache output."""
    key = (uid, server["name"])
    while not stop_event.is_set():
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            _ssh_connect(client, server, timeout=10)
            stdin, stdout, _ = client.exec_command("python3 -u -")
            stdin.write(_STATS_LOOP_SCRIPT)
            stdin.channel.shutdown_write()
            for line in stdout:
                if stop_event.is_set():
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    _stats_cache[key] = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    pass
            client.close()
        except Exception:
            pass
        # Wait before reconnecting (unless stopped)
        stop_event.wait(5)
    _stats_cache.pop(key, None)


def _ensure_stats_stream(uid: str, server: dict):
    """Start the stats stream thread for a server if not already running."""
    key = (uid, server["name"])
    with _stats_lock:
        t = _stats_threads.get(key)
        if t and t.is_alive():
            return
        # Clean up old thread/event
        old_stop = _stats_stop.pop(key, None)
        if old_stop:
            old_stop.set()
        stop_event = threading.Event()
        _stats_stop[key] = stop_event
        t = threading.Thread(
            target=_stats_stream_worker,
            args=(uid, server, stop_event),
            daemon=True,
            name=f"stats-{uid}-{server['name']}",
        )
        t.start()
        _stats_threads[key] = t
    _stats_threads[key] = t


def _stop_stats_stream(uid: str, name: str):
    """Stop the stats stream for a server."""
    key = (uid, name)
    stop_event = _stats_stop.pop(key, None)
    if stop_event:
        stop_event.set()
    _stats_threads.pop(key, None)
    _stats_cache.pop(key, None)


BASE = Path(__file__).parent
USERS_FILE = BASE / "users.json"
APP_SETTINGS_FILE = BASE / "app_settings.json"
ENV_FILE = BASE / ".env"
DATA_DIR = BASE / "data"
CHATS_DIR = BASE / "chats"
MEMORY_DIR = BASE / "memories"

CHATS_DIR.mkdir(exist_ok=True)
MEMORY_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# App-level settings (persistent secret key)
# ---------------------------------------------------------------------------


def _load_app_settings() -> dict:
    if not APP_SETTINGS_FILE.exists():
        return {}
    try:
        return json.loads(APP_SETTINGS_FILE.read_text())
    except Exception:
        return {}


def _save_app_settings(s: dict):
    APP_SETTINGS_FILE.write_text(json.dumps(s, indent=2))


def _get_or_create_secret_key() -> str:
    s = _load_app_settings()
    if "secret_key" not in s:
        s["secret_key"] = os.urandom(24).hex()
        _save_app_settings(s)
    return s["secret_key"]


app = Flask(__name__)
app.secret_key = _get_or_create_secret_key()
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB upload limit
sock = Sock(app)


@app.after_request
def _set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.errorhandler(404)
def _page_not_found(e):
    if request.accept_mimetypes.best == "application/json":
        return jsonify({"error": "Not found"}), 404
    return render_template("base.html", error_code=404, error_msg="Page not found"), 404


@app.errorhandler(413)
def _file_too_large(e):
    return jsonify({"error": "File too large. Maximum upload size is 50 MB."}), 413


@app.errorhandler(500)
def _internal_error(e):
    if request.accept_mimetypes.best == "application/json":
        return jsonify({"error": "Internal server error"}), 500
    return render_template(
        "base.html", error_code=500, error_msg="Internal server error"
    ), 500


login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = ""


# ---------------------------------------------------------------------------
# User model
# ---------------------------------------------------------------------------


class User(UserMixin):
    def __init__(self, id: str, username: str, password_hash: str, is_admin: bool):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.is_admin = is_admin


# ---------------------------------------------------------------------------
# User helpers
# ---------------------------------------------------------------------------


def load_users() -> list:
    if not USERS_FILE.exists():
        return []
    try:
        return json.loads(USERS_FILE.read_text())
    except Exception:
        return []


def save_users(users: list):
    USERS_FILE.write_text(json.dumps(users, indent=2))


def get_user_by_id(uid: str) -> "User | None":
    for u in load_users():
        if u["id"] == uid:
            return User(
                u["id"], u["username"], u["password_hash"], u.get("is_admin", False)
            )
    return None


def get_user_by_username(username: str) -> "User | None":
    for u in load_users():
        if u["username"] == username:
            return User(
                u["id"], u["username"], u["password_hash"], u.get("is_admin", False)
            )
    return None


@login_manager.user_loader
def user_loader(uid: str) -> "User | None":
    return get_user_by_id(uid)


# ---------------------------------------------------------------------------
# Default admin + migration
# ---------------------------------------------------------------------------


def ensure_default_admin():
    users = load_users()
    if not users:
        # Generate a random password and print it once to the console
        import secrets

        default_pw = os.environ.get("AISSH_ADMIN_PASSWORD", secrets.token_urlsafe(12))
        users = [
            {
                "id": "1",
                "username": "admin",
                "password_hash": generate_password_hash(default_pw),
                "is_admin": True,
            }
        ]
        save_users(users)
        print("=" * 50)
        print("  AISSH -- Default admin account created")
        print(f"  Username: admin")
        print(f"  Password: {default_pw}")
        print("  Change this password immediately in Settings!")
        print("=" * 50)


def _migrate_legacy():
    """Migrate pre-multiuser data into data/1/ (admin's directory)."""
    uid = "1"

    # Migrate servers.json
    old_servers = BASE / "servers.json"
    if old_servers.exists():
        new_servers = _servers_file(uid)
        if not new_servers.exists():
            new_servers.parent.mkdir(parents=True, exist_ok=True)
            new_servers.write_text(old_servers.read_text())

    # Migrate settings (ai_provider) + API keys from .env
    new_user_settings = _user_settings_file(uid)
    if not new_user_settings.exists():
        new_user_settings.parent.mkdir(parents=True, exist_ok=True)
        user_settings = {}
        old_settings = BASE / "settings.json"
        if old_settings.exists():
            try:
                old_s = json.loads(old_settings.read_text())
                if "ai_provider" in old_s:
                    user_settings["ai_provider"] = old_s["ai_provider"]
            except Exception:
                pass
        # Migrate API keys from .env
        if ENV_FILE.exists():
            load_dotenv(ENV_FILE, override=True)
        anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
        deepseek_key = os.environ.get("DEEPSEEK_API_KEY", "")
        if anthropic_key:
            user_settings["anthropic_api_key"] = anthropic_key
        if deepseek_key:
            user_settings["deepseek_api_key"] = deepseek_key
        new_user_settings.write_text(json.dumps(user_settings, indent=2))

    # Migrate chats/*.json → chats/1/*.json
    new_chats_dir = CHATS_DIR / uid
    new_chats_dir.mkdir(exist_ok=True)
    for f in CHATS_DIR.iterdir():
        if f.is_file() and f.suffix == ".json":
            dest = new_chats_dir / f.name
            if not dest.exists():
                dest.write_text(f.read_text())

    # Migrate memories/*.md → memories/1/*.md
    new_mem_dir = MEMORY_DIR / uid
    new_mem_dir.mkdir(exist_ok=True)
    for f in MEMORY_DIR.iterdir():
        if f.is_file() and f.suffix == ".md":
            dest = new_mem_dir / f.name
            if not dest.exists():
                dest.write_text(f.read_text())


# ---------------------------------------------------------------------------
# Per-user data path helpers
# ---------------------------------------------------------------------------


def _servers_file(uid: str) -> Path:
    return DATA_DIR / uid / "servers.json"


def _user_settings_file(uid: str) -> Path:
    return DATA_DIR / uid / "settings.json"


def _chat_file(uid: str, name: str) -> Path:
    slug = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
    return CHATS_DIR / uid / f"{slug}.json"


def _memory_file(uid: str, name: str) -> Path:
    slug = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
    return MEMORY_DIR / uid / f"{slug}.md"


# ---------------------------------------------------------------------------
# Per-user data helpers
# ---------------------------------------------------------------------------


def load_servers(uid: str) -> list:
    f = _servers_file(uid)
    if not f.exists():
        return []
    try:
        return json.loads(f.read_text())
    except Exception:
        return []


def save_servers(uid: str, servers: list):
    f = _servers_file(uid)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(servers, indent=2))


def get_server(uid: str, name: str) -> "dict | None":
    return next((s for s in load_servers(uid) if s["name"] == name), None)


def _load_user_settings(uid: str) -> dict:
    f = _user_settings_file(uid)
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text())
    except Exception:
        return {}


def _save_user_settings(uid: str, s: dict):
    f = _user_settings_file(uid)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(s, indent=2))


def get_api_key(uid: str) -> str:
    return _load_user_settings(uid).get("anthropic_api_key", "")


def save_api_key(uid: str, key: str):
    s = _load_user_settings(uid)
    s["anthropic_api_key"] = key
    _save_user_settings(uid, s)


def get_deepseek_key(uid: str) -> str:
    return _load_user_settings(uid).get("deepseek_api_key", "")


def save_deepseek_key(uid: str, key: str):
    s = _load_user_settings(uid)
    s["deepseek_api_key"] = key
    _save_user_settings(uid, s)


def get_provider(uid: str) -> str:
    return _load_user_settings(uid).get("ai_provider", "anthropic")


def save_provider(uid: str, p: str):
    s = _load_user_settings(uid)
    s["ai_provider"] = p
    _save_user_settings(uid, s)


# ---------------------------------------------------------------------------
# AI Provider Registry
# ---------------------------------------------------------------------------
# Each provider uses either the Anthropic SDK or the OpenAI-compatible SDK.
# format: "anthropic" = uses anthropic SDK, "openai" = uses openai-compatible SDK

AI_PROVIDERS = {
    "anthropic": {
        "label": "Anthropic (Claude)",
        "format": "anthropic",
        "base_url": None,
        "key_setting": "anthropic_api_key",
        "placeholder": "sk-ant-...",
        "models": [
            {"id": "claude-haiku-4-5-20250315", "label": "Claude Haiku 4.5"},
            {"id": "claude-sonnet-4-6-20250514", "label": "Claude Sonnet 4.6"},
            {"id": "claude-opus-4-6-20250514", "label": "Claude Opus 4.6"},
        ],
    },
    "openai": {
        "label": "OpenAI",
        "format": "openai",
        "base_url": "https://api.openai.com/v1",
        "key_setting": "openai_api_key",
        "placeholder": "sk-...",
        "models": [
            {"id": "gpt-4o", "label": "GPT-4o"},
            {"id": "gpt-4o-mini", "label": "GPT-4o Mini"},
            {"id": "gpt-4.1", "label": "GPT-4.1"},
            {"id": "gpt-4.1-mini", "label": "GPT-4.1 Mini"},
            {"id": "o3-mini", "label": "o3-mini"},
        ],
    },
    "deepseek": {
        "label": "DeepSeek",
        "format": "openai",
        "base_url": "https://api.deepseek.com/v1",
        "key_setting": "deepseek_api_key",
        "placeholder": "sk-...",
        "models": [
            {"id": "deepseek-chat", "label": "DeepSeek V3"},
            {"id": "deepseek-reasoner", "label": "DeepSeek R1"},
        ],
    },
    "kimi": {
        "label": "Kimi (Moonshot)",
        "format": "openai",
        "base_url": "https://api.moonshot.cn/v1",
        "key_setting": "kimi_api_key",
        "placeholder": "sk-...",
        "models": [
            {"id": "moonshot-v1-auto", "label": "Kimi Auto"},
            {"id": "moonshot-v1-8k", "label": "Kimi 8K"},
            {"id": "moonshot-v1-32k", "label": "Kimi 32K"},
        ],
    },
    "minimax": {
        "label": "MiniMax",
        "format": "openai",
        "base_url": "https://api.minimax.chat/v1",
        "key_setting": "minimax_api_key",
        "placeholder": "eyJ...",
        "models": [
            {"id": "MiniMax-Text-01", "label": "MiniMax Text 01"},
            {"id": "abab6.5s-chat", "label": "ABAB 6.5s"},
        ],
    },
    "groq": {
        "label": "Groq",
        "format": "openai",
        "base_url": "https://api.groq.com/openai/v1",
        "key_setting": "groq_api_key",
        "placeholder": "gsk_...",
        "models": [
            {"id": "llama-3.3-70b-versatile", "label": "Llama 3.3 70B"},
            {"id": "llama-3.1-8b-instant", "label": "Llama 3.1 8B"},
            {"id": "mixtral-8x7b-32768", "label": "Mixtral 8x7B"},
        ],
    },
    "custom": {
        "label": "Custom (OpenAI-compatible)",
        "format": "openai",
        "base_url": None,  # user provides
        "key_setting": "custom_api_key",
        "placeholder": "your-api-key",
        "models": [],  # user provides model name
    },
}

DEFAULT_MODEL = "claude-sonnet-4-6-20250514"


# Flat list for settings UI
def _build_model_options():
    opts = []
    for pid, prov in AI_PROVIDERS.items():
        for m in prov["models"]:
            opts.append(
                {
                    "id": f"{pid}:{m['id']}",
                    "label": f"{m['label']}",
                    "provider": pid,
                    "provider_label": prov["label"],
                }
            )
    return opts


MODEL_OPTIONS = _build_model_options()


def get_model(uid: str) -> str:
    return _load_user_settings(uid).get("ai_model", "")


def save_model(uid: str, model: str):
    s = _load_user_settings(uid)
    s["ai_model"] = model
    _save_user_settings(uid, s)


def get_thinking(uid: str) -> bool:
    return _load_user_settings(uid).get("thinking_enabled", False)


def save_thinking(uid: str, enabled: bool):
    s = _load_user_settings(uid)
    s["thinking_enabled"] = enabled
    _save_user_settings(uid, s)


def get_do_key(uid: str) -> str:
    return _load_user_settings(uid).get("digitalocean_api_key", "")


def save_do_key(uid: str, key: str):
    s = _load_user_settings(uid)
    s["digitalocean_api_key"] = key
    _save_user_settings(uid, s)


# ---------------------------------------------------------------------------
# Chat history + memory
# ---------------------------------------------------------------------------


def load_history(uid: str, name: str) -> list:
    f = _chat_file(uid, name)
    if not f.exists():
        return []
    try:
        return json.loads(f.read_text())
    except Exception:
        return []


def clear_history(uid: str, name: str):
    f = _chat_file(uid, name)
    if f.exists():
        f.unlink()


def load_memory(uid: str, name: str) -> str:
    f = _memory_file(uid, name)
    if not f.exists():
        return ""
    try:
        return f.read_text(encoding="utf-8")
    except Exception:
        return ""


def save_memory(uid: str, name: str, content: str):
    f = _memory_file(uid, name)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Admin decorator
# ---------------------------------------------------------------------------


def admin_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login"))
        if not current_user.is_admin:
            flash("Admin access required.", "error")
            return redirect(url_for("index"))
        return f(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------


@app.route("/terminal/<name>")
@login_required
def terminal_proxy(name):
    """Redirect to xterm.js terminal service."""
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        return "Server not found", 404

    # Redirect to external terminal service if configured
    from flask import redirect as flask_redirect

    terminal_host = os.environ.get("AISSH_TERMINAL_HOST", "127.0.0.1")
    terminal_port = int(os.environ.get("AISSH_TERMINAL_PORT", "3000"))
    target_host = server["host"]
    target_user = server["user"]
    target_port = server.get("port", 22)
    return flask_redirect(
        f"http://{terminal_host}:{terminal_port}/terminal?host={target_host}&user={target_user}&port={target_port}",
        code=307,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        pw = request.form.get("password", "")
        user = get_user_by_username(username)
        if user and check_password_hash(user.password_hash, pw):
            login_user(user, remember=True)
            return redirect(url_for("index"))
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Server list
# ---------------------------------------------------------------------------


@app.route("/")
@login_required
def index():
    return render_template("index.html", servers=load_servers(current_user.id))


@app.route("/servers/add", methods=["POST"])
@login_required
def servers_add():
    uid = current_user.id
    name = request.form.get("name", "").strip()
    host = request.form.get("host", "").strip()
    port = request.form.get("port", "22").strip()
    user = request.form.get("user", "").strip()
    password = request.form.get("password", "")
    pem_key = ""

    pem_file = request.files.get("pem_file")
    if pem_file and pem_file.filename:
        pem_key = pem_file.read().decode("utf-8", errors="replace").strip()

    if not name or not host or not user:
        flash("Name, host, and user are required.", "error")
        return redirect(url_for("index"))

    if not password and not pem_key:
        flash("Provide either a password or a PEM key.", "error")
        return redirect(url_for("index"))

    servers = load_servers(uid)
    if any(s["name"] == name for s in servers):
        flash(f"A server named '{name}' already exists.", "error")
        return redirect(url_for("index"))

    servers.append(
        {
            "name": name,
            "host": host,
            "port": int(port) if port.isdigit() else 22,
            "user": user,
            "password": password,
            "pem_key": pem_key,
        }
    )
    save_servers(uid, servers)
    flash(f"Server '{name}' added.", "success")
    return redirect(url_for("index"))


@app.route("/servers/<name>/delete", methods=["POST"])
@login_required
def servers_delete(name):
    uid = current_user.id
    servers = [s for s in load_servers(uid) if s["name"] != name]
    save_servers(uid, servers)
    clear_history(uid, name)
    # Clean up stats stream and cached connections for this server
    key = (uid, name)
    with _stats_lock:
        stop_ev = _stats_stop.pop(key, None)
        if stop_ev:
            stop_ev.set()
        _stats_threads.pop(key, None)
        _stats_cache.pop(key, None)
    with _stats_pool_lock:
        client = _stats_pool.pop(key, None)
        if client:
            try:
                client.close()
            except Exception:
                pass
    flash(f"Server '{name}' deleted.", "success")
    return redirect(url_for("index"))


@app.route("/servers/<name>/edit", methods=["GET", "POST"])
@login_required
def servers_edit(name):
    uid = current_user.id
    servers = load_servers(uid)
    server = next((s for s in servers if s["name"] == name), None)
    if not server:
        flash("Server not found.", "error")
        return redirect(url_for("index"))

    if request.method == "POST":
        new_name = request.form.get("name", "").strip()
        new_host = request.form.get("host", "").strip()
        new_port = request.form.get("port", "22").strip()
        new_user = request.form.get("user", "").strip()
        new_password = request.form.get("password", "")
        auth_type = request.form.get("auth_type", "password")

        if not new_name or not new_host or not new_user:
            flash("Name, host, and user are required.", "error")
            return render_template("edit.html", server=server)

        if new_name != name and any(s["name"] == new_name for s in servers):
            flash(f"A server named '{new_name}' already exists.", "error")
            return render_template("edit.html", server=server)

        server["name"] = new_name
        server["host"] = new_host
        server["port"] = int(new_port) if new_port.isdigit() else 22
        server["user"] = new_user

        if auth_type == "pem":
            pem_file = request.files.get("pem_file")
            if pem_file and pem_file.filename:
                server["pem_key"] = (
                    pem_file.read().decode("utf-8", errors="replace").strip()
                )
                server["password"] = ""
            # else: keep existing pem_key unchanged
        else:
            # Password auth
            if new_password:
                server["password"] = new_password
            server["pem_key"] = ""  # clear any stored key

        save_servers(uid, servers)
        if new_name != name:
            clear_history(uid, name)
        flash(f"Server '{new_name}' updated.", "success")
        return redirect(url_for("index"))

    return render_template("edit.html", server=server)


# ---------------------------------------------------------------------------
# Chat
# ---------------------------------------------------------------------------


@app.route("/chat/<name>", methods=["GET"])
@login_required
def chat_page(name):
    """Terminal page - embeds ttyd for SSH connection."""
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        flash("Server not found.", "error")
        return redirect(url_for("index"))

    return render_template(
        "terminal.html",
        server=server,
        terminal_url=f"/terminal/{name}",
        port=0,
    )


@app.route("/multi-terminal")
@login_required
def multi_terminal():
    uid = current_user.id
    servers = load_servers(uid)
    selected = request.args.getlist("s")
    if not selected:
        selected = [s["name"] for s in servers[:4]]
    return render_template(
        "multi.html",
        servers=servers,
        selected=selected,
    )


# ---------------------------------------------------------------------------
# WebSocket terminal
# ---------------------------------------------------------------------------


@sock.route("/ws/terminal/<name>")
def ws_terminal(ws, name):
    if not current_user.is_authenticated:
        ws.close()
        return
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        ws.send("\r\n\x1b[31mServer not found.\x1b[0m\r\n")
        return

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        _ssh_connect(client, server, timeout=10)
    except Exception as e:
        ws.send(f"\r\n\x1b[31mSSH connection failed: {e}\x1b[0m\r\n")
        return

    channel = client.invoke_shell(term="xterm-256color", width=220, height=50)
    channel.setblocking(False)
    stop = threading.Event()

    def _ssh_to_ws():
        while not stop.is_set():
            try:
                if channel.recv_ready():
                    data = channel.recv(4096)
                    if not data:
                        break
                    ws.send(data.decode(errors="replace"))
                elif channel.exit_status_ready():
                    break
                else:
                    _time.sleep(0.01)
            except Exception:
                break
        stop.set()
        try:
            ws.close()
        except Exception:
            pass

    t = threading.Thread(target=_ssh_to_ws, daemon=True)
    t.start()

    try:
        while not stop.is_set():
            data = ws.receive()
            if data is None:
                break
            if isinstance(data, str) and data.startswith("RESIZE:"):
                try:
                    _, cols, rows = data.split(":")
                    channel.resize_pty(width=int(cols), height=int(rows))
                except Exception:
                    pass
            else:
                channel.send(data if isinstance(data, bytes) else data.encode())
    except Exception:
        pass
    finally:
        stop.set()
        try:
            channel.close()
        except Exception:
            pass
        try:
            client.close()
        except Exception:
            pass


def _find_ai_cli() -> str | None:
    """Find opencode or claude CLI binary."""
    search_paths = [
        os.path.expanduser("~/.opencode/bin"),
        os.path.expanduser("~/.local/bin"),
        "/usr/local/bin",
        "/usr/bin",
    ]
    for cmd in ["opencode", "claude"]:
        found = shutil.which(cmd)
        if found:
            return found
        for p in search_paths:
            full = os.path.join(p, cmd)
            if os.path.isfile(full) and os.access(full, os.X_OK):
                return full
    return None


# Track which server has an active AI session per user: uid -> server_name
_active_ai_sessions: dict = {}


def _kill_ai_session(uid, name):
    """Kill the tmux AI session and orphaned processes for a given user+server."""
    safe_name = re.sub(r"[^a-zA-Z0-9]", "_", name)
    session = f"aissh_ai_{uid}_{safe_name}"
    work_dir = os.path.join(os.path.expanduser("~"), ".aissh_ai_sessions", session)
    subprocess.run(
        ["tmux", "kill-session", "-t", session], capture_output=True, timeout=5
    )
    try:
        for pid_str in os.listdir("/proc"):
            if not pid_str.isdigit():
                continue
            try:
                cwd = os.readlink(f"/proc/{pid_str}/cwd")
                if cwd == work_dir:
                    os.kill(int(pid_str), 9)
            except (OSError, ValueError):
                pass
    except Exception:
        pass
    # Don't delete work_dir -- keep CLAUDE.md for resume
    if _active_ai_sessions.get(uid) == name:
        _active_ai_sessions.pop(uid, None)


def _ensure_ai_session(uid, name, server, ai_cli):
    """Ensure a tmux session with opencode exists for this user+server. Returns session name."""
    safe_name = re.sub(r"[^a-zA-Z0-9]", "_", name)
    session = f"aissh_ai_{uid}_{safe_name}"

    # Check if session already exists
    check = subprocess.run(
        ["tmux", "has-session", "-t", session],
        capture_output=True,
        timeout=3,
    )
    if check.returncode == 0:
        return session  # already running

    # Create working directory with CLAUDE.md context
    work_dir = os.path.join(os.path.expanduser("~"), ".aissh_ai_sessions", session)
    os.makedirs(work_dir, exist_ok=True)

    host = server["host"]
    port = server.get("port", 22)
    user = server["user"]
    password = server.get("password", "")
    pem = server.get("pem_key", "")

    ssh_cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no"
    if port != 22:
        ssh_cmd += f" -p {port}"
    ssh_cmd += f" {user}@{host}"
    if pem:
        key_path = os.path.join(work_dir, ".ssh_key")
        with open(key_path, "w") as f:
            f.write(pem)
        os.chmod(key_path, 0o600)
        ssh_cmd = f"ssh -o StrictHostKeyChecking=no -i {key_path}"
        if port != 22:
            ssh_cmd += f" -p {port}"
        ssh_cmd += f" {user}@{host}"

    scp_cmd = f"sshpass -p '{password}' scp -o StrictHostKeyChecking=no"
    if port != 22:
        scp_cmd += f" -P {port}"
    if pem:
        scp_cmd = f"scp -o StrictHostKeyChecking=no -i {key_path}"
        if port != 22:
            scp_cmd += f" -P {port}"

    claude_md = f"""# Server: {name}
# Connection: {user}@{host}:{port}

You are an AI assistant managing a REMOTE Linux server called "{name}".
You are NOT running on the target server. You are running on the AISSH host machine.

## How to run commands on the server

Every command you want to run on the server MUST be wrapped with SSH:

```bash
{ssh_cmd} "COMMAND_HERE"
```

Examples:
```bash
# Check disk space
{ssh_cmd} "df -h"

# View a file
{ssh_cmd} "cat /etc/nginx/nginx.conf"

# Restart a service
{ssh_cmd} "systemctl restart nginx"

# Install a package
{ssh_cmd} "apt-get install -y htop"

# Check running processes
{ssh_cmd} "ps aux | head -20"
```

## How to copy files to/from the server

```bash
# Upload file to server
{scp_cmd} localfile {user}@{host}:/remote/path

# Download file from server
{scp_cmd} {user}@{host}:/remote/path localfile
```

## Important
- ALWAYS prefix commands with the SSH wrapper above
- Do NOT run commands directly (they would run on the AISSH host, not the target server)
- The server is: {user}@{host} on port {port}
- Server name in AISSH: {name}
"""
    with open(os.path.join(work_dir, "CLAUDE.md"), "w") as f:
        f.write(claude_md)

    cli_dir = os.path.dirname(ai_cli)
    path_env = cli_dir + ":" + os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")

    # Always use --continue so it resumes the last session in this HOME.
    # Each server has its own HOME (work_dir) so sessions never cross.
    launch_cmd = f"export HOME={work_dir} PATH={path_env} && {ai_cli} --continue"

    # Create tmux session
    subprocess.run(
        [
            "tmux",
            "new-session",
            "-d",
            "-s",
            session,
            "-c",
            work_dir,
            launch_cmd,
        ],
        env={
            **os.environ,
            "HOME": work_dir,
            "PATH": path_env,
            "TERM": "xterm-256color",
        },
        timeout=5,
    )
    # Hide tmux status bar
    subprocess.run(
        ["tmux", "set-option", "-t", session, "status", "off"],
        capture_output=True,
        timeout=2,
    )
    subprocess.run(
        ["tmux", "set-option", "-t", session, "window-size", "largest"],
        capture_output=True,
        timeout=2,
    )
    _active_ai_sessions[uid] = name
    return session


@sock.route("/ws/ai-terminal/<name>")
def ws_ai_terminal(ws, name):
    """WebSocket terminal that attaches to a persistent tmux session running opencode."""
    if not current_user.is_authenticated:
        ws.close()
        return
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        ws.send("\r\n\x1b[31mServer not found.\x1b[0m\r\n")
        return

    ai_cli = _find_ai_cli()
    if not ai_cli:
        ws.send(
            "\r\n\x1b[31mNo AI CLI found on this server.\x1b[0m\r\n"
            "\r\n  Install OpenCode:  curl -fsSL https://opencode.ai/install | bash\r\n"
            "  Install Claude:    npm install -g @anthropic-ai/claude-code\r\n"
        )
        return

    if not shutil.which("tmux"):
        ws.send("\r\n\x1b[31mtmux is not installed. Run: apt install tmux\x1b[0m\r\n")
        return

    import pty as _pty
    import fcntl
    import termios
    import struct

    try:
        from gevent.fileobject import FileObject
        import gevent
    except ImportError:
        FileObject = None

    # Wait for initial size from frontend
    init_cols, init_rows = 120, 40
    try:
        first_msg = ws.receive(timeout=5)
        if first_msg and isinstance(first_msg, str) and ":" in first_msg:
            parts = first_msg.split(":")
            init_cols, init_rows = int(parts[-2]), int(parts[-1])
    except Exception:
        pass

    # Ensure tmux session exists (creates if needed, reuses if exists)
    try:
        session = _ensure_ai_session(uid, name, server, ai_cli)
    except Exception as e:
        ws.send(f"\r\n\x1b[31mFailed to create AI session: {e}\x1b[0m\r\n")
        return

    # Attach to tmux session via PTY
    master_fd, slave_fd = _pty.openpty()
    winsize = struct.pack("HHHH", init_rows, init_cols, 0, 0)
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)

    # Set tmux window size options so it doesn't shrink to smallest client
    subprocess.run(
        ["tmux", "set-option", "-t", session, "window-size", "largest"],
        capture_output=True,
        timeout=2,
    )
    # Detach any stale clients, resize window to our PTY size
    subprocess.run(
        [
            "tmux",
            "resize-window",
            "-t",
            session,
            "-x",
            str(init_cols),
            "-y",
            str(init_rows),
        ],
        capture_output=True,
        timeout=2,
    )

    proc = subprocess.Popen(
        ["tmux", "attach-session", "-d", "-t", session],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        env={**os.environ, "TERM": "xterm-256color"},
        preexec_fn=os.setsid,
    )
    os.close(slave_fd)

    stop = threading.Event()

    if FileObject:
        fobj = FileObject(master_fd, "rb", close=False)

        def _pty_to_ws():
            while not stop.is_set():
                try:
                    chunk = fobj.read1(4096)
                    if not chunk:
                        break
                    ws.send(chunk.decode(errors="replace"))
                except Exception:
                    break
            stop.set()
            try:
                ws.close()
            except Exception:
                pass

        g = gevent.spawn(_pty_to_ws)
    else:

        def _pty_to_ws():
            os.set_blocking(master_fd, False)
            while not stop.is_set():
                try:
                    data = os.read(master_fd, 4096)
                    if not data:
                        break
                    ws.send(data.decode(errors="replace"))
                except BlockingIOError:
                    _time.sleep(0.02)
                except OSError:
                    break
            stop.set()
            try:
                ws.close()
            except Exception:
                pass

        g = threading.Thread(target=_pty_to_ws, daemon=True)
        g.start()

    try:
        while not stop.is_set():
            data = ws.receive()
            if data is None:
                break
            if isinstance(data, str) and data.startswith("RESIZE:"):
                try:
                    _, cols, rows = data.split(":")
                    winsize = struct.pack("HHHH", int(rows), int(cols), 0, 0)
                    fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
                except Exception:
                    pass
            else:
                raw = data if isinstance(data, bytes) else data.encode()
                try:
                    os.write(master_fd, raw)
                except OSError:
                    break
    except Exception:
        pass
    finally:
        stop.set()
        if FileObject and hasattr(g, "kill"):
            g.kill()
        try:
            os.close(master_fd)
        except OSError:
            pass
        # DON'T kill proc or tmux session -- let it persist for reconnection
        try:
            proc.wait(timeout=1)
        except Exception:
            pass


@app.route("/servers/<name>/ai-session/status")
@login_required
def ai_session_status(name):
    """Check if AI is running on this or another server."""
    uid = current_user.id
    active = _active_ai_sessions.get(uid)
    return jsonify(
        {
            "running": bool(active),
            "server": active or "",
            "same": active == name,
        }
    )


@app.route("/servers/<name>/ai-session/reset", methods=["POST"])
@login_required
def ai_session_reset(name):
    """Kill the tmux AI session. Saves session ID for later resume."""
    uid = current_user.id
    _kill_ai_session(uid, name)
    return jsonify({"ok": True})


@app.route("/servers/<name>/ai-session/new", methods=["POST"])
@login_required
def ai_session_new(name):
    """Kill session AND wipe the isolated HOME so next open starts completely fresh."""
    uid = current_user.id
    _kill_ai_session(uid, name)
    safe_name = re.sub(r"[^a-zA-Z0-9]", "_", name)
    work_dir = os.path.join(
        os.path.expanduser("~"), ".aissh_ai_sessions", f"aissh_ai_{uid}_{safe_name}"
    )
    shutil.rmtree(work_dir, ignore_errors=True)
    return jsonify({"ok": True})


@app.route("/ai-session/switch", methods=["POST"])
@login_required
def ai_session_switch():
    """Kill AI on the current server and prepare for a new one."""
    uid = current_user.id
    active = _active_ai_sessions.get(uid)
    if active:
        _kill_ai_session(uid, active)
    return jsonify({"ok": True})


_APP_DISCOVER_SCRIPT = r"""
import json, os, re
apps = []
seen_pids = set()
for pid_str in os.listdir('/proc'):
    if not pid_str.isdigit(): continue
    pid = int(pid_str)
    try:
        with open(f'/proc/{pid}/cmdline', 'rb') as f:
            cmdline = f.read().decode('utf-8', errors='replace').replace('\x00', ' ').strip()
        if not cmdline: continue
        is_app = False
        app_type = 'process'
        for pattern, atype in [
            ('gunicorn', 'gunicorn'), ('uvicorn', 'uvicorn'), ('flask', 'flask'),
            ('django', 'django'), ('node ', 'node'), ('node/', 'node'),
            ('npm', 'node'), ('python', 'python'), ('python3', 'python'),
            ('java ', 'java'), ('java/', 'java'),
            ('nginx:', 'nginx'), ('apache2', 'apache'), ('httpd', 'apache'),
            ('redis-server', 'redis'), ('postgres', 'postgres'), ('mysql', 'mysql'),
            ('mongod', 'mongo'), ('caddy', 'caddy'), ('traefik', 'traefik'),
            ('x-ui', 'x-ui'), ('xray', 'xray'), ('v2ray', 'v2ray'),
            ('cloudflared', 'cloudflared'), ('ttyd', 'ttyd'),
            ('pm2', 'pm2'), ('php-fpm', 'php'),
        ]:
            if pattern in cmdline.lower():
                is_app = True; app_type = atype; break
        if not is_app: continue
        with open(f'/proc/{pid}/stat') as f: stat = f.read().split()
        ppid = int(stat[3]); rss_pages = int(stat[23])
        rss_mb = round(rss_pages * 4096 / 1048576, 1)
        with open(f'/proc/{pid}/status') as f: status_lines = f.readlines()
        user = '?'
        for line in status_lines:
            if line.startswith('Uid:'):
                uid = int(line.split()[1])
                try:
                    import pwd; user = pwd.getpwuid(uid).pw_name
                except: user = str(uid)
                break
        try: cwd = os.readlink(f'/proc/{pid}/cwd')
        except: cwd = '?'
        port = None
        try:
            for proto in ['tcp', 'tcp6']:
                with open(f'/proc/net/{proto}') as f:
                    for line in f.readlines()[1:]:
                        parts = line.split(); inode = parts[9]
                        fd_dir = f'/proc/{pid}/fd'
                        if os.path.isdir(fd_dir):
                            for fd in os.listdir(fd_dir):
                                try:
                                    link = os.readlink(f'{fd_dir}/{fd}')
                                    if f'socket:[{inode}]' == link and parts[3] == '0A':
                                        port = int(parts[1].split(':')[1], 16); break
                                except: pass
                        if port: break
                if port: break
        except: pass
        apps.append({'pid': pid, 'ppid': ppid, 'type': app_type, 'user': user,
            'cmd': cmdline[:120], 'cwd': cwd, 'port': port, 'mem_mb': rss_mb})
        seen_pids.add(pid)
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError): continue
apps.sort(key=lambda a: (-a['mem_mb'],))
print(json.dumps(apps))
"""


@app.route("/servers/<name>/apps")
@login_required
def app_list(name):
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        return jsonify({"error": "Server not found"}), 404
    # Run discovery script on remote via base64 to avoid shell quoting issues
    script_b64 = base64.b64encode(_APP_DISCOVER_SCRIPT.encode()).decode()
    result = _ssh_exec(
        uid,
        server,
        f"echo '{script_b64}' | base64 -d | python3 2>&1",
        timeout=15,
    )
    if result["exit_code"] != 0:
        return jsonify({"error": result["stderr"] or "Failed to discover apps"}), 500
    try:
        apps = json.loads(result["stdout"])
    except (json.JSONDecodeError, ValueError):
        return jsonify(
            {"error": "Failed to parse app list", "raw": result["stdout"][:500]}
        ), 500
    return jsonify({"apps": apps})


@app.route("/servers/<name>/apps/<int:pid>/stop", methods=["POST"])
@login_required
def app_stop(name, pid):
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        return jsonify({"error": "Server not found"}), 404
    data = request.get_json() or {}
    force = data.get("force", False)
    sig = "SIGKILL" if force else "SIGTERM"
    result = _ssh_exec(uid, server, f"kill -s {sig} {pid} 2>&1", timeout=5)
    return jsonify(
        {
            "output": result["stdout"] or result["stderr"],
            "exit_code": result["exit_code"],
        }
    )


@app.route("/servers/<name>/apps/<int:pid>/restart", methods=["POST"])
@login_required
def app_restart(name, pid):
    """Restart an app by reading its cmdline and cwd, killing it, then relaunching."""
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        return jsonify({"error": "Server not found"}), 404
    # Get current command and working dir
    info = _ssh_exec(
        uid,
        server,
        f"cat /proc/{pid}/cmdline 2>/dev/null | tr '\\0' ' ' && echo '|||' && readlink /proc/{pid}/cwd 2>/dev/null",
        timeout=5,
    )
    if info["exit_code"] != 0 or "|||" not in info["stdout"]:
        return jsonify({"error": "Process not found or already dead"}), 404
    parts = info["stdout"].split("|||")
    cmd = parts[0].strip()
    cwd = parts[1].strip() if len(parts) > 1 else "/root"
    if not cmd:
        return jsonify({"error": "Could not read process command"}), 500
    # Kill the process
    _ssh_exec(uid, server, f"kill {pid} 2>/dev/null", timeout=3)
    _time.sleep(1)
    # Relaunch in background from same directory
    result = _ssh_exec(
        uid,
        server,
        f"cd {json.dumps(cwd)} && nohup {cmd} > /dev/null 2>&1 &",
        timeout=5,
    )
    return jsonify({"ok": True, "output": f"Restarted: {cmd[:80]}"})


@app.route("/servers/<name>/apps/<int:pid>/logs")
@login_required
def app_logs(name, pid):
    """Try to find and read log files for a process."""
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        return jsonify({"error": "Server not found"}), 404
    lines = min(max(int(request.args.get("lines", 80)), 10), 500)
    # Strategy: check /proc/pid/fd/1 (stdout) and fd/2 (stderr), or find .log files in cwd
    result = _ssh_exec(
        uid,
        server,
        f"""
LOGFILE=""
CWD=$(readlink /proc/{pid}/cwd 2>/dev/null)
# Check if stdout/stderr are files
for fd in 1 2; do
  target=$(readlink /proc/{pid}/fd/$fd 2>/dev/null)
  if [ -f "$target" ] 2>/dev/null; then
    LOGFILE="$target"
    break
  fi
done
# If no log from fd, search cwd for .log files
if [ -z "$LOGFILE" ] && [ -d "$CWD" ]; then
  LOGFILE=$(find "$CWD" -maxdepth 2 -name '*.log' -type f -printf '%T@ %p\\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2)
fi
if [ -n "$LOGFILE" ]; then
  echo "=FILE=$LOGFILE"
  tail -n {lines} "$LOGFILE" 2>/dev/null
else
  echo "=FILE=journalctl"
  COMM=$(cat /proc/{pid}/comm 2>/dev/null)
  journalctl _PID={pid} -n {lines} --no-pager 2>/dev/null || journalctl -t "$COMM" -n {lines} --no-pager 2>/dev/null || echo "No logs found for PID {pid}"
fi
""",
        timeout=10,
    )
    log_source = ""
    log_content = result["stdout"]
    if log_content.startswith("=FILE="):
        first_nl = log_content.index("\n") if "\n" in log_content else len(log_content)
        log_source = log_content[6:first_nl]
        log_content = log_content[first_nl + 1 :]
    return jsonify({"source": log_source, "logs": log_content})


@app.route("/servers/<name>/packages")
@login_required
def package_list(name):
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        return jsonify({"error": "Server not found"}), 404
    result = _ssh_exec(
        uid,
        server,
        "dpkg-query -W -f='${Package}|${Version}|${Status}\\n' 2>/dev/null | grep 'install ok installed' | "
        "sed 's/|install ok installed//' || rpm -qa --queryformat '%{NAME}|%{VERSION}-%{RELEASE}\\n' 2>/dev/null",
        timeout=15,
    )
    packages = []
    for line in result["stdout"].strip().splitlines():
        parts = line.split("|", 1)
        if len(parts) >= 2:
            packages.append({"name": parts[0], "version": parts[1]})
    packages.sort(key=lambda p: p["name"].lower())
    return jsonify({"packages": packages, "total": len(packages)})


@app.route("/servers/<name>/packages/install", methods=["POST"])
@login_required
def package_install(name):
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        return jsonify({"error": "Server not found"}), 404
    data = request.get_json() or {}
    pkg = data.get("package", "").strip()
    if not pkg or not re.match(r"^[a-zA-Z0-9._+\-]+$", pkg):
        return jsonify({"error": "Invalid package name"}), 400
    result = _ssh_exec(
        uid,
        server,
        f"DEBIAN_FRONTEND=noninteractive apt-get install -y {pkg} 2>&1 || yum install -y {pkg} 2>&1",
        timeout=120,
    )
    return jsonify(
        {
            "output": result["stdout"] or result["stderr"],
            "exit_code": result["exit_code"],
        }
    )


@app.route("/servers/<name>/packages/remove", methods=["POST"])
@login_required
def package_remove(name):
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        return jsonify({"error": "Server not found"}), 404
    data = request.get_json() or {}
    pkg = data.get("package", "").strip()
    if not pkg or not re.match(r"^[a-zA-Z0-9._+\-]+$", pkg):
        return jsonify({"error": "Invalid package name"}), 400
    result = _ssh_exec(
        uid,
        server,
        f"DEBIAN_FRONTEND=noninteractive apt-get remove -y {pkg} 2>&1 || yum remove -y {pkg} 2>&1",
        timeout=60,
    )
    return jsonify(
        {
            "output": result["stdout"] or result["stderr"],
            "exit_code": result["exit_code"],
        }
    )


# ---------------------------------------------------------------------------
# Docker Manager
# ---------------------------------------------------------------------------


@app.route("/servers/<name>/docker")
@login_required
def docker_list(name):
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        return jsonify({"error": "Server not found"}), 404
    # Check docker availability and list all containers
    result = _ssh_exec(
        uid,
        server,
        "docker ps -a --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}|{{.State}}' 2>&1",
        timeout=10,
    )
    if result["exit_code"] != 0:
        if (
            "command not found" in result["stderr"]
            or "command not found" in result["stdout"]
        ):
            return jsonify({"error": "Docker is not installed on this server"}), 404
        return jsonify({"error": result["stderr"] or result["stdout"]}), 500
    containers = []
    for line in result["stdout"].strip().splitlines():
        parts = line.split("|", 5)
        if len(parts) >= 6:
            containers.append(
                {
                    "id": parts[0][:12],
                    "name": parts[1],
                    "image": parts[2],
                    "status": parts[3],
                    "ports": parts[4],
                    "state": parts[5],
                }
            )
    # Get images
    img_result = _ssh_exec(
        uid,
        server,
        "docker images --format '{{.Repository}}:{{.Tag}}|{{.Size}}|{{.ID}}' 2>/dev/null",
        timeout=10,
    )
    images = []
    for line in (img_result["stdout"] or "").strip().splitlines():
        parts = line.split("|", 2)
        if len(parts) >= 3:
            images.append({"name": parts[0], "size": parts[1], "id": parts[2][:12]})
    # Get docker disk usage
    du_result = _ssh_exec(uid, server, "docker system df 2>/dev/null", timeout=10)
    return jsonify(
        {
            "containers": containers,
            "images": images,
            "disk_usage": du_result.get("stdout", ""),
        }
    )


@app.route("/servers/<name>/docker/<container_id>/action", methods=["POST"])
@login_required
def docker_action(name, container_id):
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        return jsonify({"error": "Server not found"}), 404
    data = request.get_json() or {}
    action = data.get("action", "")
    if action not in ("start", "stop", "restart", "pause", "unpause", "remove"):
        return jsonify({"error": f"Invalid action: {action}"}), 400
    # Sanitize container_id
    safe_id = re.sub(r"[^a-zA-Z0-9_.\-]", "", container_id)
    if action == "remove":
        cmd = f"docker rm -f {safe_id} 2>&1"
    else:
        cmd = f"docker {action} {safe_id} 2>&1"
    result = _ssh_exec(uid, server, cmd, timeout=30)
    return jsonify(
        {
            "action": action,
            "output": result["stdout"] or result["stderr"],
            "exit_code": result["exit_code"],
        }
    )


@app.route("/servers/<name>/docker/<container_id>/logs")
@login_required
def docker_logs(name, container_id):
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        return jsonify({"error": "Server not found"}), 404
    safe_id = re.sub(r"[^a-zA-Z0-9_.\-]", "", container_id)
    lines = min(max(int(request.args.get("lines", 100)), 10), 1000)
    result = _ssh_exec(
        uid, server, f"docker logs --tail {lines} {safe_id} 2>&1", timeout=15
    )
    return jsonify({"logs": result["stdout"], "exit_code": result["exit_code"]})


@app.route("/servers/<name>/docker/<container_id>/stats")
@login_required
def docker_stats(name, container_id):
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        return jsonify({"error": "Server not found"}), 404
    safe_id = re.sub(r"[^a-zA-Z0-9_.\-]", "", container_id)
    result = _ssh_exec(
        uid,
        server,
        f"docker stats --no-stream --format "
        f"'{{{{.CPUPerc}}}}|{{{{.MemUsage}}}}|{{{{.MemPerc}}}}|{{{{.NetIO}}}}|{{{{.BlockIO}}}}|{{{{.PIDs}}}}' "
        f"{safe_id} 2>&1",
        timeout=10,
    )
    if result["exit_code"] != 0:
        return jsonify({"error": result["stdout"] or result["stderr"]}), 500
    parts = result["stdout"].strip().split("|", 5)
    if len(parts) >= 6:
        return jsonify(
            {
                "cpu": parts[0],
                "mem_usage": parts[1],
                "mem_pct": parts[2],
                "net_io": parts[3],
                "block_io": parts[4],
                "pids": parts[5],
            }
        )
    return jsonify({"raw": result["stdout"]})


@app.route("/servers/<name>/docker/pull", methods=["POST"])
@login_required
def docker_pull(name):
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        return jsonify({"error": "Server not found"}), 404
    data = request.get_json() or {}
    image = data.get("image", "").strip()
    if not image or not re.match(r"^[a-zA-Z0-9._/:\-]+$", image):
        return jsonify({"error": "Invalid image name"}), 400
    result = _ssh_exec(uid, server, f"docker pull {image} 2>&1", timeout=120)
    return jsonify(
        {
            "output": result["stdout"] or result["stderr"],
            "exit_code": result["exit_code"],
        }
    )


_SNAP_DIR = "~/.aissh_snapshots"
_SNAP_TS_RE = re.compile(r"^\d{8}_\d{6}$")


def _snap_cmd(uid: str, server: dict, cmd: str, timeout: int = 30) -> tuple:
    client = _get_stats_conn(uid, server)
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    return stdout.read().decode().strip(), stderr.read().decode().strip()


@app.route("/chat/<name>/snapshots")
@login_required
def list_snapshots(name):
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        return jsonify({"error": "Server not found"}), 404
    cmd = (
        f"ls -1 {_SNAP_DIR}/ 2>/dev/null | sort -r | head -30 | "
        f"while read ts; do "
        f"  meta=$(cat {_SNAP_DIR}/$ts/meta.json 2>/dev/null || echo '{{}}'); "
        f"  size=$(du -sh {_SNAP_DIR}/$ts 2>/dev/null | cut -f1); "
        f'  echo "$ts|$size|$meta"; '
        f"done"
    )
    try:
        out, _ = _snap_cmd(uid, server, cmd, timeout=10)
        snaps = []
        for line in out.splitlines():
            parts = line.split("|", 2)
            if len(parts) < 3:
                continue
            ts, size, meta_str = parts
            try:
                meta = json.loads(meta_str)
            except Exception:
                meta = {}
            snaps.append(
                {
                    "id": ts,
                    "size": size,
                    "created": meta.get("created", ts),
                    "label": meta.get("label", ""),
                }
            )
        return jsonify({"snapshots": snaps})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/chat/<name>/snapshot", methods=["POST"])
@login_required
def create_snapshot(name):
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        return jsonify({"error": "Server not found"}), 404
    raw_label = (request.get_json() or {}).get("label", "")[:60]
    # Sanitize label to alphanumeric, spaces, hyphens, underscores only
    label = re.sub(r"[^a-zA-Z0-9 _\-.]", "", raw_label).strip()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    now = datetime.now().isoformat()
    # Build meta JSON safely via base64 to avoid any shell injection
    meta_json = json.dumps({"created": now, "label": label})
    meta_b64 = base64.b64encode(meta_json.encode()).decode()
    cmd = (
        f"mkdir -p {_SNAP_DIR}/{ts} && "
        f"tar -czf {_SNAP_DIR}/{ts}/etc.tar.gz /etc 2>/dev/null; "
        f"(dpkg --get-selections 2>/dev/null || rpm -qa 2>/dev/null) > {_SNAP_DIR}/{ts}/packages.txt; "
        f"echo '{meta_b64}' | base64 -d > {_SNAP_DIR}/{ts}/meta.json && "
        f"echo ok"
    )
    try:
        out, err = _snap_cmd(uid, server, cmd, timeout=60)
        if "ok" in out:
            return jsonify({"id": ts, "created": now, "label": label})
        return jsonify({"error": err or "Snapshot failed"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/chat/<name>/snapshot/<ts>/restore", methods=["POST"])
@login_required
def restore_snapshot(name, ts):
    if not _SNAP_TS_RE.match(ts):
        return jsonify({"error": "Invalid snapshot ID"}), 400
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        return jsonify({"error": "Server not found"}), 404
    cmd = f"tar -xzf {_SNAP_DIR}/{ts}/etc.tar.gz -C / 2>&1 && echo 'Restore complete'"
    try:
        out, err = _snap_cmd(uid, server, cmd, timeout=120)
        return jsonify({"output": out, "stderr": err})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/chat/<name>/snapshot/<ts>/delete", methods=["POST"])
@login_required
def delete_snapshot(name, ts):
    if not _SNAP_TS_RE.match(ts):
        return jsonify({"error": "Invalid snapshot ID"}), 400
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        return jsonify({"error": "Server not found"}), 404
    try:
        out, _ = _snap_cmd(
            uid, server, f"rm -rf {_SNAP_DIR}/{ts} && echo ok", timeout=10
        )
        return jsonify({"ok": "ok" in out})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Migration
# ---------------------------------------------------------------------------

_migrations: dict = {}  # migration_id → threading.Event (set = abort)

# Directories skipped during a full-server copy (virtual/hardware-specific)
# Directories completely skipped (virtual / hardware-specific filesystems)
_FULL_SERVER_EXCLUDE = frozenset(
    {
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/tmp",
        "/mnt",
        "/media",
        "/lost+found",
        "/snap",
        "/boot",
        "/swapfile",
    }
)

# Files/dirs that must NEVER be overwritten on the destination
# (overwriting these will break networking, disk mounts, or lock you out)
_FULL_SERVER_PROTECT = [
    # ── Network identity ──
    "/etc/hostname",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/network/",
    "/etc/netplan/",
    "/etc/NetworkManager/",
    "/etc/systemd/network/",
    "/etc/sysconfig/network-scripts/",
    # ── Disk / boot ──
    "/etc/fstab",
    "/etc/crypttab",
    "/etc/mtab",
    "/etc/grub.d/",
    "/etc/default/grub",
    "/boot/",
    "/etc/initramfs-tools/",
    # ── SSH host keys (overwriting = MitM warnings for everyone connecting) ──
    "/etc/ssh/ssh_host_*",
    # ── Machine identity ──
    "/etc/machine-id",
    "/var/lib/dbus/machine-id",
    # ── Cloud-init (cloud providers re-create these at boot) ──
    "/etc/cloud/",
    "/var/lib/cloud/",
    # ── Authorized keys (already handled but belt-and-suspenders) ──
    "authorized_keys",
]


def _rsync_migrate(
    ssh_src,
    ssh_dst,
    src_server,
    dst_server,
    paths,
    exclude,
    abort_event,
    sse,
    yield_log,
):
    """
    Generator — uses rsync on the source server to push files directly to the
    destination.  All file data travels source→destination; the app is not a
    relay.  Yields SSE strings and returns (transferred, errors, aborted).

    Requires:
      • rsync on the source server (installed automatically if missing)
      • SSH access from the source server to the destination server (a
        temporary ed25519 key is generated and injected automatically)
    """
    import random

    key_id = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=12))
    src_key_path = f"/tmp/.mig_{key_id}"
    pub_key_line = None
    dst_auth_keys_path = None

    try:
        # ── 1. Ensure rsync is installed on source and destination ──────────
        for label, ssh_conn in [("source", ssh_src), ("destination", ssh_dst)]:
            _, stdout, _ = ssh_conn.exec_command(
                "command -v rsync >/dev/null 2>&1 && echo OK || echo MISSING",
                timeout=10,
            )
            if stdout.read().decode().strip() != "OK":
                yield yield_log("info", f"rsync not found on {label} — installing…")
                _, so, _ = ssh_conn.exec_command(
                    'apt-get update -qq 2>&1; apt-get install -y rsync 2>&1 || yum install -y rsync 2>&1; echo "EXITCODE:$?"',
                    timeout=180,
                )
                install_out = so.read().decode().strip()
                lines = [l.strip() for l in install_out.splitlines() if l.strip()]
                last_line = lines[-1] if lines else ""
                if last_line != "EXITCODE:0":
                    yield sse(
                        "error",
                        {
                            "msg": f"Cannot install rsync on {label}. {install_out[:400]}"
                        },
                    )
                    return 0, 1, False
                yield yield_log("ok", f"rsync installed on {label}.")

        # ── 2. Generate a temporary ed25519 key on the source server ────────
        keygen_cmd = (
            f"rm -f '{src_key_path}' '{src_key_path}.pub' && "
            f"ssh-keygen -t ed25519 -f '{src_key_path}' -N '' -q 2>&1 && "
            f"printf '===PUB===\\n' && cat '{src_key_path}.pub'"
        )
        _, stdout, _ = ssh_src.exec_command(keygen_cmd, timeout=20)
        keygen_out = stdout.read().decode()
        if "===PUB===" not in keygen_out:
            yield sse(
                "error", {"msg": "Failed to generate temporary SSH key on source."}
            )
            return 0, 1, False
        pub_key_line = keygen_out.split("===PUB===", 1)[1].strip()
        if not pub_key_line.startswith("ssh-"):
            yield sse("error", {"msg": f"Invalid temp key output: {pub_key_line[:80]}"})
            return 0, 1, False

        # ── 3. Inject public key into destination's authorized_keys ─────────
        #   Uses OpenSSH's `expiry-time` restriction so the key auto-expires
        #   in 2 hours even if cleanup fails (network dies, app crashes, etc.)
        _, stdout, _ = ssh_dst.exec_command('printf "%s\\n" "$HOME"', timeout=5)
        dst_home = stdout.read().decode().strip() or "/root"
        dst_auth_keys_path = f"{dst_home}/.ssh/authorized_keys"
        # Calculate expiry 2 hours from now in UTC
        _, expiry_out, _ = ssh_dst.exec_command(
            'date -u -d "+2 hours" "+%Y%m%d%H%M%S" 2>/dev/null || '
            'date -u -v+2H "+%Y%m%d%H%M%S" 2>/dev/null || '
            'echo ""',
            timeout=5,
        )
        expiry_ts = expiry_out.read().decode().strip()
        if expiry_ts and len(expiry_ts) == 14:
            key_entry = f'expiry-time="{expiry_ts}" {pub_key_line}'
        else:
            key_entry = pub_key_line
        add_key_cmd = (
            f"mkdir -p '{dst_home}/.ssh' && chmod 700 '{dst_home}/.ssh' && "
            f"printf '%s\\n' '{key_entry}' >> '{dst_auth_keys_path}' && "
            f"chmod 600 '{dst_auth_keys_path}'"
        )
        _, _, stderr = ssh_dst.exec_command(add_key_cmd, timeout=10)
        err = stderr.read().decode().strip()
        if err:
            yield yield_log("warn", f"authorized_keys setup: {err}")

        yield yield_log("info", "Secure transfer channel established (rsync over SSH).")

        # ── 4. Run rsync path by path ────────────────────────────────────────
        dst_host = dst_server["host"]
        dst_port = dst_server.get("port", 22)
        dst_user = dst_server.get("user", "root")

        ssh_opts = (
            f"-i {src_key_path} "
            f"-o StrictHostKeyChecking=no "
            f"-o UserKnownHostsFile=/dev/null "
            f"-p {dst_port}"
        )
        # Build exclude list: always-protected files + mode-specific excludes
        all_excludes = list(_FULL_SERVER_PROTECT) + list(exclude)
        exclude_args = " ".join(f"--exclude='{p}'" for p in all_excludes)

        total_transferred = 0
        total_errors = 0
        aborted = False

        STAT_PREFIXES = (
            "Number of files:",
            "Number of created files:",
            "Number of regular files transferred:",
            "Total file size:",
            "Total transferred file size:",
            "Literal data:",
            "Matched data:",
            "File list size:",
            "sent ",
            "total size",
        )

        for path in paths:
            if abort_event.is_set():
                aborted = True
                break

            src_path = path.rstrip("/") + "/"
            dst_path = path.rstrip("/") + "/"

            ssh_dst.exec_command(f"mkdir -p '{dst_path}'", timeout=10)

            rsync_cmd = (
                f"rsync -avz --stats --partial --timeout=300 --human-readable"
                f" -e 'ssh {ssh_opts}'"
                f" {exclude_args}"
                f" '{src_path}'"
                f" '{dst_user}@{dst_host}:{dst_path}'"
                f" 2>&1"
            )
            yield yield_log("info", f"rsync → {path} …")

            transport = ssh_src.get_transport()
            chan = transport.open_session()
            chan.get_pty()
            chan.exec_command(rsync_cmd)

            buf = b""
            file_count = 0
            PROGRESS_EVERY = 20

            while not abort_event.is_set():
                if chan.recv_ready():
                    data = chan.recv(8192)
                    if not data:
                        break
                    buf += data
                    lines = buf.split(b"\n")
                    buf = lines[-1]
                    for raw in lines[:-1]:
                        line = raw.decode("utf-8", errors="replace")
                        line = re.sub(r"\x1b\[[0-9;]*[mK]", "", line).strip()
                        if not line or "\r" in line:
                            continue
                        if any(line.startswith(p) for p in STAT_PREFIXES):
                            if line.startswith("Number of regular files transferred:"):
                                try:
                                    n = int(
                                        line.split(":")[-1]
                                        .strip()
                                        .split()[0]
                                        .replace(",", "")
                                    )
                                    total_transferred += n
                                except Exception:
                                    pass
                            yield yield_log("ok", line)
                        elif "rsync error" in line or "error in rsync" in line.lower():
                            total_errors += 1
                            yield yield_log("warn", line)
                        elif (
                            line.startswith("sending")
                            or line.startswith("building")
                            or line.startswith("delta-transmission")
                        ):
                            yield yield_log("info", line)
                        elif "permission denied" in line.lower() or line.startswith(
                            "skipping"
                        ):
                            yield yield_log("warn", line)
                        else:
                            file_count += 1
                            if file_count % PROGRESS_EVERY == 0:
                                yield sse(
                                    "progress",
                                    {
                                        "done": total_transferred + file_count,
                                        "file": line,
                                    },
                                )
                elif chan.exit_status_ready():
                    break
                else:
                    _time.sleep(0.05)

            if abort_event.is_set():
                chan.send(b"\x03")
                aborted = True

            if buf:
                line = re.sub(
                    r"\x1b\[[0-9;]*[mK]", "", buf.decode("utf-8", errors="replace")
                ).strip()
                if line:
                    yield yield_log("info", line)

            exit_code = chan.recv_exit_status()
            chan.close()

            if aborted:
                yield yield_log("warn", f"Aborted during {path}.")
                break
            elif exit_code == 0:
                yield yield_log("ok", f"Completed: {path}")
            else:
                yield yield_log(
                    "warn", f"rsync exited with code {exit_code} for {path}"
                )
                total_errors += 1

        return total_transferred, total_errors, aborted

    finally:
        try:
            ssh_src.exec_command(
                f"rm -f '{src_key_path}' '{src_key_path}.pub'", timeout=5
            )
        except Exception:
            pass
        if pub_key_line and dst_auth_keys_path:
            try:
                key_token = (
                    pub_key_line.split()[1][:30]
                    if len(pub_key_line.split()) >= 2
                    else None
                )
                if key_token:
                    ssh_dst.exec_command(
                        f"grep -v '{key_token}' '{dst_auth_keys_path}'"
                        f" > '{dst_auth_keys_path}.tmp' 2>/dev/null"
                        f" && mv '{dst_auth_keys_path}.tmp' '{dst_auth_keys_path}'",
                        timeout=5,
                    )
            except Exception:
                pass


def _migrate_packages(ssh_src, ssh_dst, yield_log):
    """
    Migrate installed packages from source to destination.
    1. Detects source package manager (apt vs yum/dnf)
    2. pip: only user-installed packages (--user or venvs), not system pip
    3. apt/yum: manually installed packages only, with version pinning where possible
    """
    # ── Detect source distro ──
    _, stdout, _ = ssh_src.exec_command(
        "command -v apt-get >/dev/null 2>&1 && echo apt || "
        "(command -v yum >/dev/null 2>&1 && echo yum || "
        "(command -v dnf >/dev/null 2>&1 && echo dnf || echo unknown))",
        timeout=10,
    )
    src_pkg_mgr = stdout.read().decode().strip()

    _, stdout, _ = ssh_dst.exec_command(
        "command -v apt-get >/dev/null 2>&1 && echo apt || "
        "(command -v yum >/dev/null 2>&1 && echo yum || "
        "(command -v dnf >/dev/null 2>&1 && echo dnf || echo unknown))",
        timeout=10,
    )
    dst_pkg_mgr = stdout.read().decode().strip()

    if src_pkg_mgr != dst_pkg_mgr:
        yield_log(
            "warn",
            f"Different package managers: source={src_pkg_mgr}, dest={dst_pkg_mgr}. "
            f"Skipping system package migration (would likely cause conflicts).",
        )
    elif src_pkg_mgr == "apt":
        # apt -- manually installed packages only
        try:
            _, stdout, _ = ssh_src.exec_command(
                "apt-mark showmanual 2>/dev/null", timeout=30
            )
            apt_pkgs = [
                l.strip() for l in stdout.read().decode().splitlines() if l.strip()
            ]
            # Filter out base system packages that are always present
            base_pkgs = {
                "apt",
                "base-files",
                "bash",
                "coreutils",
                "dash",
                "dpkg",
                "grep",
                "gzip",
                "hostname",
                "init",
                "login",
                "mount",
                "sed",
                "tar",
                "util-linux",
            }
            apt_pkgs = [p for p in apt_pkgs if p not in base_pkgs]
            if apt_pkgs:
                yield_log(
                    "info",
                    f"Installing {len(apt_pkgs)} manually-installed apt packages...",
                )
                # Install in batches to avoid command-line length limits
                batch_size = 50
                for i in range(0, len(apt_pkgs), batch_size):
                    batch = apt_pkgs[i : i + batch_size]
                    pkg_list = " ".join(batch)
                    cmd = (
                        f"DEBIAN_FRONTEND=noninteractive "
                        f"apt-get install -y --no-install-recommends "
                        f"{pkg_list} 2>&1 | tail -3"
                    )
                    _, so, _ = ssh_dst.exec_command(cmd, timeout=600)
                    for line in so.read().decode().strip().splitlines():
                        yield_log("info", f"  apt: {line}")
                yield_log("ok", "apt packages installed.")
            else:
                yield_log("info", "No extra apt packages to migrate.")
        except Exception as e:
            yield_log("warn", f"apt migration failed: {e}")
    elif src_pkg_mgr in ("yum", "dnf"):
        try:
            mgr = src_pkg_mgr
            _, stdout, _ = ssh_src.exec_command(
                f"{mgr} list installed 2>/dev/null | tail -n+2 | awk '{{print $1}}'",
                timeout=30,
            )
            pkgs = [
                l.strip().split(".")[0]
                for l in stdout.read().decode().splitlines()
                if l.strip()
            ]
            if pkgs:
                yield_log("info", f"Installing {len(pkgs)} {mgr} packages...")
                pkg_list = " ".join(pkgs[:200])
                cmd = f"{mgr} install -y {pkg_list} 2>&1 | tail -5"
                _, so, _ = ssh_dst.exec_command(cmd, timeout=600)
                for line in so.read().decode().strip().splitlines():
                    yield_log("info", f"  {mgr}: {line}")
                yield_log("ok", f"{mgr} packages installed.")
            else:
                yield_log("info", f"No {mgr} packages to migrate.")
        except Exception as e:
            yield_log("warn", f"{src_pkg_mgr} migration failed: {e}")
    else:
        yield_log("warn", f"Unknown package manager on source: {src_pkg_mgr}")

    # ── pip -- only if pip3 exists on both ──
    try:
        _, stdout, _ = ssh_src.exec_command(
            "pip3 freeze --user 2>/dev/null || pip3 freeze 2>/dev/null", timeout=30
        )
        pip_reqs = stdout.read().decode().strip()
        if pip_reqs:
            # Filter out system-managed packages
            lines = [
                l for l in pip_reqs.splitlines() if l.strip() and not l.startswith("#")
            ]
            if lines:
                yield_log("info", f"Migrating {len(lines)} pip packages...")
                b64 = base64.b64encode("\n".join(lines).encode()).decode()
                cmd = (
                    f"echo '{b64}' | base64 -d > /tmp/_pip_reqs_mig.txt && "
                    f"pip3 install -r /tmp/_pip_reqs_mig.txt 2>&1 | tail -8 ; "
                    f"rm -f /tmp/_pip_reqs_mig.txt"
                )
                _, so, _ = ssh_dst.exec_command(cmd, timeout=300)
                for line in so.read().decode().strip().splitlines()[-5:]:
                    yield_log("info", f"  pip: {line}")
                yield_log("ok", "pip packages installed.")
        else:
            yield_log("info", "No pip packages found on source.")
    except Exception as e:
        yield_log("warn", f"pip migration failed: {e}")


@app.route("/chat/<name>/stats")
@login_required
def chat_stats(name):
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        return jsonify({"error": "Server not found"}), 404
    # Ensure the persistent stats stream is running
    _ensure_stats_stream(uid, server)
    key = (uid, name)
    data = _stats_cache.get(key)
    if data:
        return jsonify(data)
    return jsonify({"error": "Collecting stats..."}), 202


# ---------------------------------------------------------------------------
# Background task endpoints
# ---------------------------------------------------------------------------


@app.route("/settings/model", methods=["POST"])
@login_required
def set_model():
    data = request.get_json() or {}
    model_id = data.get("model", "")
    if any(m["id"] == model_id for m in MODEL_OPTIONS):
        save_model(current_user.id, model_id)
    cur_model = get_model(current_user.id) or DEFAULT_MODEL
    return jsonify({"model": cur_model})


# ---------------------------------------------------------------------------
# Migration routes
# ---------------------------------------------------------------------------


@app.route("/servers/<src_name>/migrate", methods=["POST"])
@login_required
def migrate_servers(src_name):
    uid = current_user.id
    src_server = get_server(uid, src_name)
    if not src_server:
        return jsonify({"error": "Source server not found"}), 404

    body = request.get_json() or {}
    target_name = body.get("target", "")
    full_server = bool(body.get("full_server", False))
    paths = (
        ["/"]
        if full_server
        else body.get("paths", ["/etc", "/home", "/var/www", "/opt"])
    )
    exclude = _FULL_SERVER_EXCLUDE if full_server else frozenset()
    do_packages = bool(body.get("do_packages", False))

    dst_server = get_server(uid, target_name)
    if not dst_server:
        return jsonify({"error": "Target server not found"}), 404
    if src_name == target_name:
        return jsonify({"error": "Source and target must differ"}), 400

    migration_id = str(uuid.uuid4())
    abort_event = threading.Event()
    _migrations[migration_id] = {"event": abort_event, "uid": uid}

    def generate():
        ssh_src = paramiko.SSHClient()
        ssh_src.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_dst = paramiko.SSHClient()
        ssh_dst.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        def sse(event: str, payload: dict) -> str:
            return f"event: {event}\ndata: {json.dumps(payload)}\n\n"

        def yield_log(level: str, msg: str):
            return sse("log", {"level": level, "msg": msg})

        try:
            yield sse("start", {"migration_id": migration_id})

            # Connect source
            try:
                _ssh_connect(ssh_src, src_server, timeout=15)
            except Exception as e:
                yield sse("error", {"msg": f"Cannot connect to source: {e}"})
                return

            # Connect target
            try:
                _ssh_connect(ssh_dst, dst_server, timeout=15)
            except Exception as e:
                yield sse("error", {"msg": f"Cannot connect to target: {e}"})
                return

            mode_label = "full server" if full_server else ", ".join(paths)
            yield yield_log("info", f"Starting rsync migration ({mode_label})...")
            yield yield_log(
                "info",
                "Files travel directly source->destination via rsync over SSH "
                "(app is not a relay).",
            )
            if full_server:
                yield yield_log(
                    "info",
                    "Protected: hostname, network config, fstab, SSH host keys, "
                    "machine-id, cloud-init (will NOT be overwritten).",
                )

            # rsync-based transfer (source pushes directly to destination)
            transferred, errors, aborted = yield from _rsync_migrate(
                ssh_src,
                ssh_dst,
                src_server,
                dst_server,
                paths,
                exclude,
                abort_event,
                sse,
                yield_log,
            )

            yield sse("progress", {"done": transferred, "file": ""})

            if aborted:
                yield yield_log("warn", "Migration aborted by user.")

            # Optional package migration
            if do_packages and not aborted:
                logs = []

                def log_collector(level: str, msg: str):
                    logs.append((level, msg))

                _migrate_packages(ssh_src, ssh_dst, log_collector)
                for level, msg in logs:
                    yield yield_log(level, msg)

            yield sse(
                "done",
                {
                    "transferred": transferred,
                    "skipped": 0,
                    "errors": errors,
                    "aborted": aborted,
                },
            )

        except Exception as e:
            yield sse("error", {"msg": f"Unexpected error: {e}"})
        finally:
            for obj in (ssh_src, ssh_dst):
                try:
                    obj.close()
                except Exception:
                    pass
            _migrations.pop(migration_id, None)

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@app.route("/migrate/<migration_id>/abort", methods=["POST"])
@login_required
def migrate_abort(migration_id):
    entry = _migrations.get(migration_id)
    if entry and entry["uid"] == current_user.id:
        entry["event"].set()
        return jsonify({"ok": True})
    return jsonify({"ok": False, "msg": "Migration not found or already done"}), 404


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    uid = current_user.id
    msg = None
    error = None

    if request.method == "POST":
        action = request.form.get("action")

        if action == "password":
            current_pw = request.form.get("current_password", "")
            new_pw = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            user_obj = get_user_by_id(uid)
            if not check_password_hash(user_obj.password_hash, current_pw):
                error = "Current password is incorrect."
            elif len(new_pw) < 8:
                error = "New password must be at least 8 characters."
            elif new_pw != confirm:
                error = "Passwords do not match."
            else:
                users = load_users()
                for u in users:
                    if u["id"] == uid:
                        u["password_hash"] = generate_password_hash(new_pw)
                        break
                save_users(users)
                msg = "Password updated."

        elif action == "apikey":
            key = request.form.get("api_key", "").strip()
            if key:
                save_api_key(uid, key)
                msg = "Anthropic API key saved."
            else:
                msg = "API key unchanged (blank submission)."

        elif action == "deepseekkey":
            key = request.form.get("deepseek_key", "").strip()
            if key:
                save_deepseek_key(uid, key)
                msg = "DeepSeek API key saved."
            else:
                msg = "DeepSeek API key unchanged (blank submission)."

        elif action == "digitaloceankey":
            key = request.form.get("digitalocean_key", "").strip()
            if key:
                save_do_key(uid, key)
                msg = "DigitalOcean API token saved."
            else:
                msg = "DigitalOcean token unchanged (blank submission)."

    api_key = get_api_key(uid)
    masked = (
        ("*" * (len(api_key) - 4) + api_key[-4:])
        if len(api_key) > 4
        else ("*" * len(api_key))
    )
    ds_key = get_deepseek_key(uid)
    ds_masked = (
        ("*" * (len(ds_key) - 4) + ds_key[-4:])
        if len(ds_key) > 4
        else ("*" * len(ds_key))
    )
    do_key = get_do_key(uid)
    do_masked = (
        ("*" * (len(do_key) - 4) + do_key[-4:])
        if len(do_key) > 4
        else ("*" * len(do_key))
    )
    servers = load_servers(uid)
    cur_provider = get_provider(uid)
    cur_model = get_model(uid) or DEFAULT_MODEL
    return render_template(
        "settings.html",
        msg=msg,
        error=error,
        masked_key=masked,
        has_key=bool(api_key),
        ds_masked_key=ds_masked,
        has_ds_key=bool(ds_key),
        do_masked_key=do_masked,
        has_do_key=bool(do_key),
        provider=cur_provider,
        model=cur_model,
        thinking=get_thinking(uid),
        model_options=MODEL_OPTIONS,
        servers=servers,
    )


# ---------------------------------------------------------------------------
# DigitalOcean Droplets
# ---------------------------------------------------------------------------

_DO_API = "https://api.digitalocean.com/v2"


def _do_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


@app.route("/droplets")
@login_required
def droplets_page():
    uid = current_user.id
    token = get_do_key(uid)
    droplets = []
    regions = []
    sizes = []
    images = []
    vpcs = []
    error = None

    if token:
        try:
            # Fetch droplets
            r = _requests.get(
                f"{_DO_API}/droplets?per_page=200",
                headers=_do_headers(token),
                timeout=10,
            )
            if r.status_code == 200:
                droplets = r.json().get("droplets", [])
            else:
                error = f"Failed to fetch droplets: {r.status_code}"

            # Fetch regions, sizes, images, vpcs in parallel-ish
            rr = _requests.get(
                f"{_DO_API}/regions?per_page=200",
                headers=_do_headers(token),
                timeout=10,
            )
            if rr.status_code == 200:
                regions = [
                    r for r in rr.json().get("regions", []) if r.get("available")
                ]

            rs = _requests.get(
                f"{_DO_API}/sizes?per_page=200", headers=_do_headers(token), timeout=10
            )
            if rs.status_code == 200:
                sizes = rs.json().get("sizes", [])

            ri = _requests.get(
                f"{_DO_API}/images?type=distribution&per_page=200",
                headers=_do_headers(token),
                timeout=10,
            )
            if ri.status_code == 200:
                images = ri.json().get("images", [])

            rv = _requests.get(
                f"{_DO_API}/vpcs?per_page=200", headers=_do_headers(token), timeout=10
            )
            if rv.status_code == 200:
                vpcs = rv.json().get("vpcs", [])

        except Exception as e:
            error = str(e)

    # Build existing server names for the user
    existing_servers = {s["host"] for s in load_servers(uid)}

    return render_template(
        "droplets.html",
        droplets=droplets,
        regions=regions,
        sizes=sizes,
        images=images,
        vpcs=vpcs,
        has_token=bool(token),
        error=error,
        existing_servers=existing_servers,
    )


@app.route("/droplets/create", methods=["POST"])
@login_required
def droplets_create():
    uid = current_user.id
    token = get_do_key(uid)
    if not token:
        flash("DigitalOcean API token not configured.", "error")
        return redirect(url_for("settings"))

    payload = {
        "name": request.form.get("name", "").strip(),
        "region": request.form.get("region", ""),
        "size": request.form.get("size", ""),
        "image": request.form.get("image", ""),
    }
    vpc = request.form.get("vpc_uuid", "").strip()
    if vpc:
        payload["vpc_uuid"] = vpc
    password = request.form.get("root_password", "").strip()
    if password:
        payload["user_data"] = (
            f"#!/bin/bash\necho 'root:{password}' | chpasswd\nsed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config\nsed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config\nsystemctl restart sshd"
        )

    if not payload["name"]:
        flash("Droplet name is required.", "error")
        return redirect(url_for("droplets_page"))

    try:
        r = _requests.post(
            f"{_DO_API}/droplets", headers=_do_headers(token), json=payload, timeout=15
        )
        if r.status_code in (201, 202):
            d = r.json().get("droplet", {})
            flash(
                f"Droplet '{d.get('name')}' (ID {d.get('id')}) is being created.",
                "success",
            )
        else:
            err = r.json().get("message", r.text)
            flash(f"DigitalOcean error: {err}", "error")
    except Exception as e:
        flash(f"Request failed: {e}", "error")

    return redirect(url_for("droplets_page"))


@app.route("/droplets/<int:droplet_id>/delete", methods=["POST"])
@login_required
def droplets_delete(droplet_id):
    uid = current_user.id
    token = get_do_key(uid)
    if not token:
        flash("DigitalOcean API token not configured.", "error")
        return redirect(url_for("settings"))

    try:
        r = _requests.delete(
            f"{_DO_API}/droplets/{droplet_id}", headers=_do_headers(token), timeout=10
        )
        if r.status_code == 204:
            flash("Droplet deleted.", "success")
        else:
            err = r.json().get("message", r.text)
            flash(f"Delete failed: {err}", "error")
    except Exception as e:
        flash(f"Request failed: {e}", "error")

    return redirect(url_for("droplets_page"))


@app.route("/droplets/<int:droplet_id>/add-server", methods=["POST"])
@login_required
def droplets_add_server(droplet_id):
    """Add a droplet as an SSH server entry."""
    uid = current_user.id
    token = get_do_key(uid)
    if not token:
        flash("DigitalOcean API token not configured.", "error")
        return redirect(url_for("droplets_page"))

    try:
        r = _requests.get(
            f"{_DO_API}/droplets/{droplet_id}", headers=_do_headers(token), timeout=10
        )
        if r.status_code != 200:
            flash("Could not fetch droplet info.", "error")
            return redirect(url_for("droplets_page"))
        d = r.json().get("droplet", {})
    except Exception as e:
        flash(f"Request failed: {e}", "error")
        return redirect(url_for("droplets_page"))

    # Get public IPv4
    ip = None
    for net in d.get("networks", {}).get("v4", []):
        if net.get("type") == "public":
            ip = net["ip_address"]
            break
    if not ip:
        flash("Droplet has no public IP yet. Try again in a moment.", "error")
        return redirect(url_for("droplets_page"))

    name = d.get("name", f"do-{droplet_id}")
    password = request.form.get("password", "").strip()
    servers = load_servers(uid)
    # Check for duplicate
    if any(s["host"] == ip for s in servers):
        flash(f"Server with IP {ip} already exists.", "error")
        return redirect(url_for("droplets_page"))

    servers.append(
        {
            "name": name,
            "host": ip,
            "port": 22,
            "user": "root",
            "password": password,
            "pem_key": "",
        }
    )
    save_servers(uid, servers)
    flash(f"Server '{name}' ({ip}) added.", "success")
    return redirect(url_for("droplets_page"))


@app.route("/droplets/<int:droplet_id>/reboot", methods=["POST"])
@login_required
def droplets_reboot(droplet_id):
    uid = current_user.id
    token = get_do_key(uid)
    if not token:
        flash("DigitalOcean API token not configured.", "error")
        return redirect(url_for("droplets_page"))
    try:
        r = _requests.post(
            f"{_DO_API}/droplets/{droplet_id}/actions",
            headers=_do_headers(token),
            json={"type": "reboot"},
            timeout=10,
        )
        if r.status_code in (200, 201):
            flash("Reboot initiated.", "success")
        else:
            flash(f"Reboot failed: {r.json().get('message', r.text)}", "error")
    except Exception as e:
        flash(f"Request failed: {e}", "error")
    return redirect(url_for("droplets_page"))


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------


@app.route("/admin/users")
@admin_required
def admin_users():
    users = load_users()
    return render_template("admin.html", users=users, current_uid=current_user.id)


@app.route("/admin/users/add", methods=["POST"])
@admin_required
def admin_users_add():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    is_admin = request.form.get("is_admin") == "1"

    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for("admin_users"))

    if len(password) < 4:
        flash("Password must be at least 4 characters.", "error")
        return redirect(url_for("admin_users"))

    users = load_users()
    if any(u["username"] == username for u in users):
        flash(f"Username '{username}' already exists.", "error")
        return redirect(url_for("admin_users"))

    new_id = str(max((int(u["id"]) for u in users), default=0) + 1)
    users.append(
        {
            "id": new_id,
            "username": username,
            "password_hash": generate_password_hash(password),
            "is_admin": is_admin,
        }
    )
    save_users(users)
    flash(f"User '{username}' created.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<uid>/delete", methods=["POST"])
@admin_required
def admin_users_delete(uid):
    if uid == current_user.id:
        flash("You cannot delete yourself.", "error")
        return redirect(url_for("admin_users"))

    users = load_users()
    target = next((u for u in users if u["id"] == uid), None)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("admin_users"))

    users = [u for u in users if u["id"] != uid]
    save_users(users)

    # Delete user data directories
    for d in [DATA_DIR / uid, CHATS_DIR / uid, MEMORY_DIR / uid]:
        if d.exists():
            shutil.rmtree(d)

    flash(f"User '{target['username']}' deleted.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<uid>/reset-password", methods=["POST"])
@admin_required
def admin_users_reset_password(uid):
    new_pw = request.form.get("password", "")
    if len(new_pw) < 8:
        flash("Password must be at least 4 characters.", "error")
        return redirect(url_for("admin_users"))

    users = load_users()
    target = next((u for u in users if u["id"] == uid), None)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("admin_users"))

    target["password_hash"] = generate_password_hash(new_pw)
    save_users(users)
    flash(f"Password reset for '{target['username']}'.", "success")
    return redirect(url_for("admin_users"))


# ---------------------------------------------------------------------------
# Install Claude Code on server
# ---------------------------------------------------------------------------

_CLAUDE_INSTALL_SCRIPT = r"""#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

if [[ $EUID -ne 0 ]]; then
  fail "Please run as root:  sudo bash install-claude-code.sh"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Claude Code CLI — VPS Installer (No Prompts Mode)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

TOTAL_RAM_MB=$(free -m | awk '/Mem:/ {print $2}')
SWAP_MB=$(free -m | awk '/Swap:/ {print $2}')

info "Detected RAM: ${TOTAL_RAM_MB} MB  |  Swap: ${SWAP_MB} MB"

if [[ "$SWAP_MB" -lt 512 ]]; then
  SWAP_SIZE="2G"
  SWAP_FILE="/swapfile"

  if [[ -f "$SWAP_FILE" ]]; then
    warn "Swapfile exists but swap is small — recreating."
    swapoff "$SWAP_FILE" 2>/dev/null || true
    rm -f "$SWAP_FILE"
  fi

  info "Creating ${SWAP_SIZE} swap (prevents OOM during install)..."
  fallocate -l "$SWAP_SIZE" "$SWAP_FILE" 2>/dev/null || dd if=/dev/zero of="$SWAP_FILE" bs=1M count=2048 status=progress
  chmod 600 "$SWAP_FILE"
  mkswap "$SWAP_FILE" >/dev/null
  swapon "$SWAP_FILE"

  if ! grep -q "$SWAP_FILE" /etc/fstab; then
    echo "$SWAP_FILE none swap sw 0 0" >> /etc/fstab
  fi
  info "Swap active: $(free -m | awk '/Swap:/ {print $2}') MB"
else
  info "Swap is sufficient — skipping."
fi

info "Updating package lists..."
apt-get update -qq

info "Installing required packages (curl, git, ripgrep)..."
apt-get install -y -qq curl git ripgrep >/dev/null 2>&1
info "System packages ready."

if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
  TARGET_USER="$SUDO_USER"
else
  TARGET_USER="root"
fi

TARGET_HOME=$(eval echo "~$TARGET_USER")
info "Installing Claude Code for user: $TARGET_USER ($TARGET_HOME)"

info "Running the official Anthropic native installer..."
su - "$TARGET_USER" -c 'curl -fsSL https://claude.ai/install.sh | bash' || {
  fail "Native installer failed. Check network connectivity and try again."
}

SHELL_RC="$TARGET_HOME/.bashrc"
[[ -f "$TARGET_HOME/.zshrc" ]] && SHELL_RC="$TARGET_HOME/.zshrc"

PATHS_TO_ADD=("$TARGET_HOME/.local/bin" "$TARGET_HOME/.claude/bin")

for P in "${PATHS_TO_ADD[@]}"; do
  if ! grep -qF "$P" "$SHELL_RC" 2>/dev/null; then
    echo "export PATH=\"$P:\$PATH\"" >> "$SHELL_RC"
    info "Added $P to $SHELL_RC"
  fi
done

CLAUDE_CONFIG_DIR="$TARGET_HOME/.claude"
CLAUDE_SETTINGS="$CLAUDE_CONFIG_DIR/settings.json"

info "Configuring auto-approve for all tools..."

mkdir -p "$CLAUDE_CONFIG_DIR"

cat > "$CLAUDE_SETTINGS" << 'SETTINGS'
{
  "permissions": {
    "allow": [
      "Bash(*)",
      "Read(*)",
      "Edit(*)",
      "Write(*)",
      "MultiEdit(*)",
      "WebFetch(*)",
      "WebSearch",
      "TodoRead(*)",
      "TodoWrite(*)",
      "Glob(*)",
      "Grep(*)",
      "LS(*)",
      "mcp__*"
    ],
    "defaultMode": "acceptEdits"
  }
}
SETTINGS

info "Written: $CLAUDE_SETTINGS"

CLAUDE_CREDS="$CLAUDE_CONFIG_DIR/.credentials.json"
if [[ -f /tmp/.claude-creds-inject.json ]]; then
  cp /tmp/.claude-creds-inject.json "$CLAUDE_CREDS"
  chmod 600 "$CLAUDE_CREDS"
  rm -f /tmp/.claude-creds-inject.json
  info "Credentials injected — no manual login needed!"
else
  warn "No credentials provided — you will need to run 'claude' and log in manually."
fi

if command -v python3 &>/dev/null; then
  CLAUDE_JSON="$TARGET_HOME/.claude.json"
  python3 -c "
import json, os
path = '$CLAUDE_JSON'
try:
    with open(path) as f:
        data = json.load(f)
except:
    data = {}
data['autoUpdater'] = True
data['hasCompletedOnboarding'] = True
data['lastOnboardingVersion'] = '2.1.72'
data['numStartups'] = 1
data.setdefault('projects', {}).setdefault('default', {})['allowedTools'] = [
    'Bash(*)', 'Read(*)', 'Edit(*)', 'Write(*)', 'MultiEdit(*)',
    'WebFetch(*)', 'WebSearch', 'TodoRead(*)', 'TodoWrite(*)',
    'Glob(*)', 'Grep(*)', 'LS(*)', 'mcp__*'
]
with open(path, 'w') as f:
    json.dump(data, f, indent=2)
"
  info "Written: $CLAUDE_JSON"
fi

if [[ "$TARGET_USER" != "root" ]]; then
  chown -R "$TARGET_USER:$TARGET_USER" "$CLAUDE_CONFIG_DIR"
  [[ -f "$CLAUDE_JSON" ]] && chown "$TARGET_USER:$TARGET_USER" "$CLAUDE_JSON"
fi

CLAUDE_BIN=""
for P in "${PATHS_TO_ADD[@]}"; do
  [[ -x "$P/claude" ]] && CLAUDE_BIN="$P/claude" && break
done

if [[ -n "$CLAUDE_BIN" ]]; then
  CLAUDE_VERSION=$( su - "$TARGET_USER" -c "'$CLAUDE_BIN' --version 2>/dev/null" || echo "unknown" )
  info "Claude Code installed!  Version: $CLAUDE_VERSION"
else
  warn "Binary not found yet. Log out and back in, then run: claude --version"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Installation complete! (All permissions auto-approved)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Run:  source $SHELL_RC && claude"
echo "  All tools pre-approved. No permission prompts."
echo ""
"""

_claude_install_lock = threading.Lock()
_claude_install_active = set()  # set of (uid, server_name)


@app.route("/install_claude_code/<name>", methods=["POST"])
@login_required
def install_claude_code(name):
    uid = current_user.id
    server = get_server(uid, name)
    if not server:
        return jsonify({"error": "Server not found"}), 404

    lock_key = (uid, name)
    with _claude_install_lock:
        if lock_key in _claude_install_active:
            return jsonify({"error": "Installation already in progress"}), 409
        _claude_install_active.add(lock_key)

    def generate():
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            _ssh_connect(client, server, timeout=15)

            def sse(data):
                return f"data: {json.dumps(data)}\n\n"

            yield sse("Connecting to server...")

            # Upload live credentials from this server
            creds_content = ""
            try:
                with open(os.path.expanduser("~/.claude/.credentials.json")) as _cf:
                    creds_content = _cf.read().strip()
            except Exception:
                pass

            sftp = client.open_sftp()

            if creds_content:
                yield sse("Uploading credentials...")
                with sftp.file("/tmp/.claude-creds-inject.json", "w") as f:
                    f.write(creds_content)
                sftp.chmod("/tmp/.claude-creds-inject.json", 0o600)
            else:
                yield sse(
                    "Warning: No local credentials found — manual login will be required."
                )

            # Write script to /tmp
            yield sse("Writing install script to /tmp/install-claude-code.sh...")
            with sftp.file("/tmp/install-claude-code.sh", "w") as f:
                f.write(_CLAUDE_INSTALL_SCRIPT)
            sftp.chmod("/tmp/install-claude-code.sh", 0o755)
            sftp.close()

            # Execute with combined stdout+stderr via channel
            yield sse("Starting installation...")
            transport = client.get_transport()
            channel = transport.open_session()
            channel.set_combine_stderr(True)
            channel.get_pty(width=200)
            channel.exec_command("bash /tmp/install-claude-code.sh")

            buf = b""
            while True:
                if channel.recv_ready():
                    chunk = channel.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    # Split on newlines and emit complete lines
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        yield sse(line.decode("utf-8", errors="replace"))
                elif channel.exit_status_ready():
                    # Flush remaining buffer
                    if buf:
                        yield sse(buf.decode("utf-8", errors="replace"))
                    break
                else:
                    _time.sleep(0.05)

            exit_code = channel.recv_exit_status()
            channel.close()

            # Cleanup script on success
            if exit_code == 0:
                try:
                    client.exec_command("rm -f /tmp/install-claude-code.sh")
                except Exception:
                    pass

            client.close()
            yield f"event: done\ndata: {exit_code}\n\n"
        except Exception as e:
            yield sse(f"Error: {e}")
            yield f"event: done\ndata: 1\n\n"
        finally:
            with _claude_install_lock:
                _claude_install_active.discard(lock_key)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# Startup (runs on import - needed for both dev and gunicorn)
# ---------------------------------------------------------------------------

ensure_default_admin()
_migrate_legacy()


# Dev server (only when running directly, NOT used in production)
if __name__ == "__main__":
    import sys

    print(
        "WARNING: Running Flask dev server. Use Gunicorn for production:",
        file=sys.stderr,
    )
    print("  gunicorn -c gunicorn.conf.py app:app", file=sys.stderr)
    app.run(host="0.0.0.0", port=5002, debug=False)
