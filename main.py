#!/usr/bin/env python3
"""
main.py - Authentication server + blind relay.

Run this first:
    python3 main.py

It owns users.json and shadows.txt. Clients never touch those files; they
send credentials over TLS and the server does the Argon2 verification.

Because chat messages are end-to-end encrypted by the clients, this server
relays ciphertext it cannot read. It only knows *that* alice talked to bob.
"""

import base64
import json
import os
import re
import secrets
import socket
import ssl
import threading
import time
import uuid
from datetime import datetime, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

from common import JSONReader, send_json

HOST, PORT = "0.0.0.0", 8443
USERS_FILE = "users.json"
SHADOWS_FILE = "shadows.txt"
CERTFILE, KEYFILE = "server.crt", "server.key"

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")
LOCKOUT_CAP_MINUTES = 15

ph = PasswordHasher()
# Verified against when a username does not exist, so that a bad username and a
# bad password take the same amount of time. Otherwise an attacker can tell which
# accounts exist just by timing the response.
DUMMY_HASH = ph.hash("timing-equalizer-not-a-real-password")

state_lock = threading.RLock()
online = {}     # username -> Session
lockouts = {}   # username -> [consecutive_failures, unlock_epoch_seconds]


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------

def load_users():
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_users(users):
    # Write to a temp file then rename. os.replace is atomic, so a crash
    # mid-write can never leave you with a truncated users.json.
    tmp = USERS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(users, f, indent=4)
    os.replace(tmp, USERS_FILE)


def load_shadows():
    shadows = {}
    try:
        with open(SHADOWS_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                user, hashed = line.split(":", 1)
                shadows[user] = hashed
    except FileNotFoundError:
        pass
    return shadows


def append_shadow(username, password):
    with open(SHADOWS_FILE, "a") as f:
        f.write(f"{username}:{ph.hash(password)}\n")


def verify_login(username, password):
    """Constant-ish time credential check."""
    stored = load_shadows().get(username)
    try:
        ph.verify(stored if stored else DUMMY_HASH, password)
    except VerificationError:
        return False
    # The `stored is not None` guard means that even if somebody's password
    # happened to equal the dummy, a nonexistent account still cannot log in.
    return stored is not None


# --------------------------------------------------------------------------
# Lockout: exponential backoff, enforced server-side only
# --------------------------------------------------------------------------

def seconds_locked(username):
    with state_lock:
        entry = lockouts.get(username)
        if not entry:
            return 0
        return max(0, entry[1] - time.time())


def record_failure(username):
    """Increment the failure counter and return the new lockout in minutes."""
    with state_lock:
        entry = lockouts.setdefault(username, [0, 0])
        entry[0] += 1
        minutes = min(2 ** (entry[0] - 1), LOCKOUT_CAP_MINUTES)
        entry[1] = time.time() + minutes * 60
        return minutes


def clear_failures(username):
    with state_lock:
        lockouts.pop(username, None)


# --------------------------------------------------------------------------
# Per-connection session
# --------------------------------------------------------------------------

class Session:
    def __init__(self, sock, addr):
        self.sock = sock
        self.addr = addr
        self.reader = JSONReader(sock)
        self.wlock = threading.Lock()   # relay means other threads write here
        self.user = None
        self.peer = None                # username of the person we're chatting with
        self.initiator = False          # did we start the current chat?

    def send(self, obj):
        try:
            send_json(self.sock, obj, self.wlock)
        except OSError:
            pass


def peer_session(session):
    with state_lock:
        return online.get(session.peer) if session.peer else None


def end_chat(session, reason="Chat ended."):
    with state_lock:
        other = online.get(session.peer) if session.peer else None
        if other:
            other.peer = None
            other.initiator = False
            other.send({"ev": "info", "text": reason})
        session.peer = None
        session.initiator = False


# --------------------------------------------------------------------------
# Command handlers
# --------------------------------------------------------------------------

def cmd_register(session, msg):
    username = (msg.get("user") or "").strip().lower()
    password = msg.get("pass") or ""
    display = (msg.get("display") or "").strip()

    if not USERNAME_RE.match(username):
        return session.send({"ev": "error",
                             "text": "Username must be 3-20 chars: a-z, 0-9, underscore."})
    if len(password) < 8:
        return session.send({"ev": "error", "text": "Password must be at least 8 characters."})
    if not display:
        return session.send({"ev": "error", "text": "Display name required."})

    with state_lock:
        users = load_users()
        if any(u["username"] == username for u in users):
            return session.send({"ev": "error", "text": "That username is already taken."})
        if any(u["display_name"] == display for u in users):
            return session.send({"ev": "error", "text": "That display name is already taken."})

        now = datetime.now(timezone.utc).isoformat()
        users.append({
            "username": username,
            "user_id": str(uuid.uuid4()),
            "display_name": display,
            "created_at": now,
            "last_login": now,
        })
        save_users(users)
        append_shadow(username, password)

    session.send({"ev": "ok", "text": "Account created. You can log in now."})


def cmd_login(session, msg):
    username = (msg.get("user") or "").strip().lower()
    password = msg.get("pass") or ""

    remaining = seconds_locked(username)
    if remaining > 0:
        return session.send({"ev": "error",
                             "text": f"Account locked. Try again in {int(remaining)}s."})

    if not verify_login(username, password):
        mins = record_failure(username)
        return session.send({"ev": "error",
                             "text": f"Invalid username or password. Locked for {mins} min."})

    with state_lock:
        if username in online:
            return session.send({"ev": "error", "text": "That account is already logged in."})
        session.user = username
        online[username] = session

        users = load_users()
        for u in users:
            if u["username"] == username:
                u["last_login"] = datetime.now(timezone.utc).isoformat()
                break
        save_users(users)

    clear_failures(username)
    session.send({"ev": "ok", "text": f"Login successful. Welcome, {username}."})


def cmd_who(session, _msg):
    with state_lock:
        others = sorted(u for u in online if u != session.user)
    session.send({"ev": "info", "text": "Online: " + (", ".join(others) or "(nobody else)")})


def cmd_chat(session, msg):
    target = (msg.get("with") or "").strip().lower()

    remaining = seconds_locked(session.user)
    if remaining > 0:
        return session.send({"ev": "error",
                             "text": f"You are locked out. Try again in {int(remaining)}s."})
    if target == session.user:
        return session.send({"ev": "error", "text": "You cannot chat with yourself."})

    with state_lock:
        other = online.get(target)
        if not other:
            return session.send({"ev": "error", "text": f"{target} is not online."})
        if other.peer or session.peer:
            return session.send({"ev": "error", "text": "One of you is already in a chat."})

        # Fresh random salt per session. Both sides get the same one, so both
        # derive the same key from the same password+number. Rotating it means
        # no attacker can precompute against a fixed salt.
        salt = base64.b64encode(secrets.token_bytes(16)).decode()

        session.peer, session.initiator = target, True
        other.peer, other.initiator = session.user, False

        session.send({"ev": "chat_start", "peer": target, "salt": salt, "initiator": True})
        other.send({"ev": "chat_start", "peer": session.user, "salt": salt, "initiator": False})


def cmd_relay(session, msg):
    """Forward an opaque ciphertext blob. The server cannot decrypt this."""
    other = peer_session(session)
    if not other:
        return session.send({"ev": "error", "text": "You are not in a chat."})
    other.send({"ev": "cipher", "from": session.user, "blob": msg.get("blob", "")})


def cmd_handshake_failed(session, _msg):
    """
    The peer could not decrypt our key-confirmation probe, which means the
    channel password or the number did not match.

    We always penalize the *initiator*, since they are the party requesting
    access. Note this is reported by the honest peer's client, not the
    guesser's, so an attacker cannot patch the lockout out of their own client.
    """
    with state_lock:
        other = online.get(session.peer) if session.peer else None
        culprit = session.user if session.initiator else (other.user if other else None)

    if culprit:
        mins = record_failure(culprit)
        target = online.get(culprit)
        if target:
            target.send({"ev": "error",
                         "text": f"Wrong channel password or number. Locked for {mins} min."})
    end_chat(session, "Handshake failed. Chat closed.")
    session.send({"ev": "info", "text": "Handshake failed. Chat closed."})


def cmd_handshake_ok(session, _msg):
    other = peer_session(session)
    if other:
        other.send({"ev": "hs_ok"})
    session.send({"ev": "hs_ok"})


def cmd_endchat(session, _msg):
    end_chat(session, f"{session.user} left the chat.")
    session.send({"ev": "info", "text": "Chat closed."})


HANDLERS = {
    "register": (False, cmd_register),
    "login":    (False, cmd_login),
    "who":      (True,  cmd_who),
    "chat":     (True,  cmd_chat),
    "relay":    (True,  cmd_relay),
    "hs_fail":  (True,  cmd_handshake_failed),
    "hs_ok":    (True,  cmd_handshake_ok),
    "endchat":  (True,  cmd_endchat),
}


# --------------------------------------------------------------------------
# Connection loop
# --------------------------------------------------------------------------

def handle_client(sock, addr):
    session = Session(sock, addr)
    print(f"[+] connection from {addr[0]}:{addr[1]}")
    try:
        while True:
            msg = session.reader.recv()
            if msg is None:
                break

            cmd = msg.get("cmd")
            if cmd == "quit":
                break

            entry = HANDLERS.get(cmd)
            if not entry:
                session.send({"ev": "error", "text": f"Unknown command: {cmd}"})
                continue

            needs_auth, handler = entry
            if needs_auth and not session.user:
                session.send({"ev": "error", "text": "You must log in first."})
                continue
            handler(session, msg)
    except (ConnectionResetError, ssl.SSLError, OSError):
        pass
    finally:
        if session.user:
            end_chat(session, f"{session.user} disconnected.")
            with state_lock:
                online.pop(session.user, None)
            print(f"[-] {session.user} disconnected")
        else:
            print(f"[-] {addr[0]}:{addr[1]} disconnected")
        try:
            sock.close()
        except OSError:
            pass


def main():
    if not (os.path.exists(CERTFILE) and os.path.exists(KEYFILE)):
        print("Missing server.crt / server.key. Generate them with:\n")
        print('  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \\')
        print('    -keyout server.key -out server.crt -subj "/CN=localhost"\n')
        return

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERTFILE, KEYFILE)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((HOST, PORT))
    listener.listen(16)
    print(f"Server listening on {HOST}:{PORT} (TLS). Ctrl-C to stop.")

    try:
        while True:
            raw, addr = listener.accept()
            try:
                tls = ctx.wrap_socket(raw, server_side=True)
            except ssl.SSLError as e:
                print(f"[!] TLS handshake failed from {addr[0]}: {e}")
                raw.close()
                continue
            threading.Thread(target=handle_client, args=(tls, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        listener.close()


if __name__ == "__main__":
    main()