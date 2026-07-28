#!/usr/bin/env python3
"""
client.py - Terminal chat client.

Run after main.py is up:
    python3 client.py

Only the MAIN thread ever reads stdin. The receive thread only prints and
does crypto. Mixing input() across two threads produces chaos, so we avoid it.
"""

import base64
import getpass
import os
import re
import socket
import ssl
import sys
import threading

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from common import JSONReader, send_json

HOST, PORT = "localhost", 8443
CAFILE = "server.crt"          # we pin the server's self-signed cert as our CA
PROBE = "KEYCHECK"
CONFIRM = "KEYOK"

state = {
    "key": None,          # bytes, the derived AES-256 key
    "peer": None,
    "salt": None,
    "initiator": False,
    "ready": False,       # handshake confirmed
    "pending": [],        # ciphertext that arrived before we set up our key
}
state_lock = threading.Lock()
salt_ready = threading.Event()
sock = None
wlock = threading.Lock()


# --------------------------------------------------------------------------
# Crypto
# --------------------------------------------------------------------------

def derive_key(password, number, salt):
    """
    Argon2id used as a KDF, not a password hasher. Same password + same number
    + same salt on both machines produces the same 32-byte key. Different
    inputs produce a different key, and AES-GCM's tag check then fails.
    """
    return hash_secret_raw(
        secret=f"{password}|{number:02d}".encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )


def encrypt(key, plaintext):
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt(key, blob):
    """Raises InvalidTag if the key is wrong or the message was tampered with."""
    raw = base64.b64decode(blob)
    return AESGCM(key).decrypt(raw[:12], raw[12:], None).decode("utf-8")


def strong_channel_password(pw):
    return (len(pw) >= 8
            and re.search(r"[A-Z]", pw)
            and re.search(r"[a-z]", pw)
            and re.search(r"[^A-Za-z0-9]", pw))


# --------------------------------------------------------------------------
# Networking helpers
# --------------------------------------------------------------------------

def send(obj):
    try:
        send_json(sock, obj, wlock)
    except OSError:
        pass


def send_encrypted(text):
    with state_lock:
        key = state["key"]
    if not key:
        print("No secure channel set up yet.")
        return
    send({"cmd": "relay", "blob": encrypt(key, text)})


def handle_cipher(blob, sender):
    """Decrypt an incoming blob. Wrong key -> InvalidTag -> report the failure."""
    with state_lock:
        key = state["key"]
        if not key:
            state["pending"].append((blob, sender))
            return

    try:
        text = decrypt(key, blob)
    except (InvalidTag, ValueError):
        print("\n[!] Could not decrypt. The channel password or number does not match.")
        send({"cmd": "hs_fail"})
        return

    if text.startswith(PROBE):
        # The initiator proved they can encrypt; prove we can too.
        send({"cmd": "relay", "blob": encrypt(key, CONFIRM)})
        send({"cmd": "hs_ok"})
    elif text == CONFIRM:
        send({"cmd": "hs_ok"})
    else:
        print(f"\n{sender}: {text}")


def flush_pending():
    with state_lock:
        queued, state["pending"] = state["pending"], []
    for blob, sender in queued:
        handle_cipher(blob, sender)


# --------------------------------------------------------------------------
# Receive thread
# --------------------------------------------------------------------------

def receive_loop(reader):
    while True:
        msg = reader.recv()
        if msg is None:
            print("\n[!] Server closed the connection.")
            os._exit(0)

        ev = msg.get("ev")
        if ev == "chat_start":
            with state_lock:
                state["peer"] = msg["peer"]
                state["salt"] = base64.b64decode(msg["salt"])
                state["initiator"] = msg["initiator"]
                state["key"] = None
                state["ready"] = False
            if msg["initiator"]:
                salt_ready.set()
            else:
                print(f"\n[*] {msg['peer']} wants to open a channel. Type /join to set it up.")
        elif ev == "cipher":
            handle_cipher(msg["blob"], msg["from"])
        elif ev == "hs_ok":
            with state_lock:
                already, state["ready"] = state["ready"], True
            if not already:
                print(f"\n[*] Secure channel established with {state['peer']}. Type to chat.")
        elif ev in ("info", "ok"):
            print(f"\n[*] {msg['text']}")
        elif ev == "error":
            print(f"\n[!] {msg['text']}")
            with state_lock:
                state["key"] = state["peer"] = None
                state["ready"] = False
            salt_ready.clear()


# --------------------------------------------------------------------------
# Main-thread flows
# --------------------------------------------------------------------------

def setup_channel():
    """Prompt for the second password + number, derive the key, confirm it."""
    with state_lock:
        salt, initiator, peer = state["salt"], state["initiator"], state["peer"]
    if not salt:
        print("No pending channel.")
        return

    print(f"\nSetting up an encrypted channel with {peer}.")
    print("Both of you must enter the SAME channel password and number.")

    while True:
        pw = getpass.getpass("Channel password (8+, upper, lower, special): ")
        if strong_channel_password(pw):
            break
        print("Too weak. Needs 8+ chars with uppercase, lowercase, and a special character.")

    while True:
        raw = input("Shared number (0-99): ").strip()
        if raw.isdigit() and 0 <= int(raw) <= 99:
            number = int(raw)
            break
        print("Must be a whole number between 0 and 99.")

    print("Deriving key...")
    key = derive_key(pw, number, salt)
    with state_lock:
        state["key"] = key

    if initiator:
        send({"cmd": "relay", "blob": encrypt(key, PROBE + os.urandom(8).hex())})
    flush_pending()


def login_flow(reader):
    """Register or log in. Runs before the receive thread starts."""
    while True:
        print("\n1. Login\n2. Register")
        choice = input("Choose an option (1 or 2): ").strip()

        if choice == "1":
            user = input("Username: ").strip().lower()
            pw = getpass.getpass("Password: ")
            send({"cmd": "login", "user": user, "pass": pw})
        elif choice == "2":
            user = input("Choose a username: ").strip().lower()
            pw = getpass.getpass("Choose a password: ")
            display = input("Choose a display name: ").strip()
            send({"cmd": "register", "user": user, "pass": pw, "display": display})
        else:
            print("Invalid option.")
            continue

        reply = reader.recv()
        if reply is None:
            print("Server closed the connection.")
            sys.exit(1)
        print(f"{'[!]' if reply.get('ev') == 'error' else '[*]'} {reply.get('text', '')}")
        if reply.get("ev") == "ok" and choice == "1":
            return user


HELP = """
Commands:
  /who          list who else is online
  /chat <user>  open an encrypted channel with someone
  /join         accept a channel someone opened with you
  /end          close the current channel
  /quit         disconnect
Anything else you type is sent encrypted to your peer.
"""


def main():
    global sock

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        ctx.load_verify_locations(cafile=CAFILE)
    except FileNotFoundError:
        print(f"Missing {CAFILE}. Copy it from the server directory.")
        return
    ctx.check_hostname = True          # real verification, not CERT_NONE
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        raw = socket.create_connection((HOST, PORT), timeout=10)
        sock = ctx.wrap_socket(raw, server_hostname=HOST)
        sock.settimeout(None)
    except (OSError, ssl.SSLError) as e:
        print(f"Could not connect: {e}")
        return

    reader = JSONReader(sock)
    me = login_flow(reader)
    print(HELP)

    threading.Thread(target=receive_loop, args=(reader,), daemon=True).start()

    while True:
        try:
            line = input()
        except (EOFError, KeyboardInterrupt):
            break
        line = line.strip()
        if not line:
            continue

        if line == "/quit":
            break
        elif line == "/who":
            send({"cmd": "who"})
        elif line.startswith("/chat "):
            salt_ready.clear()
            send({"cmd": "chat", "with": line.split(" ", 1)[1].strip().lower()})
            # Wait for the server to hand us the channel salt, then prompt.
            if salt_ready.wait(timeout=10):
                setup_channel()
        elif line == "/join":
            setup_channel()
        elif line == "/end":
            send({"cmd": "endchat"})
            with state_lock:
                state["key"] = state["peer"] = None
                state["ready"] = False
        elif line == "/help":
            print(HELP)
        elif line.startswith("/"):
            print("Unknown command. Try /help")
        else:
            send_encrypted(line)

    send({"cmd": "quit"})
    sock.close()
    print("Disconnected.")


if __name__ == "__main__":
    main()
