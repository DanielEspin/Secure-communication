"""
common.py - Message framing shared by main.py and client.py.

TCP is a byte stream, not a message stream. One recv() can return half a
message, or two messages glued together. We solve that by terminating every
message with a newline and buffering until we see one.
"""

import json
import threading


def send_json(sock, obj, wlock=None):
    """Serialize obj to one newline-terminated JSON line and send it."""
    data = (json.dumps(obj) + "\n").encode("utf-8")
    if wlock:
        with wlock:
            sock.sendall(data)
    else:
        sock.sendall(data)


class JSONReader:
    """Reads newline-delimited JSON objects off a socket, one at a time."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def recv(self):
        """Return the next message as a dict, or None if the peer disconnected."""
        while b"\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                return None
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        try:
            return json.loads(line.decode("utf-8"))
        except json.JSONDecodeError:
            return {"cmd": "__malformed__"}
