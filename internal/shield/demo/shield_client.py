"""
Shield IPC client — sends intercepted content to the daemon for inspection.

Wire protocol (little-endian, matches Go ipc.go):
  [4 bytes] body length
  [1 byte]  type: 0x01=request, 0x02=response
  [4 bytes] PID
  [2 bytes] host length
  [N bytes] host string
  [4 bytes] payload length
  [N bytes] payload
Reply: [1 byte] 0x00=allow, 0x01=block
"""

import os
import socket
import struct


VERDICT_ALLOW = 0x00
VERDICT_BLOCK = 0x01

MSG_REQUEST = 0x01
MSG_RESPONSE = 0x02


class ShieldClient:
    def __init__(self, socket_path=None):
        if socket_path is None:
            socket_path = os.environ.get(
                "SHIELD_SOCKET",
                os.path.expanduser("~/.defenseclaw-shield/shield.sock"),
            )
        self._path = socket_path
        self._sock = None

    def _connect(self):
        if self._sock is not None:
            return
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.connect(self._path)

    def _send(self, msg_type, host, payload):
        self._connect()
        pid = os.getpid()
        host_bytes = host.encode()
        payload_bytes = payload if isinstance(payload, bytes) else payload.encode()

        body = struct.pack("<BIH", msg_type, pid, len(host_bytes))
        body += host_bytes
        body += struct.pack("<I", len(payload_bytes))
        body += payload_bytes

        header = struct.pack("<I", len(body))
        self._sock.sendall(header + body)

        verdict = self._sock.recv(1)
        if not verdict:
            raise ConnectionError("daemon closed connection")
        return verdict[0]

    def check_request(self, host, payload):
        return self._send(MSG_REQUEST, host, payload)

    def check_response(self, host, payload):
        return self._send(MSG_RESPONSE, host, payload)

    def close(self):
        if self._sock:
            self._sock.close()
            self._sock = None
