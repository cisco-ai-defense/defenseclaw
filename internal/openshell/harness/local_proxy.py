#!/usr/bin/python3 -I
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Route sandbox-local HTTP through its own namespace, other HTTP to egress."""

import base64
import fcntl
import hashlib
import ipaddress
import os
import select
import socket
import socketserver
import string
import subprocess
import sys
import tempfile
from urllib.parse import unquote, urlsplit

EGRESS_URL_KEY = "DEFENSECLAW_EGRESS_URL"
MAX_HEADER = 65536


def loopback_aliases(path="/etc/hosts"):
    """Names explicitly mapped only to this namespace's loopback in hosts."""
    local, other = set(), set()
    try:
        with open(path, encoding="utf-8", errors="replace") as hosts:
            for line in hosts:
                fields = line.split("#", 1)[0].split()
                if len(fields) < 2:
                    continue
                try:
                    address = ipaddress.ip_address(fields[0])
                except ValueError:
                    continue
                if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                    address = address.ipv4_mapped
                names = {name.lower().rstrip(".") for name in fields[1:]}
                (local if address.is_loopback else other).update(names)
    except OSError:
        return frozenset()
    return frozenset(local - other)


LOCAL_ALIASES = loopback_aliases()


def upstream():
    raw = os.environ.get(EGRESS_URL_KEY, "")
    parsed = urlsplit(raw)
    if (parsed.scheme != "http" or parsed.hostname not in
            ("host.openshell.internal", "127.0.0.1", "::1") or
            not parsed.port or parsed.path or parsed.query or parsed.fragment):
        raise ValueError("invalid sandbox egress URL")
    user = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    auth = ("Proxy-Authorization: Basic " +
            base64.b64encode((user + ":" + password).encode()).decode() + "\r\n"
            if parsed.username is not None else "")
    return raw, parsed.hostname, parsed.port, auth


def local_address(host):
    name = host.lower().rstrip(".")
    if (name in {"localhost", "localhost4", "localhost6", "ip6-localhost", "ip6-loopback"} or
            name.endswith((".localhost", ".localdomain", ".localdomain4", ".localdomain6")) or
            name in LOCAL_ALIASES):
        return True
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        # System resolvers also accept alternate numeric IPv4 forms.
        # Treat those as local only after the resolver's IPv4 interpretation.
        try:
            address = ipaddress.ip_address(socket.inet_aton(name))
        except OSError:
            return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_loopback


def connect_local(host, port):
    last_error = None
    for family, kind, protocol, _, address in socket.getaddrinfo(
            host, port, type=socket.SOCK_STREAM):
        ip = ipaddress.ip_address(address[0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_loopback:
            continue
        peer = socket.socket(family, kind, protocol)
        try:
            peer.settimeout(10)
            peer.connect(address)
            return peer
        except OSError as error:
            last_error = error
            peer.close()
    raise last_error or OSError("local destination is not on loopback")


def target_address(method, target):
    if method == "CONNECT":
        url = urlsplit("http://" + target)
        if url.path or url.query or url.fragment:
            raise ValueError("invalid CONNECT target")
        return url.hostname, url.port, target
    url = urlsplit(target)
    if url.scheme not in ("http", "https") or not url.hostname:
        raise ValueError("invalid proxy request target")
    return url.hostname, url.port or (443 if url.scheme == "https" else 80), (url.path or "/") + (("?" + url.query) if url.query else "")


def relay(left, right):
    sockets = [left, right]
    while sockets:
        readable, _, _ = select.select(sockets, [], [])
        for source in readable:
            destination = right if source is left else left
            data = source.recv(65536)
            if not data:
                sockets.remove(source)
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            else:
                destination.sendall(data)


def forward_refusal(client, peer, response):
    """Keep the upstream status and complete body when CONNECT is refused."""
    client.sendall(response)
    head, _, body = response.partition(b"\r\n\r\n")
    lengths = []
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.lower() == b"content-length":
            try:
                lengths.append(int(value.strip()))
            except ValueError:
                break
    if len(lengths) == 1 and lengths[0] >= 0:
        remaining = max(0, lengths[0] - len(body))
        while remaining:
            try:
                piece = peer.recv(min(65536, remaining))
            except OSError:
                return
            if not piece:
                return
            client.sendall(piece)
            remaining -= len(piece)
        return
    # A response without a length is delimited by the upstream close.
    peer.settimeout(5)
    try:
        while piece := peer.recv(65536):
            client.sendall(piece)
    except OSError:
        pass


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(30)
        header = bytearray()
        while b"\r\n\r\n" not in header and len(header) <= MAX_HEADER:
            piece = self.request.recv(4096)
            if not piece:
                return
            header.extend(piece)
        if len(header) > MAX_HEADER or b"\r\n\r\n" not in header:
            self.request.sendall(b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        head, body = bytes(header).split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        try:
            method, target, version = lines[0].decode("ascii").split(" ", 2)
            if (not method or not all(char in string.ascii_letters + string.digits +
                                      "!#$%&'*+-.^_`|~" for char in method) or
                    not target or not all(33 <= ord(char) <= 126 for char in target)):
                raise ValueError("invalid proxy request line")
            if version not in ("HTTP/1.0", "HTTP/1.1"):
                raise ValueError("unsupported HTTP version")
            if any(b"\n" in line or b":" not in line for line in lines[1:]):
                raise ValueError("invalid proxy header")
            host, port, path = target_address(method, target)
            if not host or not port:
                raise ValueError("missing destination")
            local = local_address(host)
            _, upstream_host, upstream_port, auth = upstream()
            peer = (connect_local(host, port) if local else
                    socket.create_connection((upstream_host, upstream_port), timeout=10))
            with peer:
                peer.settimeout(30 if method == "CONNECT" and not local else None)
                if method == "CONNECT":
                    if local:
                        self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    else:
                        request = ("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n" + auth + "\r\n")
                        peer.sendall(request.encode("ascii"))
                        response = bytearray()
                        while b"\r\n\r\n" not in response and len(response) <= MAX_HEADER:
                            piece = peer.recv(4096)
                            if not piece:
                                break
                            response.extend(piece)
                        if b"\r\n\r\n" not in response or len(response) > MAX_HEADER:
                            raise ValueError("invalid upstream response")
                        if not response.startswith(b"HTTP/1.1 200 ") and not response.startswith(b"HTTP/1.0 200 "):
                            forward_refusal(self.request, peer, response)
                            return
                        self.request.sendall(response)
                        peer.settimeout(None)
                    # A client may send its first tunnel bytes with the
                    # CONNECT head. They were already read into body.
                    if body:
                        peer.sendall(body)
                else:
                    first = (method + " " + (path if local else target) + " " + version + "\r\n").encode("ascii")
                    headers = []
                    for line in lines[1:]:
                        key = line.split(b":", 1)[0].strip().lower()
                        if key not in (b"proxy-authorization", b"proxy-connection", b"connection"):
                            headers.append(line)
                    connection = (b"Connection: Upgrade\r\n" if any(
                        line.split(b":", 1)[0].strip().lower() == b"upgrade"
                        for line in headers) else b"Connection: close\r\n")
                    peer.sendall(first + b"\r\n".join(headers) + b"\r\n" +
                                 connection + auth.encode("ascii") * (not local) +
                                 b"\r\n" + body)
                self.request.settimeout(None)
                relay(self.request, peer)
        except (OSError, ValueError, UnicodeError):
            try:
                self.request.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass


class ProxyServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False


def serve():
    upstream()
    with ProxyServer(("127.0.0.1", 0), ProxyHandler) as server:
        print("http://127.0.0.1:" + str(server.server_address[1]), flush=True)
        server.serve_forever(poll_interval=0.5)


def ensure():
    raw, _, _, _ = upstream()
    state_dir = os.path.join(tempfile.gettempdir(),
                             "defenseclaw-local-proxy-" + str(os.getuid()))
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    info = os.lstat(state_dir)
    if not os.path.isdir(state_dir) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("unsafe local proxy state directory")
    digest = hashlib.sha256(raw.encode()).hexdigest()
    with open(os.path.join(state_dir, ".lock"), "a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = os.path.join(state_dir, digest)
        try:
            with open(state, encoding="ascii") as saved:
                _, local_url = saved.read().splitlines()
            parsed = urlsplit(local_url)
            if parsed.hostname == "127.0.0.1" and parsed.port:
                with socket.create_connection(("127.0.0.1", parsed.port), timeout=0.2):
                    return local_url
        except (OSError, ValueError):
            pass
        child = subprocess.Popen([sys.executable, "-I", __file__, "--serve"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, start_new_session=True,
                                 close_fds=True, env={EGRESS_URL_KEY: raw})
        ready, _, _ = select.select([child.stdout], [], [], 3)
        if not ready:
            child.terminate()
            raise OSError("local proxy did not start")
        local_url = child.stdout.readline().decode("ascii").strip()
        child.stdout.close()
        parsed = urlsplit(local_url)
        if parsed.hostname != "127.0.0.1" or not parsed.port:
            child.terminate()
            raise OSError("local proxy returned an invalid address")
        with open(state, "w", encoding="ascii") as saved:
            saved.write(str(child.pid) + "\n" + local_url + "\n")
        return local_url


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--serve"]:
            serve()
        elif sys.argv[1:] == ["--ensure"]:
            print(ensure())
        else:
            raise ValueError("expected --serve or --ensure")
    except (OSError, ValueError) as error:
        print("DefenseClaw local proxy: " + str(error), file=sys.stderr)
        sys.exit(1)
