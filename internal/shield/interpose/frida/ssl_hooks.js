/*
 * DefenseClaw Shield — Frida SSL Hooks
 *
 * Injected into a target process by Frida. Hooks SSL_write and SSL_read
 * in OpenSSL/BoringSSL (dynamically or statically linked).
 *
 * Reads plaintext BEFORE encryption (SSL_write) and AFTER decryption (SSL_read).
 * Sends intercepted content to the shield daemon via Unix socket.
 * Daemon returns verdict: ALLOW (0x00) or BLOCK (0x01).
 * On BLOCK, SSL_write is made to return -1 (write failure).
 *
 * NO TLS termination. The actual TLS session is untouched.
 */

const SOCKET_PATH = "SHIELD_SOCKET_PLACEHOLDER";  // replaced at runtime by the launcher
const MSG_REQUEST = 0x01;
const MSG_RESPONSE = 0x02;
const VERDICT_ALLOW = 0x00;
const VERDICT_BLOCK = 0x01;

// --- Unix socket IPC to shield daemon ---

function sendToDaemon(msgType, peerAddr, data) {
    // Build the wire message matching Go ipc.go protocol.
    const hostBytes = Memory.allocUtf8String(peerAddr);
    const hostLen = peerAddr.length;
    const pid = Process.id;
    const payloadLen = data.byteLength;
    const bodyLen = 1 + 4 + 2 + hostLen + 4 + payloadLen;

    const buf = Memory.alloc(4 + bodyLen);
    buf.writeU32(bodyLen);
    buf.add(4).writeU8(msgType);
    buf.add(5).writeU32(pid);
    buf.add(9).writeU16(hostLen);
    Memory.copy(buf.add(11), hostBytes, hostLen);
    buf.add(11 + hostLen).writeU32(payloadLen);
    if (payloadLen > 0) {
        Memory.copy(buf.add(11 + hostLen + 4), data, payloadLen);
    }

    // Connect to daemon.
    const AF_UNIX = 1;
    const SOCK_STREAM = 1;
    const sock = Socket.socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock === -1) return VERDICT_ALLOW;

    try {
        Socket.connect(sock, { family: 'unix', path: SOCKET_PATH });
    } catch (e) {
        Socket.close(sock);
        return VERDICT_ALLOW;
    }

    // Send message.
    Socket.write(sock, buf.readByteArray(4 + bodyLen));

    // Read verdict (1 byte).
    const verdictBuf = Socket.read(sock, 1);
    Socket.close(sock);

    if (verdictBuf && verdictBuf.byteLength === 1) {
        return new Uint8Array(verdictBuf)[0];
    }
    return VERDICT_ALLOW;
}

// --- Get peer address from SSL* → fd → getpeername ---

const SSL_get_fd = Module.findExportByName(null, "SSL_get_fd");
const getpeername_fn = new NativeFunction(
    Module.findExportByName(null, "getpeername"),
    "int", ["int", "pointer", "pointer"]
);

function getPeerAddress(ssl) {
    if (!SSL_get_fd) return "unknown:443";

    const getFd = new NativeFunction(SSL_get_fd, "int", ["pointer"]);
    const fd = getFd(ssl);
    if (fd < 0) return "unknown:443";

    const addrBuf = Memory.alloc(128);
    const lenBuf = Memory.alloc(4);
    lenBuf.writeU32(128);

    if (getpeername_fn(fd, addrBuf, lenBuf) !== 0) return "unknown:443";

    const family = addrBuf.readU16();
    if (family === 2) {  // AF_INET
        const port = (addrBuf.add(2).readU8() << 8) | addrBuf.add(3).readU8();
        const ip = [
            addrBuf.add(4).readU8(),
            addrBuf.add(5).readU8(),
            addrBuf.add(6).readU8(),
            addrBuf.add(7).readU8()
        ].join(".");
        return ip + ":" + port;
    }
    return "unknown:443";
}

// --- Hook SSL_write ---

const ssl_write_ptr = Module.findExportByName(null, "SSL_write");
if (ssl_write_ptr) {
    Interceptor.attach(ssl_write_ptr, {
        onEnter: function(args) {
            this.ssl = args[0];
            this.buf = args[1];
            this.num = args[2].toInt32();
        },
        onLeave: function(retval) {
            if (this.num <= 0) return;

            const data = this.buf.readByteArray(this.num);
            const peer = getPeerAddress(this.ssl);
            const verdict = sendToDaemon(MSG_REQUEST, peer, data);

            if (verdict === VERDICT_BLOCK) {
                // Make SSL_write appear to fail.
                retval.replace(ptr(-1));
                send({ type: "shield", action: "BLOCKED", direction: "request", peer: peer });
            }
        }
    });
    send({ type: "shield", status: "hooked SSL_write at " + ssl_write_ptr });
} else {
    send({ type: "shield", status: "SSL_write not found — process may not use OpenSSL" });
}

// --- Hook SSL_read ---

const ssl_read_ptr = Module.findExportByName(null, "SSL_read");
if (ssl_read_ptr) {
    Interceptor.attach(ssl_read_ptr, {
        onEnter: function(args) {
            this.ssl = args[0];
            this.buf = args[1];
        },
        onLeave: function(retval) {
            const bytesRead = retval.toInt32();
            if (bytesRead <= 0) return;

            const data = this.buf.readByteArray(bytesRead);
            const peer = getPeerAddress(this.ssl);
            sendToDaemon(MSG_RESPONSE, peer, data);
            // Response inspection logs but doesn't block for POC.
        }
    });
    send({ type: "shield", status: "hooked SSL_read at " + ssl_read_ptr });
}
