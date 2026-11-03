"""Diagnostic listener for the Seitron thermostats.

For each incoming connection it logs: client address, local port, whether it is TLS,
the SNI name, whether the client completes a handshake against a self-signed
certificate (if yes, the device does not verify the server) and the length and
first line of what it sends next. Payload bytes are never logged in full.
"""

import json
import socket
import ssl
import threading
import time

PORTS = (443, 8443, 8080, 8883)


def log(**fields):
    print(json.dumps({"t": time.strftime("%H:%M:%S"), **fields}), flush=True)


def sni_from_client_hello(data):
    try:
        if len(data) < 43 or data[0] != 0x16:
            return None
        pos = 43
        pos += 1 + data[pos]
        pos += 2 + int.from_bytes(data[pos:pos + 2], "big")
        pos += 1 + data[pos]
        end = pos + 2 + int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        while pos + 4 <= end:
            kind = int.from_bytes(data[pos:pos + 2], "big")
            size = int.from_bytes(data[pos + 2:pos + 4], "big")
            if kind == 0:
                name_len = int.from_bytes(data[pos + 7:pos + 9], "big")
                return data[pos + 9:pos + 9 + name_len].decode(errors="replace")
            pos += 4 + size
    except (IndexError, ValueError):
        return None
    return None


def first_line(data):
    return data.split(b"\r\n", 1)[0][:120].decode(errors="replace")


def handle(conn, addr, port, ctx):
    conn.settimeout(15)
    try:
        head = conn.recv(4096, socket.MSG_PEEK)
        if not head:
            log(client=addr[0], port=port, event="closed-empty")
            return
        if head[0] != 0x16:
            data = conn.recv(4096)
            log(client=addr[0], port=port, tls=False, bytes=len(data), first=first_line(data))
            return
        sni = sni_from_client_hello(head)
        try:
            tls = ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            log(client=addr[0], port=port, tls=True, sni=sni, handshake="refused", error=str(exc)[:160])
            return
        log(client=addr[0], port=port, tls=True, sni=sni, handshake="accepted", version=tls.version())
        try:
            data = tls.recv(4096)
            log(client=addr[0], port=port, sni=sni, after_handshake_bytes=len(data), first=first_line(data))
        except (ssl.SSLError, OSError) as exc:
            log(client=addr[0], port=port, sni=sni, after_handshake="error", error=str(exc)[:160])
        tls.close()
    except OSError as exc:
        log(client=addr[0], port=port, event="error", error=str(exc)[:160])
    finally:
        conn.close()


def serve(port, ctx):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(16)
    log(event="listening", port=port)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr, port, ctx), daemon=True).start()


def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    ctx.load_cert_chain("/tmp/cert.pem", "/tmp/key.pem")
    for port in PORTS[1:]:
        threading.Thread(target=serve, args=(port, ctx), daemon=True).start()
    serve(PORTS[0], ctx)


if __name__ == "__main__":
    main()
