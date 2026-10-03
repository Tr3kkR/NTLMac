"""NTLM-only HTTPS test server for NTLMac.

Behaves like an IIS site with only the NTLM provider enabled: it sends
`WWW-Authenticate: NTLM` (never Negotiate), keeps the handshake on one TCP connection,
and optionally enforces channel binding (EPA) like `extendedProtection tokenChecking=Require`.

GET /stats returns per-user success/failure counts (standing in for DC 4625 events when
testing that NTLMac never causes more than one bad-password attempt) and per-host
request counts.

Users come from an NTLM_USER_FILE (lines of DOMAIN:USER:PASSWORD).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import ssl
import threading
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import spnego
from spnego.channel_bindings import GssChannelBindings
from spnego.exceptions import NegotiateOptions, SpnegoError

STATS: dict[str, dict[str, int]] = defaultdict(lambda: {"success": 0, "failure": 0})
REQUESTS: dict[str, int] = defaultdict(int)  # by Host header, proves a browser reached us
STATS_LOCK = threading.Lock()


def tls_server_end_point(cert_pem_path: str) -> GssChannelBindings:
    """RFC 5929 tls-server-end-point binding for a SHA-256-signed certificate."""
    with open(cert_pem_path) as f:
        der = ssl.PEM_cert_to_DER_cert(f.read())
    return GssChannelBindings(application_data=b"tls-server-end-point:" + hashlib.sha256(der).digest())


def record(user: str, outcome: str) -> None:
    with STATS_LOCK:
        STATS[user][outcome] += 1


class NTLMHandler(BaseHTTPRequestHandler):
    # HTTP/1.1 keep-alive: NTLM authenticates the connection, not the request.
    protocol_version = "HTTP/1.1"
    channel_bindings: GssChannelBindings | None = None

    def setup(self) -> None:
        super().setup()
        self.ctx = None
        self.authenticated_as: str | None = None

    def log_message(self, fmt: str, *args) -> None:  # quieter, single-line logs
        print(f"[ntlm-server] {self.client_address[0]} {fmt % args}", flush=True)

    def send_plain(self, status: int, body: str, headers: dict[str, str] | None = None) -> None:
        data = body.encode()
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        ctype = "application/json" if body.startswith("{") else "text/html" if body.startswith("<") else "text/plain"
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def challenge(self, token: bytes | None = None) -> None:
        value = "NTLM" if token is None else "NTLM " + base64.b64encode(token).decode()
        self.send_plain(401, "authentication required", {"WWW-Authenticate": value})

    def do_GET(self) -> None:
        if self.path == "/stats":
            with STATS_LOCK:
                self.send_plain(200, json.dumps({"users": STATS, "requests": REQUESTS}))
            return

        if self.path == "/start":
            # Unauthenticated landing page that moves on to the challenged URL after a
            # pause, so tests exercise an already-running browser, not extension install.
            self.send_plain(200, '<html><head><meta http-equiv="refresh" content="2;url=/"></head><body>starting</body></html>', {})
            return

        with STATS_LOCK:
            REQUESTS[(self.headers.get("Host") or "").split(":")[0]] += 1

        if self.authenticated_as:
            self.send_plain(200, f"hello {self.authenticated_as}\n")
            return

        header = self.headers.get("Authorization", "")
        if not header.upper().startswith("NTLM "):
            self.ctx = None
            self.challenge()
            return

        token = base64.b64decode(header[5:].strip())
        if self.ctx is None:
            self.ctx = spnego.server(
                protocol="ntlm",
                options=NegotiateOptions.use_ntlm,
                channel_bindings=self.channel_bindings,
            )
        try:
            out = self.ctx.step(token)
        except SpnegoError as e:
            user = self._claimed_user(token)
            record(user, "failure")
            print(f"[ntlm-server] auth FAILED for {user}: {e}", flush=True)
            self.ctx = None
            self.challenge()
            return

        if not self.ctx.complete:
            self.challenge(out)
            return

        self.authenticated_as = self.ctx.client_principal
        record(self.authenticated_as, "success")
        self.send_plain(200, f"hello {self.authenticated_as}\n")

    @staticmethod
    def _claimed_user(token: bytes) -> str:
        """Best-effort DOMAIN\\user from an AUTHENTICATE message, for failure stats."""
        try:
            from spnego._ntlm_raw.messages import Authenticate

            msg = Authenticate.unpack(token)
            return f"{msg.domain_name}\\{msg.user_name}"
        except Exception:
            return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", default="certs/server.pem")
    parser.add_argument("--key", default="certs/server.key")
    parser.add_argument("--users", default="users.txt", help="NTLM_USER_FILE (DOMAIN:USER:PASSWORD)")
    parser.add_argument("--require-cbt", action="store_true", help="enforce channel binding (EPA)")
    parser.add_argument("--plain-http", action="store_true", help="serve without TLS (relay-risk testing)")
    args = parser.parse_args()

    os.environ["NTLM_USER_FILE"] = os.path.abspath(args.users)
    if args.require_cbt:
        NTLMHandler.channel_bindings = tls_server_end_point(args.cert)

    httpd = ThreadingHTTPServer((args.host, args.port), NTLMHandler)
    if not args.plain_http:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(args.cert, args.key)
        httpd.socket = tls.wrap_socket(httpd.socket, server_side=True)
    scheme = "http" if args.plain_http else "https"
    print(f"[ntlm-server] {scheme}://{args.host}:{args.port} NTLM-only, cbt={'required' if args.require_cbt else 'off'}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
