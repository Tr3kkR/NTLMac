"""Proves the test server behaves like an NTLM-only IIS site before we point browsers at it."""

from __future__ import annotations

import base64
import http.client
import json
import os
import ssl
import threading
import unittest
from http.server import ThreadingHTTPServer

import spnego
from spnego.exceptions import NegotiateOptions

import server

HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "certs", "server.pem")
KEY = os.path.join(HERE, "certs", "server.key")
os.environ["NTLM_USER_FILE"] = os.path.join(HERE, "users.txt")


def start(require_cbt: bool, basic_only: bool = False) -> tuple[ThreadingHTTPServer, int]:
    handler = type(
        "H",
        (server.NTLMHandler,),
        {"channel_bindings": server.tls_server_end_point(CERT) if require_cbt else None, "basic_only": basic_only},
    )
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(CERT, KEY)
    httpd.socket = tls.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def connect(port: int) -> http.client.HTTPSConnection:
    return http.client.HTTPSConnection("127.0.0.1", port, context=ssl._create_unverified_context())


def login(port: int, password: str, cbt: bool) -> int:
    conn = connect(port)
    client = spnego.client(
        "CORP\\jbloggs",
        password,
        protocol="ntlm",
        options=NegotiateOptions.use_ntlm,
        channel_bindings=server.tls_server_end_point(CERT) if cbt else None,
    )
    token = client.step()
    conn.request("GET", "/", headers={"Authorization": "NTLM " + base64.b64encode(token).decode()})
    resp = conn.getresponse()
    resp.read()
    challenge = resp.getheader("WWW-Authenticate", "")
    assert resp.status == 401 and challenge.startswith("NTLM "), (resp.status, challenge)
    token = client.step(base64.b64decode(challenge[5:]))
    conn.request("GET", "/", headers={"Authorization": "NTLM " + base64.b64encode(token).decode()})
    resp = conn.getresponse()
    resp.read()
    conn.close()
    return resp.status


def stats(port: int) -> dict:
    conn = connect(port)
    conn.request("GET", "/stats")
    try:
        return json.loads(conn.getresponse().read())
    finally:
        conn.close()


class NTLMOnlyServerTest(unittest.TestCase):
    def setUp(self) -> None:
        server.STATS.clear()
        server.REQUESTS.clear()
        server.BASIC_ATTEMPTS.clear()

    def test_challenges_with_ntlm_only(self) -> None:
        httpd, port = start(require_cbt=False)
        try:
            conn = connect(port)
            conn.request("GET", "/")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 401)
            self.assertEqual(resp.headers.get_all("WWW-Authenticate"), ["NTLM"])
            conn.close()
        finally:
            httpd.shutdown()

    def test_correct_password_succeeds_wrong_password_counted(self) -> None:
        httpd, port = start(require_cbt=False)
        try:
            self.assertEqual(login(port, "Passw0rd!", cbt=False), 200)
            self.assertEqual(login(port, "wrong", cbt=False), 401)
            s = stats(port)
            self.assertEqual(s["users"]["CORP\\jbloggs"]["success"], 1)
            self.assertEqual(s["users"]["CORP\\jbloggs"]["failure"], 1)
            self.assertGreaterEqual(s["requests"]["127.0.0.1"], 4)
        finally:
            httpd.shutdown()

    def test_epa_rejects_missing_channel_binding(self) -> None:
        httpd, port = start(require_cbt=True)
        try:
            self.assertEqual(login(port, "Passw0rd!", cbt=False), 401)
            self.assertEqual(login(port, "Passw0rd!", cbt=True), 200)
        finally:
            httpd.shutdown()

    def test_start_page_refresh_delay_is_configurable(self) -> None:
        httpd, port = start(require_cbt=False)
        try:
            for path, delay in (("/start", "2"), ("/start?wait=40", "40"), ("/start?wait=junk", "2")):
                conn = connect(port)
                conn.request("GET", path)
                resp = conn.getresponse()
                body = resp.read().decode()
                conn.close()
                self.assertEqual(resp.status, 200, path)
                self.assertIn(f'content="{delay};url=/"', body, path)
        finally:
            httpd.shutdown()

    def test_basic_mode_challenges_with_basic_only_and_counts_basic_attempts(self) -> None:
        httpd, port = start(require_cbt=False, basic_only=True)
        try:
            conn = connect(port)
            conn.request("GET", "/")
            resp = conn.getresponse()
            resp.read()
            self.assertEqual(resp.status, 401)
            self.assertEqual(resp.headers.get_all("WWW-Authenticate"), ['Basic realm="ntlmac-test"'])
            conn.request("GET", "/", headers={"Authorization": "Basic " + base64.b64encode(b"u:p").decode()})
            resp = conn.getresponse()
            resp.read()
            self.assertEqual(resp.status, 401, "Basic credentials are never accepted")
            conn.close()
            s = stats(port)
            self.assertEqual(s["basic"], {"127.0.0.1": 1})
            self.assertEqual(s["users"], {}, "the Basic password itself is never recorded")
        finally:
            httpd.shutdown()


if __name__ == "__main__":
    unittest.main()
