#!/usr/bin/env python3
"""Fake subvanillatool.com for offline lab observation (stdlib-only).

Serves the author's endpoints with BENIGN canned responses and logs every
request. Purpose: run the ORIGINAL Vanillatool / Account Manager binaries in
an isolated Windows VM (DNS-redirected, see docs/LAB_GUIDE.md) and observe
their network behavior WITHOUT contacting the real server.

What you will see: startup beacon, auth POST field names/sizes (the ``aN``
blob stays encrypted), download attempts, then the client failing closed.

What this can NOT do (by design): return a working ``C:...;`` offset blob.
Forging one would crack the licensing into a fully functional cheat, and
real offsets only exist server-side. Expect the client to stop with
"License expired" / "Waiting for Response" / exit — that boundary itself
is the observation.

Usage:
    python3 stub_server.py --port 80 --log stub_requests.jsonl
    python3 stub_server.py --port 8443 --tls-cert lab.crt --tls-key lab.key
"""

import argparse
import datetime
import json
import ssl
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PLACEHOLDER_OFFSETS = (
    '; LAB STUB - no real offsets served\r\n'
    '[NA]\r\n[EU]\r\n[Classic]\r\n[4.6]\r\n[4.8]\r\n[Nova]\r\n'
).encode()

PLACEHOLDER_CHAT = (
    '<html><head><title>lab stub</title></head>'
    '<body><h1>lab stub chat</h1></body></html>\n'
).encode()


def route(method, path):
    """Return (status, content_type, body, route_name)."""
    if path == '/data/auth.php' and method == 'POST':
        # NOTE: deliberately no 'C:...;' blob -> client fails closed.
        return 200, 'text/plain', b'STUB: no license server in lab\n', 'auth'
    if path == '/Log/log.php':
        return 200, 'text/plain', b'STUB-MOTD: lab mode\n', 'beacon'
    if path == '/Offsets.txt':
        return 200, 'text/plain', PLACEHOLDER_OFFSETS, 'offsets'
    if path == '/data/resourceversion.txt':
        return 200, 'text/plain', b'0\n', 'resourceversion'
    if path == '/POST/':
        return 200, 'text/plain', b'OK\n', 'postsink'
    if path == '/data/chat.html':
        return 200, 'text/html', PLACEHOLDER_CHAT, 'chat'
    if path.startswith(('/data/7za.exe', '/data/dbghelp.dll',
                         '/data/mods/', '/data/PIN/')):
        return 404, 'text/plain', b'STUB: file not served in lab\n', 'dl-404'
    return 404, 'text/plain', b'STUB: unknown endpoint\n', 'unknown'


class Handler(BaseHTTPRequestHandler):
    server_version = 'StubHTTP/1.0'

    def log_message(self, *a):
        pass  # we log our own one-liners

    def _handle(self):
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length) if length else b''
        status, ctype, resp, name = route(self.command, parsed.path)
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

        try:
            fields = {k: len(v[0]) for k, v in
                      urllib.parse.parse_qs(body.decode('utf-8', 'replace')).items()}
        except Exception:
            fields = {}
        rec = {
            'ts': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'client': self.client_address[0],
            'method': self.command,
            'path': parsed.path,
            'query': parsed.query,
            'user_agent': self.headers.get('User-Agent', ''),
            'body_len': len(body),
            'body_head': body[:2048].decode('utf-8', 'replace'),
            'form_fields': fields,
            'resp': status,
            'route': name,
        }
        self.server.jsonl.write(json.dumps(rec) + '\n')
        self.server.jsonl.flush()
        ua = rec['user_agent'][:60]
        print(f"[{rec['ts'][11:19]}] {rec['client']} {self.command} "
              f"{parsed.path} route={name} -> {status} "
              f"body={len(body)}B fields={fields} UA={ua!r}", flush=True)

    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle


def main() -> None:
    ap = argparse.ArgumentParser(description='subvanillatool.com lab stub')
    ap.add_argument('--bind', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=80)
    ap.add_argument('--log', default='stub_requests.jsonl',
                    help='JSON-lines request log')
    ap.add_argument('--tls-cert', help='PEM cert for HTTPS mode')
    ap.add_argument('--tls-key', help='PEM key for HTTPS mode')
    args = ap.parse_args()

    jsonl = open(args.log, 'a', encoding='utf-8')
    srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    srv.jsonl = jsonl
    scheme = 'http'
    if args.tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        scheme = 'https'
    print(f'[*] stub listening on {scheme}://{args.bind}:{args.port} '
          f'(log: {args.log})', flush=True)
    print('[*] routes: POST /data/auth.php, /Log/log.php, /Offsets.txt, '
          '/data/resourceversion.txt, /POST/, /data/chat.html; '
          'binaries -> 404; all requests logged', flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        jsonl.close()


if __name__ == '__main__':
    main()
