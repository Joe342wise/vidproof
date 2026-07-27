#!/usr/bin/env python3
"""Minimal RFC 3161 TSA HTTP server wrapping `openssl ts -reply`.

Usage (from project root):
    python infra/tsa/tsa_server.py [port] [tsa_cnf] [tsa_crt] [tsa_key] [ca_crt]

Defaults to port 2560 and infra/tsa/* paths.
"""
import http.server
import os
import subprocess
import sys
import tempfile

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 2560
TSA_CNF = sys.argv[2] if len(sys.argv) > 2 else "infra/tsa/tsa.cnf"
TSA_CRT = sys.argv[3] if len(sys.argv) > 3 else "infra/tsa/tsa.crt"
TSA_KEY = sys.argv[4] if len(sys.argv) > 4 else "infra/tsa/tsa.key"
CA_CRT  = sys.argv[5] if len(sys.argv) > 5 else "infra/tsa/ca.crt"


class TSAHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        fd, tsq_path = tempfile.mkstemp(suffix=".tsq")
        try:
            os.write(fd, body)
            os.close(fd)

            result = subprocess.run(
                [
                    "openssl", "ts", "-reply",
                    "-config", TSA_CNF,
                    "-queryfile", tsq_path,
                    "-signer", TSA_CRT,
                    "-inkey", TSA_KEY,
                    "-chain", CA_CRT,
                ],
                capture_output=True,
            )
        finally:
            os.unlink(tsq_path)

        if result.returncode != 0:
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(result.stderr)
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(result.stdout)))
        self.end_headers()
        self.wfile.write(result.stdout)

    def log_message(self, fmt, *args):
        print(f"[TSA] {self.address_string()} - {fmt % args}", flush=True)


if __name__ == "__main__":
    with http.server.HTTPServer(("", PORT), TSAHandler) as httpd:
        httpd.allow_reuse_address = True
        print(f"[TSA] RFC 3161 server listening on :{PORT}", flush=True)
        httpd.serve_forever()
