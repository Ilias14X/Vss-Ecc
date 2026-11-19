"""Interface web locale (aucune dépendance) : python3 gui.py  puis ouvrir http://127.0.0.1:8765
Écoute uniquement sur 127.0.0.1. Les parts et engagements circulent entre la page et ce serveur local."""
import json
import os
import subprocess
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import checks
import vss
from curve import P256, InvalidPoint, validate_point

HERE = os.path.dirname(os.path.abspath(__file__))
HOST, PORT = "127.0.0.1", 8765
MAX_BODY = 1_000_000


def _int(v):
    return int(v, 0) if isinstance(v, str) else int(v)


def api_params(d):
    k, n = _int(d["k"]), _int(d["n"])
    try:
        return {"ok": True, **vss.check_params(k, n)}
    except ValueError as e:
        return {"ok": False, "error": str(e), "reste": (n - 1) % (k - 1) if k > 1 else None}


def api_share(d):
    k, n = _int(d["k"]), _int(d["n"])
    secret = _int(d["secret"]) if d.get("secret") not in (None, "") else None
    if secret is None:
        import secrets
        secret = secrets.randbelow(P256.n)
    coeffs, shares = vss.split_secret(secret, k, n, P256.n)
    comms = vss.generate_feldman_commitments(coeffs, P256, P256.G)
    return {"ok": True, "secret": hex(secret), "coeffs": [hex(c) for c in coeffs],
            "shares": [[x, hex(y)] for x, y in shares],
            "commitments": [[hex(c[0]), hex(c[1])] for c in comms]}


def _shares(d):
    return [(int(x), _int(y)) for x, y in d["shares"]]


def _comms(d):
    return [(_int(x), _int(y)) for x, y in d["commitments"]]


def api_verify(d):
    n = _int(d["n"])
    comms = _comms(d)
    out = []
    for s in _shares(d):
        out.append({"i": s[0], "valid": vss.verify_share(s, comms, P256, P256.G, n)})
    return {"ok": True, "results": out}


def api_reconstruct(d):
    shares = _shares(d)
    k = _int(d["k"])
    if len(shares) != len(set(x for x, _ in shares)):
        return {"ok": False, "error": "indices en double"}
    value = vss.reconstruct_secret(shares, P256.n)
    return {"ok": True, "value": hex(value), "enough": len(shares) >= k,
            "note": "" if len(shares) >= k else f"seulement {len(shares)} part(s) < k = {k} : le résultat est sans rapport avec le secret"}


def api_point(d):
    try:
        validate_point(P256, (_int(d["x"]), _int(d["y"])))
        return {"ok": True, "valid": True}
    except (InvalidPoint, ValueError, KeyError) as e:
        return {"ok": True, "valid": False, "why": str(e)}


def api_checks(d):
    return {"ok": True, "results": checks.run_all()}


def api_tests(d):
    p = subprocess.run([sys.executable, "-m", "pytest", "-q", "tests"], cwd=HERE, capture_output=True,
                       text=True, timeout=180)
    return {"ok": p.returncode == 0, "output": (p.stdout + p.stderr)[-4000:]}


ROUTES = {"/api/params": api_params, "/api/share": api_share, "/api/verify": api_verify,
          "/api/reconstruct": api_reconstruct, "/api/point": api_point, "/api/checks": api_checks,
          "/api/tests": api_tests}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "web", "index.html"), "rb") as f:
                self._send(200, f.read(), "text/html")
        else:
            self._send(404, json.dumps({"error": "introuvable"}))

    def do_POST(self):
        fn = ROUTES.get(self.path)
        if fn is None:
            return self._send(404, json.dumps({"error": "introuvable"}))
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_BODY:
                return self._send(413, json.dumps({"ok": False, "error": "requête trop grande"}))
            data = json.loads(self.rfile.read(length) or b"{}")
            self._send(200, json.dumps(fn(data)))
        except (ValueError, KeyError, TypeError) as e:
            self._send(200, json.dumps({"ok": False, "error": str(e)}))

    def log_message(self, *a):
        pass


def serve(port=PORT, open_browser=True):
    srv = ThreadingHTTPServer((HOST, port), Handler)
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(f"http://{HOST}:{port}")).start()
    print(f"Interface : http://{HOST}:{port}  (Ctrl+C pour arrêter)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return srv


if __name__ == "__main__":
    serve()
