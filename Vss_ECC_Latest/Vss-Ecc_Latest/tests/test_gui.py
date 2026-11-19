import json, os, sys, threading, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import gui, checks


def test_toutes_les_verifications_passent():
    assert all(r["ok"] for r in checks.run_all())


def test_api_params_et_partage():
    assert gui.api_params({"k": 3, "n": 5})["ok"]
    r = gui.api_params({"k": 10, "n": 20})
    assert not r["ok"] and r["reste"] == 1
    s = gui.api_share({"k": 3, "n": 5, "secret": "0x1234"})
    v = gui.api_verify({"shares": s["shares"], "commitments": s["commitments"], "n": 5})
    assert all(x["valid"] for x in v["results"])
    rec = gui.api_reconstruct({"shares": s["shares"][:3], "k": 3})
    assert int(rec["value"], 16) == 0x1234 and rec["enough"]
    few = gui.api_reconstruct({"shares": s["shares"][:2], "k": 3})
    assert not few["enough"] and int(few["value"], 16) != 0x1234


def test_serveur_http():
    srv = gui.ThreadingHTTPServer((gui.HOST, 0), gui.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        page = urllib.request.urlopen(f"http://127.0.0.1:{port}/").read().decode()
        assert "Vss_ECC" in page
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/params", json.dumps({"k": 4, "n": 8}).encode(),
                                     {"Content-Type": "application/json"})
        assert json.loads(urllib.request.urlopen(req).read())["ok"] is False
    finally:
        srv.shutdown()
