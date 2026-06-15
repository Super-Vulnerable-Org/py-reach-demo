"""
py-reach-demo — deliberately calls CVE-mapped functions so reachd can record
function-level runtime reachability observations.

Routes:
  GET /health                      → liveness check
  GET /fetch?url=<url>             → calls requests.get()              CVE-2024-47081
  GET /netrc?url=<url>             → calls requests.get_netrc_auth()   CVE-2024-47081
  GET /zippath                     → calls requests.extract_zipped_paths  CVE-2026-25645
  GET /low?url=<url>               → calls urllib3.request()           CVE-2026-21441
  GET /read?url=<url>              → calls urllib3.HTTPResponse.read()  CVE-2025-66471
  GET /httpresponse                → calls urllib3.HTTPResponse()       CVE-2025-66418
  GET /dotenv?key=K&val=V          → calls python_dotenv.set_key()     CVE-2026-28684
  GET /highlight?lang=<lang>       → calls pygments.get_lexer_by_name() CVE-2026-4539
"""

import os
from flask import Flask, request as freq, jsonify

app = Flask(__name__)


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ── requests.get  (CVE-2024-47081) ────────────────────────────────────────────
@app.route("/fetch")
def fetch():
    import requests
    url = freq.args.get("url", "http://example.com")
    try:
        resp = requests.get(url, timeout=3)
        return jsonify({"status": resp.status_code, "fn": "requests.get"})
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)})


# ── requests.get_netrc_auth  (CVE-2024-47081) ─────────────────────────────────
@app.route("/netrc")
def netrc():
    import requests
    url = freq.args.get("url", "http://example.com")
    try:
        s = requests.Session()
        auth = s.get_netrc_auth(url)
        return jsonify({"fn": "requests.get_netrc_auth", "auth": str(auth)})
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)})


# ── requests.extract_zipped_paths  (CVE-2026-25645) ──────────────────────────
@app.route("/zippath")
def zippath():
    try:
        from requests.utils import extract_zipped_paths
        result = extract_zipped_paths("/tmp/nonexistent.zip")
        return jsonify({"fn": "requests.extract_zipped_paths", "result": result})
    except Exception as e:
        return jsonify({"fn": "requests.extract_zipped_paths", "status": "called", "detail": str(e)})


# ── urllib3.request  (CVE-2026-21441) ─────────────────────────────────────────
@app.route("/low")
def low():
    import urllib3
    url = freq.args.get("url", "http://example.com")
    try:
        http = urllib3.PoolManager()
        resp = http.request("GET", url, timeout=3)
        return jsonify({"status": resp.status, "fn": "urllib3.request"})
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)})


# ── urllib3.HTTPResponse.read  (CVE-2025-66471) ───────────────────────────────
@app.route("/read")
def read_route():
    import urllib3
    url = freq.args.get("url", "http://example.com")
    try:
        http = urllib3.PoolManager()
        resp = http.request("GET", url, preload_content=False, timeout=3)
        data = resp.read(100)
        resp.close()
        return jsonify({"fn": "urllib3.HTTPResponse.read", "bytes": len(data)})
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)})


# ── urllib3.HTTPResponse  (CVE-2025-66418) ────────────────────────────────────
@app.route("/httpresponse")
def httpresponse():
    import urllib3
    try:
        resp = urllib3.HTTPResponse(status=200, headers={})
        return jsonify({"fn": "urllib3.HTTPResponse", "status": resp.status})
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)})


# ── python-dotenv set_key / unset_key  (CVE-2026-28684) ──────────────────────
@app.route("/dotenv")
def dotenv_route():
    from dotenv import set_key, unset_key
    key = freq.args.get("key", "DEMO_KEY")
    val = freq.args.get("val", "demo_value")
    try:
        dotenv_path = "/tmp/demo.env"
        if not os.path.exists(dotenv_path):
            open(dotenv_path, "w").close()
        set_key(dotenv_path, key, val)
        unset_key(dotenv_path, key)
        return jsonify({"fn": "dotenv.set_key+unset_key", "key": key})
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)})


# ── pygments get_lexer_by_name  (CVE-2026-4539) ───────────────────────────────
@app.route("/highlight")
def highlight():
    from pygments.lexers import get_lexer_by_name
    lang = freq.args.get("lang", "python")
    try:
        lexer = get_lexer_by_name(lang)
        return jsonify({"fn": "pygments.get_lexer_by_name", "lexer": str(lexer)})
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)})


# ── werkzeug.safe_join  (no fn map = orange) ─────────────────────────────────
@app.route("/wz")
def wz():
    from werkzeug.security import safe_join
    path = freq.args.get("path", "demo.txt")
    try:
        result = safe_join("/tmp", path)
        return jsonify({"fn": "werkzeug.safe_join", "result": result})
    except Exception as e:
        return jsonify({"fn": "werkzeug.safe_join", "status": "called", "detail": str(e)})


# ── Pillow.Image.open  (no fn map = orange) ───────────────────────────────────
@app.route("/img")
def img():
    from PIL import Image
    try:
        img = Image.new("RGB", (10, 10), color=(255, 0, 0))
        return jsonify({"fn": "PIL.Image.new", "size": list(img.size)})
    except Exception as e:
        return jsonify({"fn": "PIL.Image.new", "status": "called", "detail": str(e)})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
