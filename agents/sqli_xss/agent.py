import re
from urllib.parse import unquote_plus
from flask import Flask, request, Response, abort
import requests
from html import unescape

app = Flask(__name__)
TARGET = "http://localhost:3000"

EXCLUDED = { "content-encoding", "content-length", "transfer-encoding", "connection" }

SQLI_PATTERNS = [
    ("union select",   r"\bunion\b(?:\s+all)?\s+select\b"),
    ("tautology",      r"\b(?:or|and)\b\s+(?:\d+|'[^']{0,50}'|\"[^\"]{0,50}\")\s*(?:=|like)\s*(?:\d+|'[^']{0,50}'|\"[^\"]{0,50}\")"),
    ("quote + bool",   r"['\"]\s*(?:or|and)\b"),
    ("stacked query",  r";\s*(?:select|insert|update|delete|drop|alter|create|exec|truncate)\b"),
    ("time based",     r"\b(?:sleep|pg_sleep|benchmark)\s*\(|\bwaitfor\s+delay\b"),
    ("schema recon",   r"\binformation_schema\b|\bsysobjects\b|\bpg_catalog\b|\bsqlite_master\b"),
    ("file/exec funcs", r"\bload_file\s*\(|\binto\s+(?:out|dump)file\b|\bxp_cmdshell\b"),
    ("trailing comment", r"(?:--|#)\s*$|'\s*(?:--|#)"),
]
COMPILED = [(name, re.compile(p)) for name, p in SQLI_PATTERNS]

def normalize(s: str) -> str:
    # Decode repeatedly to defeat double/triple encoding
    for _ in range(3):
        decoded = unquote_plus(s)
        if decoded == s:
            break
        s = decoded
    s = re.sub(r"/\*.*?\*/", " ", s, flags=re.S)  # strip inline comments: UNION/**/SELECT
    s = re.sub(r"\s+", " ", s)                     # collapse whitespace/tabs/newlines
    return s.lower().strip()

def check(value: str):
    v = normalize(value)
    for name, rx in COMPILED:
        if rx.search(v):
            return name
    return None

def inspect_request():
    targets = {
        "path": request.path,
        "query": request.query_string.decode("utf-8", "ignore"),
        "user-agent": request.headers.get("User-Agent", ""),
        "referer": request.headers.get("Referer", ""),
    }
    for k, v in request.cookies.items():
        targets[f"cookie:{k}"] = v
    if request.content_length and not (request.mimetype or "").startswith("multipart/"):
        targets["body"] = request.get_data(as_text=True)

    for where, value in targets.items():
        hit = check(value)       # SQLi
        if hit:
            return where, "sqli:" + hit
        hit = check_xss(value)   # XSS
        if hit:
            return where, "xss:" + hit
    return None

XSS_PATTERNS = [
    ("script tag",       r"<\s*script\b"),
    ("event handler",     r"\bon(?:error|load|click|mouseover|focus|input|change|submit|pointerover)\s*="),
    ("javascript uri",    r"javascript\s*:"),
    ("data uri html",     r"data\s*:\s*text/html"),
    ("img/svg breakout",  r"<\s*(?:img|svg|iframe|object|embed|body|input|marquee)\b[^>]*\b(?:on\w+|src|href)\s*="),
    ("expression/eval",   r"\bexpression\s*\(|\beval\s*\(|\bFunction\s*\("),
    ("attribute breakout",r"[\"']\s*>\s*<|[\"']\s*(?:on\w+|style)\s*="),
    ("tag breakout",      r"<\s*/?\s*(?:script|style|iframe|svg)\b"),
    ("vbscript uri",      r"vbscript\s*:"),
    ("css expression/import", r"@import\b|behavior\s*:\s*url\("),
]
COMPILED_XSS = [(name, re.compile(p, re.I)) for name, p in XSS_PATTERNS]

def normalize_xss(s: str) -> str:
    for _ in range(3):
        decoded = unquote_plus(s)
        if decoded == s:
            break
        s = decoded
    s = unescape(s)                      # &lt;script&gt; -> <script>
    s = re.sub(r"\s+", " ", s)
    return s.lower().strip()

def check_xss(value: str):
    v = normalize_xss(value)
    for name, rx in COMPILED_XSS:
        if rx.search(v):
            return name
    return None

# Check each request
@app.before_request
def waf():
    result = inspect_request()
    if result:
        where, rule = result
        app.logger.warning("SQLi blocked: rule=%s where=%s ip=%s", rule, where, request.remote_addr)
        abort(403)

@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def proxy(path):
	fwd_headers = {k: v for k, v in request.headers if k.lower() not in ("host", "accept-encoding")}
	fwd_headers["Accept-Encoding"] = "gzip, deflate"

	resp = requests.request(
	    method=request.method,
	    url=f"{TARGET}/{path}",
	    params=request.args,
	    headers=fwd_headers,
	    data=request.get_data(),
	    cookies=request.cookies,
	    allow_redirects=False,  # pass redirects through to the client
	    stream=True,
	    timeout=30,
	)
	headers = [(k, v) for k, v in resp.raw.headers.items() if k.lower() not in EXCLUDED]
	return Response(resp.iter_content(chunk_size=8192), resp.status_code, headers)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
