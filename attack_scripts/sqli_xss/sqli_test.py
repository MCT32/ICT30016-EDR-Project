import requests

BASE = "http://192.168.0.172:5000"
TIMEOUT = 5

# (pattern name, request kwargs) — each payload is built to trip exactly one rule
TESTS = [
    ("union select",
     dict(params={"id": "1 UNION SELECT null, version()-- -"})),

    ("tautology",
     dict(params={"id": "1' OR '1'='1"})),

    ("quote + bool",
     dict(params={"name": "admin' or 1=1"})),

    ("stacked query",
     dict(params={"id": "1; DROP TABLE users"})),

    ("time based (sleep)",
     dict(params={"id": "1 OR SLEEP(5)"})),

    ("time based (waitfor)",
     dict(params={"id": "1'; WAITFOR DELAY '0:0:5'--"})),

    ("schema recon",
     dict(params={"id": "1 UNION SELECT table_name FROM information_schema.tables"})),

    ("file/exec funcs",
     dict(params={"id": "1' UNION SELECT load_file('/etc/passwd')-- -"})),

    ("trailing comment",
     dict(params={"id": "admin'--"})),

    ("encoded tautology (defeats naive matching without decoding)",
     dict(params={"id": "1%27%20OR%20%271%27%3D%271"})),

    ("inline-comment obfuscation (UNION/**/SELECT)",
     dict(params={"id": "1 UNION/**/SELECT null,null--"})),

    ("double-encoded quote",
     dict(params={"id": "1%2527%20OR%20%25271%2527%3D%25271"})),

    ("in cookie instead of query",
     dict(params={}, cookies={"session": "1' OR '1'='1"})),

    ("in header (User-Agent)",
     dict(params={}, headers={"User-Agent": "sqlmap/1.0 UNION SELECT 1,2,3"})),

    ("in JSON body",
     dict(json={"username": "admin' OR '1'='1", "password": "x"})),

    ("benign control — should NOT be blocked",
     dict(params={"name": "O'Brien"})),

    ("script tag",        dict(params={"q": "<script>alert(1)</script>"})),
("event handler",      dict(params={"q": "<img src=x onerror=alert(1)>"})),
("javascript uri",     dict(params={"url": "javascript:alert(document.cookie)"})),
("entity-encoded",     dict(params={"q": "&#60;script&#62;alert(1)&#60;/script&#62;"})),
("attribute breakout", dict(params={"name": "x\" onmouseover=\"alert(1)"})),
("benign — should pass", dict(params={"q": "my favorite subject is <3 coding"})),
]

def run():
    passed = failed = 0
    for name, kwargs in TESTS:
        try:
            r = requests.get(f"{BASE}/test", timeout=TIMEOUT, **kwargs)
            blocked = r.status_code == 403
        except requests.RequestException as e:
            print(f"[ERROR] {name}: {e}")
            failed += 1
            continue

        is_benign = "benign" in name
        ok = (not blocked) if is_benign else blocked
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {name} -> HTTP {r.status_code}")
        passed += ok
        failed += not ok

    print(f"\n{passed} passed, {failed} failed out of {len(TESTS)}")

if __name__ == "__main__":
    run()
