import requests

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy"
]

def check_http_security(target):
    result = {
        "status_code": None,
        "headers": {},
        "present": [],
        "missing": [],
        "content_preview": None,
        "error": None
    }
    try:
        r = requests.get(f"http://{target}", timeout=4)
        result["status_code"] = r.status_code
        result["headers"] = dict(r.headers)
        for h in SECURITY_HEADERS:
            if h in r.headers:
                result["present"].append(h)
            else:
                result["missing"].append(h)
        result["content_preview"] = r.text[:300]
    except Exception as e:
        result["error"] = str(e)
    return result