import requests

SEC_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy"
]

def check_http_security(host):
    result = {
        "present": [],
        "missing": [],
        "server": None,
        "https_redirect": False
    }

    try:
        url = f"http://{host}"
        r = requests.get(url, timeout=5, allow_redirects=True)

        # Detect redirect to HTTPS
        if r.url.startswith("https"):
            result["https_redirect"] = True

        result["server"] = r.headers.get("Server", "Unknown")

        for h in SEC_HEADERS:
            if h in r.headers:
                result["present"].append(h)
            else:
                result["missing"].append(h)

    except Exception as e:
        result["error"] = str(e)

    return result
