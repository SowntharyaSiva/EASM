# ================= RULE DEFINITIONS =================
RULES = [
    {"id": "R1", "name": "Open Ports", "severity": "LOW", "score": 10},
    {"id": "R2", "name": "Insecure Service (FTP/Telnet)", "severity": "CRITICAL", "score": 40},
    {"id": "R3", "name": "Weak TLS Version", "severity": "MEDIUM", "score": 15},
    {"id": "R4", "name": "Invalid SSL", "severity": "MEDIUM", "score": 20},
    {"id": "R5", "name": "SSH Exposed", "severity": "MEDIUM", "score": 15},
    {"id": "R6", "name": "Missing HTTP Security Headers", "severity": "HIGH", "score": 25},
    {"id": "R7", "name": "Missing SPF Record", "severity": "MEDIUM", "score": 15},
    {"id": "R8", "name": "Missing DMARC Policy", "severity": "MEDIUM", "score": 15},

]


# ================= RULE ENGINE =================
def apply_rules(scan):
    findings = []

    ports = scan.get("ports", [])
    services = scan.get("services", {})
    ssl = scan.get("ssl", {})
    ssh = scan.get("ssh", {})

    # R1 — Open Ports
    if ports:
        findings.append(_make("R1", f"{len(ports)} ports exposed"))

    # R2 — Insecure Services
    for port, service in services.items():
        if service in ["ftp", "telnet"]:
            findings.append(_make("R2", f"Insecure service {service} on port {port}"))

    # R3 — Weak TLS
    if ssl.get("tls_version") in ["TLSv1", "TLSv1.1"]:
        findings.append(_make("R3", "Weak TLS version detected"))

    # R4 — Invalid SSL
    if ssl.get("error"):
        findings.append(_make("R4", "Invalid or missing SSL"))

    # R5 — SSH Exposure
    if ssh.get("open"):
        findings.append(_make("R5", "SSH exposed to internet"))

    http = scan.get("http", {})
    dns = scan.get("dns", {})

    # Missing security headers
    if len(http.get("missing", [])) >= 3:
        findings.append(_make("R6", "Missing important HTTP security headers"))

    # No SPF/DMARC
    if not dns.get("email_security", {}).get("spf"):
        findings.append(_make("R7", "Missing SPF record — email spoofing risk"))

    if not dns.get("email_security", {}).get("dmarc"):
        findings.append(_make("R8", "Missing DMARC policy"))


    return findings


# ================= HELPER =================
def _make(rule_id, issue):
    rule = next(r for r in RULES if r["id"] == rule_id)

    ATTACK_MAP = {
        "R1": ("Reconnaissance", "More entry points for attackers", "Close unused ports"),
        "R2": ("Credential Theft", "Plaintext credentials exposed", "Disable FTP/Telnet"),
        "R3": ("MITM Attack", "Encrypted traffic can be intercepted", "Upgrade TLS to 1.2+"),
        "R4": ("Spoofing Risk", "Users may trust fake site", "Install valid SSL"),
        "R5": ("Brute Force", "Remote access compromise risk", "Restrict SSH via firewall"),
        "R6": ("Web Exploitation", "Browser attacks like XSS & Clickjacking", "Enable CSP, HSTS, X-Frame"),
        "R7": ("Email Spoofing", "Attackers can impersonate domain emails", "Configure SPF"),
        "R8": ("Phishing Campaigns", "Emails lack DMARC protection", "Implement DMARC policy"),
    }

    attack, impact, fix = ATTACK_MAP.get(rule_id, ("Unknown", "Unknown", "Review"))

    return {
        "rule_id": rule["id"],
        "issue": issue,
        "severity": rule["severity"],
        "weight": rule["score"],
        "attack": attack,
        "impact": impact,
        "fix": fix
    }
