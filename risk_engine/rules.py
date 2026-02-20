# ================= MODULE WEIGHTS =================
MODULE_WEIGHTS = {
    "network": 1.2,
    "ssl": 1.1,
    "ssh": 1.2,
    "http": 1.0,
    "dns": 0.8
}

ATTACK_MAP = {
    "NET-TELNET": ("Credential Theft", "Plaintext credentials can be intercepted"),
    "NET-FTP": ("Credential Theft", "FTP transmits credentials in plaintext"),
    "NET-RDP": ("Remote Compromise", "RDP brute-force or exploit risk"),
    "NET-SSH": ("Brute Force Attack", "SSH login attempts can compromise system"),
    "NET-DB": ("Data Breach", "Database exposure may leak sensitive data"),
    "NET-HTTP": ("MITM Attack", "Unencrypted traffic can be intercepted"),
    "SSL-INVALID": ("Spoofing / MITM", "Users may trust fake or compromised site"),
    "SSL-WEAK": ("MITM Attack", "Weak encryption can be broken"),
    "SSH-BRUTE": ("Brute Force Attack", "Repeated login attempts may succeed"),
    "HTTP-HEADERS": ("XSS / Clickjacking", "Browser-based attacks possible"),
    "DNS-SPF": ("Email Spoofing", "Attackers can forge domain emails"),
    "DNS-DMARC": ("Phishing Campaign", "No policy to block fraudulent emails"),
}



# ================= RULE ENGINE =================

def apply_rules(scan):
    findings = []

    ports = scan.get("ports", [])
    services = scan.get("services", {})
    ssl = scan.get("ssl", {})
    ssh = scan.get("ssh", {})
    http = scan.get("http", {})
    dns = scan.get("dns", {})
    public_ip = True   # assume public since private IPs blocked earlier

    # ================= NETWORK RULES =================
    for port, service in services.items():

        # TELNET
        if port == 23:
            findings.append(_make(
                module="network",
                rule_id="NET-TELNET",
                issue=f"Telnet exposed on port {port}",
                severity="CRITICAL",
                base_score=50,
                fix="Disable Telnet service immediately"
            ))

        # FTP
        elif port == 21:
            findings.append(_make(
                module="network",
                rule_id="NET-FTP",
                issue=f"FTP exposed on port {port}",
                severity="CRITICAL",
                base_score=45,
                fix="Disable FTP or enforce FTPS"
            ))

        # RDP
        elif port == 3389:
            findings.append(_make(
                module="network",
                rule_id="NET-RDP",
                issue=f"RDP exposed on port {port}",
                severity="CRITICAL",
                base_score=45,
                fix="Restrict RDP via VPN/firewall"
            ))

        # SSH Public
        elif port == 22 and public_ip:
            findings.append(_make(
                module="network",
                rule_id="NET-SSH",
                issue="SSH exposed publicly",
                severity="HIGH",
                base_score=30,
                fix="Restrict SSH via firewall or VPN"
            ))

        # Database Exposure
        elif port in [3306, 5432, 27017]:
            findings.append(_make(
                module="network",
                rule_id="NET-DB",
                issue=f"Database port {port} exposed",
                severity="HIGH",
                base_score=35,
                fix="Restrict database access to internal network"
            ))

        # HTTP without HTTPS
        elif port == 80 and 443 not in ports:
            findings.append(_make(
                module="network",
                rule_id="NET-HTTP",
                issue="HTTP open without HTTPS",
                severity="MEDIUM",
                base_score=20,
                fix="Enable HTTPS"
            ))

    # ================= SSL RULES =================
    if ssl.get("error"):
        findings.append(_make(
            module="ssl",
            rule_id="SSL-INVALID",
            issue="Invalid or expired SSL certificate",
            severity="CRITICAL",
            base_score=40,
            fix="Install valid SSL certificate"
        ))

    if ssl.get("tls_version") in ["TLSv1", "TLSv1.1"]:
        findings.append(_make(
            module="ssl",
            rule_id="SSL-WEAK",
            issue="Weak TLS version detected",
            severity="HIGH",
            base_score=25,
            fix="Upgrade to TLS 1.2 or higher"
        ))

    # ================= SSH RULE =================
    if ssh.get("open") and public_ip:
        findings.append(_make(
            module="ssh",
            rule_id="SSH-BRUTE",
            issue="SSH brute-force risk",
            severity="HIGH",
            base_score=25,
            fix="Enable rate limiting and key-based authentication"
        ))

    # ================= HTTP RULE =================
    if len(http.get("missing", [])) >= 3:
        findings.append(_make(
            module="http",
            rule_id="HTTP-HEADERS",
            issue="Missing critical HTTP security headers",
            severity="MEDIUM",
            base_score=20,
            fix="Enable CSP, HSTS, X-Frame-Options"
        ))

    # ================= DNS RULES =================
    email_sec = dns.get("email_security", {})

    if not email_sec.get("spf"):
        findings.append(_make(
            module="dns",
            rule_id="DNS-SPF",
            issue="Missing SPF record",
            severity="MEDIUM",
            base_score=15,
            fix="Configure SPF record"
        ))

    if not email_sec.get("dmarc"):
        findings.append(_make(
            module="dns",
            rule_id="DNS-DMARC",
            issue="Missing DMARC policy",
            severity="MEDIUM",
            base_score=15,
            fix="Implement DMARC policy"
        ))

    return findings


# ================= HELPER =================
def _make(module, rule_id, issue, severity, base_score, fix):
    multiplier = MODULE_WEIGHTS.get(module, 1.0)
    adjusted_score = base_score * multiplier

    attack, impact = ATTACK_MAP.get(rule_id, ("Unknown", "Security risk detected"))

    return {
        "module": module,
        "rule_id": rule_id,
        "issue": issue,
        "severity": severity,
        "weight": round(adjusted_score, 2),
        "attack": attack,
        "impact": impact,
        "fix": fix
    }

