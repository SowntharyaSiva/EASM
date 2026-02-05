def apply_rules(scan):
    findings = []

    ports = scan.get("ports", [])
    services = scan.get("services", {})
    ssl = scan.get("ssl") or {}
    ssh = scan.get("ssh")

    # Generic exposure
    if len(ports) > 0:
        findings.append({
            "category": "Attack Surface",
            "issue": f"{len(ports)} services exposed",
            "severity": "LOW",
            "weight": 10
        })

    # Service enumeration
    for port, service in services.items():
        findings.append({
            "category": "Service Exposure",
            "issue": f"{service} service running on port {port}",
            "severity": "LOW",
            "weight": 5
        })

        if service in ["ftp", "telnet"]:
            findings.append({
                "category": "Insecure Services",
                "issue": f"Insecure service {service} on port {port}",
                "severity": "CRITICAL",
                "weight": 40
            })

    # SSL issues
    if ssl and not ssl.get("valid", True):
        findings.append({
            "category": "Cryptography",
            "issue": "Invalid SSL certificate",
            "severity": "MEDIUM",
            "weight": 20
        })

    if ssl.get("tls_version") in ["TLSv1", "TLSv1.1"]:
        findings.append({
            "category": "Cryptography",
            "issue": "Weak TLS version",
            "severity": "MEDIUM",
            "weight": 15
        })

    # SSH exposure
    if ssh:
        findings.append({
            "category": "Remote Access",
            "issue": "SSH exposed to public network",
            "severity": "MEDIUM",
            "weight": 15
        })

    return findings
