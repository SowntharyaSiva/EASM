import dns.resolver

COMMON_SUBS = ["www", "mail", "api", "dev", "test", "staging"]

def dns_enum(target):
    data = {
        "A": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "subdomains": [],
        "email_security": {
            "spf": False,
            "dmarc": False
        }
    }

    # Standard Records
    for rtype in ["A", "MX", "NS", "TXT"]:
        try:
            answers = dns.resolver.resolve(target, rtype)
            records = [str(r) for r in answers]
            data[rtype] = records

            # Check SPF / DMARC inside TXT
            if rtype == "TXT":
                for r in records:
                    if "v=spf1" in r.lower():
                        data["email_security"]["spf"] = True
                    if "v=dmarc1" in r.lower():
                        data["email_security"]["dmarc"] = True

        except:
            pass

    # Subdomain discovery
    for sub in COMMON_SUBS:
        try:
            dns.resolver.resolve(f"{sub}.{target}", "A")
            data["subdomains"].append(f"{sub}.{target}")
        except:
            pass

    return data
