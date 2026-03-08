import dns.resolver
import socket
import re

COMMON_SUBS = ["www", "mail", "api", "dev", "test", "staging"]

def is_ip(target):
    return re.match(r"^\d+\.\d+\.\d+\.\d+$", target) is not None

def dns_enum(target):
    data = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "subdomains": [],
        "email_security": { "spf": False, "dmarc": False },
        "reverse_ptr": None,
        "error": None
    }

    try:
        # ================= IF INPUT IS IP =================
        if is_ip(target):
            try:
                data["reverse_ptr"] = socket.gethostbyaddr(target)[0]
            except:
                pass
            return data

        # ================= DOMAIN ENUMERATION =================
        ip = socket.gethostbyname(target)

        # Reverse PTR
        try:
            data["reverse_ptr"] = socket.gethostbyaddr(ip)[0]
        except:
            pass

        # DNS Record Types
        for rtype in ["A","AAAA","MX","NS","TXT"]:
            try:
                answers = dns.resolver.resolve(target, rtype)
                recs = [str(r) for r in answers]
                data[rtype] = recs

                # SPF detection from root TXT
                if rtype == "TXT":
                    for r in recs:
                        if "v=spf1" in r.lower():
                            data["email_security"]["spf"] = True

            except:
                pass

        # ================= DMARC CHECK =================
        try:
            dmarc_records = dns.resolver.resolve(f"_dmarc.{target}", "TXT")
            for r in dmarc_records:
                if "v=dmarc1" in str(r).lower():
                    data["email_security"]["dmarc"] = True
        except:
            pass

        # ================= COMMON SUBDOMAIN ENUM =================
        for sub in COMMON_SUBS:
            try:
                dns.resolver.resolve(f"{sub}.{target}", "A")
                data["subdomains"].append(f"{sub}.{target}")
            except:
                pass

    except Exception as e:
        data["error"] = str(e)

    return data