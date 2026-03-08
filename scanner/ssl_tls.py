import ssl
import socket
from datetime import datetime

def ssl_scan(host):
    result = {
        "valid": False,
        "issuer": None,
        "expires": None,
        "days_left": None,
        "tls_version": None,
        "cipher": None,
        "error": None
    }

    try:
        ctx = ssl.create_default_context()

        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

                result["valid"] = True
                result["issuer"] = dict(x[0] for x in cert["issuer"])
                result["expires"] = cert["notAfter"]
                result["tls_version"] = ssock.version()

                # 🔥 ADD THIS LINE
                cipher_info = ssock.cipher()
                if cipher_info:
                    result["cipher"] = cipher_info[0]

                expiry_date = datetime.strptime(
                    cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                )
                result["days_left"] = (
                    expiry_date - datetime.utcnow()
                ).days

    except Exception as e:
        result["error"] = str(e)

    return result