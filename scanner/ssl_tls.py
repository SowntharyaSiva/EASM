import ssl, socket

def ssl_scan(host):
    data = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                data['issuer'] = cert.get('issuer')
                data['expires'] = cert.get('notAfter')
                data['tls_version'] = ssock.version()
    except:
        data['error'] = 'SSL not available'
    return data
