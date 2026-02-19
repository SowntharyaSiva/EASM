import nmap

def scan_ports(target):
    nm = nmap.PortScanner()

    try:
        #nm.scan(hosts=target, ports="1-1024", arguments="-T4")
        nm.scan(hosts=target, ports="22,80,443,8080", arguments="-T4")

    except Exception as e:
        print(f"Error scanning {target}: {e}")
        return [], {}

    open_ports = []
    services = {}

    if target in nm.all_hosts():
        tcp_data = nm[target].get('tcp', {})
        for port, data in tcp_data.items():
            if data.get("state") == "open":
                open_ports.append(port)
                services[port] = data.get("name", "unknown")

    return open_ports, services
