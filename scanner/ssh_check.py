import socket

def ssh_check(target):
    try:
        s = socket.create_connection((target, 22), timeout=3)
        banner = s.recv(1024).decode(errors='ignore')
        s.close()
        return banner
    except:
        return 'SSH not reachable'
