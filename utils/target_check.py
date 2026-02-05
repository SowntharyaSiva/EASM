import ipaddress

def is_valid_target(target):
    """
    Returns True if the target is a valid public IP.
    Private and loopback IPs return False.
    """
    try:
        ip = ipaddress.ip_address(target)
        return not (ip.is_private or ip.is_loopback)
    except ValueError:
        # If it’s a domain name, assume it’s valid
        return True
