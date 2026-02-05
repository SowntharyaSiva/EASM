import dns.resolver

def dns_enum(target):
    records = {}
    for rtype in ['A', 'MX', 'NS', 'TXT']:
        try:
            answers = dns.resolver.resolve(target, rtype)
            records[rtype] = [str(r) for r in answers]
        except:
            records[rtype] = []
    return records
