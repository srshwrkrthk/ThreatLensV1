import dns.resolver


def get_dns_records(domain: str):
    record_types = ["A", "AAAA", "MX", "NS", "TXT"]
    dns_report = {}

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            dns_report[record_type] = [str(answer) for answer in answers]
        except Exception:
            dns_report[record_type] = []

    return dns_report


def get_dmarc_record(domain: str):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        return [str(answer) for answer in answers]
    except Exception:
        return []
        