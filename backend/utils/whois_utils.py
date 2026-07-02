import whois


def get_whois_info(domain: str):
    try:
        data = whois.whois(domain)

        return {
            "registrar": str(data.registrar) if data.registrar else None,
            "creation_date": str(data.creation_date) if data.creation_date else None,
            "expiration_date": str(data.expiration_date) if data.expiration_date else None,
            "updated_date": str(data.updated_date) if data.updated_date else None,
            "name_servers": list(data.name_servers) if data.name_servers else [],
            "emails": data.emails if isinstance(data.emails, list) else [data.emails] if data.emails else [],
            "country": str(data.country) if data.country else None
        }

    except Exception:
        return {
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "name_servers": [],
            "emails": [],
            "country": None
        }