import datetime
def lookup_domain(domain: str) -> dict:
    
    try:
        import whois
        w = whois.whois(domain)

      
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = min(creation_date)

        expiry_date = w.expiration_date
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]

      
        age_days = None
        if creation_date:
            if isinstance(creation_date, datetime.datetime):
                age_days = (datetime.datetime.now() - creation_date).days
            elif isinstance(creation_date, datetime.date):
                today    = datetime.date.today()
                age_days = (today - creation_date).days

       
        registrar = w.registrar or "Unknown"
        if isinstance(registrar, list):
            registrar = registrar[0]

        
        country = w.country or w.registrant_country or "Unknown"
        if isinstance(country, list):
            country = country[0]

       
        name_servers = w.name_servers or []
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        name_servers = [str(ns).lower() for ns in name_servers][:4]  # cap at 4

        return {
            "domain"       : domain,
            "registrar"    : str(registrar),
            "creation_date": str(creation_date) if creation_date else "Unknown",
            "expiry_date"  : str(expiry_date)   if expiry_date   else "Unknown",
            "country"      : str(country),
            "name_servers" : name_servers,
            "age_days"     : age_days,
        }

    except ImportError:
        return {
            "domain": domain,
            "error" : "python-whois not installed. Run: pip install python-whois",
        }
    except Exception as e:
      
        return {
            "domain": domain,
            "error" : f"WHOIS lookup failed: {str(e)[:100]}",
        }
