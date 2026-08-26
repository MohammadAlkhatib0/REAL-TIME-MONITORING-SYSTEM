def get_geoip_data(ip_address: str):
    """
    Returns country_code, country_name, and flag for a given IP address.
    Simulates real-world GeoIP lookup databases (MaxMind / Cloudflare IP Intelligence).
    """
    ip = str(ip_address or "").strip()

    if ip.startswith("45.33.") or ip.startswith("116."):
        return {"country_code": "CN", "country_name": "China", "flag": "🇨🇳"}
    elif ip.startswith("185.220.") or ip.startswith("82."):
        return {"country_code": "DE", "country_name": "Germany", "flag": "🇩🇪"}
    elif ip.startswith("193.142.") or ip.startswith("95."):
        return {"country_code": "RU", "country_name": "Russian Federation", "flag": "🇷🇺"}
    elif ip.startswith("103.251.") or ip.startswith("200."):
        return {"country_code": "BR", "country_name": "Brazil", "flag": "🇧🇷"}
    elif ip.startswith("14.") or ip.startswith("106."):
        return {"country_code": "IN", "country_name": "India", "flag": "🇮🇳"}
    elif ip.startswith("110.") or ip.startswith("51."):
        return {"country_code": "GB", "country_name": "United Kingdom", "flag": "🇬🇧"}
    elif ip.startswith("104.") or ip.startswith("172."):
        return {"country_code": "FR", "country_name": "France", "flag": "🇫🇷"}
    else:
        return {"country_code": "US", "country_name": "United States", "flag": "🇺🇸"}
