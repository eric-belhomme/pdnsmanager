
from fastapi import Request
from fastapi.templating import Jinja2Templates
import os
import json
import re
import ipaddress

templates = Jinja2Templates(directory=f"{os.path.dirname(__file__)}/templates")

def load_translations():
    """Load translation files from the locales directory."""
    translations = {}
    locales_dir = os.path.join(os.path.dirname(__file__), "locales")
    if os.path.exists(locales_dir):
        for filename in os.listdir(locales_dir):
            if filename.endswith(".json"):
                lang = filename.split(".")[0]
                with open(os.path.join(locales_dir, filename), "r", encoding="utf-8") as f:
                    translations[lang] = json.load(f)
    return translations

TRANSLATIONS = load_translations()

def get_locale(request: Request) -> str:
    """Detects locale from query param, cookie, or accept-language header."""
    lang = request.query_params.get("lang")
    if not lang:
        lang = request.cookies.get("pdns_lang")
    if not lang:
        accept = request.headers.get("accept-language", "")
        lang = "fr" if "fr" in accept.lower() else "en"
    return lang if lang in TRANSLATIONS else "en"

def validate_record(rtype: str, content: str, lang: str = "en"):
    """Validates record content based on its type."""
    t = TRANSLATIONS[lang]
    content = content.strip()
    
    if rtype == 'A':
        try:
            ip = ipaddress.ip_address(content)
            if ip.version != 4: return False, t["err_ipv4"]
        except ValueError: return False, t["err_ip"]
    elif rtype == 'AAAA':
        try:
            ip = ipaddress.ip_address(content)
            if ip.version != 6: return False, t["err_ipv6"]
        except ValueError: return False, t["err_ip"]
    elif rtype == 'MX':
        parts = content.split(maxsplit=1)
        if len(parts) != 2: return False, t["err_mx_fmt"]
        if not parts[0].isdigit(): return False, t["err_mx_int"]
    elif rtype in ['CNAME', 'PTR', 'NS']:
        if not re.match(r'^[a-zA-Z0-9\-\._]+$', content):
            return False, t["err_domain"]
    elif rtype == 'TXT':
        if not content: return False, t["err_empty"]
    elif rtype == 'CAA':
        parts = content.split()
        if len(parts) < 3: return False, t["err_caa_fmt"]
        if not parts[0].isdigit(): return False, t["err_caa_int"]
    elif rtype == 'SRV':
        parts = content.split()
        if len(parts) != 4: return False, t["err_srv_fmt"]
        if not all(p.isdigit() for p in parts[:3]): return False, t["err_srv_int"]
    elif rtype in ['LOC', 'SPF']:
        if not content: return False, t["err_empty"]
    elif rtype == 'SOA':
        parts = content.split()
        if len(parts) != 7: return False, t["err_soa_fmt"]
        if not all(p.isdigit() for p in parts[2:]): return False, t["err_soa_int"]
    
    return True, ""

def check_policy_match(policy_zone: str, zone_name: str) -> bool:
    """Checks if a zone name matches a policy zone pattern (supports wildcards)."""
    if policy_zone == '*':
        return True
    if policy_zone == zone_name:
        return True
    if policy_zone.startswith('*.'):
        suffix = policy_zone[2:]
        if zone_name.endswith("." + suffix):
            return True
    return False

def ip_to_ptr_info(ip_address: str) -> tuple[str, str]:
    """
    Converts an IP address to its corresponding PTR record name and reverse zone name.
    e.g., "192.168.1.10" -> ("10.1.168.192.in-addr.arpa.", "1.168.192.in-addr.arpa.")
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        if ip.version == 4:
            parts = str(ip).split('.')
            ptr_name = f"{'.'.join(reversed(parts))}.in-addr.arpa."
            # For a /24 network (common for in-addr.arpa), the reverse zone is the first three octets reversed.
            # This is a simplification; real reverse zones can be more complex (e.g., /16, /28).
            # For now, assume /24 for in-addr.arpa.
            reverse_zone = f"{'.'.join(reversed(parts[:-1]))}.in-addr.arpa."
            return ptr_name, reverse_zone
        elif ip.version == 6:
            # IPv6 PTR records are more complex, requiring nibble-level reversal.
            # For simplicity, we raise an error for now.
            raise ValueError("IPv6 PTR management is not yet supported.")
    except ValueError as e:
        raise ValueError(f"Invalid IP address for PTR conversion: {e}")
