from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from client import PowerDNSClient
from config import settings
import httpx
import ipaddress
import re
import os
import json

app = FastAPI(title="PowerDNS Manager")
app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
pdns = PowerDNSClient()

def load_translations():
    """Load translation files from the locales directory.

    Returns:
        dict: A dictionary of translations keyed by language code.
    """
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
    """Detects locale from query param, cookie, or accept-language header.

    Args:
        request (Request): The incoming HTTP request.

    Returns:
        str: The detected language code (e.g., 'en', 'fr').
    """
    lang = request.query_params.get("lang")
    if not lang:
        lang = request.cookies.get("pdns_lang")
    if not lang:
        accept = request.headers.get("accept-language", "")
        lang = "fr" if "fr" in accept.lower() else "en"
    return lang if lang in TRANSLATIONS else "en"

# --- Authentication Setup ---
oauth = OAuth()
if settings.OIDC_CLIENT_ID and settings.OIDC_DISCOVERY_URL:
    oauth.register(
        name='oidc',
        client_id=settings.OIDC_CLIENT_ID,
        client_secret=settings.OIDC_CLIENT_SECRET,
        server_metadata_url=settings.OIDC_DISCOVERY_URL,
        client_kwargs={'scope': 'openid email profile'}
    )

class NotAuthenticated(Exception): pass

@app.exception_handler(NotAuthenticated)
async def not_authenticated_exception_handler(request: Request, exc: NotAuthenticated):
    return RedirectResponse(url="/login")

async def get_current_user(request: Request):
    user = request.session.get("user")
    if not user:
        raise NotAuthenticated()
    return user

def validate_record(rtype: str, content: str, lang: str = "en"):
    """Validates record content based on its type.

    Args:
        rtype (str): The DNS record type (A, AAAA, MX, etc.).
        content (str): The value of the record.
        lang (str, optional): The language code for error messages. Defaults to "en".

    Returns:
        tuple: A tuple (is_valid, error_message).
    """
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
    
    return True, ""

# --- Auth Routes ---

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    lang = get_locale(request)
    _ = lambda key: TRANSLATIONS[lang].get(key, key)
    return templates.TemplateResponse("login.html", {
        "request": request, 
        "lang": lang, 
        "_": _,
        "oidc_enabled": bool(settings.OIDC_CLIENT_ID)
    })

@app.post("/login")
async def login_local(request: Request, username: str = Form(...), password: str = Form(...)):
    lang = get_locale(request)
    _ = lambda key: TRANSLATIONS[lang].get(key, key)
    
    if username == settings.LOCAL_USER and password == settings.LOCAL_PASSWORD:
        request.session["user"] = {"name": username, "type": "local"}
        return RedirectResponse(url="/", status_code=303)
    
    return templates.TemplateResponse("login.html", {
        "request": request, 
        "error": _("login_failed"),
        "lang": lang, 
        "_": _,
        "oidc_enabled": bool(settings.OIDC_CLIENT_ID)
    })

@app.get("/login/oidc")
async def login_oidc(request: Request):
    if not settings.OIDC_CLIENT_ID:
        return RedirectResponse(url="/login")
    redirect_uri = request.url_for('auth_callback')
    return await oauth.oidc.authorize_redirect(request, redirect_uri)

@app.get("/auth/callback")
async def auth_callback(request: Request):
    try:
        token = await oauth.oidc.authorize_access_token(request)
        user_info = token.get('userinfo')
        request.session["user"] = {"name": user_info.get("name", "User"), "email": user_info.get("email"), "type": "oidc"}
        return RedirectResponse(url="/")
    except Exception as e:
        return RedirectResponse(url=f"/login?error={str(e)}")

@app.get("/logout")
async def logout(request: Request):
    request.session.pop("user", None)
    return RedirectResponse(url="/login")

# --- Protected Routes ---

@app.get("/", response_class=HTMLResponse)
async def list_zones(request: Request, user: dict = Depends(get_current_user)):
    """Lists all DNS zones, separated by forward and reverse types.

    Args:
        request (Request): The HTTP request.

    Returns:
        TemplateResponse: The rendered index page with zone lists.
    """
    lang = get_locale(request)
    _ = lambda key: TRANSLATIONS[lang].get(key, key)
    
    try:
        zones = await pdns.get_zones()
    except httpx.HTTPError as e:
        return templates.TemplateResponse("index.html", {
            "request": request, 
            "error": f"{_('error')}: {str(e)}", 
            "forward_zones": [],
            "reverse_zones": [],
            "lang": lang,
            "user": user,
            "_": _
        })

    forward_zones = []
    reverse_zones = []
    for zone in zones:
        if 'in-addr.arpa' in zone['name'] or 'ip6.arpa' in zone['name']:
            reverse_zones.append(zone)
        else:
            forward_zones.append(zone)

    return templates.TemplateResponse("index.html", {
        "request": request, 
        "forward_zones": forward_zones,
        "reverse_zones": reverse_zones,
        "lang": lang,
        "user": user,
        "_": _
    })

@app.post("/zones/add")
async def add_zone(domain: str = Form(...), kind: str = Form("Native"), user: dict = Depends(get_current_user)):
    """Creates a new zone via the API.

    Args:
        domain (str): The domain name.
        kind (str): The zone type.

    Returns:
        RedirectResponse: Redirects to the index page.
    """
    try:
        await pdns.create_zone(domain=domain, kind=kind)
    except httpx.HTTPStatusError as e:
        # In a real app, we would send the error to the UI via a flash message or HTMX
        print(f"Creation error: {e.response.text}")
    return RedirectResponse(url="/", status_code=303)

@app.post("/zones/delete/{zone_id}")
async def delete_zone(zone_id: str, user: dict = Depends(get_current_user)):
    """Deletes a zone via the API.

    Args:
        zone_id (str): The ID of the zone to delete.

    Returns:
        RedirectResponse: Redirects to the index page.
    """
    try:
        await pdns.delete_zone(zone_id)
    except httpx.HTTPError as e:
        print(f"Deletion error: {str(e)}")
    return RedirectResponse(url="/", status_code=303)

@app.get("/zones/{zone_id}", response_class=HTMLResponse)
async def view_zone(request: Request, zone_id: str, user: dict = Depends(get_current_user)):
    """Displays zone details and records, merging API data with pending session changes.

    Args:
        request (Request): The HTTP request.
        zone_id (str): The ID of the zone to view.

    Returns:
        TemplateResponse: The rendered zone details page.
    """
    lang = get_locale(request)
    _ = lambda key: TRANSLATIONS[lang].get(key, key)
    
    try:
        zone = await pdns.get_zone(zone_id)
        
        # Retrieve pending changes from session
        pending_changes = request.session.get('changes', {}).get(zone_id, {})
        
        # Merge data for display
        # Create a dictionary indexed by (name, type) to facilitate merging
        rrsets_map = {(r['name'], r['type']): r for r in zone['rrsets']}
        
        # Apply pending changes to local view
        for key, change in pending_changes.items():
            name, rtype = key.split('|')
            
            if change['changetype'] == 'DELETE':
                if (name, rtype) in rrsets_map:
                    # Mark record as "to be deleted"
                    rrsets_map[(name, rtype)]['status'] = 'deleted'
            
            elif change['changetype'] == 'REPLACE':
                # Create or update record
                rrset_data = {
                    'name': name,
                    'type': rtype,
                    'ttl': change['ttl'],
                    'records': change['records'],
                    'status': 'modified' if (name, rtype) in rrsets_map else 'new'
                }
                rrsets_map[(name, rtype)] = rrset_data

        # Convert back to list
        zone['rrsets'] = list(rrsets_map.values())
        # Sort records for display
        zone['rrsets'].sort(key=lambda x: (x['type'], x['name']))
        
    except httpx.HTTPError as e:
        return RedirectResponse(url=f"/?error=Unable to load zone: {e}")
    
    return templates.TemplateResponse("zone_details.html", {
        "request": request, 
        "zone": zone,
        "has_pending_changes": bool(pending_changes),
        "lang": lang,
        "user": user,
        "_": _
    })

@app.post("/zones/{zone_id}/records/add")
async def add_record(
    request: Request,
    zone_id: str, 
    name: str = Form(...), 
    rtype: str = Form(...), 
    content: str = Form(...), 
    ttl: int = Form(3600),
    user: dict = Depends(get_current_user)
):
    """Validates and adds a record change to the session.

    Args:
        request (Request): The HTTP request.
        zone_id (str): The ID of the zone.
        name (str): The record name.
        rtype (str): The record type.
        content (str): The record content.
        ttl (int): The record TTL.

    Returns:
        TemplateResponse | RedirectResponse: Error page or redirect to zone view.
    """
    lang = get_locale(request)
    _ = lambda key: TRANSLATIONS[lang].get(key, key)
    
    is_valid, error_msg = validate_record(rtype, content, lang)
    if not is_valid:
        zone = await pdns.get_zone(zone_id)
        return templates.TemplateResponse("zone_details.html", {
            "request": request, 
            "zone": zone, 
            "error": f"{_('error')} {rtype}: {error_msg}",
            "form_data": {"name": name, "type": rtype, "content": content, "ttl": ttl},
            "lang": lang,
            "user": user,
            "_": _
        })

    # Name normalization (FQDN)
    canonical_zone = zone_id # zone_id est typiquement "example.com."
    if name == '@':
        final_name = canonical_zone
    elif not name.endswith('.'):
        final_name = f"{name}.{canonical_zone}"
    else:
        final_name = name

    # Store in session (Atomicity)
    changes = request.session.get('changes', {})
    if zone_id not in changes:
        changes[zone_id] = {}
    
    key = f"{final_name}|{rtype}"
    
    changes[zone_id][key] = {
        "name": final_name,
        "type": rtype,
        "ttl": ttl,
        "changetype": "REPLACE",
        "records": [{"content": content, "disabled": False}]
    }
    
    request.session['changes'] = changes
         
    return RedirectResponse(url=f"/zones/{zone_id}", status_code=303)

@app.post("/zones/{zone_id}/records/delete")
async def delete_record(request: Request, zone_id: str, name: str = Form(...), rtype: str = Form(...), user: dict = Depends(get_current_user)):
    """Marks a record for deletion in the session.

    Args:
        request (Request): The HTTP request.
        zone_id (str): The ID of the zone.
        name (str): The record name.
        rtype (str): The record type.

    Returns:
        RedirectResponse: Redirects to the zone view.
    """
    changes = request.session.get('changes', {})
    if zone_id not in changes:
        changes[zone_id] = {}
        
    key = f"{name}|{rtype}"
    changes[zone_id][key] = {
        "name": name,
        "type": rtype,
        "changetype": "DELETE",
        "records": []
    }
    request.session['changes'] = changes
    
    return RedirectResponse(url=f"/zones/{zone_id}", status_code=303)

@app.post("/zones/{zone_id}/apply")
async def apply_changes(request: Request, zone_id: str, user: dict = Depends(get_current_user)):
    """Applies all pending changes for a zone to the PowerDNS API.

    Args:
        request (Request): The HTTP request.
        zone_id (str): The ID of the zone.

    Returns:
        RedirectResponse: Redirects to the zone view.
    """
    changes = request.session.get('changes', {}).get(zone_id, {})
    if not changes:
        return RedirectResponse(url=f"/zones/{zone_id}", status_code=303)
    
    rrsets_to_apply = list(changes.values())
    
    try:
        await pdns.batch_apply_records(zone_id, rrsets_to_apply)
        # Clean up session after success
        del request.session['changes'][zone_id]
    except httpx.HTTPError as e:
        print(f"Application error: {e}")
        
    return RedirectResponse(url=f"/zones/{zone_id}", status_code=303)

@app.post("/zones/{zone_id}/discard")
async def discard_changes(request: Request, zone_id: str, user: dict = Depends(get_current_user)):
    """Discards pending changes for a zone.

    Args:
        request (Request): The HTTP request.
        zone_id (str): The ID of the zone.

    Returns:
        RedirectResponse: Redirects to the zone view.
    """
    if 'changes' in request.session and zone_id in request.session['changes']:
        del request.session['changes'][zone_id]
    return RedirectResponse(url=f"/zones/{zone_id}", status_code=303)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
