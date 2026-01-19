from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from client import PowerDNSClient
import httpx
import ipaddress
import re
import os

app = FastAPI(title="PowerDNS Manager")
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SECRET_KEY", "change-me-in-production"))
templates = Jinja2Templates(directory="templates")
pdns = PowerDNSClient()

def validate_record(rtype: str, content: str):
    """Valide le contenu d'un enregistrement selon son type."""
    content = content.strip()
    if rtype == 'A':
        try:
            ip = ipaddress.ip_address(content)
            if ip.version != 4: return False, "Doit être une adresse IPv4 valide"
        except ValueError: return False, "Adresse IP invalide"
    elif rtype == 'AAAA':
        try:
            ip = ipaddress.ip_address(content)
            if ip.version != 6: return False, "Doit être une adresse IPv6 valide"
        except ValueError: return False, "Adresse IP invalide"
    elif rtype == 'MX':
        parts = content.split(maxsplit=1)
        if len(parts) != 2: return False, "Format attendu: 'Priorité Cible' (ex: 10 mail.exemple.com)"
        if not parts[0].isdigit(): return False, "La priorité doit être un nombre entier"
    elif rtype in ['CNAME', 'PTR', 'NS']:
        # Validation basique de nom de domaine (autorise le point final)
        if not re.match(r'^[a-zA-Z0-9\-\._]+$', content):
            return False, "Nom de domaine invalide"
    elif rtype == 'TXT':
        if not content: return False, "Le contenu ne peut pas être vide"
    elif rtype == 'CAA':
        parts = content.split()
        if len(parts) < 3: return False, "Format: 'flag tag value'"
        if not parts[0].isdigit(): return False, "Flag doit être un entier"
    elif rtype == 'SRV':
        parts = content.split()
        if len(parts) != 4: return False, "Format: 'priority weight port target'"
        if not all(p.isdigit() for p in parts[:3]): return False, "Priority, weight et port doivent être des entiers"
    elif rtype in ['LOC', 'SPF']:
        if not content: return False, "Le contenu ne peut pas être vide"
    
    return True, ""

@app.get("/", response_class=HTMLResponse)
async def list_zones(request: Request):
    try:
        zones = await pdns.get_zones()
    except httpx.HTTPError as e:
        return templates.TemplateResponse("index.html", {
            "request": request, 
            "error": f"Erreur de connexion à PowerDNS: {str(e)}", 
            "forward_zones": [],
            "reverse_zones": []
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
        "reverse_zones": reverse_zones
    })

@app.post("/zones/add")
async def add_zone(domain: str = Form(...), kind: str = Form("Native")):
    try:
        await pdns.create_zone(domain=domain, kind=kind)
    except httpx.HTTPStatusError as e:
        # Dans une vraie app, on renverrait l'erreur à l'UI via un message flash ou HTMX
        print(f"Erreur création: {e.response.text}")
    return RedirectResponse(url="/", status_code=303)

@app.post("/zones/delete/{zone_id}")
async def delete_zone(zone_id: str):
    try:
        await pdns.delete_zone(zone_id)
    except httpx.HTTPError as e:
        print(f"Erreur suppression: {str(e)}")
    return RedirectResponse(url="/", status_code=303)

@app.get("/zones/{zone_id}", response_class=HTMLResponse)
async def view_zone(request: Request, zone_id: str):
    try:
        zone = await pdns.get_zone(zone_id)
        
        # Récupération des changements en attente depuis la session
        pending_changes = request.session.get('changes', {}).get(zone_id, {})
        
        # Fusion des données pour l'affichage
        # On crée un dictionnaire indexé par (name, type) pour faciliter la fusion
        rrsets_map = {(r['name'], r['type']): r for r in zone['rrsets']}
        
        # Appliquer les changements en attente sur la vue locale
        for key, change in pending_changes.items():
            name, rtype = key.split('|')
            
            if change['changetype'] == 'DELETE':
                if (name, rtype) in rrsets_map:
                    # On marque l'enregistrement comme "à supprimer"
                    rrsets_map[(name, rtype)]['status'] = 'deleted'
            
            elif change['changetype'] == 'REPLACE':
                # On crée ou met à jour l'enregistrement
                rrset_data = {
                    'name': name,
                    'type': rtype,
                    'ttl': change['ttl'],
                    'records': change['records'],
                    'status': 'modified' if (name, rtype) in rrsets_map else 'new'
                }
                rrsets_map[(name, rtype)] = rrset_data

        # Reconversion en liste
        zone['rrsets'] = list(rrsets_map.values())
        # Tri des enregistrements pour l'affichage
        zone['rrsets'].sort(key=lambda x: (x['type'], x['name']))
        
    except httpx.HTTPError as e:
        return RedirectResponse(url=f"/?error=Impossible de charger la zone: {e}")
    
    return templates.TemplateResponse("zone_details.html", {
        "request": request, 
        "zone": zone,
        "has_pending_changes": bool(pending_changes)
    })

@app.post("/zones/{zone_id}/records/add")
async def add_record(
    request: Request,
    zone_id: str, 
    name: str = Form(...), 
    rtype: str = Form(...), 
    content: str = Form(...), 
    ttl: int = Form(3600)
):
    # 1. Validation
    is_valid, error_msg = validate_record(rtype, content)
    if not is_valid:
        zone = await pdns.get_zone(zone_id)
        return templates.TemplateResponse("zone_details.html", {
            "request": request, 
            "zone": zone, 
            "error": f"Erreur {rtype}: {error_msg}",
            "form_data": {"name": name, "type": rtype, "content": content, "ttl": ttl}
        })

    # 2. Normalisation du nom (FQDN)
    # Si le nom est "@", c'est la racine de la zone.
    # Si le nom ne finit pas par un point, on ajoute le nom de la zone.
    canonical_zone = zone_id # zone_id est typiquement "example.com."
    if name == '@':
        final_name = canonical_zone
    elif not name.endswith('.'):
        final_name = f"{name}.{canonical_zone}"
    else:
        final_name = name

    # 3. Stockage en session (Atomicité)
    changes = request.session.get('changes', {})
    if zone_id not in changes:
        changes[zone_id] = {}
    
    # Clé unique pour le RRSet
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
async def delete_record(request: Request, zone_id: str, name: str = Form(...), rtype: str = Form(...)):
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
async def apply_changes(request: Request, zone_id: str):
    changes = request.session.get('changes', {}).get(zone_id, {})
    if not changes:
        return RedirectResponse(url=f"/zones/{zone_id}", status_code=303)
    
    rrsets_to_apply = list(changes.values())
    
    try:
        await pdns.batch_apply_records(zone_id, rrsets_to_apply)
        # Nettoyage de la session après succès
        del request.session['changes'][zone_id]
    except httpx.HTTPError as e:
        print(f"Erreur application: {e}")
        
    return RedirectResponse(url=f"/zones/{zone_id}", status_code=303)

@app.post("/zones/{zone_id}/discard")
async def discard_changes(request: Request, zone_id: str):
    if 'changes' in request.session and zone_id in request.session['changes']:
        del request.session['changes'][zone_id]
    return RedirectResponse(url=f"/zones/{zone_id}", status_code=303)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
