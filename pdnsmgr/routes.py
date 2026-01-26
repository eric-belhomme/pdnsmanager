from fastapi import APIRouter, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from .client import PowerDNSClient
from .utils import templates, get_locale, TRANSLATIONS, validate_record
from .dependencies import get_current_user
from .rbac import rbac
import logging
import httpx

router = APIRouter()
pdns = PowerDNSClient()

logger = logging.getLogger(__name__)

@router.get("/", response_class=HTMLResponse)
async def list_zones(request: Request, user: dict = Depends(get_current_user)):
    """Lists all DNS zones, separated by forward and reverse types."""
    lang = get_locale(request)
    _ = lambda key: TRANSLATIONS[lang].get(key, key)
    
    logger.info("User '%s' is requesting list of zones.", user.get("username"))
    try:
        zones = await pdns.get_zones()
    except httpx.HTTPError as e:
        logger.error("Failed to retrieve zones for user '%s': %s", user.get("username"), e, exc_info=True)
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
        logger.debug("Checking role for user '%s' on zone '%s'.", user.get("username"), zone['name'])
        role = await rbac.get_role(user, zone['name'])
        zone['role'] = role
        if 'in-addr.arpa' in zone['name'] or 'ip6.arpa' in zone['name']:
            reverse_zones.append(zone)
        else:
            forward_zones.append(zone)

    # Default sorting
    forward_zones.sort(key=lambda z: z['name'])

    def reverse_zone_key(z):
        name = z['name'].rstrip('.')
        if name.endswith('.in-addr.arpa'):
            try:
                parts = name[:-13].split('.')
                return [int(p) for p in reversed(parts) if p.isdigit()]
            except ValueError:
                pass
        return name

    reverse_zones.sort(key=reverse_zone_key)

    logger.info("Successfully listed zones for user '%s'. Forward: %d, Reverse: %d.", user.get("username"), len(forward_zones), len(reverse_zones))
    return templates.TemplateResponse("index.html", {
        "request": request, 
        "forward_zones": forward_zones,
        "reverse_zones": reverse_zones,
        "lang": lang,
        "user": user,
        "_": _
    })

@router.post("/zones/add")
async def add_zone(domain: str = Form(...), kind: str = Form("Native"), user: dict = Depends(get_current_user)):
    """Creates a new zone via the API."""
    # Check if user has global create permissions or is owner on *
    logger.info("User '%s' attempting to add zone '%s' (kind: %s).", user.get("username"), domain, kind)
    if await rbac.get_role(user, "*") != 'owner':
        logger.warning("User '%s' denied permission to create zone '%s': Insufficient permissions.", user.get("username"), domain)
        raise HTTPException(status_code=403, detail="Insufficient permissions to create zones")

    try:
        await pdns.create_zone(domain=domain, kind=kind)
        logger.info("Zone '%s' created successfully by user '%s'.", domain, user.get("username"))
    except httpx.HTTPStatusError as e:
        logger.error("Failed to create zone '%s' for user '%s': %s", domain, user.get("username"), e.response.text, exc_info=True)
    return RedirectResponse(url="/", status_code=303)


@router.post("/zones/delete/{zone_id}")
async def delete_zone(zone_id: str, user: dict = Depends(get_current_user)):
    """Deletes a zone via the API."""
    logger.info("User '%s' attempting to delete zone '%s'.", user.get("username"), zone_id)
    if await rbac.get_role(user, zone_id) != 'owner':
        raise HTTPException(status_code=403, detail="Insufficient permissions")
        
    try:
        await pdns.delete_zone(zone_id)
    except httpx.HTTPError as e:
        logger.error("Failed to delete zone '%s' for user '%s': %s", zone_id, user.get("username"), e, exc_info=True)
    return RedirectResponse(url="/", status_code=303)

@router.get("/zones/{zone_id}", response_class=HTMLResponse)
async def view_zone(request: Request, zone_id: str, user: dict = Depends(get_current_user)):
    """Displays zone details and records, merging API data with pending session changes."""
    lang = get_locale(request)
    _ = lambda key: TRANSLATIONS[lang].get(key, key)
    
    logger.info("User '%s' is viewing zone '%s'.", user.get("username"), zone_id)
    role = await rbac.get_role(user, zone_id)
    if role == 'none':
        return RedirectResponse(url="/")
    logger.debug("User '%s' has role '%s' on zone '%s'.", user.get("username"), role, zone_id)

    try:
        zone = await pdns.get_zone(zone_id)
        
        # Retrieve pending changes from session
        pending_changes = request.session.get('changes', {}).get(zone_id, {})
        
        # Merge data for display
        rrsets_map = {(r['name'], r['type']): r for r in zone['rrsets']}
        
        # Apply pending changes to local view
        for key, change in pending_changes.items():
            name, rtype = key.split('|')
            
            if change['changetype'] == 'DELETE':
                if (name, rtype) in rrsets_map:
                    rrsets_map[(name, rtype)]['status'] = 'deleted'
            
            elif change['changetype'] == 'REPLACE':
                rrset_data = {
                    'name': name,
                    'type': rtype,
                    'ttl': change['ttl'],
                    'records': change['records'],
                    'status': 'modified' if (name, rtype) in rrsets_map else 'new'
                }
                rrsets_map[(name, rtype)] = rrset_data

        zone['rrsets'] = list(rrsets_map.values())
        zone['rrsets'].sort(key=lambda x: (0 if x['type'] == 'SOA' else 1, x['type'], x['name']))
        
    except httpx.HTTPError as e:
        logger.error("Failed to load zone '%s' for user '%s': %s", zone_id, user.get("username"), e, exc_info=True)
        return RedirectResponse(url=f"/?error=Unable to load zone: {e}")
    
    return templates.TemplateResponse("zone_details.html", {
        "request": request, 
        "zone": zone,
        "has_pending_changes": bool(pending_changes),
        "lang": lang,
        "user": user,
        "user_role": role,
        "_": _
    })

@router.post("/zones/{zone_id}/records/add")
async def add_record(
    request: Request,
    zone_id: str, 
    name: str = Form(...), 
    rtype: str = Form(...), 
    content: str = Form(...), 
    ttl: int = Form(3600),
    user: dict = Depends(get_current_user)
):
    """Validates and adds a record change to the session."""
    lang = get_locale(request)
    _ = lambda key: TRANSLATIONS[lang].get(key, key)
    
    role = await rbac.get_role(user, zone_id)
    logger.info("User '%s' attempting to add record (type: %s) to zone '%s'. Role: %s", user.get("username"), rtype, zone_id, role)
    if not rbac.can_write_record(role, rtype):
        logger.warning("User '%s' denied permission to add record type '%s' to zone '%s'.", user.get("username"), rtype, zone_id)
        raise HTTPException(status_code=403, detail="Insufficient permissions for this record type")
    
    is_valid, error_msg = validate_record(rtype, content, lang)
    if not is_valid:
        zone = await pdns.get_zone(zone_id)
        logger.warning("Record validation failed for user '%s' in zone '%s': %s", user.get("username"), zone_id, error_msg)
        return templates.TemplateResponse("zone_details.html", {
            "request": request, 
            "zone": zone, 
            "error": f"{_('error')} {rtype}: {error_msg}",
            "form_data": {"name": name, "type": rtype, "content": content, "ttl": ttl},
            "lang": lang,
            "user": user,
            "user_role": role,
            "_": _
        })

    canonical_zone = zone_id
    if name == '@':
        final_name = canonical_zone
    elif not name.endswith('.'):
        final_name = f"{name}.{canonical_zone}"
    else:
        final_name = name

    changes = request.session.get('changes', {})
    if zone_id not in changes:
        logger.debug("Initializing pending changes for zone '%s' in session.", zone_id)
        changes[zone_id] = {}
    
    key = f"{final_name}|{rtype}"
    
    changes[zone_id][key] = {
        "name": final_name,
        "type": rtype,
        "ttl": ttl,
        "changetype": "REPLACE",
        "records": [{"content": content, "disabled": False}]
    }
    
    logger.info("Record change for '%s' (type: %s) added to session for zone '%s' by user '%s'.", final_name, rtype, zone_id, user.get("username"))
    request.session['changes'] = changes
         
    return RedirectResponse(url=f"/zones/{zone_id}", status_code=303)

@router.post("/zones/{zone_id}/records/delete")
async def delete_record(request: Request, zone_id: str, name: str = Form(...), rtype: str = Form(...), user: dict = Depends(get_current_user)):
    """Marks a record for deletion in the session."""
    logger.info("User '%s' attempting to mark record '%s' (type: %s) for deletion in zone '%s'.", user.get("username"), name, rtype, zone_id)
    role = await rbac.get_role(user, zone_id)
    if not rbac.can_write_record(role, rtype):
        logger.warning("User '%s' denied permission to delete record type '%s' from zone '%s'.", user.get("username"), rtype, zone_id)
        raise HTTPException(status_code=403, detail="Insufficient permissions")


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
    logger.info("Record change for '%s' (type: %s) marked for deletion in session for zone '%s' by user '%s'.", name, rtype, zone_id, user.get("username"))
    request.session['changes'] = changes
    
    return RedirectResponse(url=f"/zones/{zone_id}", status_code=303)

@router.post("/zones/{zone_id}/apply")
async def apply_changes(request: Request, zone_id: str, user: dict = Depends(get_current_user)):
    """Applies all pending changes for a zone to the PowerDNS API."""
    logger.info("User '%s' attempting to apply changes for zone '%s'.", user.get("username"), zone_id)
    changes = request.session.get('changes', {}).get(zone_id, {})
    if not changes:
        logger.info("No pending changes to apply for zone '%s'.", zone_id)
        return RedirectResponse(url=f"/zones/{zone_id}", status_code=303)
    
    # Re-validate permissions for all pending changes
    logger.debug("Re-validating permissions for %d pending changes in zone '%s'.", len(changes), zone_id)
    role = await rbac.get_role(user, zone_id)
    for change in changes.values():
        if not rbac.can_write_record(role, change['type']):
             raise HTTPException(status_code=403, detail=f"Insufficient permissions to apply change for {change['type']}")

    rrsets_to_apply = list(changes.values())
    
    try:
        await pdns.batch_apply_records(zone_id, rrsets_to_apply)
        logger.info("Successfully applied %d changes to zone '%s' by user '%s'.", len(rrsets_to_apply), zone_id, user.get("username"))
        del request.session['changes'][zone_id]
    except httpx.HTTPError as e:
        logger.error("Failed to apply changes to zone '%s' for user '%s': %s", zone_id, user.get("username"), e, exc_info=True)
        
    return RedirectResponse(url=f"/zones/{zone_id}", status_code=303)

@router.post("/zones/{zone_id}/discard")
async def discard_changes(request: Request, zone_id: str, user: dict = Depends(get_current_user)):
    """Discards pending changes for a zone."""
    logger.info("User '%s' attempting to discard changes for zone '%s'.", user.get("username"), zone_id)
    if 'changes' in request.session and zone_id in request.session['changes']:
        del request.session['changes'][zone_id]
        logger.info("Pending changes for zone '%s' discarded by user '%s'.", zone_id, user.get("username"))
    return RedirectResponse(url=f"/zones/{zone_id}", status_code=303)

@router.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request, user: dict = Depends(get_current_user)):
    if "admins" not in user.get("groups", []):
        raise HTTPException(status_code=403, detail="Access denied")
    
    logger.info("User '%s' accessing admin page.", user.get("username"))
    groups = await rbac.get_all_groups()
    users_list = await rbac.get_all_users()
    members = await rbac.get_all_members()
    policies = await rbac.get_all_policies()
    
    lang = get_locale(request)
    _ = lambda key: TRANSLATIONS[lang].get(key, key)
    
    return templates.TemplateResponse("admin.html", {
        "request": request,
        "user": user,
        "users_list": users_list,
        "groups": groups,
        "members": members,
        "policies": policies,
        "lang": lang,
        "_": _
    })

@router.post("/admin/users/add")
async def admin_add_user(username: str = Form(...), name: str = Form(None), email: str = Form(None), password: str = Form(None), user: dict = Depends(get_current_user)):
    if "admins" not in user.get("groups", []):
        logger.warning("User '%s' denied access to admin_add_user.", user.get("username"))
        raise HTTPException(status_code=403)
    await rbac.create_user(username, name, email, type="local", password=password)
    return RedirectResponse(url="/admin", status_code=303)

@router.post("/admin/users/update")
async def admin_update_user(username: str = Form(...), name: str = Form(...), email: str = Form(None), password: str = Form(None), user: dict = Depends(get_current_user)):
    if "admins" not in user.get("groups", []):
        logger.warning("User '%s' denied access to admin_update_user.", user.get("username"))
        raise HTTPException(status_code=403)
    await rbac.update_user(username, name, email, password if password and password.strip() else None)
    return RedirectResponse(url="/admin", status_code=303)

@router.post("/admin/users/delete")
async def admin_delete_user(username: str = Form(...), user: dict = Depends(get_current_user)):
    if "admins" not in user.get("groups", []):
        logger.warning("User '%s' denied access to admin_delete_user.", user.get("username"))
        raise HTTPException(status_code=403)
    await rbac.delete_user(username)
    return RedirectResponse(url="/admin", status_code=303)

@router.post("/admin/groups/add")
async def admin_add_group(name: str = Form(...), user: dict = Depends(get_current_user)):
    if "admins" not in user.get("groups", []):
        logger.warning("User '%s' denied access to admin_add_group.", user.get("username"))
        raise HTTPException(status_code=403)
    await rbac.create_group(name)
    return RedirectResponse(url="/admin", status_code=303)

@router.post("/admin/groups/rename")
async def admin_rename_group(id: int = Form(...), name: str = Form(...), user: dict = Depends(get_current_user)):
    if "admins" not in user.get("groups", []):
        logger.warning("User '%s' denied access to admin_rename_group.", user.get("username"))
        raise HTTPException(status_code=403)
    await rbac.rename_group(id, name)
    return RedirectResponse(url="/admin", status_code=303)

@router.post("/admin/groups/delete")
async def admin_delete_group(id: int = Form(...), user: dict = Depends(get_current_user)):
    if "admins" not in user.get("groups", []):
        logger.warning("User '%s' denied access to admin_delete_group.", user.get("username"))
        raise HTTPException(status_code=403)
    await rbac.delete_group(id)
    return RedirectResponse(url="/admin", status_code=303)

@router.post("/admin/members/add")
async def admin_add_member(group_name: str = Form(...), username: str = Form(...), user: dict = Depends(get_current_user)):
    if "admins" not in user.get("groups", []):
        logger.warning("User '%s' denied access to admin_add_member.", user.get("username"))
        raise HTTPException(status_code=403)
    await rbac.add_member(group_name, username)
    return {"status": "ok"}

@router.post("/admin/members/remove")
async def admin_remove_member(group_name: str = Form(...), username: str = Form(...), user: dict = Depends(get_current_user)):
    if "admins" not in user.get("groups", []):
        logger.warning("User '%s' denied access to admin_remove_member.", user.get("username"))
        raise HTTPException(status_code=403)
    await rbac.remove_member(group_name, username)
    return {"status": "ok"}

@router.post("/admin/policies/add")
async def admin_add_policy(zone_name: str = Form(...), entity_name: str = Form(...), role: str = Form(...), user: dict = Depends(get_current_user)):
    if "admins" not in user.get("groups", []):
        logger.warning("User '%s' denied access to admin_add_policy.", user.get("username"))
        raise HTTPException(status_code=403)
    await rbac.create_policy(zone_name, entity_name, role)
    return RedirectResponse(url="/admin", status_code=303)

@router.post("/admin/policies/update")
async def admin_update_policy(id: int = Form(...), zone_name: str = Form(...), entity_name: str = Form(...), role: str = Form(...), user: dict = Depends(get_current_user)):
    if "admins" not in user.get("groups", []):
        logger.warning("User '%s' denied access to admin_update_policy.", user.get("username"))
        raise HTTPException(status_code=403)
    await rbac.update_policy(id, zone_name, entity_name, role)
    return RedirectResponse(url="/admin", status_code=303)

@router.post("/admin/policies/delete")
async def admin_delete_policy(id: int = Form(...), user: dict = Depends(get_current_user)):
    if "admins" not in user.get("groups", []):
        logger.warning("User '%s' denied access to admin_delete_policy.", user.get("username"))
        raise HTTPException(status_code=403)
    await rbac.delete_policy(id)
    return RedirectResponse(url="/admin", status_code=303)
