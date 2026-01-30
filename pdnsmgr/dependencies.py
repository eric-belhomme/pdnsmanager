from fastapi import Request, HTTPException
import logging
from .database import dbmgr
from .client import PowerDNSClient
from .config import settings

logger = logging.getLogger(__name__)

class NotAuthenticated(Exception): pass

async def get_current_user(request: Request):
    user = request.session.get("user")
    if not user:
        logger.debug("get_current_user: User not found in session, raising NotAuthenticated.")
        raise NotAuthenticated()

    # Merge OIDC groups with local RBAC groups
    user = user.copy() # type: ignore
    user["groups"] = await dbmgr.get_user_groups(user.get("username", user.get("name")), user.get("groups", []))
    logger.debug("get_current_user: User '%s' authenticated with groups: %s", user.get("username"), user["groups"])
    return user

async def get_optional_user(request: Request):
    """Returns the current user if authenticated, otherwise None."""
    return request.session.get("user")

#async def get_pdns_client_id(request: Request) -> str:
async def get_powerdns_client(request: Request) -> PowerDNSClient:
    """Detects pDNS Client id (tid) from query param or cookie."""
    pdns_client_id = request.query_params.get("pdns_client_id")
    if not pdns_client_id:
        pdns_client_id = request.cookies.get("pdns_client_id")
    if not pdns_client_id:
        servers = await dbmgr.get_all_pdns_servers()
        pdns_client_id = min(i.tid for i in servers)
    await PowerDNSClient.ping_all()
    return await PowerDNSClient.get_or_create_by_pk(pdns_client_id)

#async def get_powerdns_client() -> PowerDNSClient:
#    """Dependency to provide a PowerDNSClient instance."""
#    # For now, we'll fetch the default server. In a multi-server setup,
#    # this might need to be dynamic based on user context or a selected server.
#      
#    return await PowerDNSClient.get_or_create_by_pk(await get_pdns_client_id())
