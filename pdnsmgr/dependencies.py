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

async def get_powerdns_client() -> PowerDNSClient:
    """Dependency to provide a PowerDNSClient instance."""
    # For now, we'll fetch the default server. In a multi-server setup,
    # this might need to be dynamic based on user context or a selected server.
    server_details = await dbmgr.get_pdns_server(settings.PDNS_DEFAULT_SERVER_ID)
    if not server_details:
        logger.error("PowerDNS server details not found for server_id '%s'.", settings.PDNS_DEFAULT_SERVER_ID)
        raise HTTPException(status_code=500, detail="PowerDNS server configuration missing.")
    
    return PowerDNSClient(
        api_url=server_details.api_url,
        api_key=server_details.api_key,
        server_id=server_details.server_id
    )
