from fastapi import Request
import logging
from .database import dbmgr

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
