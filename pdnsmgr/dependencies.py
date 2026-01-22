from fastapi import Request
from .rbac import rbac

class NotAuthenticated(Exception): pass

async def get_current_user(request: Request):
    user = request.session.get("user")
    if not user:
        raise NotAuthenticated()

    # Merge OIDC groups with local RBAC groups
    user = user.copy()
    user["groups"] = await rbac.get_user_groups(user.get("username", user.get("name")), user.get("groups", []))

    return user
