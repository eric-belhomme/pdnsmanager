from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from .config import settings
from .utils import templates, get_locale, TRANSLATIONS # Cette ligne reste inchangée
from .dependencies import NotAuthenticated, get_current_user, get_optional_user
from .routes import router as zones_router
from .database import dbmgr
from . import BASE_DIR

import logging

__version__ = "0.0.1"

logger = logging.getLogger(__name__)

app = FastAPI(title="PowerDNS Manager")
app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY, max_age=settings.SESSION_MAX_AGE)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

app.include_router(zones_router)


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
    logger.info("OIDC authentication configured: client_id=%s, discovery_url=%s", settings.OIDC_CLIENT_ID, settings.OIDC_DISCOVERY_URL)
else:
    logger.info("OIDC authentication not configured (OIDC_CLIENT_ID or OIDC_DISCOVERY_URL missing).")


# --- Event Handlers ---

@app.on_event("startup")
async def startup_event(): # type: ignore
    # Basic logging configuration
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
    logger.info("Application startup event triggered.")
    logger.info("Initializing database.")
    await dbmgr.init_db()


@app.exception_handler(NotAuthenticated)
async def not_authenticated_exception_handler(request: Request, exc: NotAuthenticated):
    logging.getLogger(__name__).warning("User not authenticated, redirecting to login page.")
    return RedirectResponse(url="/login")

# --- Auth Routes ---

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, user: dict | None = Depends(get_optional_user)):
    if user: # If already logged in, redirect to home
        return RedirectResponse(url="/")
    lang = get_locale(request)
    _ = lambda key: TRANSLATIONS[lang].get(key, key)
    return templates.TemplateResponse("login.html", {
        "request": request, 
        "lang": lang, 
        "_": _,
        "oidc_enabled": bool(settings.OIDC_CLIENT_ID),
    })

@app.post("/login")
async def login_local(request: Request, username: str = Form(...), password: str = Form(...)):
    lang = get_locale(request)
    _ = lambda key: TRANSLATIONS[lang].get(key, key)
    
    user = await dbmgr.get_user(username)
    if user and user.type == "local" and user.password_hash and dbmgr.verify_password(password, user.password_hash):
        logging.getLogger(__name__).info("Local user '%s' logged in successfully.", username)
        request.session["user"] = {"name": user.name, "username": user.username, "type": "local", "groups": []}
        return RedirectResponse(url="/", status_code=303)
    logging.getLogger(__name__).warning("Local login failed for user '%s'.", username)
    
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
        logging.getLogger(__name__).warning("OIDC login attempted but OIDC is not configured.")
        return RedirectResponse(url="/login")
    redirect_uri = request.url_for('auth_callback')
    return await oauth.oidc.authorize_redirect(request, redirect_uri)

@app.get("/auth/callback")
async def auth_callback(request: Request):
    try:
        token = await oauth.oidc.authorize_access_token(request)
        logging.getLogger(__name__).debug("OIDC token received.")
        user_info = token.get('userinfo')
        # Use preferred_username, email or sub as unique identifier
        username = user_info.get("preferred_username") or user_info.get("email") or user_info.get("sub")
        
        # Sync OIDC user and groups to DB
        await dbmgr.sync_oidc_user(username, user_info.get("name"), user_info.get("email"), user_info.get("groups", []))
        
        request.session["user"] = {
            "name": user_info.get("name", username), 
            "username": username,
            "email": user_info.get("email"), 
            "type": "oidc",
            "groups": user_info.get("groups", []),
            "oidc_info": dict(user_info)
        }
        logging.getLogger(__name__).info("OIDC user '%s' logged in successfully.", username)
        return RedirectResponse(url="/")
    except Exception as e:
        logging.getLogger(__name__).error("OIDC authentication callback failed: %s", e, exc_info=True)
        return RedirectResponse(url=f"/login?error={str(e)}")

@app.get("/profile", response_class=HTMLResponse)
async def profile(request: Request, user: dict = Depends(get_current_user)):
    lang = get_locale(request)
    _ = lambda key: TRANSLATIONS[lang].get(key, key)
    
    db_user = await dbmgr.get_user(user["username"])
    if db_user:
        user["name"] = db_user.name
        user["email"] = db_user.email
    logging.getLogger(__name__).debug("Viewing profile for user '%s'.", user.get("username"))
    
    return templates.TemplateResponse("profile.html", {
        "request": request,
        "user": user,
        "lang": lang,
        "_": _
    })

@app.post("/profile/update")
async def update_profile(request: Request, name: str = Form(...), email: str = Form(None), password: str = Form(None), user: dict = Depends(get_current_user)):
    if user.get("type") != "local":
        return RedirectResponse(url="/profile", status_code=303)
    logging.getLogger(__name__).info("User '%s' attempting to update profile.", user.get("username"))
    await dbmgr.update_user(user["username"], name, email, password if password and password.strip() else None)
    # Update session
    request.session["user"]["name"] = name
    logging.getLogger(__name__).info("User '%s' profile updated successfully.", user.get("username"))
    return RedirectResponse(url="/profile", status_code=303)

@app.get("/logout")
async def logout(request: Request):
    username = request.session.get("user", {}).get("username", "unknown")
    request.session.pop("user", None)
    logging.getLogger(__name__).info("User '%s' logged out.", username)
    return RedirectResponse(url="/login")

def main():
    import uvicorn
    logging.getLogger(__name__).info("Starting Uvicorn server.")
    uvicorn.run(app, host="127.0.0.1", port=8000)
