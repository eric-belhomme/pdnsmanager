from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Removed PDNS_API_URL, PDNS_API_KEY, PDNS_SERVER_ID
    PDNS_DEFAULT_SERVER_ID: str = "localhost"
    PDNS_DEFAULT_API_URL: str = "http://localhost:8081/api/v1"
    PDNS_DEFAULT_API_KEY: str = "your_powerdns_api_key"

    PDNS_TIMEOUT: float = 10.0
    PDNS_MAX_CONNECTIONS: int = 100
    PDNS_MAX_KEEPALIVE: int = 20
    
    # Authentication
    SECRET_KEY: str = "change-me-in-production"
    OIDC_CLIENT_ID: str = ""
    OIDC_CLIENT_SECRET: str = ""
    OIDC_DISCOVERY_URL: str = ""
    SESSION_MAX_AGE: int = 3600
    DATABASE_URL: str = "sqlite+aiosqlite:///rbac.db"

    class Config:
        env_file = ".env"

settings = Settings()
