from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PDNS_API_URL: str = "http://localhost:8081/api/v1"
    PDNS_API_KEY: str = "your_powerdns_api_key"
    PDNS_SERVER_ID: str = "localhost"
    PDNS_TIMEOUT: float = 10.0
    PDNS_MAX_CONNECTIONS: int = 100
    PDNS_MAX_KEEPALIVE: int = 20
    
    # Authentication
    SECRET_KEY: str = "change-me-in-production"
    LOCAL_USER: str = "admin"
    LOCAL_PASSWORD: str = "password"
    OIDC_CLIENT_ID: str = ""
    OIDC_CLIENT_SECRET: str = ""
    OIDC_DISCOVERY_URL: str = ""

    class Config:
        env_file = ".env"

settings = Settings()
