from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PDNS_API_URL: str = "http://localhost:8081/api/v1"
    PDNS_API_KEY: str = "votre_cle_api_powerdns"
    PDNS_SERVER_ID: str = "localhost"

    class Config:
        env_file = ".env"

settings = Settings()
