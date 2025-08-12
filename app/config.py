from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    app_name: str = "User Management"
    debug: bool = False

def get_settings() -> Settings:
    return Settings()
