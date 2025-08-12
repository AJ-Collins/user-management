from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    app_name: str = "User Management"
    debug: bool = False
    max_login_attempts: int = 5

def get_settings() -> Settings:
    return Settings()
