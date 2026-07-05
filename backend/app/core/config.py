from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    app_name: str = "CCVM"
    app_version: str = "0.3.0"
    db_host: str = "postgres"
    db_port: int = 5432
    db_name: str = "ccvm"
    db_user: str = "ccvm"
    db_pass: str = "ChangeMeStrongPassword"

    @property
    def database_url(self) -> str:
        return f"postgresql://{self.db_user}:{self.db_pass}@{self.db_host}:{self.db_port}/{self.db_name}"

settings = Settings()
