from pydantic import BaseSettings


class Settings(BaseSettings):
    LOG_LEVEL: str = "WARNING"
    REDIS_SOCKET: str = "127.0.0.1:6379"
    POSTGRES_URI: str = "postgresql://postgres@127.0.0.1:5432/auth"
    DEBUG: bool = False
    SECRET_KEY: str

    JWT_PRIVATE_KEY: str
    JWT_PUBLIC_KEY: str

    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


config = Settings()
