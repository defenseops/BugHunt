from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://pentrascan:password@postgres:5432/pentrascan"

    # Redis
    REDIS_URL: str = "redis://redis:6379/0"

    # Security
    SECRET_KEY: str = "change-me-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Google OAuth
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""

    # OSINT APIs
    SHODAN_API_KEY: str = ""
    CENSYS_API_ID: str = ""
    CENSYS_API_SECRET: str = ""

    # Stripe
    STRIPE_SECRET_KEY: str = ""
    STRIPE_WEBHOOK_SECRET: str = ""
    STRIPE_PRO_PRICE_ID: str = ""

    # Kaspi
    KASPI_API_KEY: str = ""
    KASPI_MERCHANT_ID: str = ""

    # Metasploit RPC
    MSF_RPC_HOST: str = "msfrpcd"
    MSF_RPC_PORT: int = 55553
    MSF_RPC_USER: str = "msf"
    MSF_RPC_PASS: str = "change-me"

    # App
    APP_ENV: str = "development"
    APP_URL: str = "http://localhost"
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:5173"
    MAX_CONCURRENT_SCANS: int = 3
    SCAN_TIMEOUT_SECONDS: int = 3600

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",")]

    class Config:
        env_file = ".env"


settings = Settings()
