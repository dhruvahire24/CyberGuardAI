import os
from dataclasses import dataclass, field
from typing import Mapping, Optional, Tuple
from urllib.parse import urlsplit

from dotenv import load_dotenv


def get_cors_origins(environment: str, configured_origins: Optional[str]) -> list[str]:
    is_production = environment.lower() in ("production", "prod")
    if configured_origins is not None:
        origins = []
        for value in configured_origins.split(","):
            origin = value.strip().rstrip("/")
            if not origin:
                continue
            parsed = urlsplit(origin)
            if (
                origin == "*"
                or "*" in origin
                or parsed.scheme not in ("http", "https")
                or not parsed.netloc
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path
                or parsed.query
                or parsed.fragment
                or (is_production and parsed.scheme != "https")
            ):
                raise ValueError("CYBERGUARD_CORS_ORIGINS must contain valid origins.")
            _ = parsed.port
            origins.append("{}://{}".format(parsed.scheme, parsed.netloc))
        return list(dict.fromkeys(origins))

    if is_production:
        return []

    return [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]


@dataclass(frozen=True)
class Settings:
    app_env: str
    database_url: str = field(repr=False)
    gemini_api_key: Optional[str] = field(default=None, repr=False)
    cors_origins: Tuple[str, ...] = ()

    @property
    def is_production(self) -> bool:
        return self.app_env in ("production", "prod")

    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> "Settings":
        if environ is None:
            load_dotenv()
            environ = os.environ

        app_env = environ.get("CYBERGUARD_ENV", "development").strip().lower()
        if app_env not in ("development", "dev", "test", "production", "prod"):
            raise ValueError("CYBERGUARD_ENV must be development, test, or production.")

        database_url = environ.get("DATABASE_URL", "sqlite:///./cyberguard.db").strip()
        if database_url.startswith("postgres://"):
            database_url = "postgresql+psycopg://" + database_url[len("postgres://"):]
        elif database_url.startswith("postgresql://"):
            database_url = "postgresql+psycopg://" + database_url[len("postgresql://"):]

        if not database_url:
            raise ValueError("DATABASE_URL must be configured.")
        if app_env in ("production", "prod") and not database_url.startswith(
            "postgresql+psycopg://"
        ):
            raise ValueError("Production requires a PostgreSQL DATABASE_URL.")

        cors_origins = get_cors_origins(
            app_env,
            environ.get("CYBERGUARD_CORS_ORIGINS"),
        )

        return cls(
            app_env=app_env,
            database_url=database_url,
            gemini_api_key=environ.get("GEMINI_API_KEY") or None,
            cors_origins=tuple(cors_origins),
        )

    def get_gemini_api_key(self) -> Optional[str]:
        load_dotenv()
        return os.getenv("GEMINI_API_KEY") or self.gemini_api_key


settings = Settings.from_env()
