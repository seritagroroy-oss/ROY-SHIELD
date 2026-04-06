import os

from dotenv import load_dotenv

load_dotenv()

APP_VERSION = "2.1"
APP_ENV = os.getenv("ROY_SHIELD_ENV", "development")
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ROY_SHIELD_ALLOWED_ORIGINS", "*").split(",")
    if origin.strip()
]
FETCH_TIMEOUT = float(os.getenv("ROY_SHIELD_FETCH_TIMEOUT", "8"))
SSL_TIMEOUT = float(os.getenv("ROY_SHIELD_SSL_TIMEOUT", "5"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("ROY_SHIELD_RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_SCAN = int(os.getenv("ROY_SHIELD_RATE_LIMIT_SCAN", "20"))
RATE_LIMIT_REPORTS = int(os.getenv("ROY_SHIELD_RATE_LIMIT_REPORTS", "12"))
RATE_LIMIT_AUTH = int(os.getenv("ROY_SHIELD_RATE_LIMIT_AUTH", "8"))
WEBHOOK_URL = os.getenv("ROY_SHIELD_WEBHOOK_URL", "").strip()
ADMIN_TOKEN = os.getenv("ROY_SHIELD_ADMIN_TOKEN", "").strip()
