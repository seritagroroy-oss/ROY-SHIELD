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
