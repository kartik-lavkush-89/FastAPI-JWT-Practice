from dotenv import load_dotenv
import os

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
SENTRY_DSN = os.getenv("SENTRY_DSN")
connected_websockets = set()