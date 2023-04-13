from fastapi import FastAPI
from src.routes.views import api
import os
from dotenv import load_dotenv
import sentry_sdk


load_dotenv()

# Initialize Sentry SDK for error logging and tracing
sentry_sdk.init(
    dsn=os.getenv("SENTRY_DSN"),
    traces_sample_rate=1.0,
)

"""MAIN APP FILE"""

# Initialize the FastAPI app
app = FastAPI()

# Include the api router from views.py
app.include_router(api)

if __name__ == "__main__":
    # Start the application server
    app.run()
