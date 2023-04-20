from fastapi import FastAPI
from src.routes.views import api
from config import SENTRY_DSN
from dotenv import load_dotenv
import sentry_sdk
from fastapi.staticfiles import StaticFiles


# Load environment variables
load_dotenv()

# Initialize Sentry SDK for error logging and tracing
sentry_sdk.init(
    dsn=SENTRY_DSN,
    traces_sample_rate=1.0,
)


"""MAIN APP FILE"""


# Initialize the FastAPI app
app = FastAPI()

# Adding css files to the project
app.mount("/static", StaticFiles(directory="src/static"), name="static")


# Include the api router from views.py
app.include_router(api)

if __name__ == "__main__":
    # Start the application server
    app.run()
