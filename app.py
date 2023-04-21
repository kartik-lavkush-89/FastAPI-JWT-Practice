from fastapi import FastAPI, WebSocketDisconnect, WebSocket
from src.routes.views import api
from config import SENTRY_DSN
from dotenv import load_dotenv
import sentry_sdk
from fastapi.staticfiles import StaticFiles
# from sockets import sio_app

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

# app.mount('/all-tokens', app=sio_app)

connected_websockets = set()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_websockets.add(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            for client in connected_websockets:
                await client.send_text(data)
    except WebSocketDisconnect:
        connected_websockets.remove(websocket)

# Include the api router from views.py
app.include_router(api)

if __name__ == "__main__":
    # Start the application server
    app.run()
