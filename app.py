from fastapi import FastAPI, WebSocketDisconnect, WebSocket
from src.routes.views import api
from config import SENTRY_DSN, connected_websockets
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


# Define a WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # Accept the WebSocket connection
    await websocket.accept()

    # Add the connected WebSocket to the set of connected websockets
    connected_websockets.add(websocket)

    try:
        # Start an infinite loop to listen for incoming messages
        while True:
            # Wait for a message to be received from the client
            message = await websocket.receive_text()

            # Iterate over all connected websockets and send the message to each one
            for client in connected_websockets:
                await client.send_text(message)

    # Handle the case where a WebSocketDisconnect exception is raised
    except WebSocketDisconnect:
        # Remove the disconnected WebSocket from the set of connected websockets
        connected_websockets.remove(websocket)

# Include the api router from views.py
app.include_router(api)


if __name__ == "__main__":
    # Start the application server
    app.run()
