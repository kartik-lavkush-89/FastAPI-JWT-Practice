import jwt
import os
from fastapi import Header, HTTPException
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get the secret key from environment variables
secret_key = os.getenv("SECRET_KEY")


# Create a function to verify the JWT token
def token_required(token: str = Header(...)):
    try:
        # Verify the JWT token with the secret key and algorithm
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        # Return the email from the payload
        return payload["email"]
    except:
        # Raise an HTTP exception if the JWT token is invalid or expired
        raise HTTPException(status_code=401, detail="Invalid or expired token")
