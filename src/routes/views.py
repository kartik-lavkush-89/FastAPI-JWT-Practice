from fastapi import APIRouter, HTTPException, Header
from src.models.user import Signup, Login
from src.schemas.user import userEntity
from src.decorators.helper import token_required
from dotenv import load_dotenv
from pymongo import MongoClient
import os
import bcrypt
import jwt
import datetime
import redis


# Load environment variables
load_dotenv()

# Get the secret key from the environment variables
secret_key = os.getenv("SECRET_KEY")

# Create a new FastAPI router
api = APIRouter()

# Connect to the MongoDB database
conn = MongoClient()

# Connect to the Redis cache
redis_cache = redis.Redis(host="localhost", port=6379, db=0)




@api.post("/signup")
async def signup(user: Signup):
    # Check if the phone number already exists
    phone_number = conn.tokenPractice.data.find_one({"phone": user.phone})
    if not phone_number:
        # Check if the email already exists
        email_id = conn.tokenPractice.data.find_one({"email": user.email})
        if not email_id:
            # Hash the user's password
            hashed_password = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt())
            # Create a new user document
            data = {
                "username": user.username,
                "email": user.email,
                "phone": user.phone,
                "password": hashed_password,
            }
            conn.tokenPractice.data.insert_one(dict(data))
            # Return a success message
            return {
                "message": "user_verified!",
                "success": "user_regitered_successfully",
            }
        else:
            # Raise an exception if the email already exists
            raise HTTPException(status_code=404, detail="email_already_exist!")
    else:
        # Raise an exception if the phone number already exists
        raise HTTPException(status_code=404, detail="phone_already_exist!")




@api.post("/login")
async def login(details: Login):
    # Check if the email exists
    email_id = conn.tokenPractice.data.find_one({"email": details.email})
    if email_id:
        # Get the hashed password from the user document
        pwd = email_id.get("password")
        # Check if the password matches the hashed password
        if bcrypt.checkpw(details.password.encode(), pwd):
            # Create a new JWT token
            payload = {
                "email": details.email,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
            }
            token = jwt.encode(payload, secret_key, "HS256")
            # Return the token and a success message
            return {"message": "you_are_logged_in_successfully", "token": token}
        # Raise an exception if the password is incorrect
        raise HTTPException(status_code=404, detail="wrong_password!")
    # Raise an exception if the email doesn't exist
    raise HTTPException(status_code=404, detail="email_doesn't_exist!")



# protected route
@api.get("/get_data")
async def get_data(token: str = Header(...)):
    # Check if the token is revoked
    if redis_cache.exists(token):
        return {"message": "Unauthorized"}
    else:
        # Verify the JWT token and get the user's email
        user_email = token_required(token)
        # Get the user's data from the database
        user_data = conn.tokenPractice.data.find_one({"email": user_email})
        # Return the user's data
        return userEntity(user_data)




# logout route
# blacklisting the token for one hour time using redis
@api.get("/logout")
async def logout(token: str = Header(...)):
    # Store the revoked token in the Redis cache with the expire time in seconds
    redis_cache.set(token, "revoked", ex=3600)

    # Return a success message indicating that the user has been logged out
    return {"message": "Logout successful"}
