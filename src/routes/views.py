from fastapi import APIRouter, HTTPException, Header, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from src.models.user import Signup, Login
from src.schemas.user import userEntity
from src.decorators.helper import token_required
from dotenv import load_dotenv
from pymongo import MongoClient
import os
import bcrypt
import jwt
# import datetime
from datetime import datetime, timedelta
import time
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



templates = Jinja2Templates(directory="templates")


#signup route
#adding user details to the database
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



#login route
#verifying user through credentials
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
                "iat" : datetime.utcnow(),
                "exp": datetime.utcnow() + timedelta(minutes=30),
            }
            token = jwt.encode(payload, secret_key, "HS256")
            # Return the token and a success message
            return {"message": "you_are_logged_in_successfully", "token": token}
        # Raise an exception if the password is incorrect
        raise HTTPException(status_code=404, detail="wrong_password!")
    # Raise an exception if the email doesn't exist
    raise HTTPException(status_code=404, detail="email_doesn't_exist!")



# protected route
#retrieving data from database by verifying user through token
@api.get("/get_data")
async def get_data(token: str = Header(...)):

    # Check if the token is revoked
    if redis_cache.sismember("revoked",token):
         return {"message": "Unauthorized"}
    else:
        # Verify the JWT token and get the user's email
        user_email = token_required(token)
        # Get the user's data from the database
        user_data = conn.tokenPractice.data.find_one({"email": user_email})
        # Return the user's data
        return userEntity(user_data)




@api.post("/blacklist/{token}")
async def blacklist(token: str):
    # Add the token to the Redis cache
    redis_cache.sadd("revoked",token)
    
    return {"message": "Token is Blacklisted"}




@api.get("/revoked-tokens",response_class=HTMLResponse)
async def get_blacklisted_tokens(request : Request):
    # Retrieve the list of blacklisted tokens from Redis cache
    revoked_tokens = list(redis_cache.smembers("revoked"))
    
    return templates.TemplateResponse("revoked_tokens.html", {"request": request, "revoked_tokens": revoked_tokens})



@api.post("/whitelist/{token}")
async def whitelist(token: str):
    # Delete the token from the Redis cache
    redis_cache.srem("revoked", token)
    
    return {"message": "Token is Whitelisted"}


@api.get("/info/{token}", response_class=HTMLResponse)
async def token_info(request:Request, token: str):
   
    token_required(token)

    if redis_cache.sismember("revoked",token):
         return {"message": "Unauthorized"}

    else :
    # Decode the token to get the payload
        try:
            payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        except jwt.InvalidTokenError:
            return {"error": "Invalid token"}

        # Extract the relevant information from the payload
        email = payload.get("email")
        info = conn.tokenPractice.data.find_one({"email": email})
        username = info.get("username")
        issued_at = datetime.fromtimestamp(payload.get("iat"))
        expires_at = datetime.fromtimestamp(payload.get("exp"))

        
        return templates.TemplateResponse("index.html",{"request":request, "username" : username,"email" : email, "token" : token, "issued_at" : issued_at, "expires_at" : expires_at})