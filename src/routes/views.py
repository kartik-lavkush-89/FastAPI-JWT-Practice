from fastapi import APIRouter, HTTPException, Header, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from src.models.user import Signup, Login, Employee, Get, Time
from src.schemas.user import userEntity, employeeEntity, employeesEntity
from src.decorators.helper import token_required
from dotenv import load_dotenv
from pymongo import MongoClient
from config import SECRET_KEY, connected_websockets
import bcrypt
import jwt
from datetime import datetime, timedelta
import redis


# Load environment variables
load_dotenv()

# Create a new FastAPI router
api = APIRouter()

# Connect to the MongoDB database
conn = MongoClient()

# Connect to the Redis 
redis_cache = redis.Redis(host="localhost", port=6379, db=0)

# Adding HTML files to projcet
templates = Jinja2Templates(directory="src/templates")



# signup route
# adding user details to the database
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


# login route
# verifying user through credentials
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
                "iat": datetime.utcnow(),
                "exp": datetime.utcnow() + timedelta(minutes=10),
            }
            token = jwt.encode(payload, SECRET_KEY, "HS256")
            redis_cache.sadd("all_tokens", token)
            
            for websocket in connected_websockets:
                await websocket.send_text("Token added to all_tokens")
            
            redis_cache.sadd("unrevoked", token)
            # Return the token and a success message
            return {"message": "you_are_logged_in_successfully", "token": token}
        # Raise an exception if the password is incorrect
        raise HTTPException(status_code=404, detail="wrong_password!")
    # Raise an exception if the email doesn't exist
    raise HTTPException(status_code=404, detail="email_doesn't_exist!")



# protected route
# retrieving data from database by verifying user through token
@api.get("/get_data")
async def get_data(token: str = Header(...)):
    # Check if the token is revoked
    if redis_cache.sismember("revoked", token):
        return {"message": "Unauthorized"}
    else:
        # Verify the JWT token and get the user's email
        user_email = token_required(token)
        # Get the user's data from the database
        user_data = conn.tokenPractice.data.find_one({"email": user_email})
        # Return the user's data
        return userEntity(user_data)



# Route to mark token as blacklist
@api.post("/blacklist/b'{token}'")
async def blacklist(token: str):
    # Add the token to the Redis cache saved under revoked list
    redis_cache.sadd("revoked", token)
    for websocket in connected_websockets:
        await websocket.send_text("Token added to revoked")

    # Removing the token from the Redis cache saved under unrevoked list
    redis_cache.srem("unrevoked",token)
    for websocket in connected_websockets:
        await websocket.send_text("Token removed from unrevoked")

    return {"message": "Token is Blacklisted"}



# Route to display All created tokens whie user login
@api.get("/all-tokens", response_class=HTMLResponse)
async def get_all_tokens(request : Request):
# async def get_all_tokens(request : Request, websocket : WebSocket):

    # Retrieve the list of all tokens from Redis cache
    all_tokens = list(redis_cache.smembers("all_tokens"))
    # Retrieve the list of blacklisted tokens from Redis cache
    blacklisted_tokens = list(redis_cache.smembers("revoked"))
    # Retrieve the list of whitelisted tokens from Redis cache
    whitelisted_tokens = list(redis_cache.smembers("unrevoked"))

    for token in all_tokens:
        try:
            payload = jwt.decode(token, SECRET_KEY, "HS256")
            expiration_time = datetime.fromtimestamp(payload.get("exp"))
            if expiration_time < datetime.utcnow():

                # Removing the token from the Redis cache if token expires
                redis_cache.srem("all_tokens", token)
                for websocket in connected_websockets:
                    await websocket.send_text("Token removed from all_tokens")

        except jwt.exceptions.ExpiredSignatureError:
            redis_cache.srem("all_tokens", token)

    return templates.TemplateResponse(
        "all_tokens.html",
        {
            "request" : request,
            "all_tokens" : list(redis_cache.smembers("all_tokens")),
            "blacklisted_tokens": blacklisted_tokens,
            "whitelisted_tokens" : whitelisted_tokens
        }  
    )



# Route to display token values present in redis as 'revoked' 
@api.get("/revoked-tokens", response_class=HTMLResponse)
async def get_blacklisted_tokens(request: Request):
    # Retrieve the list of blacklisted tokens from Redis cache
    revoked_tokens = list(redis_cache.smembers("revoked"))

    return templates.TemplateResponse(
        "revoked_tokens.html", 
        {
            "request": request,
            "revoked_tokens": revoked_tokens
        }
    )



# Route to mark token as whitelist 
@api.post("/whitelist/b'{token}'")
async def whitelist(token: str):
    # Removing the token from the Redis cache saved under revoked list
    redis_cache.srem("revoked",token)
    for websocket in connected_websockets:
        await websocket.send_text("Token removed from revoked")
        
    # Add the token to the Redis cache saved under unrevoked list
    redis_cache.sadd("unrevoked",token)
    for websocket in connected_websockets:
        await websocket.send_text("Token added to unrevoked")

    return {"message": "Token is Whitelisted"}




# Route to display User details extracted from token payload
@api.get("/info/b'{token}'", response_class=HTMLResponse)
async def token_info(request: Request, token: str):

    token_required(token)

    if redis_cache.sismember("revoked", token):
        return templates.TemplateResponse("unauthorized.html", {"request" : request})

    
    # Decode the token to get the payload
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}

    # Extract the relevant information from the payload
    email = payload.get("email")
    info = conn.tokenPractice.data.find_one({"email": email})
    username = info.get("username")
    issued_at = datetime.fromtimestamp(payload.get("iat"))
    expires_at = datetime.fromtimestamp(payload.get("exp"))

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "username": username,
            "email": email,
            "token": token,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
    )




'''  Employee Task   '''

@api.post("/add-employee")
async def add_employee(details : Employee):
    username = conn.database.details.find_one({"username" : details.username})
    email = conn.database.details.find_one({"email" : details.email})
    if not username : 
        if not email :
            data = {
                "username" : details.username,
                "email" : details.email,
                "phone" : details.phone,
                "created_at" : datetime.utcnow()
            }
            conn.database.details.insert_one(dict(data))
            return {
                "message" : "user_added"
            }
        else:
            raise HTTPException(
                status_code=403, 
                detail="email_already_exist!"
                )
    else :
        raise HTTPException(
            status_code=403,
            detail="username_already_exist!"
            )






@api.get("/employee/{username}")
async def get_employee(username: str):
    employee = conn.database.details.find_one({"username": username})
    if employee:
        return employeeEntity(employee)
    else:
        raise HTTPException(
            status_code=404, 
            detail="employee_not_found"
            )




@api.get("/employees-data")
async def paginated_data(details : Time):
    try :
        # convert the 'from_date' and 'to_date' fields in the 'details' object to a datetime object
        from_date = datetime.strptime(details.from_date, '%Y-%m-%d')
        to_date = datetime.strptime(details.to_date, '%Y-%m-%d')

        page = details.page
        page_size = details.page_size

        # skip value to get different values at different page
        skip = (page - 1) * page_size

        # query variable that filters collection based on the 'created_at' field and the 'from_date' and 'to_date' values
        query = {"created_at": {"$gte": from_date, "$lt": to_date}}
        results = conn.database.details.find(query).skip(skip).limit(page_size)
        data = employeesEntity(results)
        if not data:
            return {"error": {
                "message" : "No data found. Please verify page, page_size."
            }}

        return {
            "current_page": page,
            "data": data,
            "next_page": page + 1
        }
    except ValueError:
        return {"error": {
            "message" : "Invalid date format. Please use the format: YYYY-MM-DD."
        }}