from pydantic import BaseModel


# Pydantic models for user Signup and Login
class Signup(BaseModel):
    username: str
    email: str
    phone: int
    password: str


class Login(BaseModel):
    email: str
    password: str
