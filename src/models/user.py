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

# Pydantic models for employee task
class Employee(BaseModel):
    username: str
    email: str
    phone: int

class Get(BaseModel):
    username : str

class Time(BaseModel):
    from_date : str
    to_date : str
    page : int
    page_size : int
