from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from utils import create_access_token, verify_token
from database import get_user, verify_password, create_user
from pydantic import BaseModel

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class RegisterUser(BaseModel):
    username: str
    password: str
    role: str

@app.post("/register")
def register_user(user: RegisterUser):
    if get_user(user.username):
        raise HTTPException(status_code=400, detail="Username already exists")
    create_user(user.username, user.password, user.role)
    return {"message": "User registered successfully"}

def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    user = get_user(username)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def has_role(required_role: str):
    def role_checker(user=Depends(get_current_user)):
        if user["role"] != required_role:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return role_checker

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token({"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/admin-only")
async def admin_only_route(user=Depends(has_role("admin"))):
    return {"message": f"Hello Admin {user['username']}!"}

@app.get("/user-only")
async def user_only_route(user=Depends(has_role("user"))):
    return {"message": f"Hello User {user['username']}!"}

@app.get("/public")
async def public_route():
    return {"message": "This is a public route."}