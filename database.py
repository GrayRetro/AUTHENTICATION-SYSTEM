from typing import Dict
from passlib.context import CryptContext

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

fake_users_db: Dict[str, dict] = {
    "admin": {
        "username": "admin",
        "hashed_password": password_context.hash("admin123"),
        "role": "admin"
    },
    "user": {
        "username": "user",
        "hashed_password": password_context.hash("user123"),
        "role": "user"
    }
}

def get_user(username: str):
    return fake_users_db.get(username)

def verify_password(plain_password: str, hashed_password: str):
    return password_context.verify(plain_password, hashed_password)