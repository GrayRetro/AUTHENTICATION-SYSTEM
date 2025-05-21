import mysql.connector
from passlib.context import CryptContext

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="@SKtamil29",
        database="assignment"
    )

def get_user(username: str):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM authentication WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user

def create_user(username: str, password: str, role: str):
    conn = get_connection()
    cursor = conn.cursor()
    hashed_password = password_context.hash(password)
    cursor.execute(
        "INSERT INTO authentication (username, hashed_password, role) VALUES (%s, %s, %s)",
        (username, hashed_password, role)
    )
    conn.commit()
    cursor.close()
    conn.close()

def verify_password(plain_password: str, hashed_password: str):
    return password_context.verify(plain_password, hashed_password)