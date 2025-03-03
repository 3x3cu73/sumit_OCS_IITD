from typing import Generator, List, Optional
from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from contextlib import contextmanager
import mysql.connector
from mysql.connector import pooling
import hashlib
from datetime import datetime

# Pydantic Model
class UserBase(BaseModel):
    userid: str
    role: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    cur_role: str
    all_users: List[tuple]
    status:str

# Database connection pool configuration
db_config = {
    "pool_name": "mypool",
    "pool_size": 5,
    "host": "localhost",
    "user": "root",
    "password": "Sumitocs@326#u",
    "database": "ocs"
}

# Create connection pool
connection_pool = mysql.connector.pooling.MySQLConnectionPool(**db_config)

@contextmanager
def get_db_cursor():
    connection = connection_pool.get_connection()
    cursor = connection.cursor()
    try:
        yield cursor
        connection.commit()
    except Exception as e:
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
    finally:
        cursor.close()
        connection.close()

class UserService:
    @staticmethod
    def get_role(cursor, userid: str, hashed_password: str) -> Optional[str]:
        select_query = "SELECT role, password_hash FROM users WHERE userid = %s"
        cursor.execute(select_query, (userid,))
        result = cursor.fetchone()
        
        if result and result[1] == hashed_password:
            return result[0]
        return None

    @staticmethod
    def get_user_data(cursor, user_id: str) -> List[tuple]:
        select_query = "SELECT userid, password_hash, role FROM users WHERE userid = %s"
        cursor.execute(select_query, (user_id,))
        return cursor.fetchall()

    @staticmethod
    def get_all_users(cursor) -> List[tuple]:
        select_query = "SELECT userid, password_hash, role FROM users"
        cursor.execute(select_query)
        return cursor.fetchall()

app = FastAPI(root_path="/api")

@app.post("/ocs/login", response_model=UserResponse)
def login(username: str, password: str):
    with get_db_cursor() as cursor:
        try:
            role = UserService.get_role(cursor, username, password)
            
            if role == "admin":
                return UserResponse(
                    cur_role="admin",
                    all_users=UserService.get_all_users(cursor),
                    status="Success"
                )
            elif role=="basic":
                return UserResponse(
                    cur_role="basic",
                    all_users=UserService.get_user_data(cursor, username),
                    status="Success"
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Invalid credentials"
                )
                
        except mysql.connector.Error as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error: {str(e)}"
            )

# Error handling middleware
@app.middleware("http")
async def db_session_middleware(request, call_next):
    response = await call_next(request)
    return response

# Health check endpoint
@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.now()}
