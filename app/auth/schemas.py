from typing import Optional
from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    username: str
    email: str
    password: str


class UserLogin(UserBase):
    email: str
    password: str


class TokenData(BaseModel):
    email: Optional[EmailStr] = None
