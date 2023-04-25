from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from auth.models import User
from auth.schemas import UserCreate
from auth.auth_handler import pwd_context, send_verification_email

import os
import secrets


# create SQLAlchemy engine and session
SQLALCHEMY_DATABASE_URL = os.environ.get("SQLALCHEMY_DATABASE_URL")
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def create_user(db: Session, user: UserCreate):
    hashed_password = pwd_context.hash(user.password)
    verification_token = secrets.token_urlsafe(32)
    db_user = User(
        username=user.username, 
        email=user.email, 
        hashed_password=hashed_password,
        verification_token=verification_token
        )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    send_verification_email(user=db_user, base_url='localhost:8000')
    return db_user

async def authenticate_user(db, email: str, password: str):
    user = get_user_by_email(db, email)
    if not user:
        return False
    if not pwd_context.verify(password, user.hashed_password):
        return False
    return user

