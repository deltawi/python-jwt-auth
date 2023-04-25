from datetime import datetime, timedelta
from auth.schemas import TokenData
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from typing import Dict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from auth.models import User

import os
import jwt
import smtplib

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# helper function to verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# helper function to create access token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, os.environ.get('JWT_SECRET_KEY'), algorithm=os.environ.get('JWT_ALGORITHM'))
    return encoded_jwt

def decode_access_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, os.environ.get('JWT_SECRET_KEY'), algorithms=[os.environ.get('JWT_ALGORITHM')])
        email: str = payload.get("sub")
        if email is None:
            raise ValueError("Invalid token")
        token_data = TokenData(email=email)
    except jwt.ExpiredSignatureError:
        raise ValueError("Expired token")
    except jwt.DecodeError:
        raise ValueError("Invalid token")
    except Exception:
        raise ValueError("Could not validate credentials")
    return token_data

def signJWT(data: Dict) -> str:
    payload = {
        'exp': datetime.utcnow() + timedelta(hours=24),
        'iat': datetime.utcnow(),
        'data': data
    }
    encoded_jwt = jwt.encode(payload, os.environ.get('JWT_SECRET_KEY'), algorithm=os.environ.get('JWT_ALGORITHM'))
    return encoded_jwt.decode('utf-8')

def send_verification_email(user: User, base_url: str):
    to = user.email
    verification_link = f"{base_url}/verify-email?token={user.verification_token}"
    message = MIMEMultipart()
    message['From'] = os.environ.get("SMTP_EMAIL")
    message['To'] = to
    message['Subject'] = 'Verify Your Email Address'
    body = f'<pre>\
        Hi {user.username}, <br/>\
        Please click the following link to verify your email address: <br/> \
        <a href="{verification_link}">{verification_link}</a> <br/> <br/> \
        Thanks! <br/> \
        Your App Team </pre>'
    message.attach(MIMEText(body, 'html'))
    text = message.as_string()
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(os.environ.get("SMTP_EMAIL"), os.environ.get("SMTP_NOREPLY_GMAIL_APP_PASSWORD"))
    server.sendmail(os.environ.get("SMTP_EMAIL"), to, text)
    server.quit()