from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidSignatureError, ExpiredSignatureError
from jose import JWTError
from auth.auth_handler import create_access_token, decode_access_token, verify_password
from database.base import get_db, get_user, get_user_by_email, create_user as crud_create_user, authenticate_user
from auth.models import User
from auth.schemas import UserCreate, TokenData, UserLogin

auth_router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = decode_access_token(token=token)
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")
        token_data = TokenData(username=username)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")

    user = get_user(db, username=token_data.username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")
    return user

# authenticate user and create access token
@auth_router.post("/login/")
async def login_user(request: UserLogin, db: Session = Depends(get_db)):
    user = await authenticate_user(db, email=request.email, password=request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    print(user)
    access_token = create_access_token(data={'username': user.username, 'email': user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@auth_router.get("/users/me")
def read_current_user(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return current_user

""" @auth_router.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    if not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"} """

# protected route that requires authentication
@auth_router.get("/protected")
async def protected_route(token: str = Depends(oauth2_scheme)):
    try:
        decoded_token = decode_access_token(token=token)
        username = decoded_token["username"]
        user = get_user(username)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return {"message": "You are authenticated!"}
    except (InvalidSignatureError, ExpiredSignatureError):
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

# route for User registration
@auth_router.post("/register/")
async def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return crud_create_user(db, user)

# route to handle email verification link
@auth_router.get('/verify-email')
async def verify_email(token: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.verification_token == token).first()
    if user:
        user.email_verified = True
        user.verification_token = None
        db.commit()
        return {'message': 'Email verified'}
    else:
        raise HTTPException(status_code=400, detail='Invalid verification token')

