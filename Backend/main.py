from fastapi import FastAPI, HTTPException, Depends, APIRouter, status, Cookie, Response
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from models import TodoList, CompletedList, Users, RefreshToken
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timedelta
from typing import Optional, List
import logging
from fastapi.responses import JSONResponse

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174",
                   "https://todolist-application-9jvne2ayx-abas-imans-projects.vercel.app"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)
app.add_middleware(
    SessionMiddleware,
    secret_key='your-secret-key'  # replace with your actual secret key
)


class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str
    username: str


bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
SECRET_KEY = '194679e3j938492938382883dej3ioms998323ftu933@jd7233!'
ALGORITHM = 'HS256'

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(create_user_request: CreateUserRequest, db: Session = Depends(get_db)):
    try:
        create_user_model = Users(
            username=create_user_request.username,
            email=create_user_request.email,
            hashed_password=bcrypt_context.hash(create_user_request.password),
        )
        db.add(create_user_model)
        db.commit()
    except SQLAlchemyError as e:
        logger.error(f"Error creating user: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create user")
    except Exception as e:
        logger.error(f"Unexpected error creating user: {e}")
        raise HTTPException(status_code=500, detail="Unexpected error")


def create_refresh_token(user_id: int, expires_delta: Optional[timedelta] = None):
    encode = {'id': user_id}
    if expires_delta:
        expires = datetime.utcnow() + expires_delta
        encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


@router.post("/refresh", response_model=Token)
async def refresh_access_token(refresh_token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("id")
        if user_id is None:
            raise HTTPException(
                status_code=401, detail="Invalid refresh token")

        db_token = db.query(RefreshToken).filter(
            RefreshToken.token == refresh_token, RefreshToken.user_id == user_id).first()
        if not db_token or db_token.expires_at < datetime.utcnow():
            raise HTTPException(
                status_code=401, detail="Refresh token expired")

        user = db.query(Users).filter(Users.id == user_id).first()
        new_access_token = create_user_token(
            user.username, user.email, user.id, timedelta(hours=24))

        return {"access_token": new_access_token, "token_type": "bearer"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    try:
        user = authenticate_user(form_data.username, form_data.password, db)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='Incorrect email or password')

        access_token = create_user_token(
            username=user.username,
            email=user.email,
            user_id=user.id,
            expires_delta=timedelta(hours=24)
        )
        refresh_token = create_refresh_token(user.id, timedelta(days=7))
        new_refresh_token = RefreshToken(
            token=refresh_token, user_id=user.id, expires_at=datetime.utcnow() +
            timedelta(days=7)
        )
        db.add(new_refresh_token)
        db.commit()

        response = JSONResponse(content={
            "access_token": access_token, "token_type": "bearer", "username": user.username
        })
        response.set_cookie(key="session_token",
                            value=access_token, httponly=True, secure=True)

        return response
    except Exception as e:
        logger.error(f"Unexpected error during login: {e}")
        raise HTTPException(
            status_code=500, detail="Unexpected error during login")


def authenticate_user(email: str, password: str, db: Session):
    user = db.query(Users).filter(Users.email == email).first()
    if user and bcrypt_context.verify(password, user.hashed_password):
        return user
    return None


def create_user_token(username: str, email: str, user_id: int, expires_delta: Optional[timedelta] = None):
    encode = {'sub': username, 'email': email, 'id': user_id}
    if expires_delta:
        expires = datetime.utcnow() + expires_delta
        encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


class TodoBase(BaseModel):
    newItem: str


class TodoModel(TodoBase):
    id: int

    class Config:
        orm_mode = True


Base.metadata.create_all(bind=engine)


@app.post("/TodoList/", response_model=TodoModel)
async def create_todos(todo: TodoBase, db: Session = Depends(get_db)):
    db_todo = TodoList(newItem=todo.newItem)
    db.add(db_todo)
    db.commit()
    db.refresh(db_todo)
    return db_todo


@app.get("/TodoList/", response_model=List[TodoModel])
async def get_todos(db: Session = Depends(get_db)):
    return db.query(TodoList).all()


@app.delete("/TodoList/{todo_id}/", response_model=TodoModel)
async def delete_todo(todo_id: int, db: Session = Depends(get_db)):
    db_todo = db.query(TodoList).filter(TodoList.id == todo_id).first()
    if db_todo is None:
        raise HTTPException(status_code=404, detail="Todo not found")
    db.delete(db_todo)
    db.commit()
    return db_todo


@app.put("/TodoList/{todo_id}/", response_model=TodoModel)
async def update_todo(todo_id: int, todo: TodoBase, db: Session = Depends(get_db)):
    db_todo = db.query(TodoList).filter(TodoList.id == todo_id).first()
    if db_todo is None:
        raise HTTPException(status_code=404, detail="Todo not found")
    db_todo.newItem = todo.newItem
    db.commit()
    db.refresh(db_todo)
    return db_todo


@app.delete("/TodoList/", response_model=None)
async def clear_todo_list(db: Session = Depends(get_db)):
    try:
        db.query(TodoList).delete()
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


class CompletedBase(BaseModel):
    completedItem: str


class CompletedModel(CompletedBase):
    id: int

    class Config:
        orm_mode = True


@app.post("/CompletedList/", response_model=CompletedModel)
async def create_completed(completed: CompletedBase, db: Session = Depends(get_db)):
    db_completed = CompletedList(completedItem=completed.completedItem)
    db.add(db_completed)
    db.commit()


app.include_router(router)
