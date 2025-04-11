from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas.user import Token, UserCreate, UserInDB
from app.models.user import User
from app.utils.security import (
    hash_password,
    verify_password,
    create_access_token
)
from config.database import get_db

router = APIRouter(tags=["Authentication"])

@router.post("/register", response_model=UserInDB)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    existing_user = await User.get_by_email(db, user.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email уже зарегистрирован"
        )
    
    hashed_password = hash_password(user.password)
    new_user = User(
        email=user.email,
        username=user.username,
        hashed_password=hashed_password
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user

@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    user = await User.get_by_email(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный email или пароль",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}