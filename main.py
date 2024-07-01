from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import jwt
from typing import Optional, Annotated

app = FastAPI()

# Секретный ключ для подписи и верификации JWT токенов
# В продакшене используется безопасно сгенерированный ключ, например, с помощью команды 'openssl rand -hex 32',
# и он хранится в защищенном месте.
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"  # Также обычно устанавливается "время жизни" токена (exp)

# Пример данных пользователей, обычно получаемых из базы данных
USERS_DATA = {
    "admin": {"username": "admin", "password": "adminpass", "role": "admin"},
    "user": {"username": "user", "password": "userpass", "role": "user"},
}
# В реальных приложениях пароли хранятся в виде хэшей, с использованием библиотеки вроде 'passlib', и с добавлением
# соли.

# OAuth2PasswordBearer указывает URL для получения токена
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Модель для представления данных пользователя при аутентификации
class User(BaseModel):
    username: str
    password: str
    role: Optional[str] = None  # Роль пользователя (например, 'admin' или 'user')


# Функция для создания JWT токена
def create_jwt_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


# Функция для извлечения пользователя из JWT токена
def get_user_from_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")  # Получение subject из полезной нагрузки токена (обычно содержит username)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# Функция для получения данных пользователя на основе имени пользователя
def get_user(username: str):
    if username in USERS_DATA:
        user_data = USERS_DATA[username]
        return User(**user_data)
    return None


# Эндпоинт для получения JWT токена (аутентификация)
@app.post("/token/")
def login(user_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_data_from_db = get_user(user_data.username)
    if user_data_from_db is None or user_data.password != user_data_from_db.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Генерация JWT токена с username в качестве subject
    return {"access_token": create_jwt_token({"sub": user_data.username})}


# Защищенный эндпоинт для администраторов
@app.get("/admin/")
def get_admin_info(current_user: str = Depends(get_user_from_token)):
    user_data = get_user(current_user)
    if user_data.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    return {"message": "Welcome Admin!"}


# Защищенный эндпоинт для пользователей
@app.get("/user/")
def get_user_info(current_user: str = Depends(get_user_from_token)):
    user_data = get_user(current_user)
    if user_data.role != "user":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    return {"message": "Hello User!"}
